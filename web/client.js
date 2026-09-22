export class MhfeWorkerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MhfeWorkerError';
    this.code = code;
  }
}

export class MhfeCancelledError extends Error {
  constructor(message = 'MHFE operation cancelled.') {
    super(message);
    this.name = 'MhfeCancelledError';
  }
}

export class MhfeWorkerClient {
  #worker;
  #nextId = 1;
  #pending = new Map();
  #ready;
  #resolveReady;
  #rejectReady;
  #terminated = false;
  #maxPim = 31;

  static fromUrl(url, wasmModuleOrBytes) {
    return new MhfeWorkerClient(
      new Worker(url, { type: 'module', name: 'mhfe-backup' }),
      wasmModuleOrBytes,
    );
  }

  constructor(worker, wasmModuleOrBytes) {
    let prepared;
    try {
      prepared = prepareWasmModule(wasmModuleOrBytes);
    } catch (error) {
      worker.terminate();
      throw error;
    }
    this.#worker = worker;
    this.#ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
    // A caller may cancel immediately without ever awaiting ready(). Keep the
    // original promise rejectable for callers while marking that rejection as
    // observed so cancellation cannot create an unhandled-rejection event.
    this.#ready.catch(() => {});
    worker.addEventListener('message', (event) => {
      const response = event.data;
      if (response?.type === 'ready' && !('id' in response)) {
        this.#maxPim = response.parameters.maxPim;
        this.#resolveReady(response.parameters);
        return;
      }
      if (response?.type === 'initializationError' && !('id' in response)) {
        const failure = new MhfeWorkerError(response.error.code, response.error.message);
        this.#terminated = true;
        this.#worker.terminate();
        this.#rejectReady(failure);
        this.#failAll(failure);
        return;
      }
      const pending = this.#pending.get(response?.id);
      if (pending === undefined) return;
      this.#pending.delete(response.id);
      if (response.ok) pending.resolve(response.result);
      else pending.reject(new MhfeWorkerError(response.error.code, response.error.message));
    });
    worker.addEventListener('error', (event) => {
      const failure = new Error(event.message || 'MHFE Worker stopped unexpectedly.');
      this.#terminated = true;
      this.#worker.terminate();
      this.#rejectReady(failure);
      this.#failAll(failure);
    });
    worker.addEventListener('messageerror', () => {
      const failure = new Error('MHFE Worker returned an unreadable message.');
      this.#terminated = true;
      this.#worker.terminate();
      this.#rejectReady(failure);
      this.#failAll(failure);
    });
    const { module, transfer } = prepared;
    try {
      worker.postMessage({ type: 'initialize', module }, transfer);
    } catch (error) {
      wipeTransferBuffers(transfer);
      this.#terminated = true;
      worker.terminate();
      this.#rejectReady(error);
    }
  }

  ready() {
    return this.#ready;
  }

  parameters() {
    return this.#request({ type: 'parameters' });
  }

  encryptAscii(mnemonic, passwordAscii, pim = 0) {
    requirePim(pim, this.#maxPim);
    return this.#request({ type: 'encrypt', mnemonic, passwordAscii, pim });
  }

  decryptAscii(container, sourceWords, passwordAscii, pim = 0) {
    requirePim(pim, this.#maxPim);
    return this.#request({ type: 'decrypt', container, sourceWords, passwordAscii, pim });
  }

  decryptAsciiAuto(container, passwordAscii, pim = 0) {
    requirePim(pim, this.#maxPim);
    return this.#request({ type: 'decryptAuto', container, passwordAscii, pim });
  }

  encryptPreNormalizedUtf8(mnemonic, passwordUtf8, pim = 0) {
    requirePim(pim, this.#maxPim);
    requireUint8Array(passwordUtf8);
    const password = passwordUtf8.slice();
    return this.#request({ type: 'encrypt', mnemonic, passwordUtf8: password, pim }, [password.buffer]);
  }

  decryptPreNormalizedUtf8(container, sourceWords, passwordUtf8, pim = 0) {
    requirePim(pim, this.#maxPim);
    requireUint8Array(passwordUtf8);
    const password = passwordUtf8.slice();
    return this.#request(
      { type: 'decrypt', container, sourceWords, passwordUtf8: password, pim },
      [password.buffer],
    );
  }

  decryptPreNormalizedUtf8Auto(container, passwordUtf8, pim = 0) {
    requirePim(pim, this.#maxPim);
    requireUint8Array(passwordUtf8);
    const password = passwordUtf8.slice();
    return this.#request(
      { type: 'decryptAuto', container, passwordUtf8: password, pim },
      [password.buffer],
    );
  }

  disposeEngine() {
    return this.#request({ type: 'dispose' });
  }

  cancel() {
    this.terminate(new MhfeCancelledError());
  }

  terminate(reason = new MhfeCancelledError('MHFE Worker terminated.')) {
    if (this.#terminated) return;
    this.#terminated = true;
    this.#worker.terminate();
    this.#rejectReady(reason);
    this.#failAll(reason);
  }

  #request(request, transfer = []) {
    if (this.#terminated) return Promise.reject(new MhfeCancelledError('MHFE Worker is unavailable.'));
    const id = this.#nextId++;
    return this.#ready.then(
      () => {
        if (this.#terminated) throw new MhfeCancelledError('MHFE Worker is unavailable.');
        return new Promise((resolve, reject) => {
          this.#pending.set(id, { resolve, reject });
          try {
            this.#worker.postMessage({ id, ...request }, transfer);
          } catch (error) {
            this.#pending.delete(id);
            wipeTransferBuffers(transfer);
            reject(error);
          }
        });
      },
    );
  }

  #failAll(error) {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }
}

function requireUint8Array(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError('passwordUtf8 must be a Uint8Array.');
  }
}

function requirePim(value, maxPim) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maxPim) {
    throw new RangeError(`pim must be an integer from 0 through ${maxPim}.`);
  }
}

function prepareWasmModule(value) {
  if (value instanceof WebAssembly.Module) return { module: value, transfer: [] };
  if (value instanceof Uint8Array) {
    const bytes = value.slice();
    return { module: bytes, transfer: [bytes.buffer] };
  }
  if (value instanceof ArrayBuffer) {
    const buffer = value.slice(0);
    return { module: buffer, transfer: [buffer] };
  }
  throw new TypeError('wasmModuleOrBytes must be a WebAssembly.Module, Uint8Array, or ArrayBuffer.');
}

function wipeTransferBuffers(buffers) {
  for (const buffer of buffers) {
    if (buffer instanceof ArrayBuffer && buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
  }
}
