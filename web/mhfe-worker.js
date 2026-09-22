import { initSync, MhfeEngine, suiteParametersJson } from './wasm/mhfe.js';

let engine = null;
let enginePim = null;
let initialized = false;
let maxPim = 31;

function closeEngine() {
  if (engine !== null) engine.free();
  engine = null;
  enginePim = null;
}

function requireInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`INVALID_REQUEST: ${label} must be a non-negative integer.`);
  return value;
}

function requireSourceWords(value) {
  const words = requireInteger(value, 'sourceWords');
  if (![12, 15, 18, 21, 24].includes(words)) {
    throw new Error('INVALID_SOURCE_WORDS: sourceWords must be 12, 15, 18, 21, or 24.');
  }
  return words;
}

function ensureEngine(pim) {
  const selected = requireInteger(pim, 'pim');
  if (selected > maxPim) {
    throw new Error(`INVALID_PIM: PIM must be an integer from 0 through ${maxPim}.`);
  }
  if (engine !== null && enginePim === selected) return engine;
  closeEngine();
  engine = new MhfeEngine(selected);
  enginePim = selected;
  return engine;
}

function parseError(error) {
  const message = error instanceof Error ? error.message : String(error);
  const match = /^([A-Z][A-Z0-9_]+):\s*(.*)$/su.exec(message);
  return match === null ? { code: 'WORKER_FAILURE', message } : { code: match[1], message: match[2] };
}

function normalizedBytes(request) {
  if (!(request.passwordUtf8 instanceof Uint8Array)) {
    throw new Error('INVALID_REQUEST: passwordUtf8 must be a Uint8Array.');
  }
  return request.passwordUtf8;
}

function runWithPassword(selected, request, operation) {
  if (typeof request.passwordAscii === 'string') {
    selected.setAsciiPassword(request.passwordAscii);
  } else {
    const password = normalizedBytes(request);
    try {
      selected.setPreNormalizedPassword(password);
    } finally {
      password.fill(0);
    }
  }
  try {
    return JSON.parse(operation());
  } finally {
    selected.clearPassword();
  }
}

function execute(request) {
  if (!initialized) throw new Error('WORKER_NOT_READY: WASM is not initialized.');
  switch (request.type) {
    case 'parameters':
      return JSON.parse(suiteParametersJson());
    case 'encrypt': {
      const selected = ensureEngine(request.pim);
      return runWithPassword(selected, request, () => selected.encryptJson(request.mnemonic));
    }
    case 'decrypt': {
      const selected = ensureEngine(request.pim);
      const sourceWords = requireSourceWords(request.sourceWords);
      return runWithPassword(selected, request, () => selected.decryptJson(request.container, sourceWords));
    }
    case 'decryptAuto': {
      const selected = ensureEngine(request.pim);
      return runWithPassword(selected, request, () => selected.decryptAutoJson(request.container));
    }
    case 'dispose':
      closeEngine();
      return null;
    default:
      throw new Error(`INVALID_REQUEST: unsupported operation ${String(request.type)}.`);
  }
}

self.addEventListener('message', (event) => {
  const request = event.data;
  if (request?.type === 'initialize' && !('id' in request)) {
    try {
      if (initialized) throw new Error('INVALID_REQUEST: Worker is already initialized.');
      initSync({ module: request.module });
      initialized = true;
      const parameters = JSON.parse(suiteParametersJson());
      maxPim = parameters.maxPim;
      self.postMessage({ type: 'ready', parameters });
    } catch (error) {
      self.postMessage({ type: 'initializationError', error: parseError(error) });
    }
    return;
  }
  const id = request?.id;
  if (!Number.isSafeInteger(id) || id < 0) return;
  try {
    self.postMessage({ id, ok: true, type: request.type, result: execute(request) });
  } catch (error) {
    self.postMessage({ id, ok: false, type: request?.type ?? 'unknown', error: parseError(error) });
  }
});
