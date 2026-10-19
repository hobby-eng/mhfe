// @ts-check
/** @import { LongOptions } from "../types/client-shared.d.ts" */
import { FAST_MODE, STANDARD_MODE, HIGHEST_BROWSER_MEMORY_LEVEL, CORE_MODULE } from "./values.js";
import { requireSettings, requireRepetition } from "./input.js";
import {
  OperationSlot,
  CompiledModule,
  WorkerJob,
  requireCallback,
  encodeSecret,
  SecretRequest,
  InputTextBoundary,
} from "../../runtime/runtime.js";
/** @import { MhfeSources } from "../client.d.ts" */
/** @import { WorkerRequest } from "../../runtime/runtime.js" */

/** CoreRuntime owns this operation group behind the client's shared worker boundary. */
export class CoreRuntime {
  /** @type {Omit<MhfeSources, "wasm">} */
  #sources;
  /** @type {CompiledModule} */
  #wasm;
  #slot = new OperationSlot();
  #inputText = new InputTextBoundary(() => this.quick({ operation: "parameters" }));
  /** @type {() => Promise<void>} */
  #readyGate;
  /** @param {Partial<MhfeSources> | undefined} sources
   * @param {() => Promise<void>} ready */
  constructor({ workerSource, wasm, argon2Threaded, argon2SingleThreaded } = {}, ready) {
    for (const [name, value] of Object.entries({
      workerSource,
      argon2Threaded,
      argon2SingleThreaded,
    })) {
      if (typeof value !== "string" || value.length === 0)
        throw new TypeError(`${name} must be the text of the file.`);
    }
    this.#wasm = new CompiledModule(wasm, "wasm");
    // The loop above checked that each is text.
    this.#sources = /** @type {Omit<MhfeSources, "wasm">} */ ({
      workerSource,
      argon2Threaded,
      argon2SingleThreaded,
    });
    this.#readyGate = ready;
  }
  /** The shared compiled module, without making another instance. */
  get wasm() {
    return this.#wasm;
  }
  /** The reviewed worker source for check-only jobs. */
  get workerSource() {
    return this.#sources.workerSource;
  }
  /** Resolves after the owning client has passed its startup check. */
  ready() {
    return this.#readyGate();
  }
  /**
   * "fast" on a cross-origin isolated page, otherwise "standard" (about three times slower).
   * @returns {typeof FAST_MODE | typeof STANDARD_MODE}
   */
  mode() {
    return globalThis.crossOriginIsolated === true ? FAST_MODE : STANDARD_MODE;
  }
  /**
   * The highest memory level this browser build can use: 0 (2 GiB).
   * @returns {0}
   */
  maxSupportedMemLevel() {
    return HIGHEST_BROWSER_MEMORY_LEVEL;
  }
  /**
   * Stops the running long operation or session: its promise rejects at once with
   * MhfeCancelledError, and its worker is terminated, as soon as it has loaded the WebAssembly if
   * it is still loading it.
   */
  cancel() {
    this.#slot.cancel();
  }
  /**
   * A quick operation in a worker of its own, never BUSY. The job owns its secret buffers.
   * @param {WorkerRequest} message
   */
  async quick(message) {
    if ("container" in message) await this.readInputText(message.container, "container");
    return new WorkerJob([this.#sources.workerSource]).run(
      { module: CORE_MODULE, ...message },
      this.#wasm,
    );
  }
  /** Admits borrowed phrase/container text using the library's raw limit before a copy.
   * @param {unknown} value
   * @param {string} name */
  readInputText(value, name) {
    return this.#inputText.read(value, name);
  }
  /**
   * A long operation, which resolves to its result; see CoreRuntime.begin.
   * @param {WorkerRequest} request
   * @param {LongOptions} options
   * @param {boolean} [gated]
   */
  async long(request, options, gated = true) {
    const { done } = await this.begin(request, options, gated);
    return done;
  }
  /**
   * Starts a long operation in the slot and resolves to `{ job, done }`, `done` resolving to its
   * result. Everything that is not secret is checked first; then, when `gated`, the startup check
   * is awaited with the slot held; only then are the secrets copied into bytes, and until the
   * worker owns them, every failure wipes the copies.
   * @param {WorkerRequest} request
   * @param {LongOptions} options
   * @param {boolean} [gated]
   * @returns {Promise<{ job: WorkerJob, done: Promise<unknown> }>}
   */
  async begin(request, options, gated = true) {
    const { pim = 0, memoryLevel = 0 } = options;
    this.#slot.requireIdle();
    requireSettings(pim, memoryLevel);
    requireCallback(options.onProgress, "onProgress");
    const typedTwice = { ...options };
    if (options.passwordRepeat !== undefined || request.operation === "encrypt") {
      typedTwice.passwordRepeat = requireRepetition(
        options.password,
        options.passwordRepeat,
        "password",
      );
    }
    if (options.newPassword !== undefined || request.operation === "rekey") {
      typedTwice.newPasswordRepeat = requireRepetition(
        options.newPassword,
        options.newPasswordRepeat,
        "new password",
      );
    }
    const start = () => this.#start(request, typedTwice);
    const ready = gated
      ? this.ready().then(() => this.#admitInput(request, typedTwice))
      : this.#admitInput(request, typedTwice);
    return this.#slot.after(ready, start);
  }
  /** @param {WorkerRequest} request
   * @param {LongOptions} options */
  async #admitInput(request, options) {
    if (options.phrase !== undefined) await this.readInputText(options.phrase, "phrase");
    if ("container" in request) await this.readInputText(request.container, "container");
  }
  /**
   * Copies the secrets of a checked request and starts its job in the slot; see CoreRuntime.begin.
   * @param {WorkerRequest} request
   * @param {LongOptions} options
   */
  #start(
    request,
    {
      phrase,
      password,
      passwordRepeat,
      pim = 0,
      memoryLevel = 0,
      passphrase,
      newPassword,
      newPasswordRepeat,
      mainPassphrase,
      onProgress,
      handlers = {},
      noPassword = false,
    },
  ) {
    /** @type {WorkerRequest} */
    const message = { module: CORE_MODULE, ...request, pim, memoryLevel };
    let handed = false;
    try {
      // An empty phrase is the core's to refuse (INVALID_PHRASE), as any other invalid one.
      if (phrase !== undefined) message.phrase = encodeSecret(phrase, "phrase");
      if (!noPassword) message.password = encodeSecret(password, "password");
      if (passwordRepeat !== undefined) {
        message.passwordRepeat = encodeSecret(passwordRepeat, "repeated password");
      }
      if (passphrase !== undefined) message.passphrase = encodeSecret(passphrase, "passphrase");
      if (newPassword !== undefined) {
        message.newPassword = encodeSecret(newPassword, "new password");
        message.newPasswordRepeat = encodeSecret(newPasswordRepeat, "repeated new password");
      }
      if (mainPassphrase !== undefined) {
        message.mainPassphrase = encodeSecret(mainPassphrase, "main passphrase");
      }
      message.argon2Script = this.argon2Script(this.mode() === FAST_MODE);
      const job = this.#slot.job([this.argon2Source(), this.#sources.workerSource], {
        progress: onProgress,
        ...handlers,
      });
      const done = job.run(message, this.#wasm);
      handed = true;
      return { job, done };
    } finally {
      if (!handed) new SecretRequest(message).wipe();
    }
  }
  /** The text of this mode's Argon2 build: threaded on a cross-origin isolated page. */
  argon2Source(threaded = this.mode() === FAST_MODE) {
    return threaded ? this.#sources.argon2Threaded : this.#sources.argon2SingleThreaded;
  }
  /**
   * The threaded build's lane workers run this same script and may only come from a Blob.
   * @param {boolean} threaded
   */
  argon2Script(threaded) {
    return threaded ? new Blob([this.#sources.argon2Threaded], { type: "text/javascript" }) : null;
  }
}
