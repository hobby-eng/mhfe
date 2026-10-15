// @ts-check
// Lazy, shared compilation of one WebAssembly module.

/** The package's WebAssembly, compiled the first time a worker needs it and then shared. */
export class CompiledModule {
  /** @type {Uint8Array | WebAssembly.Module} */
  #wasm;
  /** @type {Promise<WebAssembly.Module> | null} */
  #compiled = null;

  /**
   * `wasm` is what the page passed as `name`: runtime/mhfe.wasm as bytes or as a compiled module.
   * @param {unknown} wasm
   * @param {string} name
   */
  constructor(wasm, name) {
    // A browser without WebAssembly gets this far, so that the class's self-check can say what
    // is missing instead of the constructor failing with a ReferenceError.
    if (!(wasm instanceof Uint8Array) && !isCompiledModule(wasm)) {
      throw new TypeError(`${name} must be a Uint8Array or a WebAssembly.Module.`);
    }
    this.#wasm = wasm;
  }

  /**
   * The bytes or the module the page passed: the classes made with the same one share their
   * self-check results on the page.
   */
  get source() {
    return this.#wasm;
  }

  /**
   * The compiled WebAssembly, which a worker receives as it is: no worker compiles it again.
   * @returns {Promise<WebAssembly.Module>}
   */
  get() {
    this.#compiled ??= isCompiledModule(this.#wasm)
      ? Promise.resolve(this.#wasm)
      : WebAssembly.compile(this.#wasm);
    return this.#compiled;
  }
}

/**
 * Whether `value` is a compiled WebAssembly module, in a browser that has WebAssembly.
 * @param {unknown} value
 * @returns {value is WebAssembly.Module}
 */
function isCompiledModule(value) {
  return typeof WebAssembly === "object" && value instanceof WebAssembly.Module;
}
