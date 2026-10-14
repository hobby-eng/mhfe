// @ts-check
// The worker side of the runtime the modules of the mhfe browser package share. The package's one
// worker.js is the wasm-bindgen glue of its one WebAssembly (the global `mhfe`), the Argon2 bridge,
// this file, the table of operations of each module and web/worker-start.js, joined by
// scripts/build-wasm.sh. Under the tools' Content-Security-Policy a worker may not load any further
// script, so everything arrives in that one Blob, the core's Emscripten Argon2 build in front of it
// when an operation needs Argon2.
"use strict";

/**
 * Checked primitive field types of the page-worker protocol. Numeric business rules remain in
 * Rust; these checks establish JavaScript types, including optional field values.
 * @typedef {"text" | "number" | "boolean" | "bytes" | "texts" | "numbers" |
 *   "optionalNumber" | "optionalBoolean" | "triBoolean" | "script"} FieldKind
 */
/** @typedef {Record<string, FieldKind>} FieldSchema */
/**
 * @template {FieldKind} Kind
 * @typedef {Kind extends "text" ? string : Kind extends "number" ? number :
 *   Kind extends "boolean" ? boolean : Kind extends "bytes" ? Uint8Array :
 *   Kind extends "texts" ? string[] : Kind extends "numbers" ? number[] :
 *   Kind extends "optionalNumber" ? number | undefined :
 *   Kind extends "optionalBoolean" ? boolean | undefined :
 *   Kind extends "triBoolean" ? boolean | null | undefined : Blob | null | undefined} FieldValue
 */
/**
 * @template {FieldSchema} Schema
 * @typedef {{ [Key in keyof Schema]: FieldValue<Schema[Key]> }} CheckedFields
 */

/**
 * Whether a value has its protocol field's type, without coercion or cryptographic rules.
 * @param {unknown} value
 * @param {FieldKind} kind
 */
function hasFieldType(value, kind) {
  switch (kind) {
    case "text":
      return typeof value === "string";
    case "number":
      return typeof value === "number";
    case "boolean":
      return typeof value === "boolean";
    case "bytes":
      return value instanceof Uint8Array;
    case "texts":
      return Array.isArray(value) && value.every((item) => typeof item === "string");
    case "numbers":
      return Array.isArray(value) && value.every((item) => typeof item === "number");
    case "optionalNumber":
      return value === undefined || typeof value === "number";
    case "optionalBoolean":
      return value === undefined || typeof value === "boolean";
    case "triBoolean":
      return value === undefined || value === null || typeof value === "boolean";
    case "script":
      return value === undefined || value === null || value instanceof Blob;
  }
}

/**
 * A decoded record with every schema property checked before a consumer uses it. The assertion
 * follows the complete field check; missing values get no invented defaults. A malformed
 * secret-bearing answer is wiped before its refusal escapes.
 * @template {FieldSchema} Schema
 * @param {unknown} value
 * @param {Schema} fields
 * @returns {CheckedFields<Schema>}
 */
function checkedFields(value, fields) {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw packageMismatch("The page sent a malformed request or answer");
    }
    const source = /** @type {Record<string, unknown>} */ (value);
    for (const [name, kind] of Object.entries(fields)) {
      if (!hasFieldType(source[name], kind)) {
        throw packageMismatch(`The page sent a malformed ${name} field`);
      }
    }
    // Every property of this mapped type was checked against the corresponding field kind.
    return /** @type {CheckedFields<Schema>} */ (source);
  } catch (error) {
    new SecretRequest(value).wipe();
    throw error;
  }
}

/**
 * A nullable answer, or a record with every schema property checked before use.
 * @template {FieldSchema} Schema
 * @param {unknown} value
 * @param {Schema} fields
 * @returns {CheckedFields<Schema> | null}
 */
// oxlint-disable-next-line no-unused-vars -- core-worker.js calls it in the joined classic worker
function checkedNullableFields(value, fields) {
  return value === null ? null : checkedFields(value, fields);
}

/**
 * An operation's module view: fields present are checked at the protocol trust boundary, and every subsequent
 * field access checks its type. Missing required fields throw instead of becoming defaults;
 * optional fields can return undefined. The single assertion follows these checked getters.
 * @template {FieldSchema} Schema
 * @param {unknown} value
 * @param {Schema} fields
 * @returns {CheckedFields<Schema>}
 */
function checkedOperationView(value, fields) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw packageMismatch("The page sent a malformed operation request");
  }
  const source = /** @type {Record<string, unknown>} */ (value);
  const checked = (/** @type {string} */ name, /** @type {unknown} */ item) => {
    const kind = fields[name];
    if (kind !== undefined && !hasFieldType(item, kind)) {
      throw packageMismatch(`The page sent a malformed ${name} field`);
    }
    return item;
  };
  for (const [name, item] of Object.entries(source)) checked(name, item);
  return /** @type {CheckedFields<Schema>} */ (
    new Proxy(source, {
      get(target, name) {
        const item = Reflect.get(target, name);
        return typeof name === "string" ? checked(name, item) : item;
      },
    })
  );
}

/**
 * Wraps a module's typed operations with its checked field view. The dispatch table accepts
 * unknown bodies; each implementation receives only checked values through its getters.
 * @template {FieldSchema} Schema
 * @param {Schema} fields
 * @param {Record<string, Operation<CheckedFields<Schema>>>} operations
 * @returns {Record<string, Operation<unknown>>}
 */
// oxlint-disable-next-line no-unused-vars -- module tables call it in the joined classic worker
function operationsWithFields(fields, operations) {
  return Object.fromEntries(
    Object.entries(operations).map(([name, operation]) => [
      name,
      (/** @type {unknown} */ request, /** @type {WorkerHost} */ host) =>
        operation(checkedOperationView(request, fields), host),
    ]),
  );
}

/**
 * What the page's runtime of this build sends (WorkerJob in web/runtime.js): a request, which
 * names its module and operation and carries the operation's fields, the first one with the
 * compiled WebAssembly; or the answer to a question, `{ type: "answer", value }`.
 * @typedef {{ module: string, operation: string, compiled?: unknown, type?: undefined,
 *   [field: string]: unknown } | { type: "answer", value: unknown }} PageMessage
 */

/**
 * The common page envelope. Operation fields and answers have their own readers.
 * @param {unknown} value
 * @returns {PageMessage}
 */
function readPageMessage(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw packageMismatch("The page sent a malformed message");
  }
  const message = /** @type {Record<string, unknown>} */ (value);
  if (message.type === "answer") return { type: "answer", value: message.value };
  if (
    message.type !== undefined ||
    typeof message.module !== "string" ||
    typeof message.operation !== "string"
  ) {
    throw packageMismatch("The page sent a malformed operation envelope");
  }
  return { ...message, type: undefined, module: message.module, operation: message.operation };
}

/**
 * A branded compiled module, checked by the platform rather than a prototype or a sender cast.
 * @param {unknown} value
 * @returns {WebAssembly.Module}
 */
function readCompiledModule(value) {
  // customSections performs the platform's internal Module brand check, including across realms.
  const candidate = /** @type {WebAssembly.Module} */ (value);
  try {
    WebAssembly.Module.customSections(candidate, BUILD_SECTION);
  } catch {
    throw packageMismatch("The page sent a value that is not a compiled WebAssembly module");
  }
  return candidate;
}

/**
 * An operation of a module, which takes the request that the module's class sends it and the
 * host (serveOperations), and resolves to its result.
 * @template Request
 * @typedef {(request: Request, host: WorkerHost) => unknown} Operation
 */

/**
 * The fields of a request to a self-check of a module: its tier and the parts left out.
 * @typedef {{ tier: string, skip: string[] }} SelfCheckRequest
 */

/**
 * A part of a self-check as the WebAssembly reports it and as the page reads it.
 * @typedef {{ id: string, label: string, outcome: string, detail?: string }} ComponentResult
 */

/**
 * The report of a module's set of known answers as the WebAssembly gives it (src/self_check.rs).
 * @typedef {{ version: string, tier: string, passed: boolean, components: ComponentResult[],
 *   ids?: string[] }} SelfCheckReport
 */

/**
 * How an operation talks to the page (serveOperations).
 * @typedef {{ progress: RoundListener, post: (type: string, value: unknown) => void,
 *   ask: (question: string, value: unknown) => Promise<unknown>, random: RandomSource,
 *   selfCheck: (tier: string, run: (onStart: PartStartListener,
 *     onResult: PartResultListener) => string,
 *     outcomeOf?: (result: ComponentResult) => ComponentResult) => SelfCheckReport }} WorkerHost
 */

/**
 * The build of this worker script, which scripts/stamp-build-id.mjs writes here and into
 * runtime/mhfe.wasm, runtime/runtime.js and each class; "development" before the build stamps it.
 */
const WORKER_BUILD_ID = "development";
/** The custom section of runtime/mhfe.wasm that names its build (scripts/stamp-build-id.mjs). */
const BUILD_SECTION = "mhfe-build";
/**
 * The custom section of runtime/mhfe.wasm that says where its shadow stack ends
 * (scripts/mark-wasm-stack.mjs).
 */
const STACK_SECTION = "mhfe-stack";
/** The detail of a part in which the WebAssembly stopped: a Rust panic or a fault of the computer. */
const STOPPED_DETAIL = "the WebAssembly stopped";

// Deliberate copy: secret owners from web/runtime.js; a classic worker cannot import modules.
// scripts/package-check/core-operations.mjs compares both definitions.
// SECRET_OWNERS_BEGIN
/** A byte buffer owned by this operation; wiping is best effort in JavaScript. */
class SecretBytes {
  /** @type {Uint8Array} */
  #bytes;
  // Deliberate copy: page and classic worker share this owner; the package compares both.

  /** Takes ownership of an already copied or transferred buffer, without another copy.
   * @param {Uint8Array} bytes */
  constructor(bytes) {
    this.#bytes = bytes;
  }

  /** The owned bytes, for protocol serialization or a library call. */
  get bytes() {
    return this.#bytes;
  }

  /** Erases the live buffer; a detached buffer is already owned by the receiver. */
  wipe() {
    if (this.#bytes.byteLength > 0) this.#bytes.fill(0);
  }
}

/** A request owns every secret at any depth and supplies its plain wire value and transfer list. */
class SecretRequest {
  /** @type {Set<SecretBytes>} */
  #secrets = new Set();
  // Deliberate copy: page and classic worker share this owner; the package compares both.
  /** @type {unknown} */
  #message;

  /** Collects byte owners by type, never by a field name. Cycles and repeated references are safe.
   * @param {unknown} message */
  constructor(message) {
    /** @type {WeakMap<object, object>} */
    const seen = new WeakMap();
    /** @param {unknown} value
     * @returns {unknown} */
    const wire = (value) => {
      if (value instanceof SecretBytes) {
        this.#secrets.add(value);
        return value.bytes;
      }
      if (value instanceof Uint8Array) {
        this.#secrets.add(new SecretBytes(value));
        return value;
      }
      if (typeof value !== "object" || value === null) return value;
      const known = seen.get(value);
      if (known !== undefined) return known;
      if (Array.isArray(value)) {
        /** @type {unknown[]} */
        const items = [];
        seen.set(value, items);
        for (const item of value) items.push(wire(item));
        return items;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) return value;
      /** @type {Record<string, unknown>} */
      const record = {};
      seen.set(value, record);
      for (const [key, item] of Object.entries(value)) {
        Object.defineProperty(record, key, { value: wire(item), enumerable: true });
      }
      return record;
    };
    this.#message = wire(message);
  }

  /** The serializable value, with owners replaced by their byte buffers. */
  get message() {
    return this.#message;
  }

  /** Each transferable secret buffer once, independent of its name and nesting. */
  get transfer() {
    return [...new Set([...this.#secrets].map((secret) => secret.bytes.buffer))].filter(
      (buffer) => buffer instanceof ArrayBuffer,
    );
  }

  /** Erases all buffers this request owns, including partially constructed answers. */
  wipe() {
    for (const secret of this.#secrets) secret.wipe();
  }
}

// Older browsers may lack Symbol.dispose; the owners still have explicit wipe().
const disposeSymbol = Reflect.get(Symbol, "dispose");
if (typeof disposeSymbol === "symbol") {
  for (const Owner of [SecretBytes, SecretRequest]) {
    Object.defineProperty(Owner.prototype, disposeSymbol, {
      /** @this {SecretBytes | SecretRequest} */
      value() {
        this.wipe();
      },
    });
  }
}
// SECRET_OWNERS_END

/**
 * Serves the operations of the modules: the first message initializes `bindings`, the wasm-bindgen
 * glue, with the compiled WebAssembly it carries, once its build is this script's, and the worker
 * tells the page it is ready; each message names a module and an operation, which resolves to the
 * result. An operation talks to the page through `host`: progress, other news, a question whose
 * answer it awaits, the page's random source, and the run of a self-check.
 * @param {typeof mhfe} bindings
 * @param {Record<string, Record<string, Operation<unknown>>>} modules
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js calls it in runtime/worker.js
function serveOperations(bindings, modules) {
  let initialized = false;
  /**
   * Zeroes the module's shadow stack, which is all dead while no WebAssembly frame is active: a
   * call leaves secrets there, such as a BIP39 seed, a master key and the salt block of a
   * passphrase, until a later call overwrites them (AUD-024-SEC003). Called only from JavaScript
   * that the WebAssembly did not call, after an operation and before a question to the page.
   */
  let clearStack = () => {};
  /** @type {((answer: unknown) => void) | null} */
  let pendingAnswer = null;
  /** @type {WorkerHost} */
  const host = {
    progress(round, rounds, stage) {
      self.postMessage({ type: "progress", value: { stage, round, rounds } });
    },
    post(type, value) {
      self.postMessage({ type, value });
    },
    ask(question, value) {
      clearStack();
      return new Promise((resolve) => {
        pendingAnswer = resolve;
        self.postMessage({ type: "ask", question, value });
      });
    },
    // A view of the module's memory: getRandomValues fills it in place (at most 65,536 bytes a
    // call, far more than any draw asks for).
    random: { fill: (bytes) => self.crypto.getRandomValues(bytes) },
    /**
     * Runs a self-check binding, `run(onStart, onResult)`, and tells the page of each part as it
     * starts and ends. `outcomeOf(result)` gives a part's result as the page reads it, such as an
     * Argon2 part whose build did not start (web/core-worker.js); the report's `passed` follows.
     * When the WebAssembly stops inside a part (a trap: a Rust panic or a fault of the computer),
     * that part fails, so that the report names it instead of the worker failing; the WebAssembly
     * is not called again after that.
     */
    selfCheck(tier, run, outcomeOf = (result) => result) {
      const version = bindings.packageVersion();
      /** @type {ComponentResult[]} */
      const results = [];
      // The part that runs, which only the callbacks below set.
      let running = /** @type {{ id: string, label: string } | null} */ (null);
      try {
        /** @type {SelfCheckReport} */
        const report = JSON.parse(
          run(
            (id, label) => {
              running = { id, label };
              self.postMessage({ type: "componentStart", value: running });
            },
            (json) => {
              const result = outcomeOf(JSON.parse(json));
              running = null;
              results.push(result);
              self.postMessage({ type: "component", value: result });
            },
          ),
        );
        const components = report.components.map(outcomeOf);
        return {
          ...report,
          passed: components.every(({ outcome }) => outcome !== "failed"),
          components,
        };
      } catch (error) {
        if (!(error instanceof WebAssembly.RuntimeError) || running === null) throw error;
        const stopped = { ...running, outcome: "failed", detail: STOPPED_DETAIL };
        self.postMessage({ type: "component", value: stopped });
        return { version, tier, passed: false, components: [...results, stopped] };
      }
    },
  };
  self.onmessage = async (/** @type {MessageEvent<unknown>} */ event) => {
    let message;
    try {
      message = readPageMessage(event.data);
    } catch (error) {
      new SecretRequest(event.data).wipe();
      self.postMessage({ type: "error", error: describeError(error) });
      return;
    }
    if (message.type === "answer") {
      const resolve = pendingAnswer;
      pendingAnswer = null;
      resolve?.(message.value);
      return;
    }
    const owned = new SecretRequest(message);
    try {
      if (!initialized) {
        const compiled = readCompiledModule(message.compiled);
        requireSameBuild(compiled);
        const top = stackTopOf(compiled);
        const { memory } = bindings.initSync({ module: compiled });
        // A view made for each clear: the memory may have grown, which replaces its buffer.
        clearStack = () => new Uint8Array(memory.buffer, 0, top).fill(0);
        initialized = true;
        self.postMessage({ type: "ready", buildId: WORKER_BUILD_ID });
      }
      const operation = operationOf(modules, message.module, message.operation);
      if (typeof operation !== "function") {
        throw new Error(
          `INVALID_REQUEST: unknown operation ${String(message.module)}.${String(message.operation)}`,
        );
      }
      const result = await operation(message, host);
      self.postMessage({ type: "result", result });
    } catch (error) {
      self.postMessage({ type: "error", error: describeError(error) });
    } finally {
      owned.wipe();
      clearStack();
    }
  };
}

/**
 * Where the shadow stack of `compiled` ends, which scripts/mark-wasm-stack.mjs writes into it; a
 * WebAssembly without it was not built by scripts/bind-wasm.sh, and is refused.
 * @param {WebAssembly.Module} compiled
 */
function stackTopOf(compiled) {
  const [section] = WebAssembly.Module.customSections(compiled, STACK_SECTION);
  const top = section === undefined ? Number.NaN : Number(new TextDecoder().decode(section));
  if (!Number.isSafeInteger(top) || top <= 0) {
    throw packageMismatch("the file runtime/mhfe.wasm does not say where its stack ends");
  }
  return top;
}

/**
 * The operation `name` of the module `module`, or undefined. Only the tables' own entries are
 * operations: every object inherits names such as "constructor", "toString" and "__proto__" from
 * Object.prototype, which must be refused like any other unknown name, not called with the
 * request.
 * @param {Record<string, Record<string, Operation<unknown>>>} modules
 * @param {string} module
 * @param {string} name
 */
function operationOf(modules, module, name) {
  const table = Object.hasOwn(modules, module) ? modules[module] : undefined;
  return table !== undefined && Object.hasOwn(table, name) ? table[name] : undefined;
}

/**
 * Refuses a WebAssembly of another build than this script before it runs: parts of different
 * builds may call each other wrongly. One without the section has not been stamped either. The
 * message starts with a word, not the file's path, since the page makes a sentence of it
 * (sentence() in web/runtime.js), which would capitalize the path.
 * @param {WebAssembly.Module} compiled
 */
function requireSameBuild(compiled) {
  const sections = WebAssembly.Module.customSections(compiled, BUILD_SECTION);
  const build =
    sections.length === 0
      ? "development"
      : sections.map((bytes) => new TextDecoder().decode(bytes)).join("+");
  if (build !== WORKER_BUILD_ID) {
    throw packageMismatch(
      `the file runtime/mhfe.wasm is of build ${build} and runtime/worker.js of build ` +
        WORKER_BUILD_ID,
    );
  }
}

/**
 * Parts of the package that come from different builds: `what` says which, and the advice follows,
 * a deliberate copy of the page runtime's packageMismatch() (web/runtime.js): a worker imports
 * nothing and the package checks keep the messages equal. It starts with a word,
 * not a file's path, which the page's sentence() would capitalize.
 * @param {string} what
 */
function packageMismatch(what) {
  return new Error(`PACKAGE_MISMATCH: ${what}: take every file of the package from one build.`);
}

/**
 * Runs `use(session)` on a session of the WebAssembly and frees the session after it, unless the
 * WebAssembly stopped inside (a trap): the instance can then not be called again, a call would
 * only replace the trap with an error of its own, and the page terminates the worker, whose memory
 * goes with it. The first error is the one thrown.
 * @template {{ free(): void }} Session
 * @template Result
 * @param {Session} session
 * @param {(session: Session) => Promise<Result>} use
 * @returns {Promise<Result>}
 */
// oxlint-disable-next-line no-unused-vars -- web/core-worker.js calls it in runtime/worker.js
async function withSession(session, use) {
  let stopped = false;
  try {
    return await use(session);
  } catch (error) {
    stopped = error instanceof WebAssembly.RuntimeError;
    throw error;
  } finally {
    if (!stopped) session.free();
  }
}

/**
 * Errors from the Rust core read "CODE: message". A trap, a Rust panic or a fault of the computer
 * that stopped the WebAssembly, is INTERNAL_ERROR with the self-check's wording for it.
 * @param {unknown} error
 * @returns {{ code: string, message: string }}
 */
function describeError(error) {
  if (error instanceof WebAssembly.RuntimeError) {
    return { code: "INTERNAL_ERROR", message: STOPPED_DETAIL };
  }
  const text = error instanceof Error ? error.message : String(error);
  const match = /^([A-Z][A-Z0-9_]+): (.*)$/su.exec(text);
  return match === null
    ? { code: "INTERNAL_ERROR", message: text }
    : // Both groups take part in every match.
      { code: /** @type {string} */ (match[1]), message: /** @type {string} */ (match[2]) };
}
