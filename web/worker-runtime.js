// @ts-check
// The worker side of the runtime the modules of the mhfe browser package share. The package's one
// worker.js is the wasm-bindgen glue of its one WebAssembly (the global `mhfe`), the Argon2 bridge,
// this file, the table of operations of each module and web/worker-start.js, joined by
// scripts/build-wasm.sh. Under the tools' Content-Security-Policy a worker may not load any further
// script, so everything arrives in that one Blob, the core's Emscripten Argon2 build in front of it
// when an operation needs Argon2.
"use strict";

/**
 * What the page's runtime of this build sends (WorkerJob in web/runtime.js): a request, which
 * names its module and operation and carries the operation's fields, the first one with the
 * compiled WebAssembly; or the answer to a question, `{ type: "answer", value }`.
 * @typedef {{ module: string, operation: string, compiled: WebAssembly.Module, type?: string,
 *   value?: unknown, [field: string]: unknown }} PageMessage
 */

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
/** The detail of a part in which the WebAssembly stopped: a Rust panic or a fault of the computer. */
const STOPPED_DETAIL = "the WebAssembly stopped";

/**
 * The fields of a request or an answer that hold secrets; the worker wipes its copies. The page's
 * runtime lists the same fields (web/runtime.js), as a worker script imports nothing.
 */
const SECRET_FIELDS = [
  "phrase",
  "password",
  "passwordRepeat",
  "passphrase",
  "passphraseRepeat",
  "chosenWords",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
  "typed",
];

/**
 * Serves the operations of the modules: the first message initializes `bindings`, the wasm-bindgen
 * glue, with the compiled WebAssembly it carries, once its build is this script's, and the worker
 * tells the page it is ready; each message names a module and an operation, which resolves to the
 * result. An operation talks to the page through `host`: progress, other news, a question whose
 * answer it awaits, the page's random source, and the run of a self-check.
 * @param {typeof mhfe} bindings
 * @param {Record<string, Record<string, Operation<never>>>} modules
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js calls it in runtime/worker.js
function serveOperations(bindings, modules) {
  let initialized = false;
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
  self.onmessage = async (event) => {
    /** @type {PageMessage} */
    const message = event.data;
    if (message?.type === "answer") {
      const resolve = pendingAnswer;
      pendingAnswer = null;
      resolve?.(message.value);
      return;
    }
    try {
      if (!initialized) {
        requireSameBuild(message.compiled);
        bindings.initSync({ module: message.compiled });
        initialized = true;
        self.postMessage({ type: "ready", buildId: WORKER_BUILD_ID });
      }
      const operation = operationOf(modules, message.module, message.operation);
      if (typeof operation !== "function") {
        throw new Error(
          `INVALID_REQUEST: unknown operation ${String(message.module)}.${String(message.operation)}`,
        );
      }
      // The page's class of this build sends each operation the request that its table names.
      const result = await /** @type {Operation<PageMessage>} */ (operation)(message, host);
      self.postMessage({ type: "result", result });
    } catch (error) {
      self.postMessage({ type: "error", error: describeError(error) });
    } finally {
      wipeSecrets(message);
    }
  };
}

/**
 * The operation `name` of the module `module`, or undefined. Only the tables' own entries are
 * operations: every object inherits names such as "constructor", "toString" and "__proto__" from
 * Object.prototype, which must be refused like any other unknown name, not called with the
 * request.
 * @param {Record<string, Record<string, Operation<never>>>} modules
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
 * in the words of the page's runtime (packageMismatch() in web/runtime.js). It starts with a word,
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
 * The Rust core has its own copies, which it wipes; these are the copies in this worker, the
 * Uint8Arrays the page transferred.
 * @param {Record<string, unknown> | null | undefined} message
 */
function wipeSecrets(message) {
  for (const field of SECRET_FIELDS) {
    const bytes = message?.[field];
    if (bytes instanceof Uint8Array) bytes.fill(0);
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
