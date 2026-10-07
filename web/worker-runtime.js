// The worker side of the runtime the modules of the mhfe browser package share. The package's one
// worker.js is the wasm-bindgen glue of its one WebAssembly (the global `mhfe`), the Argon2 bridge,
// this file, the table of operations of each module and web/worker-start.js, joined by
// scripts/build-wasm.sh. Under the tools' Content-Security-Policy a worker may not load any further
// script, so everything arrives in that one Blob, the core's Emscripten Argon2 build in front of it
// when an operation needs Argon2.
"use strict";

/**
 * The build of this worker script, which scripts/stamp-build-id.mjs writes here and into
 * runtime/mhfe.wasm, runtime/runtime.js and each class; "development" before the build stamps it.
 */
const WORKER_BUILD_ID = "development";
/** The custom section of runtime/mhfe.wasm that names its build (scripts/stamp-build-id.mjs). */
const BUILD_SECTION = "mhfe-build";
/** The detail of a part in which the WebAssembly stopped: a Rust panic or a fault of the computer. */
const STOPPED_DETAIL = "the WebAssembly stopped";

/** The fields of a request or an answer that hold secrets; the worker wipes its copies. */
const SECRET_FIELDS = [
  "phrase",
  "password",
  "passwordRepeat",
  "passphrase",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
];

/**
 * Serves the operations of the modules: the first message initializes `bindings`, the wasm-bindgen
 * glue, with the compiled WebAssembly it carries, once its build is this script's, and the worker
 * tells the page it is ready; each message names a module and an operation, which resolves to the
 * result. An operation talks to the page through `host`: progress, other news, a question whose
 * answer it awaits, the page's random source, and the run of a self-check.
 */
function serveOperations(bindings, modules) {
  let initialized = false;
  let pendingAnswer = null;
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
      const results = [];
      let running = null;
      try {
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
      const result = await operation(message, host);
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
 */
function requireSameBuild(compiled) {
  const sections = WebAssembly.Module.customSections(compiled, BUILD_SECTION);
  const build =
    sections.length === 0
      ? "development"
      : sections.map((bytes) => new TextDecoder().decode(bytes)).join("+");
  if (build !== WORKER_BUILD_ID) {
    throw new Error(
      `PACKAGE_MISMATCH: the file runtime/mhfe.wasm is of build ${build} and runtime/worker.js ` +
        `of build ${WORKER_BUILD_ID}: take every file of the package from one build.`,
    );
  }
}

/** The Rust core has its own copies, which it wipes; these are the copies in this worker. */
function wipeSecrets(message) {
  for (const field of SECRET_FIELDS) message?.[field]?.fill?.(0);
}

/** Errors from the Rust core read "CODE: message". */
function describeError(error) {
  const text = error instanceof Error ? error.message : String(error);
  const match = /^([A-Z][A-Z0-9_]+): (.*)$/su.exec(text);
  return match === null
    ? { code: "INTERNAL_ERROR", message: text }
    : { code: match[1], message: match[2] };
}
