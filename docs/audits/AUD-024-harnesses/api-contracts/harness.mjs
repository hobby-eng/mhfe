// AUD-024 api-contracts harness (commit b6fca69): runs the browser package's real classes (dist/) in Node.js
// with the package's real worker script (dist/runtime/worker.js) in this process, in place of a
// browser's Worker. Review only: it reads dist/ and writes nothing. Argon2 is the single-threaded
// Emscripten build of dist/core/argon2-st.js; probes must stop before any full-cost round.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolveObjectURL } from "node:buffer";

export const ROOT = process.env.MHFE_ROOT ?? new URL("../../../../", import.meta.url).pathname.replace(/\/$/u, "");
const require = createRequire(import.meta.url);
const read = (path) => readFileSync(`${ROOT}/${path}`);
export const workerSource = read("dist/runtime/worker.js").toString();
export const argon2SingleThreaded = read("dist/core/argon2-st.js").toString();
export const argon2Threaded = read("dist/core/argon2-mt.js").toString();
export const wasmBytes = new Uint8Array(read("dist/runtime/mhfe.wasm"));
export const BUILD_ID = JSON.parse(read("dist/modules.json").toString()).buildId;
const createArgon2St = require(`${ROOT}/dist/core/argon2-st.js`);

/** Every in-process worker started, for the probes to look at. */
export const workers = [];
/** What each worker received from the page and posted to it, in order. */
export class InProcessWorker {
  constructor(url) {
    this.terminated = false;
    this.log = [];
    this.onmessage = null;
    this.onerror = null;
    workers.push(this);
    const self = {
      postMessage: (message) => {
        this.log.push({ from: "worker", message: summarize(message) });
        if (this.terminated) return;
        const data = structuredClone(message);
        setTimeout(() => {
          if (!this.terminated) this.onmessage?.({ data });
        }, 0);
      },
      crypto: globalThis.crypto,
      crossOriginIsolated: false,
    };
    this.self = self;
    this.loaded = resolveObjectURL(url)
      .text()
      .then((script) => {
        const globals = {};
        let body = script;
        if (script.startsWith(argon2SingleThreaded)) {
          body = script.slice(argon2SingleThreaded.length);
          globals.createArgon2St = createArgon2St;
          globals.ARGON2_SINGLE_THREADED_BUILD_ID = BUILD_ID;
        }
        // oxlint-disable-next-line typescript/no-implied-eval -- the package's own worker script
        new Function("self", ...Object.keys(globals), body)(self, ...Object.values(globals));
      });
  }
  postMessage(message, transfer = []) {
    const data = structuredClone(message, { transfer });
    this.log.push({ from: "page", message: summarize(data) });
    this.loaded.then(() =>
      setTimeout(() => {
        if (!this.terminated) this.self.onmessage?.({ data });
      }, 0),
    );
  }
  terminate() {
    this.terminated = true;
  }
}

/** A message without the compiled module and with byte arrays shown as their length. */
export function summarize(message) {
  return JSON.parse(
    JSON.stringify(message, (key, value) => {
      if (key === "compiled") return "[module]";
      if (value instanceof Uint8Array) return `bytes(${value.length})`;
      if (typeof Blob !== "undefined" && value instanceof Blob) return "[blob]";
      return value;
    }) ?? "null",
  );
}

export function install() {
  globalThis.Worker = InProcessWorker;
}

/** Runs `promise` and gives what it resolved to or how it rejected, as text. */
export async function outcome(promise) {
  try {
    const value = await promise;
    return { resolved: value };
  } catch (error) {
    return {
      rejected: {
        name: error?.name,
        code: error?.code,
        message: error?.message,
        cause: error?.cause?.message ?? error?.cause,
      },
    };
  }
}

export const sources = () => ({ workerSource, wasm: wasmBytes });
export const coreSources = () => ({
  workerSource,
  wasm: wasmBytes,
  argon2Threaded,
  argon2SingleThreaded,
});
export const dist = (path) => `${ROOT}/dist/${path}`;
