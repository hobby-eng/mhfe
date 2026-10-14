// AUD-024 guide-browser harness support (review only), adapted from the browser-isolation
// role's harness. Runs the built browser package of dist/ (build of b6fca69) in Node: the page
// classes as they are, and each Worker they start as the real runtime/worker.js evaluated in this
// process with a stand-in `self`. Messages are structured clones and transfers detach buffers.
// Argon2 rounds run at a reduced cost (256 KiB, one pass): only the known answers of the Argon2
// build (1 MiB/1, 64 MiB/3, 256 MiB/2) reach the real single-threaded build unchanged, so no
// suite-cost Argon2 ever runs. `argon2Fault.code`, when set, makes every round that is not a known
// answer return that error code of argon2.h instead, as a build whose lane threads cannot start
// would. Public test data only.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolveObjectURL } from "node:buffer";

export const REPO = new URL("../../../../", import.meta.url).pathname;
const require = createRequire(import.meta.url);
export const BUILD_ID = JSON.parse(readFileSync(REPO + "dist/modules.json", "utf8")).buildId;
export const workerSource = readFileSync(REPO + "dist/runtime/worker.js", "utf8");
export const argon2St = readFileSync(REPO + "dist/core/argon2-st.js", "utf8");
export const argon2Mt = readFileSync(REPO + "dist/core/argon2-mt.js", "utf8");
export const compiled = new WebAssembly.Module(readFileSync(REPO + "dist/runtime/mhfe.wasm"));
const createSt = require(REPO + "dist/core/argon2-st.js");

const KNOWN_ANSWERS = ["1024/1", "65536/3", "262144/2"];
/** Set `code` to make every round that is not a known answer fail with that argon2.h code. */
export const argon2Fault = { code: null };

async function reducedFactory() {
  const real = await createSt();
  return {
    get HEAPU8() {
      return real.HEAPU8;
    },
    _malloc: (size) => real._malloc(size),
    _free: (pointer) => real._free(pointer),
    _argon2id_hash_raw(passes, memoryKib, lanes, pw, pwLen, salt, saltLen, key, keyLen) {
      if (KNOWN_ANSWERS.includes(`${memoryKib}/${passes}`)) {
        return real._argon2id_hash_raw(passes, memoryKib, lanes, pw, pwLen, salt, saltLen, key, keyLen);
      }
      if (argon2Fault.code !== null) return argon2Fault.code;
      return real._argon2id_hash_raw(1, 256, lanes, pw, pwLen, salt, saltLen, key, keyLen);
    },
  };
}

/** A browser Worker over a Blob URL, run in this process. */
class InProcessWorker {
  constructor(url) {
    this.terminated = false;
    this.queue = [];
    resolveObjectURL(url)
      .text()
      .then((text) => this.#start(text));
  }
  #start(text) {
    const at = text.indexOf("let mhfe = (function(exports) {");
    const self = {
      postMessage: (message) => {
        if (this.terminated) return;
        const copy = structuredClone(message);
        setTimeout(() => {
          if (!this.terminated) this.onmessage?.({ data: copy });
        }, 0);
      },
      crypto: globalThis.crypto,
      crossOriginIsolated: false,
    };
    this.self = self;
    const globals =
      at > 0 ? { createArgon2St: reducedFactory, ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID } : {};
    new Function("self", ...Object.keys(globals), text.slice(at))(self, ...Object.values(globals));
    for (const message of this.queue) this.#deliver(message);
    this.queue = [];
  }
  #deliver(message) {
    setTimeout(() => {
      if (!this.terminated) this.self.onmessage({ data: message });
    }, 0);
  }
  postMessage(message, transfer = []) {
    const copy = structuredClone(message, { transfer });
    if (this.terminated) return;
    if (this.self === undefined) this.queue.push(copy);
    else this.#deliver(copy);
  }
  terminate() {
    this.terminated = true;
  }
}

globalThis.Worker = InProcessWorker;

const load = async (path) => import(REPO + path);
export const { MhfeClient } = await load("dist/core/client.js");
export const { MhfeRepair } = await load("dist/repair/repair.js");
export const { MhfePasswords } = await load("dist/passwords/passwords.js");
export const { MhfeWallet } = await load("dist/wallet/wallet.js");

export const PASSWORD = "public test password";
export const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/** The container of PHRASE under PASSWORD at 256 KiB and one pass (scripts/public-test-data.mjs). */
export const REDUCED_COST_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
/** BIP84 m/84'/0'/0'/0/0 of PHRASE without a passphrase (BIP-0084 test vector). */
export const PHRASE_BIP84_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

export const sources = {
  workerSource,
  wasm: compiled,
  argon2Threaded: argon2Mt,
  argon2SingleThreaded: argon2St,
};
export const moduleSources = { workerSource, wasm: compiled };

/** Settles `promise` and returns a line of how it ended, with an MhfeError's cause. */
export async function outcome(promise) {
  try {
    const value = await promise;
    return `resolved ${JSON.stringify(value)}`;
  } catch (error) {
    const cause =
      error?.cause === undefined ? "" : ` [cause: ${error.cause?.name}: ${error.cause?.message}]`;
    return `rejected ${error?.name}${error?.code === undefined ? " (no code)" : ` ${error.code}`}: ${error?.message}${cause}`;
  }
}
