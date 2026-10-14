// AUD-024 browser-isolation harness support (review only, not part of the package). Runs the built
// browser package of dist/ in Node: the page classes as they are, and each Worker they start as the
// package's real runtime/worker.js evaluated in this process with a stand-in `self`. Messages are
// structured clones, transfers detach the sender's buffers, and terminate() stops delivery both
// ways. Argon2 rounds run at a reduced cost (256 KiB, one pass): only the known answers of the
// Argon2 build (1 MiB/1, 64 MiB/3, 256 MiB/2) reach the real single-threaded build unchanged, so no
// suite-cost Argon2 runs. Public test data only.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolveObjectURL } from "node:buffer";
import { fileURLToPath } from "node:url";

/** The repository's root folder, from this file's place in docs/audits/AUD-024-harnesses/<role>/. */
export const ROOT = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT));
const require = createRequire(import.meta.url);
export const BUILD_ID = JSON.parse(read("dist/modules.json").toString()).buildId;
export const workerSource = read("dist/runtime/worker.js").toString();
export const compiled = new WebAssembly.Module(read("dist/runtime/mhfe.wasm"));
const createSt = require(fileURLToPath(new URL("dist/core/argon2-st.js", ROOT)));

/** The known-answer costs (memory KiB / passes) that reach the real build unchanged. */
const KNOWN_ANSWERS = ["1024/1", "65536/3", "262144/2"];

/** An Emscripten factory like createArgon2St whose rounds run at 256 KiB and one pass. */
async function reducedFactory() {
  const real = await createSt();
  return {
    get HEAPU8() {
      return real.HEAPU8;
    },
    _malloc: (size) => real._malloc(size),
    _free: (pointer) => real._free(pointer),
    _argon2id_hash_raw(passes, memoryKib, lanes, pw, pwLength, salt, saltLength, key, keyLength) {
      const known = KNOWN_ANSWERS.includes(`${memoryKib}/${passes}`);
      return real._argon2id_hash_raw(
        known ? passes : 1,
        known ? memoryKib : 256,
        lanes,
        pw,
        pwLength,
        salt,
        saltLength,
        key,
        keyLength,
      );
    },
  };
}

/** Every stand-in worker started, in order, and a hook that sees each message of the page. */
export const workers = [];
export const hooks = { onPageMessage: null };

/** A browser Worker over a Blob URL, run in this process. */
class InProcessWorker {
  constructor(url) {
    this.terminated = false;
    this.fromPage = [];
    this.fromWorker = [];
    this.queue = [];
    workers.push(this);
    resolveObjectURL(url)
      .text()
      .then((text) => this.#start(text));
  }
  #start(text) {
    // The Blob is the Argon2 build(s), then runtime/worker.js; the worker part runs here with the
    // reduced-cost single-threaded Argon2 build standing in for whatever was in front of it. The
    // last line lets a check read the worker's WebAssembly memory, as a heap scan would.
    const at = text.indexOf("let mhfe = (function(exports) {");
    const script = `${text.slice(at)}\n;self.__memory = () => mhfe.initSync().memory;\n`;
    const self = {
      postMessage: (message) => {
        if (this.terminated) return;
        const copy = structuredClone(message);
        this.fromWorker.push(copy);
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
    // The package's own worker text, run as a browser runs a worker script.
    new Function("self", ...Object.keys(globals), script)(self, ...Object.values(globals));
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
    this.fromPage.push(copy);
    hooks.onPageMessage?.(this, copy);
    if (this.terminated) return;
    if (this.self === undefined) this.queue.push(copy);
    else this.#deliver(copy);
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = InProcessWorker;

/** The package's classes, imported once the stand-in Worker is in place. */
export const { MhfeClient } = await import(new URL("dist/core/client.js", ROOT).href);

/** The parts every MhfeClient takes. */
export const sources = () => ({
  workerSource,
  wasm: compiled,
  argon2Threaded: read("dist/core/argon2-mt.js").toString(),
  argon2SingleThreaded: read("dist/core/argon2-st.js").toString(),
});

export const PASSWORD = "public test password";
/** The container of BIP39's all-zero 12-word phrase under PASSWORD at 256 KiB and one pass
 * (REDUCED_COST_CONTAINER of scripts/public-test-data.mjs). */
export const REDUCED_COST_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
/** BIP39's all-zero 24-word phrase. */
export const ZERO_24 = `${"abandon ".repeat(23)}art`;
/** BIP32 master key fingerprints of the all-zero 12-word phrase: without a passphrase, with TREZOR. */
export const PHRASE_FINGERPRINT = "73c5da0a";
export const PHRASE_TREZOR_FINGERPRINT = "b4e3f5ed";

/** How `promise` settles, as one line. */
export async function outcome(promise) {
  try {
    return `resolved ${JSON.stringify(await promise)}`;
  } catch (error) {
    return `rejected ${error?.name} ${error?.code ?? ""} ${error?.message}`.replace(/ +/gu, " ");
  }
}
