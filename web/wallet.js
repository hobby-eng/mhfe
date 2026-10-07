// The wallet module of the mhfe browser package: the wallet check of a recovered phrase
// (MHFE-WALLET-CHECK-SEED-1), master key fingerprints, what an address check searches, and new
// 24-word phrases. No Argon2. A page supplies the module's files as text and bytes:
//
//   const wallet = new MhfeWallet({
//     workerSource,   // text of runtime/worker.js
//     wasm,           // runtime/mhfe.wasm as a Uint8Array or a WebAssembly.Module
//   });
//
// A page that uses several module classes compiles runtime/mhfe.wasm once, with
// WebAssembly.compile, and passes the WebAssembly.Module to each.
//
// Every method returns a promise and reports every error by rejecting it; none throws when it is
// called. Each call runs in a worker of its own, terminated afterwards. A new phrase is a
// JavaScript string, which cannot be wiped: a page shows it only on request and drops it soon
// after. The first call waits for the class's startup check (startupCheck()).

import {
  CompiledModule,
  MhfeCancelledError,
  MhfeError,
  PackageCheck,
  WorkerJob,
  encodeSecret,
  requireCallback,
  requireSecret,
  requireText,
  secretBuffers,
  wipeSecrets,
} from "../runtime/runtime.js";

export { MhfeCancelledError, MhfeError } from "../runtime/runtime.js";

/** Workers that draw a checked phrase at once by default; each takes a processor core. */
const MOST_DRAW_WORKERS = 8;

/** The name of this module's operations in the package's worker. */
const WALLET_MODULE = "wallet";
/** The build of this file, which scripts/stamp-build-id.mjs writes; see BUILD_ID in the runtime. */
const WALLET_BUILD_ID = "development";

export class MhfeWallet {
  #workerSource;
  #wasm;
  #check;
  #drawing = null;

  constructor({ workerSource, wasm } = {}) {
    if (typeof workerSource !== "string" || workerSource.length === 0) {
      throw new TypeError("workerSource must be the text of runtime/worker.js.");
    }
    this.#workerSource = workerSource;
    this.#wasm = new CompiledModule(wasm, "wasm");
    this.#check = new PackageCheck({
      wasm: this.#wasm,
      classFile: "wallet/wallet.js",
      classBuildId: WALLET_BUILD_ID,
      needs: ["random"],
      secrets: true,
    });
  }

  /**
   * The quick self-check of this class, which every other method but cancel() awaits before its
   * first call: known answers of each part the class computes, each with a case it must refuse,
   * and what the page itself must do; no part names a coin. Resolves to `{ passed, tier, version,
   * buildId, components: [{ id, label, outcome, detail? }] }`, made once per page: parts that
   * another class of the page passed with the same WebAssembly are not run again. When a part has
   * failed, every method of the class rejects with SELF_CHECK_FAILED from then on, the report
   * attached; a page keeps its controls closed and shows the report.
   */
  async startupCheck() {
    return this.#check.startup("startup", (skip, handlers) =>
      this.#selfCheck("startup", skip, handlers),
    );
  }

  /**
   * The full self-check, run anew each time: every part with its slower cases, the browser's
   * random generator included. `onProgress({ id, label, running, outcome?, detail? })` hears of
   * each part as it starts and ends. Resolves to a report as startupCheck() does; a failed part
   * closes the class as there.
   */
  async fullCheck({ onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    return this.#check.full(
      [{ run: (skip, handlers) => this.#selfCheck("full", skip, handlers) }],
      onProgress,
    );
  }

  /**
   * The module's fixed values: `{ version, coins: [{ id, name, addressForms }], walletCheckBits,
   * drawReportInterval }`.
   */
  async parameters() {
    return this.#run({ operation: "parameters" });
  }

  /**
   * Whether a recovered 24-word phrase passes the wallet check with the owner's BIP39 passphrase.
   * The check is offered with a passphrase only: an empty one is refused
   * (WALLET_CHECK_NEEDS_PASSPHRASE), and so is a phrase of another length (INVALID_WORD_COUNT).
   * A pass is evidence, not proof, and never says which wallet it is.
   */
  async walletCheck({ phrase, passphrase } = {}) {
    requireText(phrase, "phrase");
    await this.#ready();
    return this.#run(phraseRequest("walletCheck", phrase, passphrase ?? ""));
  }

  /** The master key fingerprint of a phrase with a BIP39 passphrase, which may be empty. */
  async fingerprint({ phrase, passphrase = "" } = {}) {
    requireText(phrase, "phrase");
    await this.#ready();
    return this.#run(phraseRequest("fingerprint", phrase, passphrase));
  }

  /**
   * What an address check would search, to show before it runs: `{ type, search, addresses,
   * onlyPath }`. `coin`, required, is a coin id of parameters().coins; `path` limits the search
   * to one path. No coin is the default, so that a page for one coin names no other.
   */
  async describeAddress({ address, coin, path = "" } = {}) {
    requireText(address, "address");
    if (coin === undefined) {
      throw new TypeError("coin must name the coin of the address, an id of parameters().coins.");
    }
    requireText(coin, "coin");
    requireText(path, "path");
    await this.#ready();
    return this.#run({ operation: "describeAddress", address, coin, path });
  }

  /**
   * Draws a new 24-word phrase from the browser's random generator. With a passphrase, typed twice,
   * the page must say whether the phrase gets the wallet check (`walletCheck`, a required boolean
   * then, never preselected). A checked phrase takes about 65,536 BIP39 seeds: it is drawn on
   * `workers` workers at once, by default as many as the processor's cores up to eight, and the
   * first phrase found is taken, every passing phrase being equally likely. `onProgress({ stage:
   * "draw", draws })` reports the draws of all workers; cancel() stops them. Resolves to
   * `{ phrase, words, walletCheck, fingerprintWithPassphrase, workers }`.
   */
  async drawPhrase({ passphrase = "", passphraseRepeat, walletCheck, workers, onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    if (this.#drawing !== null) throw new MhfeError("BUSY", "Another phrase is being drawn.");
    const hasPassphrase = passphrase !== "" && passphrase?.length !== 0;
    if (hasPassphrase && typeof walletCheck !== "boolean") {
      throw new TypeError("walletCheck must be true or false when a passphrase is given.");
    }
    // A page that asked for the check must never get a phrase without it.
    if (!hasPassphrase && walletCheck === true) {
      throw new MhfeError(
        "WALLET_CHECK_NEEDS_PASSPHRASE",
        "The wallet check needs a BIP39 passphrase; a phrase without one gets no check.",
      );
    }
    const checked = hasPassphrase && walletCheck;
    const count = checked ? (workers ?? defaultWorkers()) : 1;
    if (!Number.isSafeInteger(count) || count < 1) {
      throw new TypeError("workers must be a whole number of at least 1.");
    }
    const waiting = await this.#readyToDraw();
    // The drawing takes over from the wait with nothing in between; a cancel() since the check
    // settled stops it here.
    this.#drawing = null;
    if (waiting.stopped !== null) throw waiting.stopped;
    const first = encodeSecret(passphrase, "passphrase", true);
    if (hasPassphrase) {
      let same = false;
      try {
        const repeat = encodeSecret(passphraseRepeat ?? "", "repeated passphrase", true);
        same = repeat.length === first.length && repeat.every((byte, i) => byte === first[i]);
        repeat.fill(0);
      } finally {
        // A refused repetition must not leave the first copy behind either.
        if (!same) first.fill(0);
      }
      if (!same) {
        throw new MhfeError("PASSPHRASES_DIFFER", "The passphrase and its repetition differ.");
      }
    }
    return new Promise((resolve, reject) => {
      const draws = new Array(count).fill(0);
      const jobs = [];
      const finish = (error, result) => {
        if (this.#drawing === null) return;
        this.#drawing = null;
        for (const job of jobs) job.stop(null);
        if (error === null) resolve({ ...result, workers: count });
        else reject(error);
      };
      this.#drawing = { cancel: () => finish(new MhfeCancelledError()) };
      for (let index = 0; index < count; index += 1) {
        const job = new WorkerJob([this.#workerSource], {
          // Returned, so that a rejected promise of the page stops the drawing too.
          draws: (drawn) => {
            draws[index] = drawn;
            const total = draws.reduce((sum, value) => sum + value, 0);
            return onProgress?.({ stage: "draw", draws: total });
          },
        });
        jobs.push(job);
        const message = {
          module: WALLET_MODULE,
          operation: "drawPhrase",
          passphrase: first.slice(),
          walletCheck: checked,
        };
        job.run(message, secretBuffers(message), this.#wasm).then(
          (result) => finish(null, result),
          (error) => finish(error),
        );
      }
      first.fill(0);
    });
  }

  /** Stops a phrase being drawn; its promise rejects with MhfeCancelledError. */
  cancel() {
    this.#drawing?.cancel();
  }

  #run(message) {
    return new WorkerJob([this.#workerSource]).run(
      { module: WALLET_MODULE, ...message },
      secretBuffers(message),
      this.#wasm,
    );
  }

  /** Runs the module's set of known answers at `tier` in a worker of its own. */
  #selfCheck(tier, skip, handlers) {
    return new WorkerJob([this.#workerSource], handlers).run(
      { module: WALLET_MODULE, operation: "selfCheck", tier, skip },
      [],
      this.#wasm,
    );
  }

  /** Resolves once the startup check has passed; see startupCheck(). */
  #ready() {
    return this.#check.require(() => this.startupCheck());
  }

  /**
   * #ready() for a drawing, which counts as drawing while it waits and until the drawing takes
   * over (see drawPhrase): a second one is BUSY, and cancel() rejects the wait at once with
   * MhfeCancelledError, or, once the wait is over, sets `stopped` of the wait it resolves to.
   */
  async #readyToDraw() {
    let cancel;
    const cancelled = new Promise((_, reject) => {
      cancel = reject;
    });
    const waiting = {
      stopped: null,
      cancel: () => {
        waiting.stopped = new MhfeCancelledError();
        cancel(waiting.stopped);
      },
    };
    this.#drawing = waiting;
    try {
      await Promise.race([this.#ready(), cancelled]);
    } catch (error) {
      if (this.#drawing === waiting) this.#drawing = null;
      throw error;
    }
    return waiting;
  }
}

function defaultWorkers() {
  return Math.min(globalThis.navigator?.hardwareConcurrency || 1, MOST_DRAW_WORKERS);
}

/**
 * The request of `operation` on a phrase with a BIP39 passphrase, both as byte copies that the
 * worker and the WebAssembly wipe. A refused passphrase leaves no copy of the phrase behind.
 */
function phraseRequest(operation, phrase, passphrase) {
  requireSecret(passphrase, "passphrase");
  const message = { operation, phrase: encodeSecret(phrase, "phrase", true) };
  try {
    message.passphrase = encodeSecret(passphrase, "passphrase", true);
  } catch (error) {
    wipeSecrets(message);
    throw error;
  }
  return message;
}
