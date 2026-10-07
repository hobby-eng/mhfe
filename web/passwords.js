// The passwords module of the mhfe browser package: the review of a typed password under its check
// word (MHFE-PASSWORD-CHECK-1), the strength estimate and the password generator. No Argon2. A page
// supplies the module's files as text and bytes:
//
//   const passwords = new MhfePasswords({
//     workerSource,   // text of runtime/worker.js
//     wasm,           // runtime/mhfe.wasm as a Uint8Array or a WebAssembly.Module
//   });
//
// A page that uses several module classes compiles runtime/mhfe.wasm once, with
// WebAssembly.compile, and passes the WebAssembly.Module to each.
//
// Every method returns a promise and reports every error by rejecting it; none throws when it is
// called. Each call runs in a worker of its own, which is terminated afterwards with every copy of
// the password in it. Results that hold a password or its words are JavaScript strings, which
// cannot be wiped: a page shows them only on request and drops them soon after. The first call
// waits for the class's startup check (startupCheck()).

import {
  CompiledModule,
  PackageCheck,
  WorkerJob,
  describeChoice,
  encodeSecret,
  requireCallback,
  requireText,
  secretBuffers,
  wipeSecrets,
} from "../runtime/runtime.js";

export { MhfeError } from "../runtime/runtime.js";

/** The name of this module's operations in the package's worker. */
const PASSWORDS_MODULE = "passwords";
/** make()'s refusal of a count with the check word (makePassword in src/wasm_api/passwords.rs). */
const CHECK_WORD_TAKES_NO_COUNT =
  'count belongs only to the kinds "words" and "characters": "checkWord" always gives five ' +
  "words and their check word.";
/** The build of this file, which scripts/stamp-build-id.mjs writes; see BUILD_ID in the runtime. */
const PASSWORDS_BUILD_ID = "development";

export class MhfePasswords {
  #workerSource;
  #wasm;
  #check;

  constructor({ workerSource, wasm } = {}) {
    if (typeof workerSource !== "string" || workerSource.length === 0) {
      throw new TypeError("workerSource must be the text of runtime/worker.js.");
    }
    this.#workerSource = workerSource;
    this.#wasm = new CompiledModule(wasm, "wasm");
    this.#check = new PackageCheck({
      wasm: this.#wasm,
      classFile: "passwords/passwords.js",
      classBuildId: PASSWORDS_BUILD_ID,
      needs: ["random"],
      secrets: true,
    });
  }

  /**
   * The quick self-check of this class, which every other method awaits before its first call:
   * known answers of each part the class computes, each with a case it must refuse, and what the
   * page itself must do. Resolves to `{ passed, tier, version, buildId, components: [{ id, label,
   * outcome, detail? }] }`, made once per page: parts that another class of the page passed with
   * the same WebAssembly are not run again. When a part has failed, every method of the class
   * rejects with SELF_CHECK_FAILED from then on, the report attached; a page keeps its controls
   * closed and shows the report.
   */
  async startupCheck() {
    return this.#check.startup("startup", (skip, handlers) =>
      this.#selfCheck("startup", skip, handlers),
    );
  }

  /**
   * The full self-check, run anew each time: every part with its slower cases, the browser's random generator included.
   * `onProgress({ id, label, running, outcome?, detail? })` hears of each part as it starts and
   * ends. Resolves to a report as startupCheck() does; a failed part closes the class as there.
   */
  async fullCheck({ onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    return this.#check.full(
      [{ run: (skip, handlers) => this.#selfCheck("full", skip, handlers) }],
      onProgress,
    );
  }

  /**
   * The module's fixed values: `{ version, checkWordProfile, defaultWords, recommendedWords,
   * mostWords, defaultCharacters, recommendedCharacters, mostCharacters, weakBelowBits }`.
   */
  async parameters() {
    return this.#run({ operation: "parameters" });
  }

  /**
   * Reviews a typed password under the check word profile, before any long work. With
   * `passwordRepeat`, a new password typed twice, both must be the same, an empty repetition
   * included (PASSWORDS_DIFFER).
   * Resolves to `{ profile, reading, correction, correctionText, offersCorrection, repairsFirst,
   * repairs: [{ position, word, typed }] }`; `reading` is "notThisShape", "fits", "restorable" or
   * "mismatch". The answers a page offers come from it, and the one chosen goes to the long
   * operation as `passwordRepair`: "asTyped", "corrected" or `{ repair: position }`.
   */
  async review({ password, passwordRepeat } = {}) {
    await this.#ready();
    const message = {
      operation: "review",
      password: encodeSecret(password, "password", false),
      // An empty repetition is a repetition that differs, not a missing one.
      repeated: passwordRepeat !== undefined,
    };
    try {
      message.passwordRepeat = encodeSecret(passwordRepeat ?? "", "repeated password", true);
    } catch (error) {
      // A refused repetition must not leave the password's copy behind.
      wipeSecrets(message);
      throw error;
    }
    return this.#run(message);
  }

  /**
   * The rough strength of a password or passphrase after the review choice `passwordRepair`, so
   * that it is of the text that will be used. Resolves to `{ bits, weak }`; a weak one deserves a
   * warning before it protects a phrase.
   */
  async strength({ password, passwordRepair } = {}) {
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    await this.#ready();
    const message = {
      operation: "strength",
      password: encodeSecret(password, "password", true),
      choice,
      position,
    };
    return this.#run(message);
  }

  /**
   * Makes a password: `kind` "words" (`count` 1 to 32, by default 5), "checkWord" (five words
   * and their check word) or "characters" (`count` 1 to 64, by default 16). "checkWord" takes no
   * `count`, a TypeError, as `mhfe password` refuses `--check-word` with `--words`: a page never
   * gets fewer words than it asked for. With `dice`, five digits from 1 to 6 per word separated by
   * spaces, the words come from real dice; otherwise from the browser's random generator.
   * Resolves to `{ password, bits, weak, checkWord }`.
   */
  async make({ kind = "words", count, dice = "" } = {}) {
    requireText(kind, "kind");
    if (count !== undefined && !Number.isSafeInteger(count)) {
      throw new TypeError("count must be a whole number.");
    }
    if (kind === "checkWord" && count !== undefined) {
      throw new TypeError(CHECK_WORD_TAKES_NO_COUNT);
    }
    await this.#ready();
    const message = {
      operation: "make",
      kind,
      count,
      rolls: encodeSecret(dice, "dice digits", true),
    };
    return this.#run(message);
  }

  #run(message) {
    return new WorkerJob([this.#workerSource]).run(
      { module: PASSWORDS_MODULE, ...message },
      secretBuffers(message),
      this.#wasm,
    );
  }

  /** Runs the module's set of known answers at `tier` in a worker of its own. */
  #selfCheck(tier, skip, handlers) {
    return new WorkerJob([this.#workerSource], handlers).run(
      { module: PASSWORDS_MODULE, operation: "selfCheck", tier, skip },
      [],
      this.#wasm,
    );
  }

  /** Resolves once the startup check has passed; see startupCheck(). */
  #ready() {
    return this.#check.require(() => this.startupCheck());
  }
}
