// The core module of the mhfe browser package: encryption, recovery, the rehearsal check, rekey,
// hidden wallets and the self-test, with Argon2. Every operation runs in a new Web Worker, so a
// long Argon2 computation never blocks the page, cancel() can stop it at once, and the worker's
// memory is freed when it ends.
//
// The page supplies the parts of the module as text and bytes, because a page under a strict
// Content-Security-Policy may not fetch anything:
//
//   const client = new MhfeClient({
//     workerSource,          // text of runtime/worker.js
//     wasm,                  // runtime/mhfe.wasm as a Uint8Array or a WebAssembly.Module
//     argon2Threaded,        // text of core/argon2-mt.js
//     argon2SingleThreaded,  // text of core/argon2-st.js
//   });
//
// A page that uses other module classes too compiles runtime/mhfe.wasm once, with
// WebAssembly.compile, and passes the WebAssembly.Module to each.
//
// Every operation returns a promise and reports every error by rejecting it, the checks of its
// arguments included; none throws when it is called. A callback of the page that throws, or whose
// promise rejects, stops the operation and rejects it with CALLBACK_FAILED. mode(),
// maxSupportedMemLevel() and cancel() are synchronous. Only the constructor throws, for missing
// package parts. One long operation runs at a time (BUSY otherwise); reading words and the
// parameters never wait. The first operation waits for the class's startup check
// (startupCheck()); parameters(), selfTest(), startupCheck() and fullCheck() do not.

import {
  CompiledModule,
  MhfeCancelledError,
  MhfeError,
  OperationSlot,
  PackageCheck,
  WorkerJob,
  describeChoice,
  encodeSecret,
  requireBoolean,
  requireCallback,
  requireSecret,
  requireText,
  secretBuffers,
  sentence,
  wipeSecrets,
} from "../runtime/runtime.js";

export { MhfeCancelledError, MhfeError } from "../runtime/runtime.js";

/** Four Argon2 lanes in parallel; needs a cross-origin isolated page, such as `mhfe serve` gives. */
export const FAST_MODE = "fast";
/** One lane after another; works everywhere, including a page opened as a file. */
export const STANDARD_MODE = "standard";

// These limits are checked here, before any secret is copied, so that a refusal never waits for a
// worker. scripts/verify-browser-package.mjs checks that each equals the core's suiteParameters();
// a repair word count of 0 means none.
/** The reference Argon2 code allows 2 GiB when pointers are 32 bits wide, as in WebAssembly: memory level 0 only. */
const HIGHEST_BROWSER_MEMORY_LEVEL = 0;
const MAX_PIM = 1023;
const MAX_MEMORY_LEVEL = 21;
const WORD_COUNTS = [12, 15, 18, 21, 24];
const REPAIR_WORD_COUNTS = [0, 2, 4, 6, 8];
const REFERENCE_KINDS = ["address", "fingerprint", "words", "walletCheck"];
/** The name of this module's operations in the package's worker. */
const CORE_MODULE = "core";
/** The build of this file, which scripts/stamp-build-id.mjs writes; see BUILD_ID in the runtime. */
const CLIENT_BUILD_ID = "development";

/** The parts of the self-check that run Argon2: its known answer at 1 MiB, and at 64 and 256 MiB. */
const ARGON2_PART = "argon2";
const ARGON2_SIZES_PART = "argon2-sizes";
/** How the full self-check names the check at 64 and 256 MiB of each of the two Argon2 builds. */
const ARGON2_SIZES_OF_BUILD = {
  singleThreaded: {
    id: "argon2-sizes-single-threaded",
    label: "Argon2id at 64 and 256 MiB, single-threaded build",
  },
  threaded: { id: "argon2-sizes-threaded", label: "Argon2id at 64 and 256 MiB, threaded build" },
};
/**
 * What the full self-check lists without running: the published vectors, which take minutes and
 * 2 GiB and run in selfTest() only, and the parts of the command-line tool's self-test that a
 * browser cannot check, with the reason.
 */
const NOT_RUN_IN_FULL_CHECK = [
  {
    id: "published-vectors",
    label: "Published vectors",
    outcome: "notRun",
    detail: "they take minutes and 2 GiB: selfTest() runs them",
  },
  {
    id: "memory-locking",
    label: "Locked memory",
    outcome: "notAvailable",
    detail: "a web page cannot keep its memory out of swap",
  },
  {
    id: "core-dumps",
    label: "Core dumps",
    outcome: "notAvailable",
    detail: "the browser keeps its own crash reports, which a page cannot turn off",
  },
  {
    id: "isolation",
    label: "Isolation",
    outcome: "notAvailable",
    detail: "a web page cannot sandbox itself or prove that it is offline",
  },
  {
    id: "hidden-input",
    label: "Hidden input",
    outcome: "notAvailable",
    detail: "a web page has no terminal whose echo it could read back",
  },
];

export class MhfeClient {
  #sources;
  #wasm;
  #check;
  #slot = new OperationSlot();

  constructor({ workerSource, wasm, argon2Threaded, argon2SingleThreaded } = {}) {
    for (const [name, value] of Object.entries({
      workerSource,
      argon2Threaded,
      argon2SingleThreaded,
    })) {
      if (typeof value !== "string" || value.length === 0)
        throw new TypeError(`${name} must be the text of the file.`);
    }
    this.#wasm = new CompiledModule(wasm, "wasm");
    this.#sources = { workerSource, argon2Threaded, argon2SingleThreaded };
    this.#check = new PackageCheck({
      wasm: this.#wasm,
      classFile: "core/client.js",
      classBuildId: CLIENT_BUILD_ID,
      needs: ["threads"],
      secrets: true,
      // Argon2's known answer holds for the build that gave it, which another client may not use.
      identityOf: (id) => (id === ARGON2_PART ? this.#argon2Source() : undefined),
    });
  }

  /** "fast" on a cross-origin isolated page, otherwise "standard" (about three times slower). */
  mode() {
    return globalThis.crossOriginIsolated === true ? FAST_MODE : STANDARD_MODE;
  }

  /**
   * The quick self-check of the core: known answers of every part encryption, recovery, the
   * rehearsal check, rekey and hidden wallets compute, each with a case it must refuse, and what
   * the page itself must do. With `argon2` (the default) it also runs Argon2's known answer at
   * 1 MiB through this mode's Argon2 build, which it loads; `argon2: false` leaves Argon2 out (not
   * run), for a quick check at a page's start, since every operation runs that known answer itself
   * before its first round and after its last. Resolves to `{ passed, tier, version, buildId,
   * components: [{ id, label, outcome, detail? }] }`, made once per page for each choice: parts
   * that another class of the page passed with the same WebAssembly are not run again. Every
   * operation but parameters() and selfTest() awaits it before its first call (without Argon2 when
   * none ran yet). When a part has failed, every such operation rejects with SELF_CHECK_FAILED from
   * then on, the report attached; a page keeps its controls closed and shows the report.
   *
   * An Argon2 build that does not start gave no wrong answer: Argon2 is then not available, with
   * the cause, the class stays open and the next call checks again, and an operation gets its own
   * error. When only the threaded build of the fast mode does not start, the check runs the
   * single-threaded build of the standard mode instead, and Argon2 passes with a warning that says
   * so.
   */
  async startupCheck({ argon2 = true } = {}) {
    requireBoolean(argon2, "argon2");
    return this.#check.startup(argon2 ? "argon2" : "withoutArgon2", (skip, handlers) =>
      this.#coreCheck("startup", skip, argon2, handlers),
    );
  }

  /**
   * The full self-check, run anew each time, in seconds: every part with its slower cases, and
   * Argon2 at 64 and 256 MiB with each build in turn, never two at once: the single-threaded build,
   * then on a cross-origin isolated page the threaded one (not run otherwise). It lists the
   * published vectors as not run (selfTest() runs them) and the parts a browser cannot check as not
   * available, with the reason. `onProgress({ id, label, running, outcome?, detail? })` hears of
   * each part as it starts and ends. Resolves to a report as startupCheck() does; a failed part
   * closes the client as there. A browser that cannot give 256 MiB, and an Argon2 build that does
   * not start, make those parts not available rather than failed, as startupCheck() describes.
   */
  async fullCheck({ onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    const sizesOf = (build, threaded) => ({
      run: (_, handlers) => this.#argon2Check(threaded, handlers),
      rename: (component) =>
        component.id === ARGON2_SIZES_PART ? { ...component, ...build } : component,
    });
    const threaded =
      this.mode() === FAST_MODE
        ? sizesOf(ARGON2_SIZES_OF_BUILD.threaded, true)
        : {
            components: [
              {
                ...ARGON2_SIZES_OF_BUILD.threaded,
                outcome: "notRun",
                detail: "the page is not cross-origin isolated",
              },
            ],
          };
    return this.#check.full(
      [
        { run: (skip, handlers) => this.#coreCheck("full", skip, true, handlers) },
        sizesOf(ARGON2_SIZES_OF_BUILD.singleThreaded, false),
        threaded,
        { components: NOT_RUN_IN_FULL_CHECK },
      ],
      onProgress,
    );
  }

  /** The highest memory level this browser build can use: 0 (2 GiB). */
  maxSupportedMemLevel() {
    return HIGHEST_BROWSER_MEMORY_LEVEL;
  }

  /**
   * The core's fixed values: `{ version, suiteId, sameLengthSuiteId, rounds, maxPim,
   * maxMemoryLevel, highestBrowserMemoryLevel, wordCounts, builtInCheckWordCounts,
   * repairWordCounts, recommendedRepairWords, repairCapacities }`.
   */
  async parameters() {
    return this.#quick({ operation: "parameters" });
  }

  /**
   * Reads an original phrase the way a person may have typed it (any case and spacing, words cut
   * to four letters) and resolves to `{ phrase, words, otherLengths, containers: [{ sameLength,
   * words, wrongWordPassesOneIn }] }`: every word written out, for showing back, and the containers
   * it can be encrypted into. `otherLengths` is almost always empty; when it is not, automatic
   * detection would not give this phrase on its own after recovery, so the page tells the user to
   * note the word count and choose it then. Rejects an invalid phrase.
   */
  async readPhrase(phrase) {
    requireText(phrase, "phrase");
    await this.#ready();
    // The phrase goes as bytes that the worker and the WebAssembly wipe, as a password does.
    const message = { operation: "describePhrase", phrase: encodeSecret(phrase, "phrase", true) };
    return this.#quick(message, secretBuffers(message));
  }

  /**
   * Like readPhrase for a container: resolves to `{ container, words, suiteId, phraseLengths,
   * builtInCheckLengths, confirmationFor, hiddenWallets, offersWalletCheck, containerFingerprint }`.
   * `confirmationFor` says, for each phrase length, what confirms a recovery to encrypt again:
   * "builtInCheck" or "walletOrOwner".
   */
  async readContainer(container) {
    requireText(container, "container");
    await this.#ready();
    return this.#quick({ operation: "describeContainer", container });
  }

  /**
   * Encrypts an original phrase. `passwordRepeat` is the password typed a second time: a typing
   * mistake in the password would lock the phrase away for good. `passwordRepair` is the choice of
   * the check word review (MhfePasswords.review): "asTyped" (the default), "corrected" or
   * `{ repair: position }`. The encryption then decrypts the container's words again and compares
   * the result with the phrase, so it runs 24 rounds: "encrypt" 1 to 12, then "check" 13 to 24.
   *
   * Resolves only after that check has passed to `{ container, suiteId, containerFingerprint,
   * builtInCheck, otherLengths, repairWords, repairProfile, keep: [{ item, ... }] }`; a failed
   * check rejects with VERIFICATION_FAILED. `keep` lists what the owner keeps, in order:
   * containerWords {words}, password, passphrase, repairWords, pim {value}, memoryLevel {value},
   * wordCount {words}.
   *
   * The container has 24 words. With `sameLength: true`, which only the user's own choice may
   * set after the page has shown its consequences, a 12- to 21-word phrase gives a container of
   * its own length instead. `repairWordCount` 2, 4, 6 or 8 makes repair words, which come only
   * with the result. `walletHasPassphrase`, required, is the user's answer whether the wallet has
   * a BIP39 passphrase: true adds it to what to keep, since MHFE encrypts only the phrase.
   *
   * `onUnverified({ container, containerFingerprint })` is called after the first 12 rounds, so
   * that the page can show the container while the check runs, marked as not yet verified, and
   * later say how the check ended: verified, wrong (VERIFICATION_FAILED), or not verified
   * (cancelled or any other error).
   */
  async encrypt({
    phrase,
    password,
    passwordRepeat,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    sameLength = false,
    repairWordCount = 0,
    walletHasPassphrase,
    onProgress,
    onUnverified,
  } = {}) {
    requireText(phrase, "phrase");
    requireBoolean(sameLength, "sameLength");
    requireWalletPassphrase(walletHasPassphrase);
    requireRepairWordCount(repairWordCount);
    requireCallback(onUnverified, "onUnverified");
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#long(
      {
        operation: "encrypt",
        choice,
        position,
        sameLength,
        repairWordCount,
        walletHasPassphrase,
      },
      {
        phrase,
        password,
        passwordRepeat,
        pim,
        memoryLevel,
        onProgress,
        handlers: { unverified: onUnverified },
      },
    );
  }

  /**
   * Recovers the original phrase, twelve rounds, "recover". The container's word count selects
   * the suite. `words` is 0 for automatic detection or the known length. Resolves to `{ kind:
   * 'phrase' | 'ambiguous', candidates: [{ words, verified, status, phrase, suiteId,
   * fingerprintWithoutPassphrase, passesWalletCheckWithoutPassphrase }] }`; `status` is
   * "verified", "noBuiltInCheck", "readAs24" or "readAs24Chosen".
   */
  async decrypt({
    container,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    words = 0,
    onProgress,
  } = {}) {
    requireText(container, "container");
    if (words !== 0 && !WORD_COUNTS.includes(words)) {
      throw new MhfeError(
        "INVALID_WORD_COUNT",
        "words must be 0 (detect) or 12, 15, 18, 21 or 24.",
      );
    }
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#long(
      { operation: "decrypt", container, choice, position, words },
      { password, pim, memoryLevel, onProgress },
    );
  }

  /**
   * The rehearsal check. `reference` is `{ address, coin, path? }` (strong), `{ fingerprint }`
   * (quick, weaker), `{ words }` (built-in check of a 12- to 21-word original) or
   * `{ walletCheck: true }` (the phrase and passphrase check of a 24-word container, with a
   * passphrase). Resolves to `{ matches, path }`, `path` being where a matched address was found
   * and null otherwise, and never to any part of the phrase. Progress: "recover" 1 to 12, then
   * once "compare".
   */
  async check({
    container,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    reference,
    passphrase = "",
    onProgress,
  } = {}) {
    requireText(container, "container");
    const [referenceKind, referenceValue, coin, path] = describeReference(reference);
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#long(
      {
        operation: "check",
        container,
        choice,
        position,
        referenceKind,
        reference: referenceValue,
        coin,
        path,
      },
      { password, pim, memoryLevel, onProgress, passphrase },
    );
  }

  /**
   * Re-encrypts a container with a new password or settings: rounds 1 to 12 recover it with the
   * old ones, 13 to 36 seal it again. `otherWalletsMoved` must be true: the page has shown every
   * user that the wallets other passwords open on this container change with the new one, and the
   * user said yes. `words` is the phrase's word count, 0 for a same-length container's own.
   *
   * `confirmation` is exactly one of `{ builtInCheck: true }`, `{ address, coin, path? }`,
   * `{ fingerprint }` or `{ owner: (check) => boolean | Promise<boolean> }`
   * (readContainer().confirmationFor says which a length needs). The wallet check, 16 bits, never
   * confirms a phrase to encrypt again. The owner callback receives
   * `{ phrase, words, fingerprintWithoutPassphrase }` to compare with the written backup; anything
   * but true stops the rekey with NOT_CONFIRMED_BY_OWNER. Resolves as encrypt does.
   *
   * `walletHasPassphrase` is the user's answer whether the wallet has a BIP39 passphrase, which
   * the new container's keep list names. An address or a fingerprint compared with a non-empty
   * `passphrase` shows that it has one: there the answer may be left out, and false is refused.
   * Everywhere else it is required (INVALID_REQUEST without it): the built-in check and the owner
   * show nothing, and a reference without a passphrase matches the phrase's wallet without one,
   * which says nothing about funds under a passphrase. Both refusals come before any Argon2 work.
   * `passphrase` belongs only to an address or a fingerprint: a non-empty one with the built-in
   * check or the owner is a TypeError.
   */
  async rekey({
    container,
    words = 0,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    otherWalletsMoved,
    newPassword,
    newPasswordRepeat,
    newPasswordRepair,
    newPim = 0,
    newMemoryLevel = 0,
    repairWordCount = 0,
    confirmation,
    passphrase = "",
    walletHasPassphrase,
    onProgress,
    onUnverified,
  } = {}) {
    requireText(container, "container");
    if (walletHasPassphrase !== undefined) requireWalletPassphrase(walletHasPassphrase);
    if (words !== 0 && !WORD_COUNTS.includes(words)) {
      throw new MhfeError("INVALID_WORD_COUNT", "words must be 0 or 12, 15, 18, 21 or 24.");
    }
    if (otherWalletsMoved !== true) {
      throw new MhfeError(
        "OTHER_WALLETS_NOT_CONFIRMED",
        "The wallets other passwords open on this container change: move their funds first.",
      );
    }
    requireSettings(newPim, newMemoryLevel);
    requireRepairWordCount(repairWordCount);
    requireCallback(onUnverified, "onUnverified");
    const [confirmKind, reference, coin, path, owner] = describeConfirmation(confirmation);
    // Only a string or bytes has a length here; any other type is refused when it is encoded.
    const givenPassphrase =
      (typeof passphrase === "string" || passphrase instanceof Uint8Array) && passphrase.length > 0;
    if (givenPassphrase && (confirmKind === "builtInCheck" || confirmKind === "owner")) {
      throw new TypeError("passphrase belongs only to an address or fingerprint confirmation.");
    }
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    const [newChoice, newPosition] = describeChoice(newPasswordRepair, "newPasswordRepair");
    const request = {
      operation: "rekey",
      container,
      words,
      choice,
      position,
      otherWalletsMoved,
      newChoice,
      newPosition,
      newPim,
      newMemoryLevel,
      repairWordCount,
      confirmKind,
      reference,
      coin,
      path,
      walletHasPassphrase,
    };
    return this.#long(request, {
      password,
      pim,
      memoryLevel,
      onProgress,
      passphrase,
      newPassword,
      newPasswordRepeat,
      handlers: { unverified: onUnverified, ownerCheck: owner },
    });
  }

  /**
   * Opens a session of hidden wallets on a 24-word container, with the main wallet's BIP39
   * passphrase (`mainPassphrase`, required, empty for a wallet without one). Resolves, once the
   * Argon2 work area is reserved, to a handle:
   *
   * - `open({ password, passwordRepeat, passwordRepair, onProgress })` opens the wallet of a new
   *   password, twelve rounds, and resolves to `{ phrase, words, fingerprintWithoutPassphrase }`.
   *   A password used already (PASSWORD_ALREADY_USED), one whose wallet would pass a check
   *   (HIDDEN_WALLET_PASSES_CHECK) and a password refused before any work reject it, and the
   *   session stays open.
   * - `close()` ends the session: the Rust code overwrites every password and the passphrase in
   *   it, and the worker ends. During an `open` it stops the worker at once instead, which frees
   *   its memory without overwriting it. Resolves once the session has ended.
   *
   * The session holds the long-operation slot until it is closed or cancelled. Nothing is created
   * or stored: the container and each password give the same wallet every time. The page shows no
   * list or count of the wallets opened.
   */
  async openHiddenWallets({ container, pim = 0, memoryLevel = 0, mainPassphrase } = {}) {
    requireText(container, "container");
    if (mainPassphrase === undefined) {
      throw new TypeError("mainPassphrase is required; an empty one means a wallet without one.");
    }
    let pendingOpen = null;
    let nextRequest = null;
    let closing = null;
    let handle = null;
    let ready = null;
    // The worker waits for the page's next request (`nextRequest` is set) between wallets.
    const waitForPage = () =>
      new Promise((resolve) => {
        nextRequest = resolve;
      });
    const sendRequest = (request) => {
      const send = nextRequest;
      nextRequest = null;
      send(request);
    };
    const answerOpen = (settle) => {
      const open = pendingOpen;
      pendingOpen = null;
      settle(open);
      return waitForPage();
    };
    const handlers = {
      ready: () => {
        ready.resolve(handle);
        return waitForPage();
      },
      opened: (wallet) => answerOpen((open) => open?.resolve(wallet)),
      refused: (error) =>
        answerOpen((open) => open?.reject(new MhfeError(error.code, sentence(error.message)))),
      progress: (value) => pendingOpen?.onProgress?.(value),
    };
    let job;
    handle = {
      open: async ({ password, passwordRepeat, passwordRepair, onProgress } = {}) => {
        if (job.ended || closing !== null) {
          throw new MhfeError("SESSION_CLOSED", "The session is closed.");
        }
        if (pendingOpen !== null) throw new MhfeError("BUSY", "A wallet is being opened.");
        requireCallback(onProgress, "onProgress");
        requireSamePassword(password, passwordRepeat, "password");
        const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
        const message = {
          password: encodeSecret(password, "password", false),
          passwordRepeat: encodeSecret(passwordRepeat, "repeated password", false),
          choice,
          position,
        };
        return new Promise((resolve, reject) => {
          pendingOpen = { resolve, reject, onProgress };
          sendRequest({ message, transfer: secretBuffers(message) });
        });
      },
      // Every call returns the same promise, which settles once the session has ended.
      close: () => {
        closing ??= closeSession();
        return closing;
      },
    };
    const closeSession = async () => {
      if (nextRequest !== null) {
        // The worker waits: it frees the session, which overwrites its secrets, and ends.
        sendRequest({ message: { close: true }, transfer: [] });
      } else if (!job.ended) {
        // An open is running: its worker stops at once.
        const open = pendingOpen;
        pendingOpen = null;
        job.stop(new MhfeCancelledError());
        open?.reject(new MhfeCancelledError());
      }
      await done.then(
        () => undefined,
        () => undefined,
      );
    };
    const started = new Promise((resolve, reject) => {
      ready = { resolve, reject };
    });
    let done;
    ({ job, done } = await this.#begin(
      { operation: "hiddenWallets", container },
      { pim, memoryLevel, mainPassphrase, handlers, noPassword: true },
    ));
    done.then(undefined, (error) => {
      ready.reject(error);
      pendingOpen?.reject(error);
      pendingOpen = null;
    });
    return started;
  }

  /**
   * The self-test with the two published vectors at their full cost: an encryption of suite 3
   * ("encrypt", rounds 1 to 12 of 24) and a recovery of suite 4 ("recover", 13 to 24). It takes
   * minutes and 2 GiB, so a page starts it only when the person asks; it does not wait for the
   * startup check. Resolves to `{ passed, suite3: { vector, asPublished }, suite4: { vector,
   * asPublished }, firstWrongRound, fault }`. `fault`, null when the test passed, tells where it
   * first left the published path, as `{ kind, round, message }`: "argon2-input" when Argon2id
   * was given an input the published vector does not have, so the fault lies before Argon2id;
   * "argon2-key" when the published input gave another key, so the fault lies in Argon2id; and
   * "after-argon2", round null, when every input and key was as published. `message` is the
   * sentence to show. `firstWrongRound` is that round, 1 to 12 the encryption and 13 to 24 the
   * recovery, or null.
   */
  async selfTest({ onProgress } = {}) {
    return this.#long({ operation: "selfTest" }, { onProgress, noPassword: true }, false);
  }

  /** Stops the running long operation or session at once; its promise rejects with MhfeCancelledError. */
  cancel() {
    this.#slot.cancel();
  }

  /**
   * A quick operation: the Rust core only, in a worker of its own, never BUSY. `transfer` lists the
   * buffers of the message's secrets, which the job owns from here on.
   */
  #quick(message, transfer = []) {
    return new WorkerJob([this.#sources.workerSource]).run(
      { module: CORE_MODULE, ...message },
      transfer,
      this.#wasm,
    );
  }

  /** A long operation, which resolves to its result; see #begin. */
  async #long(request, options, gated = true) {
    const { done } = await this.#begin(request, options, gated);
    return done;
  }

  /**
   * Starts a long operation in the slot and resolves to `{ job, done }`, `done` resolving to its
   * result. Everything that is not secret is checked first; then, when `gated`, the startup check
   * is awaited with the slot held; only then are the secrets copied into bytes, and until the
   * worker owns them, every failure wipes the copies.
   */
  async #begin(request, options, gated = true) {
    const { pim = 0, memoryLevel = 0 } = options;
    this.#slot.requireIdle();
    requireSettings(pim, memoryLevel);
    requireCallback(options.onProgress, "onProgress");
    if (options.passwordRepeat !== undefined || request.operation === "encrypt") {
      requireSamePassword(options.password, options.passwordRepeat, "password");
    }
    if (options.newPassword !== undefined || request.operation === "rekey") {
      requireSamePassword(options.newPassword, options.newPasswordRepeat, "new password");
    }
    const start = () => this.#start(request, options);
    return gated ? this.#slot.after(this.#ready(), start) : start();
  }

  /** Copies the secrets of a checked request and starts its job in the slot; see #begin. */
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
    let message = { module: CORE_MODULE, ...request, pim, memoryLevel };
    try {
      // An empty phrase is the core's to refuse (INVALID_PHRASE), as any other invalid one.
      if (phrase !== undefined) message.phrase = encodeSecret(phrase, "phrase", true);
      if (!noPassword) message.password = encodeSecret(password, "password", false);
      if (passwordRepeat !== undefined) {
        message.passwordRepeat = encodeSecret(passwordRepeat, "repeated password", false);
      }
      if (passphrase !== undefined)
        message.passphrase = encodeSecret(passphrase, "passphrase", true);
      if (newPassword !== undefined) {
        message.newPassword = encodeSecret(newPassword, "new password", false);
        message.newPasswordRepeat = encodeSecret(newPasswordRepeat, "repeated new password", false);
      }
      if (mainPassphrase !== undefined) {
        message.mainPassphrase = encodeSecret(mainPassphrase, "main passphrase", true);
      }
      message.argon2Script = this.#argon2Script(this.mode() === FAST_MODE);
      const job = this.#slot.job([this.#argon2Source(), this.#sources.workerSource], {
        progress: onProgress,
        ...handlers,
      });
      return { job, done: job.run(message, secretBuffers(message), this.#wasm) };
    } catch (error) {
      wipeSecrets(message);
      message = null;
      throw error;
    }
  }

  /** The text of this mode's Argon2 build: threaded on a cross-origin isolated page. */
  #argon2Source() {
    return this.mode() === FAST_MODE
      ? this.#sources.argon2Threaded
      : this.#sources.argon2SingleThreaded;
  }

  /** The threaded build's lane workers run this same script and may only come from a Blob. */
  #argon2Script(threaded) {
    return threaded ? new Blob([this.#sources.argon2Threaded], { type: "text/javascript" }) : null;
  }

  /** Resolves once the startup check has passed; see startupCheck(). */
  #ready() {
    return this.#check.require(() => this.startupCheck({ argon2: false }));
  }

  /**
   * The core's set of known answers at `tier` in a worker of its own, through this mode's Argon2
   * build when `argon2`. In fast mode the single-threaded build follows the threaded one, so that
   * the check falls back to it, and says so, when the threaded build does not start
   * (web/core-worker.js); an operation still uses the threaded build and gets its own error. The
   * core's limits must be this file's, which it checks before any secret is copied: a difference
   * means parts of different builds (PACKAGE_MISMATCH).
   */
  async #coreCheck(tier, skip, argon2, handlers) {
    const scripts = [this.#sources.workerSource];
    if (argon2 && this.mode() === FAST_MODE) {
      scripts.unshift(this.#sources.argon2Threaded, this.#sources.argon2SingleThreaded);
    } else if (argon2) {
      scripts.unshift(this.#sources.argon2SingleThreaded);
    }
    const { parameters, ...report } = await new WorkerJob(scripts, handlers).run(
      {
        module: CORE_MODULE,
        operation: "selfCheck",
        tier,
        skip,
        argon2,
        argon2Script: this.#argon2Script(argon2 && this.mode() === FAST_MODE),
      },
      [],
      this.#wasm,
    );
    requireSameLimits(parameters);
    return report;
  }

  /**
   * One Argon2 build alone at 64 and 256 MiB, in a worker of its own. Its known answer at 1 MiB is
   * left out: the core's check gave it for this mode's build, and these larger ones cover it.
   */
  #argon2Check(threaded, handlers) {
    const source = threaded ? this.#sources.argon2Threaded : this.#sources.argon2SingleThreaded;
    return new WorkerJob([source, this.#sources.workerSource], handlers).run(
      {
        module: CORE_MODULE,
        operation: "selfCheckArgon2",
        tier: "full",
        skip: [ARGON2_PART],
        argon2Script: this.#argon2Script(threaded),
      },
      [],
      this.#wasm,
    );
  }
}

/**
 * The core's fixed values must be the limits this file checks before any secret is copied
 * (scripts/verify-browser-package.mjs compares them too); otherwise the files come from different
 * builds.
 */
function requireSameLimits(parameters) {
  const same =
    parameters.maxPim === MAX_PIM &&
    parameters.maxMemoryLevel === MAX_MEMORY_LEVEL &&
    parameters.highestBrowserMemoryLevel === HIGHEST_BROWSER_MEMORY_LEVEL &&
    parameters.wordCounts.join() === WORD_COUNTS.join() &&
    [0, ...parameters.repairWordCounts].join() === REPAIR_WORD_COUNTS.join();
  if (!same) {
    throw new MhfeError(
      "PACKAGE_MISMATCH",
      "The files core/client.js and runtime/mhfe.wasm have different limits: take every file of " +
        "the package from one build.",
    );
  }
}

/** The user's answer whether the wallet has a BIP39 passphrase: true or false, never a default. */
function requireWalletPassphrase(walletHasPassphrase) {
  if (typeof walletHasPassphrase !== "boolean") {
    throw new TypeError(
      "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.",
    );
  }
}

/**
 * The repeated password must be the same string, or the same bytes; `name` names the password in
 * a TypeError. The types come first: a password or a repetition that is neither a string nor a
 * Uint8Array is a TypeError, as encodeSecret makes it, not two entries that differ. A repetition
 * left out differs.
 */
function requireSamePassword(password, passwordRepeat, name) {
  requireSecret(password, name);
  if (passwordRepeat === undefined) throw passwordsDiffer();
  requireSecret(passwordRepeat, `repeated ${name}`);
  if (typeof password === "string" && typeof passwordRepeat === "string") {
    if (password !== passwordRepeat) throw passwordsDiffer();
    return;
  }
  // One of them is bytes: compare UTF-8 bytes, in copies that are wiped at once.
  const first = encodeSecret(password, name, true);
  try {
    const second = encodeSecret(passwordRepeat, `repeated ${name}`, true);
    const same =
      first.length === second.length && first.every((byte, index) => byte === second[index]);
    second.fill(0);
    if (!same) throw passwordsDiffer();
  } finally {
    first.fill(0);
  }
}

function passwordsDiffer() {
  return new MhfeError("PASSWORDS_DIFFER", "The password and its repetition differ.");
}

/** The PIM and memory level, including the browser's memory limit. */
function requireSettings(pim, memoryLevel) {
  requireSetting(pim, MAX_PIM, "INVALID_PIM", "pim");
  requireSetting(memoryLevel, MAX_MEMORY_LEVEL, "INVALID_MEMORY_LEVEL", "memoryLevel");
  if (memoryLevel > HIGHEST_BROWSER_MEMORY_LEVEL) {
    throw new MhfeError(
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      `Memory level ${memoryLevel} needs more memory than a browser can give; use the mhfe command-line tool.`,
    );
  }
}

function requireSetting(value, highest, code, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > highest) {
    throw new MhfeError(code, `${name} must be a whole number from 0 to ${highest}.`);
  }
}

function requireRepairWordCount(count) {
  if (!REPAIR_WORD_COUNTS.includes(count)) {
    throw new MhfeError("INVALID_REPAIR_WORDS", "repairWordCount must be 0, 2, 4, 6 or 8.");
  }
}

/**
 * The one reference of a check. Exactly one of address, fingerprint, words and walletCheck must
 * be given: with several, the check would silently use only one of them.
 */
function describeReference(reference) {
  const isObject = reference !== null && typeof reference === "object";
  const given = (kind) => Object.hasOwn(reference, kind) && reference[kind] !== undefined;
  const kinds = isObject ? REFERENCE_KINDS.filter(given) : [];
  if (kinds.length !== 1) {
    throw new TypeError(
      "reference must be exactly one of { address, coin, path? }, { fingerprint }, { words } or { walletCheck: true }.",
    );
  }
  for (const key of ["coin", "path"]) {
    if (reference[key] !== undefined && kinds[0] !== "address") {
      throw new TypeError(`reference.${key} belongs only to an address reference.`);
    }
  }
  switch (kinds[0]) {
    case "address":
      requireText(reference.address, "reference.address");
      if (reference.path !== undefined) requireText(reference.path, "reference.path");
      // No coin is the default, so that a page for one coin names no other.
      if (reference.coin === undefined) {
        throw new TypeError(
          "reference.coin must name the coin of the address, an id of MhfeWallet.parameters().coins.",
        );
      }
      requireText(reference.coin, "reference.coin");
      return ["address", reference.address, reference.coin, reference.path ?? ""];
    case "fingerprint":
      requireText(reference.fingerprint, "reference.fingerprint");
      return ["fingerprint", reference.fingerprint, "", ""];
    case "walletCheck":
      if (reference.walletCheck !== true)
        throw new TypeError("reference.walletCheck must be true.");
      return ["walletCheck", "", "", ""];
    default:
      if (![12, 15, 18, 21].includes(reference.words)) {
        throw new MhfeError(
          "INVALID_WORD_COUNT",
          "The built-in check needs a 12-, 15-, 18- or 21-word original.",
        );
      }
      return ["words", String(reference.words), "", ""];
  }
}

/**
 * The confirmation of a rekey: the built-in check, the owner, or an address or fingerprint of the
 * wallet. A key whose value is undefined counts as not given, as for a check's reference.
 */
function describeConfirmation(confirmation) {
  if (confirmation === null || typeof confirmation !== "object") {
    throw new TypeError(
      "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
        "{ fingerprint } or { owner }.",
    );
  }
  const given = Object.keys(confirmation).filter((key) => confirmation[key] !== undefined);
  if (given.includes("builtInCheck")) {
    if (confirmation.builtInCheck !== true || given.length !== 1) {
      throw new TypeError("confirmation must be exactly one kind; builtInCheck must be true.");
    }
    return ["builtInCheck", "", "", "", undefined];
  }
  if (given.includes("owner")) {
    if (typeof confirmation.owner !== "function" || given.length !== 1) {
      throw new TypeError("confirmation must be exactly one kind; owner must be a function.");
    }
    // Whatever the page's callback throws, even an MhfeError of another call, ends the rekey
    // with CALLBACK_FAILED and the page's error as the cause.
    const owner = async (check) => {
      try {
        return (await confirmation.owner(check)) === true;
      } catch (cause) {
        throw new MhfeError("CALLBACK_FAILED", "The page's owner callback failed.", { cause });
      }
    };
    return ["owner", "", "", "", owner];
  }
  if (given.includes("words")) {
    throw new TypeError("a rekey is confirmed by { builtInCheck: true }, not by a word count.");
  }
  if (given.includes("walletCheck")) {
    throw new TypeError(
      "a rekey is confirmed by an address or a fingerprint, not by the wallet check.",
    );
  }
  if (!given.includes("address") && !given.includes("fingerprint")) {
    throw new TypeError(
      "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
        "{ fingerprint } or { owner }.",
    );
  }
  const [kind, reference, coin, path] = describeReference(confirmation);
  return [kind, reference, coin, path, undefined];
}
