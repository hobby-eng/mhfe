// @ts-check
// The core module's operations in the package's worker: encryption, recovery, the rehearsal check,
// rekey, hidden wallets, the self-test and the self-checks. For an operation that needs Argon2, the
// core places one Emscripten build of the reference Argon2 code (argon2-mt.js or argon2-st.js) in
// front of the worker, and for a self-check on a fast-mode page both, the threaded one first;
// web/argon2-engine.js bridges it to the WebAssembly.
"use strict";

const REFERENCE_COMMON_FIELDS = /** @type {const} */ ({
  reference: "text",
  coin: "text",
  path: "text",
  passphrase: "bytes",
});
const REFERENCE_FIELDS = /** @type {const} */ ({
  ...REFERENCE_COMMON_FIELDS,
  referenceKind: "text",
});
const CONFIRMATION_FIELDS = /** @type {const} */ ({
  ...REFERENCE_COMMON_FIELDS,
  confirmKind: "text",
  words: "number",
});
const OWNER_ANSWER_FIELDS = /** @type {const} */ ({ confirmed: "boolean", passphrase: "bytes" });
const HIDDEN_OPEN_FIELDS = /** @type {const} */ ({
  password: "bytes",
  passwordRepeat: "bytes",
  choice: "text",
  position: "number",
});

/**
 * A session ends with null or close=true; otherwise every opening field is required.
 * @param {unknown} value
 * @returns {HiddenWalletRequest | null}
 */
function readHiddenWalletRequest(value) {
  if (value === null) return null;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw packageMismatch("The page sent a malformed hidden-wallet answer");
    }
    const answer = /** @type {Record<string, unknown>} */ (value);
    if (answer.close === true) {
      new SecretRequest(answer).wipe();
      return { close: true };
    }
    if (answer.close !== undefined && answer.close !== false) {
      throw packageMismatch("The page sent a malformed close field");
    }
    const opened = checkedFields(value, HIDDEN_OPEN_FIELDS);
    return {
      close: false,
      password: opened.password,
      passwordRepeat: opened.passwordRepeat,
      choice: opened.choice,
      position: opened.position,
    };
  } catch (error) {
    new SecretRequest(value).wipe();
    throw error;
  }
}

/** The field types of this module's DTO; Rust keeps numeric and mnemonic rules. */
const CORE_FIELDS = /** @type {const} */ ({
  tier: "text",
  skip: "texts",
  referenceKind: "text",
  reference: "text",
  coin: "text",
  path: "text",
  passphrase: "bytes",
  phrase: "bytes",
  password: "bytes",
  passwordRepeat: "bytes",
  choice: "text",
  position: "number",
  pim: "number",
  memoryLevel: "number",
  sameLength: "boolean",
  repairWordCount: "number",
  walletHasPassphrase: "triBoolean",
  container: "text",
  words: "number",
  asksLength: "boolean",
  scanGap: "number",
  argon2: "boolean",
  argon2Script: "script",
  newPassword: "bytes",
  newPasswordRepeat: "bytes",
  newChoice: "text",
  newPosition: "number",
  newPim: "number",
  newMemoryLevel: "number",
  confirmKind: "text",
  confirmsAgain: "boolean",
  mainPassphrase: "bytes",
});

/** @typedef {CheckedFields<typeof CORE_FIELDS>} CoreRequest */

/**
 * A reference that a recovery is compared with, as a check's request and the page's answer to
 * "noLength" (answerNoLength in web/client.js) carry it.
 * @typedef {CheckedFields<typeof REFERENCE_FIELDS>} ReferenceFields
 */

/**
 * The page's answer to "confirmAgain" (answerConfirmAgain in web/client.js): another confirmation.
 * @typedef {CheckedFields<typeof CONFIRMATION_FIELDS>} ConfirmationFields
 */

/**
 * The page's next request in a session of hidden wallets (openHiddenWallets in web/client.js): a
 * password typed twice with its review choice, or the end of the session.
 * @typedef {{ close: true } | (CheckedFields<typeof HIDDEN_OPEN_FIELDS> & { close: false })}
 *   HiddenWalletRequest
 */

/**
 * A rekey's recovery once it is confirmed, as RekeySession.recover() and confirmAgain() give it:
 * what the owner compares, if the owner confirms, and the 16-bit wallet check.
 * @typedef {{ ownerCheck: Record<string, unknown> | null, rehearsalNeedsPassphrase: boolean,
 *   walletCheck: boolean | null }} ConfirmedRecovery
 */

/**
 * An Emscripten build of the reference Argon2 code that may be in front of this file
 * (argon2Builds).
 * @typedef {{ name: "threaded" | "single-threaded", file: string,
 *   create: Argon2Factory | undefined, buildId: string }}
 *   Argon2Build
 */

/**
 * The Argon2 bridge of a self-check, and how its parts read (argon2ForCheck).
 * @typedef {{ argon2: Argon2Engine, outcomeOf: (result: ComponentResult) => ComponentResult }}
 *   Argon2ForCheck
 */

/**
 * The parts of a self-check that run Argon2, as the core names them (src/engine).
 * @type {() => string[]}
 */
const argon2Parts = () => JSON.parse(mhfe.suiteParameters()).argon2Parts;
/** What an Argon2 part of a self-check adds when the threaded build did not start. */
const FALLBACK_NOTE = "the check ran the single-threaded build of the standard mode instead";

/** A startup refusal retains known backend/context fields, never a factory's exception text. */
class Argon2StartError extends Error {
  /** @type {Argon2Build["name"]} */
  #build;
  /** @type {"notIsolated" | "startFailed"} */
  #issue;

  /** @param {Argon2Build["name"]} build
   * @param {"notIsolated" | "startFailed"} issue */
  constructor(build, issue) {
    super();
    this.#build = build;
    this.#issue = issue;
    this.name = "Argon2StartError";
    this.message = `${this.code}: ${this.detail}`;
  }

  /** The readonly code of this sanitized backend-startup refusal.
   * @returns {"INTERNAL_ERROR"} */
  get code() {
    return "INTERNAL_ERROR";
  }

  /** The safe context the self-check can render even when Rust could not start Argon2. */
  get detail() {
    const build = `the ${this.#build} Argon2 build did not start`;
    return this.#issue === "notIsolated"
      ? `${build}: the page is not cross-origin isolated, so the build cannot share its memory with its lane workers`
      : build;
  }

  /** @param {Argon2StartError[]} failures */
  static describeAll(failures) {
    return failures.map((error) => error.detail).join("; ");
  }
}

/**
 * The core's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<unknown>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const CORE_OPERATIONS = operationsWithFields(CORE_FIELDS, {
  parameters: () => JSON.parse(mhfe.suiteParameters()),
  describePhrase: (request) => JSON.parse(mhfe.describePhrase(request.phrase)),
  describeContainer: (request) => JSON.parse(mhfe.describeContainer(request.container)),

  async encrypt(request, host) {
    const argon2 = await argon2For(request);
    return JSON.parse(
      mhfe.encrypt(
        request.phrase,
        request.password,
        request.passwordRepeat,
        request.choice,
        request.position,
        request.pim,
        request.memoryLevel,
        request.sameLength,
        request.repairWordCount,
        request.walletHasPassphrase,
        argon2,
        host.progress,
        (json) => host.post("unverified", JSON.parse(json)),
      ),
    );
  },

  async decrypt(request, host) {
    const argon2 = await argon2For(request);
    return JSON.parse(
      mhfe.decrypt(
        request.container,
        request.password,
        request.choice,
        request.position,
        request.pim,
        request.memoryLevel,
        request.words,
        request.passphrase,
        argon2,
        host.progress,
      ),
    );
  },

  /**
   * The rehearsal check: one recovery, compared with the page's reference and, when detection
   * found no length (`{ words: 0 }`) and the page asks for it, with the reference the page then
   * gives, without the rounds again.
   */
  async check(request, host) {
    const argon2 = await argon2For(request);
    const session = new mhfe.CheckSession(
      request.container,
      request.password,
      request.choice,
      request.position,
      request.pim,
      request.memoryLevel,
      request.referenceKind,
      request.reference,
      request.coin,
      request.path,
      request.passphrase,
      argon2,
      host.progress,
    );
    return withSession(session, async () => {
      /** @type {(reference: ReferenceFields) => { outcome: string, evidence: unknown }} */
      const compare = (reference) =>
        JSON.parse(
          session.compare(
            reference.referenceKind,
            reference.reference,
            reference.coin,
            reference.path,
            reference.passphrase,
          ),
        );
      const result = compare(request);
      // Detection that found no verified length, none or several, asks the page for the length.
      if (!session.asksLength() || !request.asksLength) return result;
      // The page answers with a reference or null (answerNoLength in web/client.js).
      const next = checkedNullableFields(
        await host.ask("noLength", result.evidence),
        REFERENCE_FIELDS,
      );
      if (next === null) return result;
      try {
        return compare(next);
      } finally {
        new SecretRequest(next).wipe();
      }
    });
  },

  searchCandidates: (request) => JSON.parse(mhfe.searchCandidates(request.container)),

  keepOldContainer: (request) =>
    JSON.parse(mhfe.keepOldContainer(request.pim, request.memoryLevel)),

  searchDecoy: (request, host) =>
    JSON.parse(
      mhfe.searchDecoy(
        request.container,
        request.referenceKind,
        request.reference,
        request.coin,
        request.path,
        request.passphrase,
        request.scanGap,
        (candidate, candidates) =>
          host.post("progress", { stage: "search", candidate, candidates }),
      ),
    ),

  async searchWallet(request, host) {
    const argon2 = await argon2For(request);
    let candidate = 0;
    let candidates = 0;
    return JSON.parse(
      mhfe.searchWallet(
        request.container,
        request.password,
        request.choice,
        request.position,
        request.pim,
        request.memoryLevel,
        request.referenceKind,
        request.reference,
        request.coin,
        request.path,
        request.passphrase,
        argon2,
        (index, count) => {
          candidate = index;
          candidates = count;
        },
        (round, rounds) =>
          host.post("progress", { stage: "search", candidate, candidates, round, rounds }),
      ),
    );
  },

  async selfTest(request, host) {
    const argon2 = await argon2For(request);
    return JSON.parse(mhfe.selfTest(argon2, host.progress));
  },

  /**
   * The core's self-check, through the Argon2 build in front of the worker when `request.argon2`
   * is true (see argon2ForCheck), with the core's fixed values, which the page compares with its
   * own limits.
   */
  async selfCheck(request, host) {
    const start = request.argon2 ? await argon2ForCheck(request) : null;
    const parameters = JSON.parse(mhfe.suiteParameters());
    const report = host.selfCheck(
      request.tier,
      (onStart, onResult) =>
        mhfe.selfCheckCore(request.tier, request.skip, start?.argon2, onStart, onResult),
      (result) => (start === null ? result : start.outcomeOf(result)),
    );
    return { ...report, parameters };
  },

  /**
   * The process parts of the command-line tool's self-test as a page reports them: the memory
   * lock from the library's probe and the parts a page cannot check, not available.
   */
  selfCheckProcess: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckProcess(request.tier, request.skip, onStart, onResult),
    ),

  /** The self-check of the Argon2 build in front of the worker alone. */
  async selfCheckArgon2(request, host) {
    const start = await argon2ForCheck(request);
    return host.selfCheck(
      request.tier,
      (onStart, onResult) =>
        mhfe.selfCheckArgon2(request.tier, request.skip, start.argon2, onStart, onResult),
      (result) => start.outcomeOf(result),
    );
  },

  /**
   * A rekey in its order: the old container and password, the new password and settings, the
   * recovery and its confirmation (again on the same recovery after a refusal that allows it,
   * when the page gives another), the owner's answer where the owner confirms the phrase, then
   * the seal.
   */
  async rekey(request, host) {
    const argon2 = await argon2For(request);
    const session = new mhfe.RekeySession(
      request.container,
      request.words,
      request.password,
      request.choice,
      request.position,
      request.pim,
      request.memoryLevel,
      argon2,
    );
    return withSession(session, async () => {
      session.setNew(
        request.newPassword,
        request.newPasswordRepeat,
        request.newChoice,
        request.newPosition,
        request.newPim,
        request.newMemoryLevel,
        request.repairWordCount,
      );
      const recovered = await recoverConfirmed(session, request, host);
      if (recovered.ownerCheck !== null) {
        // The page answers with the owner's yes or no (answerOwner in web/client.js).
        const answer = checkedNullableFields(
          await host.ask("ownerCheck", {
            ...recovered.ownerCheck,
            rehearsalNeedsPassphrase: recovered.rehearsalNeedsPassphrase,
          }),
          OWNER_ANSWER_FIELDS,
        );
        try {
          session.ownerAnswer(answer?.confirmed === true, answer?.passphrase ?? new Uint8Array());
        } finally {
          new SecretRequest(answer).wipe();
        }
      }
      const sealed = JSON.parse(
        session.seal(host.progress, (json) => host.post("unverified", JSON.parse(json))),
      );
      // The 16-bit wallet check of the recovered 24-word reading, reported beside the result.
      return { ...sealed, walletCheck: recovered.walletCheck };
    });
  },

  /**
   * A session of hidden wallets: ready once the Argon2 work area is reserved, then one wallet for
   * each password the page sends, until it sends `{ close: true }`. A documented refusal leaves
   * the session open; any other error ends it.
   */
  async hiddenWallets(request, host) {
    const argon2 = await argon2For(request);
    const session = new mhfe.HiddenWalletSession(
      request.container,
      request.pim,
      request.memoryLevel,
      request.mainPassphrase,
      argon2,
    );
    return withSession(session, async () => {
      /** @type {Set<string>} */
      const keepsSessionOpen = new Set(JSON.parse(mhfe.suiteParameters()).hiddenWalletRefusals);
      // The page answers each question with its next request (openHiddenWallets in
      // web/client.js).
      let next = readHiddenWalletRequest(await host.ask("ready", null));
      while (next !== null && next?.close !== true) {
        /** @type {[question: string, value: unknown]} */
        let reply;
        try {
          const wallet = JSON.parse(
            session.open(
              next.password,
              next.passwordRepeat,
              next.choice,
              next.position,
              host.progress,
            ),
          );
          reply = ["opened", wallet];
        } catch (error) {
          const refusal = describeError(error);
          // The library says which refusals leave the session open for another password.
          if (!keepsSessionOpen.has(refusal.code)) throw error;
          reply = ["refused", refusal];
        } finally {
          new SecretRequest(next).wipe();
        }
        next = readHiddenWalletRequest(await host.ask(...reply));
      }
      return { closed: true };
    });
  },
});

/**
 * A rekey's recovery and confirmation. When a confirmation is refused after the rounds and the
 * core allows another on the same recovery (its ownerLengths), the page is asked for one, if it
 * gives them (`request.confirmsAgain`), and it is confirmed without the rounds again; null from
 * the page, or no answer asked for, ends the rekey with the refusal.
 * @param {mhfe.RekeySession} session
 * @param {CoreRequest} request
 * @param {WorkerHost} host
 * @returns {Promise<ConfirmedRecovery>}
 */
async function recoverConfirmed(session, request, host) {
  let confirm = () =>
    session.recover(
      request.confirmKind,
      request.reference,
      request.coin,
      request.path,
      request.passphrase,
      request.walletHasPassphrase,
      host.progress,
    );
  for (;;) {
    let refusal;
    try {
      return JSON.parse(confirm());
    } catch (error) {
      // After a trap the session is not asked anything more (withSession).
      if (error instanceof WebAssembly.RuntimeError) throw error;
      refusal = error;
    }
    /** @type {number[] | null} */
    const ownerLengths = JSON.parse(session.ownerLengths());
    if (ownerLengths === null || !request.confirmsAgain) throw refusal;
    // The page answers with another confirmation or null (answerConfirmAgain in web/client.js).
    const next = checkedNullableFields(
      await host.ask("confirmAgain", { ...describeError(refusal), ownerLengths }),
      CONFIRMATION_FIELDS,
    );
    if (next === null) throw refusal;
    confirm = () => {
      try {
        return session.confirmAgain(
          next.confirmKind,
          next.reference,
          next.coin,
          next.path,
          next.passphrase,
          next.words,
          host.progress,
        );
      } finally {
        new SecretRequest(next).wipe();
      }
    };
  }
}

/**
 * The Argon2 bridge over the Emscripten build placed in front of this file; see startArgon2.
 * @param {CoreRequest} request
 */
async function argon2For(request) {
  const builds = argon2Builds();
  const build = builds.threaded.create === undefined ? builds.singleThreaded : builds.threaded;
  return argon2Engine(await startArgon2(build, request.argon2Script ?? null));
}

/**
 * The Argon2 bridge of a self-check, and how its parts read once the start of the builds is known.
 * A build that does not start gave no wrong answer: a browser may refuse its memory or its lane
 * workers, and an operation then gets its own error. So, on a fast-mode page whose threaded build
 * does not start, the check runs the single-threaded build of the standard mode, which the page
 * placed in front too, and its Argon2 parts say so; when no build starts, the bridge refuses
 * every call with the causes, and those parts are not available rather than failed. A wrong
 * answer of a build that started stays a failure, and parts of different builds stay an error
 * (PACKAGE_MISMATCH).
 * @param {CoreRequest} request
 * @returns {Promise<Argon2ForCheck>}
 */
async function argon2ForCheck(request) {
  const builds = argon2Builds();
  const tried = [builds.threaded, builds.singleThreaded].filter(({ create }) => create);
  if (tried.length === 0) throw noArgon2Build();
  /** @type {Argon2StartError[]} */
  const failures = [];
  for (const build of tried) {
    try {
      const argon2 = argon2Engine(await startArgon2(build, request.argon2Script ?? null));
      return { argon2, outcomeOf: (result) => afterFallback(result, failures) };
    } catch (error) {
      if (!(error instanceof Argon2StartError)) throw error;
      failures.push(error);
    }
  }
  const refuse = () => {
    throw new Error(Argon2StartError.describeAll(failures));
  };
  return {
    argon2: { derive: refuse, reserve: refuse },
    outcomeOf: (result) =>
      argon2Parts().includes(result.id) && result.outcome === "failed"
        ? {
            ...result,
            outcome: "notAvailable",
            detail: `Argon2id could not run: ${Argon2StartError.describeAll(failures)}`,
          }
        : result,
  };
}

/**
 * A part of a self-check whose Argon2 build started after the threaded one did not, `failures`
 * naming why: it passes with a warning that says so, and its failure, a wrong answer, says so too.
 * @param {ComponentResult} result
 * @param {Argon2StartError[]} failures
 * @returns {ComponentResult}
 */
function afterFallback(result, failures) {
  if (failures.length === 0 || !argon2Parts().includes(result.id)) return result;
  const note = `${Argon2StartError.describeAll(failures)}; ${FALLBACK_NOTE}`;
  if (result.outcome === "passed") return { ...result, outcome: "warning", detail: note };
  return { ...result, detail: `${note}; ${result.detail}` };
}

/**
 * The Emscripten builds of the reference Argon2 code that may be placed in front of this file:
 * the factory each defines, and its build, which scripts/stamp-build-id.mjs stamps into it. A
 * build that is not in front leaves its names undefined, hence typeof.
 * @returns {{ threaded: Argon2Build, singleThreaded: Argon2Build }}
 */
function argon2Builds() {
  return {
    threaded: {
      name: "threaded",
      file: "core/argon2-mt.js",
      create: typeof createArgon2Mt === "function" ? createArgon2Mt : undefined,
      buildId:
        typeof ARGON2_THREADED_BUILD_ID === "string" ? ARGON2_THREADED_BUILD_ID : "development",
    },
    singleThreaded: {
      name: "single-threaded",
      file: "core/argon2-st.js",
      create: typeof createArgon2St === "function" ? createArgon2St : undefined,
      buildId:
        typeof ARGON2_SINGLE_THREADED_BUILD_ID === "string"
          ? ARGON2_SINGLE_THREADED_BUILD_ID
          : "development",
    },
  };
}

/**
 * Starts one of the Argon2 builds of argon2Builds(), once it is known to be of this worker's
 * build: an Argon2 build of another build is refused before it runs (PACKAGE_MISMATCH).
 * @param {Argon2Build} build
 * @param {Blob | null} threadedScript
 * @returns {Promise<Argon2Module>}
 */
async function startArgon2(build, threadedScript) {
  if (build.create === undefined) throw noArgon2Build();
  if (build.buildId !== WORKER_BUILD_ID) {
    throw packageMismatch(
      `the file ${build.file} is of build ${build.buildId} and runtime/worker.js of build ` +
        WORKER_BUILD_ID,
    );
  }
  if (build.name === "threaded" && self.crossOriginIsolated !== true) {
    // Without cross-origin isolation the threaded build cannot share its memory with its lane
    // workers, and its start-up would wait forever instead of failing, so refuse it here.
    throw new Argon2StartError(build.name, "notIsolated");
  }
  try {
    // The lane workers run this same Argon2 script, which the CSP allows only from a Blob.
    return await (build.name === "threaded"
      ? build.create({ mainScriptUrlOrBlob: threadedScript })
      : build.create());
  } catch (error) {
    let mismatch = false;
    try {
      mismatch = describeError(error).code === "PACKAGE_MISMATCH";
    } catch {
      // A malformed page exception is still a failure, with the same safe startup reason.
    }
    if (mismatch) throw packageMismatch("the Argon2 build reported a package mismatch");
    throw new Argon2StartError(build.name, "startFailed");
  }
}

/** The error of an operation that needs Argon2 when no Argon2 build is in front of the worker. */
function noArgon2Build() {
  return new Error("INTERNAL_ERROR: this operation needs an Argon2 build in front of the worker");
}
