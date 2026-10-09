// The core module's operations in the package's worker: encryption, recovery, the rehearsal check,
// rekey, hidden wallets, the self-test and the self-checks. For an operation that needs Argon2, the
// core places one Emscripten build of the reference Argon2 code (argon2-mt.js or argon2-st.js) in
// front of the worker, and for a self-check on a fast-mode page both, the threaded one first;
// web/argon2-engine.js bridges it to the WebAssembly.
"use strict";

/** The parts of a self-check that run Argon2, as the core names them (src/engine). */
const argon2Parts = () => JSON.parse(mhfe.suiteParameters()).argon2Parts;
/** What an Argon2 part of a self-check adds when the threaded build did not start. */
const FALLBACK_NOTE = "the check ran the single-threaded build of the standard mode instead";

const CORE_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.suiteParameters()),
  packageVersion: () => mhfe.packageVersion(),
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
    try {
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
      if (result.matches || !request.asksLength) return result;
      const next = await host.ask("noLength", null);
      if (next === null) return result;
      try {
        return compare(next);
      } finally {
        wipeSecrets(next);
      }
    } finally {
      session.free();
    }
  },

  searchCandidates: (request) => JSON.parse(mhfe.searchCandidates(request.container)),

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
   * recovery, the owner's answer where the owner confirms the phrase, then the seal.
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
    try {
      session.setNew(
        request.newPassword,
        request.newPasswordRepeat,
        request.newChoice,
        request.newPosition,
        request.newPim,
        request.newMemoryLevel,
        request.repairWordCount,
      );
      const recovered = JSON.parse(
        session.recover(
          request.confirmKind,
          request.reference,
          request.coin,
          request.path,
          request.passphrase,
          request.walletHasPassphrase,
          host.progress,
        ),
      );
      if (recovered.ownerCheck !== null) {
        const confirmed = await host.ask("ownerCheck", recovered.ownerCheck);
        session.ownerAnswer(confirmed === true);
      }
      const sealed = JSON.parse(
        session.seal(host.progress, (json) => host.post("unverified", JSON.parse(json))),
      );
      // The 16-bit source check of the recovered 24-word reading, reported beside the result.
      return { ...sealed, walletCheck: recovered.walletCheck };
    } finally {
      session.free();
    }
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
    try {
      const keepsSessionOpen = new Set(JSON.parse(mhfe.suiteParameters()).hiddenWalletRefusals);
      let next = await host.ask("ready", null);
      while (next !== null && next?.close !== true) {
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
          wipeSecrets(next);
        }
        next = await host.ask(...reply);
      }
      return { closed: true };
    } finally {
      session.free();
    }
  },
};

/** The Argon2 bridge over the Emscripten build placed in front of this file; see startArgon2. */
async function argon2For(request) {
  const builds = argon2Builds();
  const build = builds.threaded.create === undefined ? builds.singleThreaded : builds.threaded;
  return argon2Engine(await startArgon2(build, request.argon2Script));
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
 */
async function argon2ForCheck(request) {
  const builds = argon2Builds();
  const tried = [builds.threaded, builds.singleThreaded].filter(({ create }) => create);
  if (tried.length === 0) throw noArgon2Build();
  const failures = [];
  for (const build of tried) {
    try {
      const argon2 = argon2Engine(await startArgon2(build, request.argon2Script));
      return { argon2, outcomeOf: (result) => afterFallback(result, failures) };
    } catch (error) {
      const { code, message } = describeError(error);
      if (code === "PACKAGE_MISMATCH") throw error;
      failures.push(`the ${build.name} Argon2 build did not start: ${message}`);
    }
  }
  const refuse = () => {
    throw new Error(failures.join("; "));
  };
  return {
    argon2: { derive: refuse, reserve: refuse },
    outcomeOf: (result) =>
      argon2Parts().includes(result.id) && result.outcome === "failed"
        ? { ...result, outcome: "notAvailable" }
        : result,
  };
}

/**
 * A part of a self-check whose Argon2 build started after the threaded one did not, `failures`
 * naming why: it passes with a warning that says so, and its failure, a wrong answer, says so too.
 */
function afterFallback(result, failures) {
  if (failures.length === 0 || !argon2Parts().includes(result.id)) return result;
  const note = `${failures.join("; ")}; ${FALLBACK_NOTE}`;
  if (result.outcome === "passed") return { ...result, outcome: "warning", detail: note };
  return { ...result, detail: `${note}; ${result.detail}` };
}

/**
 * The Emscripten builds of the reference Argon2 code that may be placed in front of this file:
 * the factory each defines, and its build, which scripts/stamp-build-id.mjs stamps into it. A
 * build that is not in front leaves its names undefined, hence typeof.
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
 */
function startArgon2(build, threadedScript) {
  if (build.create === undefined) throw noArgon2Build();
  if (build.buildId !== WORKER_BUILD_ID) {
    throw packageMismatch(
      `the file ${build.file} is of build ${build.buildId} and runtime/worker.js of build ` +
        WORKER_BUILD_ID,
    );
  }
  if (build.name === "threaded") {
    // Without cross-origin isolation the threaded build cannot share its memory with its lane
    // workers, and its start-up would wait forever instead of failing, so refuse it here.
    if (self.crossOriginIsolated !== true) {
      throw new Error(
        "INTERNAL_ERROR: the page is not cross-origin isolated, so the build cannot share its " +
          "memory with its lane workers",
      );
    }
    // The lane workers run this same Argon2 script, which the CSP allows only from a Blob.
    return build.create({ mainScriptUrlOrBlob: threadedScript });
  }
  return build.create();
}

function noArgon2Build() {
  return new Error("INTERNAL_ERROR: this operation needs an Argon2 build in front of the worker");
}
