// Part 2c of the checks of the browser package (scripts/verify-browser-package.mjs): the package's
// worker.js in this process, its `self` a stand-in that collects what it posts: the build
// handshake, the self-checks of the worker's tables, the operations it serves, and a WebAssembly
// that stops.
import assert from "node:assert/strict";

import { PHRASE, REDUCED_COST_CONTAINER } from "../public-test-data.mjs";
import { nextTurn } from "./expect.mjs";
import { BUILD_ID, VERSION, builds, packageWasm, parameters, read } from "./package.mjs";
import { checkWorkerProtocol } from "./protocol-values.mjs";
import { checkArgon2StartupPrivacy } from "./worker-startup-privacy.mjs";
import { CORE_PARTS, LABELS, PASSWORD_PARTS, REPAIR_PARTS, part, reports } from "./self-checks.mjs";
import {
  CHECKED_PHRASE,
  KNOWN_ANSWER_COSTS,
  PHRASE_TREZOR_FINGERPRINT,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  encode,
  noBytes,
  typedForm,
} from "./test-values.mjs";

/** The package's worker script, runtime/worker.js. */
export const workerScript = read("dist/runtime/worker.js").toString();
/** The package's WebAssembly compiled once, as a page passes it to each worker. */
export const compiledPackage = new WebAssembly.Module(packageWasm);
/**
 * The worker's PACKAGE_MISMATCH message for `file` of build `build`, as it posts it. It starts
 * with a word, not the file's path, which the page's sentence() would capitalize.
 */
export const workerMismatch = (file, build) =>
  `the file ${file} is of build ${build} and runtime/worker.js of build ${BUILD_ID}: ` +
  "take every file of the package from one build.";

/** Runs worker `script` with the stand-in `workerSelf` as its `self`, and `globals` beside it. */
function runWorkerScript(script, workerSelf, globals) {
  // A worker's script runs as a browser runs it, its `self` and globals given as parameters.
  // oxlint-disable-next-line typescript/no-implied-eval -- the package's own worker scripts
  new Function("self", ...Object.keys(globals), script)(workerSelf, ...Object.values(globals));
}

/**
 * Runs worker `script` with `globals` (such as an Argon2 build in front of it) and returns `send`,
 * which delivers a message as the page would and resolves to what the worker posted for it.
 * `isolated` stands for a cross-origin isolated page.
 */
export function inProcessWorker(script, globals = {}, { isolated = false } = {}) {
  const posted = [];
  const workerSelf = {
    postMessage: (message) => posted.push(structuredClone(message)),
    crypto: globalThis.crypto,
    crossOriginIsolated: isolated,
  };
  runWorkerScript(script, workerSelf, globals);
  return async (message) => {
    posted.length = 0;
    await workerSelf.onmessage({ data: message });
    return [...posted];
  };
}
/** The messages of a self-check: a start and an end for each part, then the result. */
function selfCheckMessages(parts, report) {
  return [
    ...parts.flatMap(({ id, label, outcome, detail }) => [
      { type: "componentStart", value: { id, label } },
      {
        type: "component",
        value: detail === undefined ? { id, label, outcome } : { id, label, outcome, detail },
      },
    ]),
    { type: "result", result: report },
  ];
}
/** A self-check of the repair module at startup, without the compiled module. */
export const repairRequest = {
  module: "repair",
  operation: "selfCheck",
  tier: "startup",
  skip: [],
};
/** A self-check of the core at startup, through an Argon2 build in front of the worker. */
const coreRequest = {
  module: "core",
  operation: "selfCheck",
  tier: "startup",
  skip: [],
  argon2: true,
};
/** The single-threaded Argon2 build in front of the worker, with its stamped build. */
const singleThreadedBuild = {
  createArgon2St: builds["single-threaded"],
  ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID,
};
/** The threaded Argon2 build in front of the worker, with its stamped build. */
const threadedBuild = { createArgon2Mt: builds.threaded, ARGON2_THREADED_BUILD_ID: BUILD_ID };
/** A threaded build whose lane workers do not start, and what the check says of it. */
const noLanes = () => Promise.reject(new Error("synthetic private lane-start marker"));
const lanesFailed = "the threaded Argon2 build did not start";
/** What the worker posts for the core's self-check whose Argon2 part is `argon2`. */
function coreCheckMessages(argon2) {
  const components = CORE_PARTS.map((id) => (id === "argon2" ? argon2 : part(id)));
  const report = {
    version: VERSION,
    tier: "startup",
    passed: argon2.outcome !== "failed",
    ids: CORE_PARTS,
    components,
  };
  return [
    { type: "ready", buildId: BUILD_ID },
    ...selfCheckMessages(components, { ...report, parameters }),
  ];
}
/** What the worker posts for the core's self-check with `globals`, such as a build, in front. */
const coreCheckWith = (globals, options) =>
  inProcessWorker(workerScript, globals, options)({ ...coreRequest, compiled: compiledPackage });

/**
 * The worker serves every self-check, names a part that stops, and refuses other builds; gives the
 * worker's refusals of parts of other builds, for the classes' checks in part 4b.
 */
export async function checkWorkerInProcess() {
  await checkWorkerProtocol(inProcessWorker, workerScript, compiledPackage);
  await checkWalletSearchProgress();
  await checkRepairAndCoreChecks();
  await checkArgon2BuildsNotStarted();
  await checkArgon2StartupPrivacy((globals, request) =>
    inProcessWorker(workerScript, globals, { isolated: true })({
      ...request,
      compiled: compiledPackage,
    }),
  );
  await checkSizesAndMissingBuild();
  const workerRefusals = await checkOtherArgon2Builds();
  await checkPasswordsFullTier();
  await checkUnknownOperations();
  await checkPhraseRequests();
  await checkHandshake(workerRefusals);
  await checkTrapInPart();
  await checkTrapInSession();
  await checkStackCleared();
  console.log(
    "The worker serves every self-check, names a part that stops, refuses other builds, and " +
      "zeroes the WebAssembly's stack between calls.",
  );
  return workerRefusals;
}

/** Real searchWallet dispatch composes candidate and round progress at the public reduced cost. */
async function checkWalletSearchProgress() {
  // Deliberate copy of the test engine's cost selection: this executes in a classic worker's
  // scope, which cannot import the package-check modules; known answers keep their real cost.
  const reducedWorker =
    workerScript +
    `\n{
    const fullCost = argon2For;
    argon2For = async (request) => {
      const engine = await fullCost(request);
      return {
        derive(password, salt, memory, passes, key) {
          const known = ${JSON.stringify(KNOWN_ANSWER_COSTS)}.includes(memory + "/" + passes);
          engine.derive(password, salt, known ? memory : ${REDUCED_MEMORY_KIB},
            known ? passes : ${REDUCED_PASSES}, key);
        },
        reserve() {},
      };
    };
  }`;
  const posted = await inProcessWorker(
    reducedWorker,
    singleThreadedBuild,
  )({
    module: "core",
    operation: "searchWallet",
    compiled: compiledPackage,
    container: REDUCED_COST_CONTAINER.split(" ").slice(0, -1).concat("?").join(" "),
    password: encode("public test password"),
    choice: "",
    position: 0,
    pim: 0,
    memoryLevel: 0,
    referenceKind: "fingerprint",
    reference: "73c5da0a",
    coin: "",
    path: "",
    passphrase: noBytes(),
  });
  const result = posted.at(-1);
  assert.equal(result.type, "result");
  assert.equal(
    typeof result.result,
    "object",
    "the worker parses the result instead of returning JSON text",
  );
  assert.equal(result.result.found, true);
  assert.equal(result.result.container, REDUCED_COST_CONTAINER);
  assert.deepEqual(result.result.words, [{ position: 24, word: "sweet" }]);
  const steps = posted.filter(({ type }) => type === "progress").map(({ value }) => value);
  assert.ok(steps.length > 0);
  for (let index = 0; index < steps.length; index += 1) {
    const step = steps[index];
    assert.equal(step.stage, "search");
    assert.equal(step.candidates, 8);
    assert.equal(step.candidate, Math.floor(index / 12) + 1);
    assert.equal(step.rounds, 12);
    assert.equal(step.round, (index % 12) + 1);
  }
}

/** The repair module's self-check, and the core's through the single-threaded Argon2 build. */
async function checkRepairAndCoreChecks() {
  const repairWorker = inProcessWorker(workerScript);
  const repairReport = {
    version: VERSION,
    tier: "startup",
    passed: true,
    ids: REPAIR_PARTS,
    components: REPAIR_PARTS.map((id) => part(id)),
  };
  assert.deepEqual(await repairWorker({ ...repairRequest, compiled: compiledPackage }), [
    { type: "ready", buildId: BUILD_ID },
    ...selfCheckMessages(repairReport.components, repairReport),
  ]);
  // The core through the single-threaded Argon2 build in front of the worker, with the core's
  // limits. Each Argon2 build carries its stamped build, which the worker compares with its own.
  const withArgon2 = await inProcessWorker(
    workerScript,
    singleThreadedBuild,
  )({
    ...coreRequest,
    compiled: compiledPackage,
  });
  assert.deepEqual(withArgon2.at(-1).result.parameters, parameters);
  assert.deepEqual(
    withArgon2.at(-1).result.components.map(({ id, outcome }) => `${id} ${outcome}`),
    CORE_PARTS.map((id) => `${id} passed`),
  );
}

/** Argon2 builds that do not start: Argon2 not available, or the single-threaded build instead. */
async function checkArgon2BuildsNotStarted() {
  // An Argon2 build that does not start gave no wrong answer: Argon2 is not available, with the
  // known backend, and the report passes. A wrong answer of a build that started still fails it.
  const refusedStart = () => Promise.reject(new Error("synthetic private memory-start marker"));
  assert.deepEqual(
    await coreCheckWith({ ...singleThreadedBuild, createArgon2St: refusedStart }),
    coreCheckMessages(
      part(
        "argon2",
        "notAvailable",
        "Argon2id could not run: the single-threaded Argon2 build did not start",
      ),
    ),
  );
  // On a fast-mode page the single-threaded build follows the threaded one. When the threaded one
  // does not start, here because the page is not cross-origin isolated or its lane workers do not
  // start, the check runs the single-threaded build instead and says so.
  const notIsolated =
    "the threaded Argon2 build did not start: the page is not cross-origin isolated, so the build " +
    "cannot share its memory with its lane workers";
  const fellBack = "; the check ran the single-threaded build of the standard mode instead";
  assert.deepEqual(
    await coreCheckWith({ ...threadedBuild, ...singleThreadedBuild }),
    coreCheckMessages(part("argon2", "warning", `${notIsolated}${fellBack}`)),
  );
  assert.deepEqual(
    await coreCheckWith(
      { ...threadedBuild, createArgon2Mt: noLanes, ...singleThreadedBuild },
      { isolated: true },
    ),
    coreCheckMessages(part("argon2", "warning", `${lanesFailed}${fellBack}`)),
  );
  const wrongTag = async () => {
    const module = await builds["single-threaded"]();
    const realHash = module._argon2id_hash_raw;
    module._argon2id_hash_raw = (...args) => {
      const code = realHash(...args);
      module.HEAPU8[args[7]] ^= 1;
      return code;
    };
    return module;
  };
  assert.deepEqual(
    await coreCheckWith(
      {
        ...threadedBuild,
        createArgon2Mt: noLanes,
        ...singleThreadedBuild,
        createArgon2St: wrongTag,
      },
      { isolated: true },
    ),
    coreCheckMessages(
      part(
        "argon2",
        "failed",
        `${lanesFailed}${fellBack}; the page's Argon2 build gives another tag`,
      ),
    ),
  );
  assert.deepEqual(
    await coreCheckWith(
      {
        ...threadedBuild,
        createArgon2Mt: noLanes,
        ...singleThreadedBuild,
        createArgon2St: refusedStart,
      },
      { isolated: true },
    ),
    coreCheckMessages(
      part(
        "argon2",
        "notAvailable",
        `Argon2id could not run: ${lanesFailed}; the single-threaded Argon2 build did not start`,
      ),
    ),
  );
}

/** The sizes of one build in the full self-check, and no build in front of the worker. */
async function checkSizesAndMissingBuild() {
  // The check of one build at 64 and 256 MiB, as the full self-check runs it for each build.
  const sizesRequest = {
    module: "core",
    operation: "selfCheckArgon2",
    tier: "full",
    skip: ["argon2"],
    compiled: compiledPackage,
  };
  const sizesNotStarted = await inProcessWorker(
    workerScript,
    { ...threadedBuild, createArgon2Mt: noLanes },
    { isolated: true },
  )(sizesRequest);
  const sizesPart = part("argon2-sizes", "notAvailable", `Argon2id could not run: ${lanesFailed}`);
  assert.deepEqual(sizesNotStarted, [
    { type: "ready", buildId: BUILD_ID },
    ...selfCheckMessages([sizesPart], {
      version: VERSION,
      tier: "full",
      passed: true,
      ids: ["argon2", "argon2-sizes"],
      components: [sizesPart],
    }),
  ]);
  // No build in front is the page's mistake, not a fault of the computer.
  assert.deepEqual(await coreCheckWith({}), [
    { type: "ready", buildId: BUILD_ID },
    {
      type: "error",
      error: {
        code: "INTERNAL_ERROR",
        message: "this operation needs an Argon2 build in front of the worker",
      },
    },
  ]);
}

/** Argon2 builds of another build are refused before they run; gives the worker's refusals. */
async function checkOtherArgon2Builds() {
  // An Argon2 build of another build, or one that was not stamped, is refused before it runs, for
  // a check and for the self-test, which waits for no check, alike. Part 4b gives the page the
  // worker's refusals as it posts them.
  const workerRefusals = [];
  for (const { file, globals, build } of [
    {
      file: "core/argon2-st.js",
      globals: { ...singleThreadedBuild, ARGON2_SINGLE_THREADED_BUILD_ID: "0123456789abcdef" },
      build: "0123456789abcdef",
    },
    {
      file: "core/argon2-st.js",
      globals: { createArgon2St: builds["single-threaded"] },
      build: "development",
    },
    {
      file: "core/argon2-mt.js",
      globals: {
        ...threadedBuild,
        ARGON2_THREADED_BUILD_ID: "0123456789abcdef",
        ...singleThreadedBuild,
      },
      build: "0123456789abcdef",
    },
  ]) {
    const mismatch = {
      type: "error",
      error: { code: "PACKAGE_MISMATCH", message: workerMismatch(file, build) },
    };
    for (const request of [coreRequest, { module: "core", operation: "selfTest" }]) {
      const posted = await inProcessWorker(workerScript, globals, { isolated: true })({
        ...request,
        compiled: compiledPackage,
      });
      assert.deepEqual(
        posted,
        [{ type: "ready", buildId: BUILD_ID }, mismatch],
        `${file} of build ${build}: ${request.operation}`,
      );
      workerRefusals.push({ file, build, error: posted[1].error });
    }
  }
  return workerRefusals;
}

/** The full tier of the passwords module tries the worker's own crypto.getRandomValues. */
async function checkPasswordsFullTier() {
  const passwordsFull = await inProcessWorker(workerScript)({
    module: "passwords",
    operation: "selfCheck",
    tier: "full",
    skip: [],
    compiled: compiledPackage,
  });
  assert.deepEqual(
    passwordsFull.at(-1).result.components,
    PASSWORD_PARTS.map((id) => part(id)),
  );
}

/** The worker serves the operations of its tables only, and wipes a refused request's secrets. */
async function checkUnknownOperations() {
  // The worker serves the operations of its tables only. A name every object inherits from
  // Object.prototype is no operation: it is refused like any other unknown name, rather than called
  // with the request, whose secrets it would post back (AUD-010). The worker wipes the request's
  // secrets either way.
  for (const [module, operation] of [
    ["core", "constructor"],
    ["repair", "toString"],
    ["passwords", "hasOwnProperty"],
    ["wallet", "__proto__"],
    ["__proto__", "constructor"],
    ["constructor", "keys"],
    ["toString", "call"],
    ["core", "encrypt "],
    ["Core", "encrypt"],
  ]) {
    const request = { module, operation, password: encode("public test password") };
    assert.deepEqual(
      await inProcessWorker(workerScript)({ ...request, compiled: compiledPackage }),
      [
        { type: "ready", buildId: BUILD_ID },
        {
          type: "error",
          error: { code: "INVALID_REQUEST", message: `unknown operation ${module}.${operation}` },
        },
      ],
      `${module}.${operation} is refused`,
    );
  }
  const inheritedRequest = {
    module: "core",
    operation: "constructor",
    password: encode("public test password"),
    compiled: compiledPackage,
  };
  await inProcessWorker(workerScript)(inheritedRequest);
  assert.ok(
    inheritedRequest.password.every((byte) => byte === 0),
    "the worker wipes the secrets of a refused request",
  );
}

/** A phrase goes to the worker as bytes, which it wipes with the passphrase. */
async function checkPhraseRequests() {
  // A phrase goes to the worker as bytes, which it hands to the WebAssembly and then wipes, with
  // the passphrase, as it wipes passwords.
  const phraseRequests = [
    [{ module: "wallet", operation: "fingerprint", passphrase: encode("TREZOR") }, PHRASE],
    [{ module: "wallet", operation: "walletCheck", passphrase: encode("TREZOR") }, CHECKED_PHRASE],
    [{ module: "core", operation: "describePhrase" }, typedForm(PHRASE)],
  ];
  const phraseResults = [];
  for (const [request, phrase] of phraseRequests) {
    const sent = { ...request, phrase: encode(phrase), compiled: compiledPackage };
    const posted = await inProcessWorker(workerScript)(sent);
    assert.equal(posted.at(-1).type, "result", `${request.operation}: ${JSON.stringify(posted)}`);
    phraseResults.push(posted.at(-1).result);
    assert.ok(
      sent.phrase.every((byte) => byte === 0),
      `${request.operation}: the phrase is wiped`,
    );
    assert.ok(
      (sent.passphrase ?? noBytes()).every((byte) => byte === 0),
      `${request.operation}: the passphrase is wiped`,
    );
  }
  assert.deepEqual(phraseResults.slice(0, 2), [PHRASE_TREZOR_FINGERPRINT, true]);
  assert.equal(phraseResults[2].phrase, PHRASE);
}

/**
 * The custom section "mhfe-build" that scripts/stamp-build-id.mjs ends the WebAssembly with: id 0,
 * 27 bytes, the 10-byte name, the 16 hex digits of the build (part 3 derives them again).
 */
const stamp = Buffer.concat([Buffer.from([0, 27, 10]), Buffer.from(`mhfe-build${BUILD_ID}`)]);
/** The package's WebAssembly without its stamp, as the build derives the stamp from it. */
export const unstamped = packageWasm.subarray(0, -stamp.length);

/** The build handshake: a WebAssembly of another build, or not stamped, is refused. */
async function checkHandshake(workerRefusals) {
  assert.deepEqual(
    packageWasm.subarray(-stamp.length),
    stamp,
    "the WebAssembly ends with its stamp",
  );
  assert.deepEqual(unstamped, read("target/wasm-bindgen/mhfe_bg.wasm"));
  // A WebAssembly of another build, or not stamped at all, is refused before it runs: no "ready".
  for (const [build, wasm] of [
    [
      "0123456789abcdef",
      Buffer.concat([unstamped, stamp.subarray(0, 13), Buffer.from("0123456789abcdef")]),
    ],
    ["development", unstamped],
  ]) {
    const posted = await inProcessWorker(workerScript)({
      ...repairRequest,
      compiled: new WebAssembly.Module(wasm),
    });
    assert.deepEqual(posted, [
      {
        type: "error",
        error: { code: "PACKAGE_MISMATCH", message: workerMismatch("runtime/mhfe.wasm", build) },
      },
    ]);
    workerRefusals.push({ file: "runtime/mhfe.wasm", build, error: posted[0].error });
  }
}

/** The custom section that says where a module's shadow stack ends (scripts/mark-wasm-stack.mjs). */
const STACK_SECTION = "mhfe-stack";
/** A module of no code that says its stack ends at `top`, unstamped. */
const moduleWithStack = (top) =>
  new WebAssembly.Module(
    Buffer.concat([
      Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]),
      Buffer.from([0, 1 + STACK_SECTION.length + String(top).length, STACK_SECTION.length]),
      Buffer.from(`${STACK_SECTION}${top}`),
    ]),
  );
// An unstamped module, as the unstamped worker runtime expects, whose stack ends at 16.
const emptyModule = moduleWithStack(16);
/** initSync of stand-in bindings: an instance whose memory is one page. */
const standInInit = () => ({ memory: new WebAssembly.Memory({ initial: 1 }) });

/**
 * A WebAssembly that stops inside a part (a trap, such as a Rust panic, which a release build
 * turns into "unreachable") fails that part with what came before, instead of the worker.
 */
async function checkTrapInPart() {
  // The worker's runtime and the repair module's table, unstamped, run over a stand-in of the
  // bindings.
  const trapping = inProcessWorker(
    `${read("web/worker-runtime.js")}\n${read("web/repair-worker.js")}\n` +
      "serveOperations(mhfe, { repair: REPAIR_OPERATIONS });",
    {
      mhfe: {
        initSync: standInInit,
        packageVersion: () => VERSION,
        selfCheckRepair: (tier, skip, onStart, onResult) => {
          onStart("bip39-words", LABELS["bip39-words"]);
          onResult(JSON.stringify(part("bip39-words")));
          onStart("repair-words", LABELS["repair-words"]);
          throw new WebAssembly.RuntimeError("unreachable");
        },
      },
    },
  );
  const stoppedReport = {
    version: VERSION,
    tier: "startup",
    passed: false,
    components: [part("bip39-words"), part("repair-words", "failed", "the WebAssembly stopped")],
  };
  reports.push(stoppedReport);
  assert.deepEqual(await trapping({ ...repairRequest, compiled: emptyModule }), [
    { type: "ready", buildId: "development" },
    { type: "componentStart", value: { id: "bip39-words", label: LABELS["bip39-words"] } },
    { type: "component", value: part("bip39-words") },
    { type: "componentStart", value: { id: "repair-words", label: LABELS["repair-words"] } },
    { type: "component", value: part("repair-words", "failed", "the WebAssembly stopped") },
    { type: "result", result: stoppedReport },
  ]);
}

// A WebAssembly that stops inside an operation of a session (a trap) is reported as INTERNAL_ERROR
// "the WebAssembly stopped", and the worker calls the session no more: freeing it, or asking its
// ownerLengths, would only replace the trap with wasm-bindgen's ownership error, as the borrow of
// the trapped call is never released (AUD-023-API002). The core's table and the worker's runtime,
// unstamped, run over a stand-in of the bindings whose session calls trap.
const calledAfterTrap = [];
/** A stand-in session whose operation `trapsIn` traps, and that records any call after that. */
class TrappingSession {
  static trapsIn = "";
  constructor() {
    this.trapped = false;
  }
  #call(name) {
    if (this.trapped) {
      calledAfterTrap.push(name);
      throw new Error("attempted to take ownership of Rust value while it was borrowed");
    }
    if (name === TrappingSession.trapsIn) {
      this.trapped = true;
      throw new WebAssembly.RuntimeError("unreachable");
    }
    return "null";
  }
  compare() {
    return this.#call("compare");
  }
  setNew() {
    return this.#call("setNew");
  }
  recover() {
    return this.#call("recover");
  }
  ownerLengths() {
    return this.#call("ownerLengths");
  }
  open() {
    return this.#call("open");
  }
  free() {
    // A session that did not trap is freed as before.
    if (this.trapped) this.#call("free");
  }
}
/** The core's table and the worker's runtime over stand-in bindings whose sessions trap. */
const coreOverStandIns = () => {
  const posted = [];
  const workerSelf = { postMessage: (message) => posted.push(structuredClone(message)) };
  runWorkerScript(
    `${read("web/worker-runtime.js")}\n${read("web/argon2-engine.js")}\n` +
      `${read("web/core-worker.js")}\nserveOperations(mhfe, { core: CORE_OPERATIONS });`,
    workerSelf,
    {
      mhfe: {
        initSync: standInInit,
        packageVersion: () => VERSION,
        suiteParameters: () => JSON.stringify({ hiddenWalletRefusals: [] }),
        CheckSession: TrappingSession,
        RekeySession: TrappingSession,
        HiddenWalletSession: TrappingSession,
      },
      createArgon2St: async () => ({}),
    },
  );
  return { posted, send: (data) => workerSelf.onmessage({ data }) };
};

/** A trap in a session is INTERNAL_ERROR, and the worker calls the session no more. */
async function checkTrapInSession() {
  const STOPPED = { code: "INTERNAL_ERROR", message: "the WebAssembly stopped" };
  for (const [operation, trapsIn] of [
    ["check", "compare"],
    ["rekey", "recover"],
    ["hiddenWallets", "open"],
  ]) {
    TrappingSession.trapsIn = trapsIn;
    calledAfterTrap.length = 0;
    const { posted, send } = coreOverStandIns();
    const done = send({
      module: "core",
      operation,
      compiled: emptyModule,
      confirmsAgain: true,
      container: "public synthetic container",
      password: new Uint8Array([1]),
      passwordRepeat: new Uint8Array([1]),
      choice: "",
      position: 0,
      pim: 0,
      memoryLevel: 0,
      words: 12,
      referenceKind: "words",
      reference: "12",
      coin: "",
      path: "",
      passphrase: new Uint8Array(),
      argon2Script: null,
      newPassword: new Uint8Array([2]),
      newPasswordRepeat: new Uint8Array([2]),
      newChoice: "",
      newPosition: 0,
      newPim: 0,
      newMemoryLevel: 0,
      repairWordCount: 0,
      confirmKind: "builtInCheck",
      mainPassphrase: new Uint8Array(),
    });
    if (operation === "hiddenWallets") {
      // The session asks for the first password once it is ready.
      await nextTurn();
      assert.deepEqual(posted.at(-1), { type: "ask", question: "ready", value: null });
      await send({
        type: "answer",
        value: {
          password: new Uint8Array([1]),
          passwordRepeat: new Uint8Array([1]),
          choice: "",
          position: 0,
        },
      });
    }
    await done;
    assert.deepEqual(posted.at(-1), { type: "error", error: STOPPED }, `a trap in ${trapsIn}`);
    assert.deepEqual(calledAfterTrap, [], `nothing is called after a trap in ${trapsIn}`);
  }
}

/**
 * The worker zeroes the WebAssembly's shadow stack after every operation and before every question
 * to the page (AUD-024-SEC003): what a fingerprint leaves there, its seed, master key and chain
 * code and the salt block of its passphrase, is gone once the result is posted, and the module
 * still works. A WebAssembly that does not say where its stack ends is refused.
 */
async function checkStackCleared() {
  const instances = [];
  /** The glue's instances, recorded, so that the check reads the worker's memory. */
  class Recorded extends WebAssembly.Instance {
    constructor(module, imports) {
      super(module, imports);
      instances.push(this);
    }
  }
  const recording = Object.create(WebAssembly, { Instance: { value: Recorded } });
  const send = inProcessWorker(workerScript, { WebAssembly: recording });
  const [section] = WebAssembly.Module.customSections(compiledPackage, STACK_SECTION);
  const top = Number(new TextDecoder().decode(section));
  for (const turn of [1, 2]) {
    const request = { module: "wallet", operation: "fingerprint", passphrase: encode("TREZOR") };
    const posted = await send({ ...request, phrase: encode(PHRASE), compiled: compiledPackage });
    assert.deepEqual(posted.at(-1), { type: "result", result: PHRASE_TREZOR_FINGERPRINT });
    const stack = new Uint8Array(instances[0].exports.memory.buffer, 0, top);
    assert.ok(
      stack.every((byte) => byte === 0),
      `fingerprint ${turn}: the stack is zeroed`,
    );
  }
  // Before a question, over stand-in bindings whose operation leaves its stack written.
  const memory = new WebAssembly.Memory({ initial: 1 });
  const zeroedAtQuestion = [];
  const workerSelf = {
    postMessage: (message) => {
      if (message.type === "ask") {
        zeroedAtQuestion.push(new Uint8Array(memory.buffer, 0, 4096).every((byte) => byte === 0));
      }
    },
  };
  runWorkerScript(
    `${read("web/worker-runtime.js")}\nserveOperations(mhfe, { probe: { asks: async (_, host) => ` +
      "{ new Uint8Array(probeMemory.buffer, 0, 4096).fill(7); await host.ask('q', null); " +
      "return true; } } });",
    workerSelf,
    { mhfe: { initSync: () => ({ memory }) }, probeMemory: memory },
  );
  const asked = workerSelf.onmessage({
    data: { module: "probe", operation: "asks", compiled: moduleWithStack(4096) },
  });
  await nextTurn();
  workerSelf.onmessage({ data: { type: "answer", value: null } });
  await asked;
  assert.deepEqual(zeroedAtQuestion, [true]);
  // A WebAssembly that does not say where its stack ends was not built by scripts/bind-wasm.sh.
  const unmarked = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
  const refused = await inProcessWorker(workerScript)({ ...repairRequest, compiled: unmarked });
  assert.equal(refused.at(-1).error?.code, "PACKAGE_MISMATCH");
}
