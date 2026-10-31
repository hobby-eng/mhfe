// Part 2c: the package's worker.js in this process, its `self` a stand-in that collects what it
// posts: the build handshake, the self-checks of the worker's tables, and a WebAssembly that stops.
const workerScript = read("dist/runtime/worker.js").toString();
const compiledPackage = new WebAssembly.Module(packageWasm);
const BUILD_ID = JSON.parse(read("dist/modules.json").toString()).buildId;
/**
 * The page's PACKAGE_MISMATCH message for the file `file` of build `build` beside `own` of this
 * package's build. The page's buildMismatch() (web/runtime.js) and its deliberate copy in the
 * worker (web/worker-runtime.js) are both held to this one wording.
 */
const buildMismatchMessage = (file, build, own) =>
  `The file ${file} is of build ${build} and ${own} of build ${BUILD_ID}: ` +
  "take every file of the package from one build.";
/**
 * The worker's PACKAGE_MISMATCH message for `file` of build `build`, as it posts it. It starts
 * with a word, not the file's path, which the page's sentence() would capitalize.
 */
const workerMismatch = (file, build) =>
  buildMismatchMessage(file, build, "runtime/worker.js").replace(/^The /u, "the ");
/**
 * Runs worker `script` with `globals` (such as an Argon2 build in front of it) and returns `send`,
 * which delivers a message as the page would and resolves to what the worker posted for it.
 * `isolated` stands for a cross-origin isolated page.
 */
function inProcessWorker(script, globals = {}, { isolated = false } = {}) {
  const posted = [];
  const workerSelf = {
    postMessage: (message) => posted.push(structuredClone(message)),
    crypto: globalThis.crypto,
    crossOriginIsolated: isolated,
  };
  new Function("self", ...Object.keys(globals), script)(workerSelf, ...Object.values(globals));
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
const repairWorker = inProcessWorker(workerScript);
const repairRequest = { module: "repair", operation: "selfCheck", tier: "startup", skip: [] };
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
const coreRequest = {
  module: "core",
  operation: "selfCheck",
  tier: "startup",
  skip: [],
  argon2: true,
};
const singleThreadedBuild = {
  createArgon2St: builds["single-threaded"],
  ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID,
};
const threadedBuild = { createArgon2Mt: builds.threaded, ARGON2_THREADED_BUILD_ID: BUILD_ID };
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
const coreCheckWith = (globals, options) =>
  inProcessWorker(workerScript, globals, options)({ ...coreRequest, compiled: compiledPackage });
// An Argon2 build that does not start gave no wrong answer: Argon2 is not available, with the
// cause, and the report passes. A wrong answer of a build that started still fails it.
// Fault: the start of the single-threaded build, refused as by a browser without the memory.
const refusedStart = () => Promise.reject(new Error("the browser refused its memory"));
assert.deepEqual(
  await coreCheckWith({ ...singleThreadedBuild, createArgon2St: refusedStart }),
  coreCheckMessages(
    part(
      "argon2",
      "notAvailable",
      "Argon2id could not run: the single-threaded Argon2 build did not start: the browser " +
        "refused its memory",
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
// Fault: the start of the threaded build, failing as when its lane workers do not start.
const noLanes = () => Promise.reject(new Error("the lane workers did not start"));
const lanesFailed = "the threaded Argon2 build did not start: the lane workers did not start";
assert.deepEqual(
  await coreCheckWith(
    { ...threadedBuild, createArgon2Mt: noLanes, ...singleThreadedBuild },
    { isolated: true },
  ),
  coreCheckMessages(part("argon2", "warning", `${lanesFailed}${fellBack}`)),
);
// Fault: one bit of each tag of the single-threaded build, flipped as by a broken build.
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
    { ...threadedBuild, createArgon2Mt: noLanes, ...singleThreadedBuild, createArgon2St: wrongTag },
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
      `Argon2id could not run: ${lanesFailed}; the single-threaded Argon2 build did not start: ` +
        "the browser refused its memory",
    ),
  ),
);
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
// An Argon2 build of another build, or one that was not stamped, is refused before it runs, for
// a check and for the self-test, which waits for no check, alike. Part 4b gives the page the
// worker's refusals as it posts them.
const workerRefusals = [];
for (const [file, globals, build] of [
  [
    "core/argon2-st.js",
    { ...singleThreadedBuild, ARGON2_SINGLE_THREADED_BUILD_ID: "0123456789abcdef" },
    "0123456789abcdef",
  ],
  ["core/argon2-st.js", { createArgon2St: builds["single-threaded"] }, "development"],
  [
    "core/argon2-mt.js",
    { ...threadedBuild, ARGON2_THREADED_BUILD_ID: "0123456789abcdef", ...singleThreadedBuild },
    "0123456789abcdef",
  ],
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
// The full tier of the passwords module tries the worker's own crypto.getRandomValues.
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
  const request = { module, operation, password: encode(TEST_PASSWORD) };
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
  password: encode(TEST_PASSWORD),
  compiled: compiledPackage,
};
await inProcessWorker(workerScript)(inheritedRequest);
assert.ok(
  inheritedRequest.password.every((byte) => byte === 0),
  "the worker wipes the secrets of a refused request",
);
// A phrase goes to the worker as bytes, which it hands to the WebAssembly and then wipes, with the
// passphrase, as it wipes passwords.
const phraseRequests = [
  [{ module: "wallet", operation: "fingerprint", passphrase: encode("TREZOR") }, PHRASE],
  [{ module: "wallet", operation: "walletCheck", passphrase: encode("TREZOR") }, checkedPhrase],
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

// The build handshake. `cargo xtask wasm stamp-build-id` ends the WebAssembly with the custom
// section "mhfe-build": id 0, 27 bytes, the 10-byte name, the 16 hex digits of the build.
const stamp = Buffer.concat([Buffer.from([0, 27, 10]), Buffer.from(`mhfe-build${BUILD_ID}`)]);
assert.deepEqual(packageWasm.subarray(-stamp.length), stamp, "the WebAssembly ends with its stamp");
const unstamped = packageWasm.subarray(0, -stamp.length);
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

// A WebAssembly that stops inside a part (a trap, such as a Rust panic, which a release build
// turns into "unreachable") fails that part with what came before, instead of the worker. The
// worker's runtime and the repair module's table, unstamped, run over a stand-in of the bindings.
// Fault: a trap of the WebAssembly inside a part, as a panic of the program would cause.
const trapping = inProcessWorker(
  `${read("web/worker-runtime.js")}\n${read("web/repair-worker.js")}\n` +
    "serveOperations(mhfe, { repair: REPAIR_OPERATIONS });",
  {
    mhfe: {
      initSync: noop,
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
// An unstamped module, as the unstamped worker runtime expects.
const emptyModule = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
assert.deepEqual(await trapping({ ...repairRequest, compiled: emptyModule }), [
  { type: "ready", buildId: "development" },
  { type: "componentStart", value: { id: "bip39-words", label: LABELS["bip39-words"] } },
  { type: "component", value: part("bip39-words") },
  { type: "componentStart", value: { id: "repair-words", label: LABELS["repair-words"] } },
  { type: "component", value: part("repair-words", "failed", "the WebAssembly stopped") },
  { type: "result", result: stoppedReport },
]);
console.log(
  "The worker serves every self-check, names a part that stops, and refuses other builds.",
);
