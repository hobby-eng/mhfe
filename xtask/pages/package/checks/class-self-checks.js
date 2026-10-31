// Part 4b: the self-checks of the classes. Each test gives its classes a WebAssembly object of
// their own, so that it starts with no part passed on the page.
const ownWasm = () => new Uint8Array(wasm);
/** A part the page checks itself. */
const pagePart = (id, outcome = "passed", detail = undefined) => {
  const label = {
    "browser-features": "Browser features",
    "package-parts": "Package parts",
    "page-encoding": "Text encoding of the page",
  }[id];
  return detail === undefined ? { id, label, outcome } : { id, label, outcome, detail };
};
const PAGE_PARTS_OF_SECRETS = ["browser-features", "package-parts", "page-encoding"].map((id) =>
  pagePart(id)
);
/** The self-check workers started from here on. */
const checksFrom = (start) => StandInWorker.checks.slice(start);
const firstMessages = (workers) =>
  workers.map(({ messages: [message] }) =>
    fieldsOf(message, ["module", "operation", "tier", "skip"])
  );

// Each class runs its parts once per page, the page's own first; a part that another class passed
// with the same WebAssembly is not run again but listed as that class found it.
const sharedWasm = ownWasm();
let checksBefore = StandInWorker.checks.length;
const walletFirst = new MhfeWallet({ workerSource: "wallet worker", wasm: sharedWasm });
const walletStartup = await walletFirst.startupCheck();
assert.deepEqual(walletStartup, {
  passed: true,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  components: [...PAGE_PARTS_OF_SECRETS, ...WALLET_PARTS.map((id) => part(id))],
});
assert.equal(await walletFirst.startupCheck(), walletStartup, "made once");
const repairSecond = new MhfeRepair({ workerSource: "repair worker", wasm: sharedWasm });
assert.deepEqual(await repairSecond.startupCheck(), {
  passed: true,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  // No secrets, so no check of their encoding.
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    ...REPAIR_PARTS.map((id) => part(id)),
  ],
});
const passwordsThird = new MhfePasswords({ workerSource: "passwords worker", wasm: sharedWasm });
await passwordsThird.startupCheck();
const coreFourth = new MhfeClient({ ...sources, wasm: sharedWasm });
const withoutArgon2 = await coreFourth.startupCheck({ argon2: false });
assert.deepEqual(withoutArgon2.components, [
  ...PAGE_PARTS_OF_SECRETS,
  ...CORE_PARTS.map((id) => (id === "argon2" ? part(id, "notRun", ARGON2_LEFT_OUT) : part(id))),
]);
// The core's check with Argon2 runs Argon2 alone: every other part has passed on this page.
const withArgon2Report = await coreFourth.startupCheck();
assert.deepEqual(withArgon2Report.components[4], part("argon2"));
assert.ok(withArgon2Report.passed);
const startupChecks = checksFrom(checksBefore);
assert.deepEqual(firstMessages(startupChecks), [
  { module: "wallet", operation: "selfCheck", tier: "startup", skip: [] },
  { module: "repair", operation: "selfCheck", tier: "startup", skip: WALLET_PARTS },
  {
    module: "passwords",
    operation: "selfCheck",
    tier: "startup",
    skip: [...WALLET_PARTS, "repair-words"],
  },
  {
    module: "core",
    operation: "selfCheck",
    tier: "startup",
    skip: [
      ...WALLET_PARTS,
      "repair-words",
      // The parts the wallet module checked already, such as the random source, once.
      ...PASSWORD_PARTS.filter((id) => !WALLET_PARTS.includes(id)),
    ],
  },
  {
    module: "core",
    operation: "selfCheck",
    tier: "startup",
    skip: [
      ...WALLET_PARTS,
      "repair-words",
      // The parts the wallet module checked already, such as the random source, once.
      ...PASSWORD_PARTS.filter((id) => !WALLET_PARTS.includes(id)),
      ...CORE_PARTS.filter(
        (id) =>
          !WALLET_PARTS.includes(id)
          && !PASSWORD_PARTS.includes(id)
          && id !== "repair-words"
          && id !== "argon2",
      ),
    ],
  },
]);
assert.deepEqual(
  startupChecks.map(({ messages: [message] }) => message.argon2),
  [undefined, undefined, undefined, false, true],
);
assert.equal(
  await startupChecks[3].script.text(),
  "worker source",
  "no Argon2 build without Argon2",
);
assert.equal(await startupChecks[4].script.text(), "single-threaded source\n;\nworker source");
// The startup check is not the rehearsal check, which only check() runs.
assert.ok(StandInWorker.checks.every(({ messages: [message] }) => message.operation !== "check"));
await assert.rejects(coreFourth.startupCheck({ argon2: "yes" }), TypeError);

// The first operation of a class waits for its startup check, without Argon2 for the core.
checksBefore = StandInWorker.checks.length;
const gatedClient = new MhfeClient({ ...sources, wasm: ownWasm() });
const gatedReading = gatedClient.readPhrase(PHRASE);
worker = await started(({ operation }) => operation === "describePhrase");
assert.deepEqual(
  checksFrom(checksBefore).map(({ messages: [message] }) => [message.operation, message.argon2]),
  [["selfCheck", false]],
  "the check ran first",
);
assert.ok(checksFrom(checksBefore)[0].terminatedAt < worker.createdAt);
// The phrase is copied into bytes only after the check, and transferred (AUD-010).
assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE);
assert.deepEqual(
  worker.transfers[0].map(({ byteLength }) => byteLength),
  [PHRASE.length],
);
worker.reply({ type: "result", result: { phrase: PHRASE } });
assert.deepEqual(await gatedReading, { phrase: PHRASE });

// A part that fails closes the class for good: every operation rejects with SELF_CHECK_FAILED and
// the report, without a worker, while parameters(), the checks and selfTest() still run.
// Fault: a card in the WebAssembly of Part 2b, damaged as by a download or memory.
StandInWorker.serveCheck = (message, worker) =>
  message.module === "repair"
    ? JSON.parse(
      damagedCard.selfCheckRepair(
        message.tier,
        message.skip,
        (id, label) => worker.reply({ type: "componentStart", value: { id, label } }),
        (json) => worker.reply({ type: "component", value: JSON.parse(json) }),
      ),
    )
    : servedByTheWebAssembly(message, worker);
const brokenRepair = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
const brokenReport = await brokenRepair.startupCheck();
const cardRefused = part("repair-words", "failed", "card 1 of 1 gives other words");
assert.deepEqual(brokenReport, {
  passed: false,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    part("bip39-words"),
    cardRefused,
  ],
});
const SELF_CHECK_FAILED_MESSAGE =
  "The self-test failed: Repair words (MHFE-REPAIR-1): card 1 of 1 gives other words. "
  + "Do not use this program on this computer";
let workersBefore = StandInWorker.started.length;
checksBefore = StandInWorker.checks.length;
for (
  const call of [
    () => brokenRepair.repairWords({ container: FULL_SIZE_CONTAINER, count: 4 }),
    () => brokenRepair.repairContainer({ container: FULL_SIZE_CONTAINER, card: "labor extra" }),
    () => brokenRepair.inspectContainer({ container: FULL_SIZE_CONTAINER }),
  ]
) {
  await assert.rejects(call(), (error) => {
    assert.equal(error.code, "SELF_CHECK_FAILED");
    assert.equal(error.message, SELF_CHECK_FAILED_MESSAGE);
    assert.equal(error.report, brokenReport);
    return true;
  });
}
assert.equal(StandInWorker.started.length, workersBefore, "a closed class starts no worker");
const brokenParameters = brokenRepair.parameters();
worker = await started(({ operation }) => operation === "parameters");
worker.reply({ type: "result", result: { profile: "MHFE-REPAIR-1" } });
assert.deepEqual(await brokenParameters, { profile: "MHFE-REPAIR-1" });
const brokenFull = await brokenRepair.fullCheck();
assert.deepEqual(
  brokenFull.components.at(-1),
  part("repair-words", "failed", "card 1 of 4 gives other words"),
);
StandInWorker.serveCheck = servedByTheWebAssembly;
// A failed full self-check closes a class too.
const fullyBroken = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
assert.ok((await fullyBroken.startupCheck()).passed);
StandInWorker.serveCheck = (message, worker) =>
  message.tier === "full"
    ? {
      ...servedByTheWebAssembly(message, worker),
      passed: false,
      components: [part("bip39-words", "failed", "case 3 of 24 differs")],
    }
    : servedByTheWebAssembly(message, worker);
assert.equal((await fullyBroken.fullCheck()).passed, false);
StandInWorker.serveCheck = servedByTheWebAssembly;
await assert.rejects(fullyBroken.repairWords({ container: "c", count: 4 }), {
  code: "SELF_CHECK_FAILED",
  message:
    "The self-test failed: BIP39 words: case 3 of 24 differs. Do not use this program on this computer",
});

// A full check that fails while an operation still waits for the startup check refuses that
// operation too, before any of its secrets reaches a worker (AUD-014-SEC001): here the startup
// report passes only after the full one has failed.
{
  let passStartup;
  StandInWorker.serveCheck = (message, worker) => {
    const report = servedByTheWebAssembly(message, worker);
    if (message.tier === "startup") {
      return new Promise((resolve) => {
        passStartup = () => resolve(report);
      });
    }
    const [first, ...rest] = report.components;
    return {
      ...report,
      passed: false,
      components: [{ ...first, outcome: "failed", detail: "case 1 of 6 differs" }, ...rest],
    };
  };
  const gated = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
  const workersBefore = StandInWorker.started.length;
  const waiting = gated.drawPhrase({ chosen: [{ word: "happy", position: 1 }] });
  while (passStartup === undefined) await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal((await gated.fullCheck()).passed, false);
  passStartup();
  await assert.rejects(waiting, { code: "SELF_CHECK_FAILED" });
  assert.ok(
    StandInWorker.started.slice(workersBefore).every((each) => each.selfCheck),
    "no drawing worker was started",
  );
  StandInWorker.serveCheck = servedByTheWebAssembly;
}

// A worker that fails gives no report and closes nothing: the next call checks again.
const retried = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
StandInWorker.serveCheck = (message, worker) => {
  worker.onerror({ preventDefault: noop, message: "The stand-in worker stopped." });
};
await assert.rejects(retried.repairWords({ container: "c", count: 4 }), {
  code: "WORKER_FAILED",
  message: "The stand-in worker stopped.",
});
StandInWorker.serveCheck = servedByTheWebAssembly;
const retriedCard = retried.repairWords({ container: "c", count: 4 });
worker = await started(({ operation }) => operation === "repairWords");
worker.reply({ type: "result", result: { words: "w" } });
assert.deepEqual(await retriedCard, { words: "w" });
// A worker that never says it is ready is given up after a minute (the timer fires at once here).
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (callback, delay, ...rest) =>
  delay === 60_000
    ? realSetTimeout(callback, 0, ...rest)
    : realSetTimeout(callback, delay, ...rest);
StandInWorker.serveCheck = () => new Promise(noop);
const silent = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
await assert.rejects(silent.startupCheck(), {
  code: "WORKER_FAILED",
  message: "The worker did not start within a minute.",
});
globalThis.setTimeout = realSetTimeout;
// A worker of another build is refused when it says it is ready; nothing is kept either.
StandInWorker.serveCheck = (message, worker) => {
  worker.reply({ type: "ready", buildId: "0123456789abcdef" });
  return servedByTheWebAssembly(message, worker);
};
await assert.rejects(silent.fingerprint({ phrase: PHRASE }), {
  code: "PACKAGE_MISMATCH",
  message: buildMismatchMessage("runtime/worker.js", "0123456789abcdef", "runtime/runtime.js"),
});
StandInWorker.serveCheck = servedByTheWebAssembly;
assert.ok((await silent.startupCheck()).passed, "checked again once the parts match");
// A core whose limits are not this client's comes from another build.
StandInWorker.serveCheck = (message, worker) => ({
  ...servedByTheWebAssembly(message, worker),
  parameters: { ...parameters, maxPim: parameters.maxPim + 1 },
});
await assert.rejects(new MhfeClient({ ...sources, wasm: ownWasm() }).startupCheck(), {
  code: "PACKAGE_MISMATCH",
  message:
    "The files core/client.js and runtime/mhfe.wasm have different limits: take every file of "
    + "the package from one build.",
});
StandInWorker.serveCheck = servedByTheWebAssembly;
// A class file of another build than the runtime: the other build of part 3, which differs from
// this one in that file alone.
const { MhfeRepair: OtherBuildRepair } = await import(
  moduleUrl(
    readOtherBuild("repair/repair.js")
      .toString()
      .replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`),
  )
);
await assert.rejects(new OtherBuildRepair({ workerSource: "w", wasm: ownWasm() }).startupCheck(), {
  code: "PACKAGE_MISMATCH",
  message: buildMismatchMessage("repair/repair.js", OTHER_BUILD_ID, "runtime/runtime.js"),
});
// The worker's own refusals of parts of another build reach the page as sentences that keep the
// paths as the package spells them: the first word is capitalized, never the folder of a path, as
// in "Runtime/mhfe.wasm" (AUD-010).
assert.equal(workerRefusals.length, 8);
for (const { file, build, error } of workerRefusals) {
  StandInWorker.serveCheck = (message, worker) => {
    worker.reply({ type: "error", error });
  };
  await assert.rejects(new MhfeRepair({ workerSource: "w", wasm: ownWasm() }).startupCheck(), {
    code: "PACKAGE_MISMATCH",
    message: buildMismatchMessage(file, build, "runtime/worker.js"),
  });
}
StandInWorker.serveCheck = servedByTheWebAssembly;

// cancel() while an operation waits for the startup check stops it at once and frees the slot.
StandInWorker.serveCheck = () => new Promise(noop);
const checksBeforeCancel = StandInWorker.checks.length;
const waitingClient = new MhfeClient({ ...sources, wasm: ownWasm() });
const waitingDecrypt = waitingClient.decrypt({ container: "c", password: "p" });
await assert.rejects(waitingClient.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
waitingClient.cancel();
await assert.rejects(waitingDecrypt, (error) => error instanceof MhfeCancelledError);
const waitingWallet = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
const waitingDraw = waitingWallet.drawPhrase();
await assert.rejects(waitingWallet.drawPhrase(), { code: "BUSY" });
waitingWallet.cancel();
await assert.rejects(waitingDraw, (error) => error instanceof MhfeCancelledError);
// A cancel() just after the startup check settled, before the operation took over from the wait,
// stops it too: here the check has passed long ago, and the page awaits a refusal in between.
const lateDraw = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 1,
});
await assert.rejects(walletClient.drawPhrase(), { code: "BUSY" });
walletClient.cancel();
await assert.rejects(lateDraw, (error) => error instanceof MhfeCancelledError);
const lateDecrypt = client.decrypt({ container: "c", password: "p" });
await assert.rejects(client.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
client.cancel();
await assert.rejects(lateDecrypt, (error) => error instanceof MhfeCancelledError);
// The two checks that were waited for keep running in their workers, unanswered here.
while (StandInWorker.checks.length < checksBeforeCancel + 2) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
StandInWorker.serveCheck = servedByTheWebAssembly;

// The page's encoding of secrets: a TextEncoder that gives other bytes, and a page that lets a
// lone surrogate through, fail it before any worker runs.
checksBefore = StandInWorker.checks.length;
const RealEncoder = globalThis.TextEncoder;
globalThis.TextEncoder = class extends RealEncoder {
  encode(text) {
    return super.encode(text.normalize("NFC"));
  }
};
const otherBytes = new MhfePasswords({ workerSource: "passwords worker", wasm: ownWasm() });
assert.deepEqual(await otherBytes.startupCheck(), {
  passed: false,
  tier: "startup",
  version: null,
  buildId: BUILD_ID,
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    pagePart("page-encoding", "failed", "the page encodes text into other UTF-8 bytes"),
  ],
});
globalThis.TextEncoder = RealEncoder;
await assert.rejects(otherBytes.review({ password: "p" }), { code: "SELF_CHECK_FAILED" });
const realIsWellFormed = String.prototype.isWellFormed;
String.prototype.isWellFormed = () => true;
const acceptsSurrogates = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
assert.deepEqual(
  (await acceptsSurrogates.startupCheck()).components[2],
  pagePart("page-encoding", "failed", "a lone surrogate is accepted instead of refused"),
);
String.prototype.isWellFormed = realIsWellFormed;
assert.equal(StandInWorker.checks.length, checksBefore, "no worker ran for a page that failed");

// A browser without WebAssembly, or whose WebAssembly does not compile (as under a
// Content-Security-Policy without 'wasm-unsafe-eval'), gets a report instead of an exception.
const RealWebAssembly = globalThis.WebAssembly;
delete globalThis.WebAssembly;
const noWebAssembly = new MhfeClient({ ...sources, wasm: ownWasm() });
const noWebAssemblyReport = await noWebAssembly.startupCheck();
globalThis.WebAssembly = RealWebAssembly;
assert.deepEqual(
  noWebAssemblyReport.components[0],
  pagePart("browser-features", "failed", "the browser lacks WebAssembly"),
);
assert.equal(noWebAssemblyReport.passed, false);
await assert.rejects(noWebAssembly.readContainer("c"), { code: "SELF_CHECK_FAILED" });
const notCompiling = await new MhfeRepair({
  workerSource: "repair worker",
  wasm: new Uint8Array([0, 97, 115, 109, 9, 0, 0, 0]),
}).startupCheck();
assert.equal(notCompiling.components[0].outcome, "failed");
assert.ok(
  notCompiling.components[0].detail.startsWith(
    "the WebAssembly does not compile here, as when the page's Content-Security-Policy lacks 'wasm-unsafe-eval': ",
  ),
);
assert.equal(StandInWorker.checks.length, checksBefore, "no worker ran for either");

// The full self-check of the core: every part at the full tier, then Argon2 at 64 and 256 MiB with
// each build in turn, each worker ended before the next starts, then the parts not run here.
const NOT_RUN_HERE = [
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
const SIZES_SINGLE = {
  id: "argon2-sizes-single-threaded",
  label: "Argon2id at 64 and 256 MiB, single-threaded build",
};
const SIZES_THREADED = {
  id: "argon2-sizes-threaded",
  label: "Argon2id at 64 and 256 MiB, threaded build",
};
for (const fast of [false, true]) {
  if (fast) globalThis.crossOriginIsolated = true;
  checksBefore = StandInWorker.checks.length;
  const fullClient = new MhfeClient({ ...sources, wasm: ownWasm() });
  const progressEvents = [];
  const started = performance.now();
  const fullReport = await fullClient.fullCheck({
    onProgress: ({ id, running, outcome }) =>
      progressEvents.push(running ? `start ${id}` : `end ${id} ${outcome}`),
  });
  console.log(
    `  MhfeClient.fullCheck() in ${fast ? "fast" : "standard"} mode: ${
      (performance.now() - started).toFixed(0)
    } ms`,
  );
  const threadedRow = fast
    ? { ...SIZES_THREADED, outcome: "passed" }
    : { ...SIZES_THREADED, outcome: "notRun", detail: "the page is not cross-origin isolated" };
  assert.deepEqual(fullReport, {
    passed: true,
    tier: "full",
    version: VERSION,
    buildId: BUILD_ID,
    components: [
      ...PAGE_PARTS_OF_SECRETS,
      ...CORE_PARTS.map((id) => part(id)),
      { ...SIZES_SINGLE, outcome: "passed" },
      threadedRow,
      ...NOT_RUN_HERE,
    ],
  });
  const ran = [...CORE_PARTS, SIZES_SINGLE.id, ...(fast ? [SIZES_THREADED.id] : [])];
  assert.deepEqual(
    progressEvents,
    ran.flatMap((id) => [`start ${id}`, `end ${id} passed`]),
  );
  const fullChecks = checksFrom(checksBefore);
  assert.deepEqual(firstMessages(fullChecks), [
    { module: "core", operation: "selfCheck", tier: "full", skip: [] },
    { module: "core", operation: "selfCheckArgon2", tier: "full", skip: ["argon2"] },
    ...(fast
      ? [{ module: "core", operation: "selfCheckArgon2", tier: "full", skip: ["argon2"] }]
      : []),
  ]);
  assert.deepEqual(await Promise.all(fullChecks.map((each) => each.script.text())), [
    // On an isolated page the single-threaded build follows the threaded one, for the check to
    // fall back to when the threaded one does not start.
    `${fast ? "threaded source\n;\nsingle-threaded" : "single-threaded"} source\n;\nworker source`,
    "single-threaded source\n;\nworker source",
    ...(fast ? ["threaded source\n;\nworker source"] : []),
  ]);
  for (let index = 1; index < fullChecks.length; index += 1) {
    assert.ok(
      fullChecks[index - 1].terminatedAt < fullChecks[index].createdAt,
      "never two at once",
    );
  }
  assert.equal(fullChecks.at(-1).messages[0].argon2Script === null, !fast);
  delete globalThis.crossOriginIsolated;
}

// An Argon2 build that does not start gave no wrong answer (the worker's side is checked in part
// 2c): the report passes with Argon2 not available, or with a warning where the check fell back to
// the single-threaded build. Such a report is not kept and closes nothing: the next call checks
// again, and an operation goes to its worker and gets its own error.
const ARGON2_NOT_STARTED = {
  notAvailable:
    "Argon2id could not run: the single-threaded Argon2 build did not start: the browser "
    + "refused its memory",
  warning: "the threaded Argon2 build did not start: the lane workers did not start; the check ran "
    + "the single-threaded build of the standard mode instead",
};
/** Serves the self-checks, the Argon2 part of the core's as `argon2` when it runs Argon2. */
const servedWithArgon2 = (argon2) => (message, worker) => {
  const report = servedByTheWebAssembly(message, worker);
  if (message.argon2 !== true) return report;
  const components = report.components.map((component) =>
    component.id === "argon2" ? argon2 : component
  );
  return {
    ...report,
    passed: components.every(({ outcome }) => outcome !== "failed"),
    components,
  };
};
for (const [outcome, detail] of Object.entries(ARGON2_NOT_STARTED)) {
  StandInWorker.serveCheck = servedWithArgon2(part("argon2", outcome, detail));
  checksBefore = StandInWorker.checks.length;
  const unstarted = new MhfeClient({ ...sources, wasm: ownWasm() });
  const first = await unstarted.startupCheck();
  assert.deepEqual(first, {
    passed: true,
    tier: "startup",
    version: VERSION,
    buildId: BUILD_ID,
    components: [
      ...PAGE_PARTS_OF_SECRETS,
      ...CORE_PARTS.map((id) => (id === "argon2" ? part(id, outcome, detail) : part(id))),
    ],
  });
  const again = await unstarted.startupCheck();
  assert.notEqual(again, first, `${outcome}: the report is not kept`);
  assert.deepEqual(again, first);
  assert.deepEqual(
    firstMessages(checksFrom(checksBefore)).map(({ skip }) => skip),
    [[], CORE_PARTS.filter((id) => id !== "argon2")],
    `${outcome}: the second check runs Argon2 alone`,
  );
  const decryption = unstarted.decrypt({ container: "c", password: "p" });
  worker = await started(({ operation }) => operation === "decrypt");
  worker.reply({
    type: "error",
    error: { code: "INTERNAL_ERROR", message: "the browser refused its memory" },
  });
  await assert.rejects(decryption, {
    code: "INTERNAL_ERROR",
    message: "The browser refused its memory",
  });
}
// The threaded build's sizes in the full self-check, when that build does not start.
globalThis.crossOriginIsolated = true;
const threadedSizesNotStarted =
  "Argon2id could not run: the threaded Argon2 build did not start: the lane workers did not start";
StandInWorker.serveCheck = (message, worker) => {
  const report = servedByTheWebAssembly(message, worker);
  const threaded = message.operation === "selfCheckArgon2" && message.argon2Script !== null;
  return threaded
    ? { ...report, components: [part("argon2-sizes", "notAvailable", threadedSizesNotStarted)] }
    : report;
};
const threadedNotStarted = await new MhfeClient({ ...sources, wasm: ownWasm() }).fullCheck();
assert.equal(threadedNotStarted.passed, true);
assert.deepEqual(threadedNotStarted.components.at(-NOT_RUN_HERE.length - 1), {
  ...SIZES_THREADED,
  outcome: "notAvailable",
  detail: threadedSizesNotStarted,
});
delete globalThis.crossOriginIsolated;
// A wrong answer of Argon2 still closes the client for good.
StandInWorker.serveCheck = servedWithArgon2(
  part("argon2", "failed", "the page's Argon2 build gives another tag"),
);
const wrongArgon2 = new MhfeClient({ ...sources, wasm: ownWasm() });
const wrongArgon2Report = await wrongArgon2.startupCheck();
assert.equal(wrongArgon2Report.passed, false);
assert.equal(await wrongArgon2.startupCheck(), wrongArgon2Report, "a failed report is kept");
await assert.rejects(wrongArgon2.readPhrase(PHRASE), (error) => {
  assert.equal(error.code, "SELF_CHECK_FAILED");
  assert.equal(
    error.message,
    "The self-test failed: Argon2id: the page's Argon2 build gives another tag. "
      + "Do not use this program on this computer",
  );
  assert.equal(error.report, wrongArgon2Report);
  return true;
});
StandInWorker.serveCheck = servedByTheWebAssembly;
console.log("The classes check themselves before their first operation and close on a failure.");
