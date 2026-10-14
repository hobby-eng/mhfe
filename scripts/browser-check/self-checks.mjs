// The page's checks of the self-checks: every class's startup and full self-check, the self-test
// at the reduced cost, a damaged WebAssembly, and Argon2 builds that do not start or are of
// another build (page code, scripts/browser-check/harness.mjs).

/** MhfeClient.selfTest at the reduced cost: both vectors, the first wrong round and its fault. */
export async function checkSelfTest(client) {
  group("MhfeClient.selfTest");
  const log = progressLog();
  const result = await client.selfTest({ onProgress: log.onProgress });
  expectEqual(
    log.lines,
    [...roundLines("encrypt", 1, 12, 24), ...roundLines("recover", 13, 24, 24)],
    "the self-test encrypts the suite 3 vector, then recovers the suite 4 vector",
  );
  // The vectors are published at full cost, so at the reduced cost neither can match, and the
  // key of the first round already differs from the published one, for the published input:
  // the fault the self-test names is in Argon2id.
  expectEqual(
    result,
    {
      passed: false,
      suite3: { vector: "zero-12", asPublished: false },
      suite4: { vector: "same-length-zero-12", asPublished: false },
      firstWrongRound: 1,
      fault: {
        kind: "argon2-key",
        round: 1,
        message:
          "first wrong round 1 of 24: Argon2id returned another key for the published input, " +
          "so the fault is in Argon2id",
      },
    },
    "at the reduced cost the self-test names both vectors, the first wrong round and its fault",
  );
}

/** The parts of a report as "id outcome" lines, with the detail of any part that did not pass. */
export function partLines(report) {
  return report.components.map(
    ({ id, outcome, detail }) => `${id} ${outcome}${detail === undefined ? "" : `: ${detail}`}`,
  );
}

/** The lines of parts that all passed. */
export function passedLines(ids) {
  return ids.map((id) => `${id} passed`);
}

/** Whether every part has the label the library gives it. */
export function labelled(report) {
  return report.components.every(
    ({ id, label }) => SELF_CHECK.labels[id] === undefined || SELF_CHECK.labels[id] === label,
  );
}

/** Every class's startup check before the first operation: its parts, its tier and its time. */
export async function checkStartupChecks(client, repair, passwords, wallet) {
  group("Startup checks, before the first operation");
  // The wallet, repair and passwords classes share one compiled WebAssembly: a part one of them
  // passed is not run again by the next. The client has its own, so it runs every part.
  const checks = [
    {
      name: "MhfeWallet",
      check: () => wallet.startupCheck(),
      ids: [...PAGE_PARTS, ...SELF_CHECK.wallet],
    },
    {
      name: "MhfeRepair",
      check: () => repair.startupCheck(),
      ids: ["browser-features", "package-parts", ...SELF_CHECK.repair],
    },
    {
      name: "MhfePasswords",
      check: () => passwords.startupCheck(),
      ids: [...PAGE_PARTS, ...SELF_CHECK.passwords],
    },
    {
      name: "MhfeClient without Argon2",
      check: () => client.startupCheck({ argon2: false }),
      ids: [...PAGE_PARTS, ...SELF_CHECK.core],
    },
    {
      name: "MhfeClient with Argon2",
      check: () => client.startupCheck(),
      ids: [...PAGE_PARTS, ...SELF_CHECK.core],
    },
  ];
  for (const { name, check, ids } of checks) {
    const started = performance.now();
    const report = await check();
    const time = Math.round(performance.now() - started);
    const expected = passedLines(ids).map((line) =>
      name === "MhfeClient without Argon2" && line === "argon2 passed"
        ? "argon2 notRun: this check leaves Argon2 out"
        : line,
    );
    expectEqual(
      partLines(report),
      expected,
      `${name}: every part reports its expected startup outcome`,
    );
    expect(
      report.passed &&
        report.tier === "startup" &&
        report.version === VERSION &&
        report.buildId === PACKAGE_BUILD_ID &&
        labelled(report),
      `${name}: passed, at the startup tier, of this version and build`,
    );
    expect(time < 2000, `${name}: the startup check took ${time} ms, under 2 s`);
  }
  expect(
    (await wallet.startupCheck()) === (await wallet.startupCheck()),
    "a startup check is made once per page",
  );
}

/** The full self-check of every class, and the core's parts as they start and end. */
export async function checkFullChecks(client, repair, passwords, wallet) {
  group("Full self-checks");
  for (const { name, check, ids } of [
    {
      name: "MhfeRepair",
      check: () => repair.fullCheck(),
      ids: ["browser-features", "package-parts", ...SELF_CHECK.repair],
    },
    {
      name: "MhfePasswords",
      check: () => passwords.fullCheck(),
      ids: [...PAGE_PARTS, ...SELF_CHECK.passwords],
    },
    {
      name: "MhfeWallet",
      check: () => wallet.fullCheck(),
      ids: [...PAGE_PARTS, ...SELF_CHECK.wallet],
    },
  ]) {
    const started = performance.now();
    const report = await check();
    const time = Math.round(performance.now() - started);
    expectEqual(partLines(report), passedLines(ids), `${name}: every part passes at the full tier`);
    expect(report.passed && report.tier === "full" && labelled(report), `${name}: passed`);
    note(`${name}: the full self-check took ${time} ms`);
  }
  // The core's, with Argon2 at 64 and 256 MiB: the single-threaded build, then on an isolated
  // page the threaded one, never both at once.
  const fast = client.mode() === "fast";
  const events = [];
  const started = performance.now();
  const report = await client.fullCheck({
    onProgress: ({ id, running, outcome }) =>
      events.push({ id, running, outcome, at: performance.now() }),
  });
  const time = Math.round(performance.now() - started);
  expectEqual(
    partLines(report),
    [
      ...passedLines([...PAGE_PARTS, ...SELF_CHECK.core]),
      "argon2-sizes-single-threaded passed",
      fast
        ? "argon2-sizes-threaded passed"
        : "argon2-sizes-threaded notRun: the page is not cross-origin isolated",
      "published-vectors notRun: they take minutes and 2 GiB: selfTest() runs them",
      "memory-locking notAvailable: a web page cannot keep its memory out of swap",
      "core-dumps notAvailable: the browser keeps its own crash reports, which a page cannot turn off",
      "isolation notAvailable: a web page cannot sandbox itself or prove that it is offline",
      "hidden-input notAvailable: a web page has no terminal whose echo it could read back",
    ],
    `MhfeClient: every part reports its full-tier outcome and Argon2's sizes pass for ${fast ? "both builds" : "the single-threaded build"}`,
  );
  expect(
    report.passed && labelled(report),
    "MhfeClient: the full self-check passes with the library's labels",
  );
  note(`MhfeClient: the full self-check took ${time} ms`);
  expectEqual(
    events.map(({ id, running, outcome }) => (running ? `start ${id}` : `end ${id} ${outcome}`)),
    report.components.flatMap(({ id, outcome }) => [`start ${id}`, `end ${id} ${outcome}`]),
    "MhfeClient: each part is reported as it starts and ends, one after the other",
  );
  if (fast) {
    const single = events.find(
      ({ id, running }) => id === "argon2-sizes-single-threaded" && !running,
    );
    const threaded = events.find(({ id, running }) => id === "argon2-sizes-threaded" && running);
    expect(
      single.at <= threaded.at,
      "the threaded build starts only after the single-threaded build has ended",
    );
  }
}

/** A damaged WebAssembly closes its classes, and a worker of another build refuses it. */
export async function checkFailingSelfCheck(compiled) {
  group("A self-check that fails");
  // The package's WebAssembly with one letter of a published repair card changed, as a damaged
  // download or memory would: the repair words and the cipher's rounds, which hold the card of
  // their first vector, fail, named by their place only, and their classes stay closed.
  const damaged = bytes(WASM_BASE64);
  const card = new TextEncoder().encode("shaft pupil patient jewel");
  let at = -1;
  for (let index = 0; index + card.length <= damaged.length; index += 1) {
    if (card.every((byte, offset) => damaged[index + offset] === byte)) {
      at = index;
      break;
    }
  }
  damaged[at + card.length - 1] ^= 1;
  const repair = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: damaged });
  const report = await repair.startupCheck();
  expectEqual(
    partLines(report),
    [
      "browser-features passed",
      "package-parts passed",
      "bip39-words passed",
      "repair-words failed: card 1 of 1 gives other words",
      // The parts of the master key fingerprint that a repair gives (AUD-023-BLD010).
      "wallet-hashes passed",
      "bip39-seed passed",
      "bip32 passed",
    ],
    "a damaged card fails the repair words at startup",
  );
  const refusal = await rejectionOf(
    repair.repairWords({ container: FULL_SIZE_CONTAINER, count: 4 }),
  );
  expect(
    refusal?.code === "SELF_CHECK_FAILED" &&
      refusal.message ===
        "The self-test failed: Repair words (MHFE-REPAIR-1): card 1 of 1 gives other words. " +
          "Do not use this program on this computer" &&
      refusal.report === report,
    `the repair module stays closed -> ${refusal?.code}: ${refusal?.message}`,
  );
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm: damaged,
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
  });
  const encryption = await rejectionOf(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    }),
  );
  expect(
    encryption?.code === "SELF_CHECK_FAILED" &&
      encryption.message ===
        "The self-test failed: Cipher rounds: vector 5 of 10 gives other repair words. " +
          "Do not use this program on this computer" &&
      encryption.report.components.find(({ id }) => id === "repair-words")?.outcome === "failed",
    `the client encrypts nothing -> ${encryption?.code}: ${encryption?.message}`,
  );
  // A worker of another build than the WebAssembly refuses it before it runs.
  const otherWorker = WORKER_SOURCE.replace(
    `WORKER_BUILD_ID = "${PACKAGE_BUILD_ID}"`,
    'WORKER_BUILD_ID = "0123456789abcdef"',
  );
  await expectExactRefusal(
    new MhfeRepair({ workerSource: otherWorker, wasm: compiled }).parameters(),
    "PACKAGE_MISMATCH",
    `The file runtime/mhfe.wasm is of build ${PACKAGE_BUILD_ID} and runtime/worker.js of ` +
      "build 0123456789abcdef: take every file of the package from one build.",
    "a worker of another build refuses the WebAssembly",
  );
}

/** An Argon2 build that does not start leaves the client open; one of another build is refused. */
export async function checkArgon2Start() {
  group("An Argon2 build that does not start, or of another build");
  // A build that does not start gave no wrong answer, as when the browser refuses its memory:
  // Argon2 is not available, the client stays open, the report is not kept, and an operation
  // gets its own error. On an isolated page, a threaded build that does not start makes the
  // check fall back to the single-threaded build, with a warning. The stand-in builds are the
  // package's own, whose start is replaced by one that fails.
  const fast = globalThis.crossOriginIsolated === true;
  const cause = fast
    ? "the stand-in threaded build does not start"
    : "the stand-in build does not start";
  const failingStart = (name) =>
    `\n${name} = () => Promise.reject(new Error(${JSON.stringify(cause)}));\n`;
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm: bytes(WASM_BASE64),
    argon2Threaded: fast ? ARGON2_THREADED + failingStart("createArgon2Mt") : ARGON2_THREADED,
    argon2SingleThreaded: fast
      ? ARGON2_SINGLE_THREADED
      : ARGON2_SINGLE_THREADED + failingStart("createArgon2St"),
  });
  const notStarted = `the ${fast ? "threaded" : "single-threaded"} Argon2 build did not start: ${cause}`;
  const argon2Line = fast
    ? `argon2 warning: ${notStarted}; the check ran the single-threaded build of the standard mode instead`
    : `argon2 notAvailable: Argon2id could not run: ${notStarted}`;
  const startupLines = [...PAGE_PARTS, ...SELF_CHECK.core].map((id) =>
    id === "argon2" ? argon2Line : `${id} passed`,
  );
  const first = await client.startupCheck();
  expectEqual(
    partLines(first),
    startupLines,
    `startupCheck(): Argon2 says why (${fast ? "fast" : "standard"} mode)`,
  );
  expect(
    first.passed && labelled(first),
    "the report passes: a build that does not start is no wrong answer",
  );
  const again = await client.startupCheck();
  expect(
    again !== first && sameValue(again, first),
    "the report is not kept: the next call checks again",
  );
  await expectExactRefusal(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    }),
    "INTERNAL_ERROR",
    cause.charAt(0).toUpperCase() + cause.slice(1),
    "the client stays open, and an encryption gets its own error",
  );
  const full = await client.fullCheck();
  expectEqual(
    partLines(full).filter((line) => line.startsWith("argon2")),
    [
      argon2Line,
      fast
        ? "argon2-sizes-single-threaded passed"
        : `argon2-sizes-single-threaded notAvailable: Argon2id could not run: ${notStarted}`,
      fast
        ? `argon2-sizes-threaded notAvailable: Argon2id could not run: ${notStarted}`
        : "argon2-sizes-threaded notRun: the page is not cross-origin isolated",
    ],
    "fullCheck(): every Argon2 part says why",
  );
  expect(full.passed, "the full report passes too");
  // An Argon2 build of another build than the worker is refused before it runs, by a check and
  // by the self-test, which waits for no check.
  const file = fast ? "core/argon2-mt.js" : "core/argon2-st.js";
  const constant = fast ? "ARGON2_THREADED_BUILD_ID" : "ARGON2_SINGLE_THREADED_BUILD_ID";
  const otherBuild = (source) =>
    source.replace(`${constant} = "${PACKAGE_BUILD_ID}";`, `${constant} = "0123456789abcdef";`);
  const mixed = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm: bytes(WASM_BASE64),
    argon2Threaded: fast ? otherBuild(ARGON2_THREADED) : ARGON2_THREADED,
    argon2SingleThreaded: fast ? ARGON2_SINGLE_THREADED : otherBuild(ARGON2_SINGLE_THREADED),
  });
  // The path keeps its spelling: the message starts with a word (AUD-010).
  const mismatch =
    `The file ${file} is of build 0123456789abcdef and runtime/worker.js of build ` +
    `${PACKAGE_BUILD_ID}: take every file of the package from one build.`;
  await expectExactRefusal(
    mixed.startupCheck(),
    "PACKAGE_MISMATCH",
    mismatch,
    `${file} of another build: startupCheck()`,
  );
  await expectExactRefusal(
    mixed.selfTest(),
    "PACKAGE_MISMATCH",
    mismatch,
    `${file} of another build: selfTest()`,
  );
}
