  async function checkSelfTest(client) {
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
  function partLines(report) {
    return report.components.map(
      ({ id, outcome, detail }) => `${id} ${outcome}${detail === undefined ? "" : `: ${detail}`}`,
    );
  }

  /** The lines of parts that all passed. */
  function passedLines(ids) {
    return ids.map((id) => `${id} passed`);
  }

  /** Whether every part has the label the library gives it. */
  function labelled(report) {
    return report.components.every(
      ({ id, label }) => SELF_CHECK.labels[id] === undefined || SELF_CHECK.labels[id] === label,
    );
  }

  async function checkStartupChecks(client, repair, passwords, wallet) {
    group("Startup checks, before the first operation");
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    // The wallet, repair and passwords classes share one compiled WebAssembly: a part one of them
    // passed is not run again by the next. The client has its own, so it runs every part.
    const checks = [
      ["MhfeWallet", () => wallet.startupCheck(), [...pageParts, ...SELF_CHECK.wallet]],
      [
        "MhfeRepair",
        () => repair.startupCheck(),
        ["browser-features", "package-parts", ...SELF_CHECK.repair],
      ],
      ["MhfePasswords", () => passwords.startupCheck(), [...pageParts, ...SELF_CHECK.passwords]],
      [
        "MhfeClient without Argon2",
        () => client.startupCheck({ argon2: false }),
        [...pageParts, ...SELF_CHECK.core],
      ],
      ["MhfeClient with Argon2", () => client.startupCheck(), [...pageParts, ...SELF_CHECK.core]],
    ];
    for (const [name, check, ids] of checks) {
      const started = performance.now();
      const report = await check();
      const time = Math.round(performance.now() - started);
      const expected = passedLines(ids).map((line) =>
        name === "MhfeClient without Argon2" && line === "argon2 passed"
          ? "argon2 notRun: this check leaves Argon2 out"
          : line,
      );
      expectEqual(partLines(report), expected, `${name}: every part as expected`);
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

  async function checkFullChecks(client, repair, passwords, wallet) {
    group("Full self-checks");
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    for (const [name, check, ids] of [
      [
        "MhfeRepair",
        () => repair.fullCheck(),
        ["browser-features", "package-parts", ...SELF_CHECK.repair],
      ],
      ["MhfePasswords", () => passwords.fullCheck(), [...pageParts, ...SELF_CHECK.passwords]],
      ["MhfeWallet", () => wallet.fullCheck(), [...pageParts, ...SELF_CHECK.wallet]],
    ]) {
      const started = performance.now();
      const report = await check();
      const time = Math.round(performance.now() - started);
      expectEqual(
        partLines(report),
        passedLines(ids),
        `${name}: every part passes at the full tier`,
      );
      expect(report.passed && report.tier === "full" && labelled(report), `${name}: passed`);
      expect(true, `${name}: the full self-check took ${time} ms`);
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
        ...passedLines([...pageParts, ...SELF_CHECK.core]),
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
      `MhfeClient: every part at the full tier, Argon2's sizes of ${fast ? "both builds" : "the single-threaded build"}`,
    );
    expect(report.passed && labelled(report), `MhfeClient: the full self-check took ${time} ms`);
    const ran = [...SELF_CHECK.core, "argon2-sizes-single-threaded"];
    if (fast) ran.push("argon2-sizes-threaded");
    expectEqual(
      events.map(({ id, running, outcome }) => (running ? `start ${id}` : `end ${id} ${outcome}`)),
      ran.flatMap((id) => [`start ${id}`, `end ${id} passed`]),
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

  async function checkFailingSelfCheck(compiled) {
    group("A self-check that fails");
    // The package's WebAssembly with one letter of a published repair card changed, as a damaged
    // download or memory would: the repair words and the cipher's rounds, which hold the card of
    // their first vector, fail, named by their place only, and their classes stay closed.
    // Fault: a letter of a published card in the WebAssembly, damaged as by a download or memory.
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

