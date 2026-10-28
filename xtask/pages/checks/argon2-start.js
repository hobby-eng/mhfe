  async function checkArgon2Start() {
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
    // Fault: the start of the package's Argon2 build, failing as when the browser refuses memory.
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
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    const startupLines = [...pageParts, ...SELF_CHECK.core].map((id) =>
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

