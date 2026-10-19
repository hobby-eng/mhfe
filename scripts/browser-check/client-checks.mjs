// The page's checks of MhfeClient's construction, reading, cancellation and callbacks, of memory
// the browser cannot give, and of the runtime (page code, scripts/browser-check/harness.mjs).

/** MhfeClient's construction: its refusals, its fixed values and a compiled WebAssembly.Module. */
export async function checkConstruction(client, compiled) {
  group("MhfeClient: construction and fixed values");
  const parts = {
    workerSource: WORKER_SOURCE,
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
  };
  expectThrownTypeError(
    () => new MhfeClient(),
    "workerSource must be the text of the file.",
    "a client without its parts is refused",
  );
  expectThrownTypeError(
    () => new MhfeClient({ ...parts, workerSource: "", wasm: compiled }),
    "workerSource must be the text of the file.",
    "an empty workerSource is refused",
  );
  expectThrownTypeError(
    () => new MhfeClient({ ...parts, argon2Threaded: undefined, wasm: compiled }),
    "argon2Threaded must be the text of the file.",
    "a missing threaded Argon2 build is refused",
  );
  expectThrownTypeError(
    () => new MhfeClient({ ...parts, argon2SingleThreaded: 42, wasm: compiled }),
    "argon2SingleThreaded must be the text of the file.",
    "a single-threaded Argon2 build that is not text is refused",
  );
  expectThrownTypeError(
    () => new MhfeClient({ ...parts, wasm: "runtime/mhfe.wasm" }),
    "wasm must be a Uint8Array or a WebAssembly.Module.",
    "a wasm that is neither bytes nor a compiled module is refused",
  );
  expect(client.maxSupportedMemLevel() === 0, "maxSupportedMemLevel is 0, 2 GiB");
  const parameters = await client.parameters();
  expect(parameters.version === VERSION, "the core reports the package version");
  expectEqual(
    parameters,
    {
      maxInputTextBytes: UTILITY_INPUT_BYTES,
      version: VERSION,
      suiteId: SUITE_3,
      sameLengthSuiteId: SUITE_4,
      rounds: 12,
      progressStages: ["recover", "encrypt", "check", "compare"],
      progressRoundTotals: [12, 24, 36],
      openedWordCount: 24,
      maxPim: 1023,
      maxMemoryLevel: 21,
      highestBrowserMemoryLevel: 0,
      wordCounts: [12, 15, 18, 21, 24],
      builtInCheckWordCounts: [12, 15, 18, 21],
      ...REPAIR_PARAMETERS,
      hiddenWalletRefusals: [
        "PASSWORD_ALREADY_USED",
        "HIDDEN_WALLET_PASSES_CHECK",
        "PASSWORDS_DIFFER",
        "PASSWORD_REPAIR_NOT_OFFERED",
        "EMPTY_PASSWORD",
        "PASSWORD_TOO_LONG",
        "INVALID_PASSWORD_UTF8",
        "CONTROL_CHARACTER_IN_PASSWORD",
        "UNASSIGNED_CHARACTER",
      ],
      decoyScanGap: 20,
      argon2Parts: ["argon2", "argon2-sizes"],
    },
    "parameters gives every fixed value of the core",
  );
  const fromModule = new MhfeClient({ ...parts, wasm: compiled });
  expect(fromModule.maxSupportedMemLevel() === 0, "a client takes a compiled WebAssembly.Module");
  const recovery = await fromModule.decrypt({
    container: REDUCED_COST_CONTAINER,
    password: PASSWORD,
  });
  expect(
    recovery.candidates[0].phrase === PHRASE,
    "a client given the compiled module runs a long operation",
  );
}

/** MhfeClient.readPhrase, readContainer and the search for missing words without repair words. */
export async function checkReading(client, made) {
  group("MhfeClient.readPhrase and readContainer");
  await checkReadPhrase(client);
  await checkReadContainer(client);
  await checkCandidateSearch(client, made);
}

/** readPhrase: the forms it reads, the containers a phrase can have, and its refusals. */
export async function checkReadPhrase(client) {
  const atLimit = " ".repeat(UTILITY_INPUT_BYTES - PHRASE.length) + PHRASE;
  expectEqual((await client.readPhrase(atLimit)).phrase, PHRASE, "raw limit preserves the phrase");
  await expectRejection(
    client.readPhrase(`${atLimit} `),
    "INVALID_REQUEST",
    "raw phrase size is checked before whitespace normalization",
  );
  const read = await client.readPhrase(PHRASE.toUpperCase());
  expect(
    read.phrase === PHRASE && read.words === 12 && read.otherLengths.length === 0,
    "readPhrase writes every word out",
  );
  const shortForms = PHRASE.split(" ")
    .map((word) => word.slice(0, 4))
    .join("  ");
  expectEqual(
    await client.readPhrase(shortForms),
    {
      phrase: PHRASE,
      words: 12,
      otherLengths: [],
      containers: [
        { sameLength: false, words: 24, wrongWordPassesOneIn: 256, otherLengths: [] },
        { sameLength: true, words: 12, wrongWordPassesOneIn: 16, otherLengths: [] },
      ],
    },
    "readPhrase reads four-letter forms and lists the 24-word and the same-length container",
  );
  expectEqual(
    (await client.readPhrase(AMBIGUOUS_12_WORDS)).otherLengths,
    [21],
    "readPhrase names the other length that detection would also accept",
  );
  const long = await client.readPhrase(ZERO_24);
  expect(
    long.containers.length === 1 &&
      long.containers[0].sameLength === false &&
      long.containers[0].words === 24,
    "a 24-word phrase has only the 24-word container",
  );
  await expectRejection(
    client.readPhrase("abandon about"),
    "INVALID_PHRASE",
    "a phrase of two words is refused",
  );
  await expectRejection(
    client.readPhrase("abandon ".repeat(11) + "abandon"),
    "INVALID_PHRASE",
    "a phrase whose checksum fails is refused",
  );
}

/** readContainer: every fact of a 24-word and of a same-length container, and a refusal. */
export async function checkReadContainer(client) {
  const containerShortForms = REDUCED_COST_CONTAINER.toUpperCase()
    .split(" ")
    .map((word) => word.slice(0, 4))
    .join(" ");
  expectEqual(
    await client.readContainer(containerShortForms),
    {
      container: REDUCED_COST_CONTAINER,
      words: 24,
      suiteId: SUITE_3,
      phraseLengths: [12, 15, 18, 21, 24],
      builtInCheckLengths: [12, 15, 18, 21],
      // A detected length needs the wallet or its owner: a 24-word original may pass a short
      // check by chance (AUD-017-FUN001).
      confirmationFor: {
        0: "walletOrOwner",
        12: "builtInCheck",
        15: "builtInCheck",
        18: "builtInCheck",
        21: "builtInCheck",
        24: "walletOrOwner",
      },
      hiddenWallets: true,
      offersWalletCheck: true,
      containerFingerprint: FINGERPRINTS.reducedCostContainer,
    },
    "readContainer gives every fact of a 24-word container typed in capitals and short forms",
  );
  expectEqual(
    await client.readContainer(REDUCED_COST_SAME_LENGTH_CONTAINER),
    {
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      words: 12,
      suiteId: SUITE_4,
      phraseLengths: [12],
      builtInCheckLengths: [],
      confirmationFor: { 0: "walletOrOwner", 12: "walletOrOwner" },
      hiddenWallets: false,
      offersWalletCheck: false,
      containerFingerprint: FINGERPRINTS.sameLengthContainer,
    },
    "readContainer gives every fact of a same-length container",
  );
  await expectRejection(
    client.readContainer("abandon about"),
    "INVALID_CONTAINER",
    "a container of two words is refused",
  );
}

/** searchCandidates, searchDecoy and searchWallet without the repair words. */
export async function checkCandidateSearch(client, made) {
  // The search for missing words without the repair words: the candidates, and the decoy
  // wallet, the container itself, found by its fingerprint without a password or Argon2.
  const missingLast = FULL_SIZE_CONTAINER.split(" ")
    .map((word, index) => (index === 23 ? "?" : word))
    .join(" ");
  expectEqual(
    await client.searchCandidates({ container: missingLast }),
    { missing: [24], candidates: 8, offersWalletSearch: true, offersOwnChecks: true },
    "searchCandidates counts the 8 candidates of a missing last word",
  );
  const progress = [];
  const found = await client.searchDecoy({
    container: missingLast,
    reference: { fingerprint: FINGERPRINTS.fullSizeContainer },
    onProgress: (value) => progress.push(value),
  });
  expectEqual(
    fieldsOf(found, ["found", "container", "words", "containerFingerprint"]),
    {
      found: true,
      container: FULL_SIZE_CONTAINER,
      words: [{ position: 24, word: "peace" }],
      containerFingerprint: FINGERPRINTS.fullSizeContainer,
    },
    "searchDecoy finds the missing word by the container's own fingerprint",
  );
  expect(
    progress.at(-1)?.stage === "search" && progress.at(-1)?.candidates === 8,
    "searchDecoy tells how far it has come",
  );
  const missed = await client.searchDecoy({
    container: missingLast,
    reference: { fingerprint: "00000000" },
  });
  expectEqual(
    fieldsOf(missed, ["found", "container"]),
    { found: false, container: null },
    "searchDecoy finds nothing with another fingerprint",
  );
  const missingReduced = REDUCED_COST_CONTAINER.split(" ").slice(0, -1).concat("?").join(" ");
  for (const reference of [
    { fingerprint: FINGERPRINTS.phrase },
    { address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/0'/0'/0/0" },
    { builtInCheck: true },
  ]) {
    const steps = [];
    const recovered = await client.searchWallet({
      container: missingReduced,
      password: PASSWORD,
      reference,
      onProgress: (step) => steps.push(step),
    });
    expectEqual(
      fieldsOf(recovered, ["found", "container", "words", "containerFingerprint"]),
      {
        found: true,
        container: REDUCED_COST_CONTAINER,
        words: [{ position: 24, word: "sweet" }],
        containerFingerprint: FINGERPRINTS.reducedCostContainer,
      },
      "searchWallet finds the missing word with " + JSON.stringify(reference),
    );
    expect(
      steps.length > 0 &&
        steps.every(
          (step, index) =>
            step.stage === "search" &&
            step.candidates === 8 &&
            step.candidate >= 1 &&
            step.candidate <= 8 &&
            step.rounds === 12 &&
            step.round === (index % 12) + 1 &&
            (index === 0 ||
              step.candidate === steps[index - 1].candidate + (step.round === 1 ? 1 : 0)),
        ),
      "searchWallet reports each candidate and all twelve rounds in order",
    );
  }
  const missingChecked = made.checked.split(" ").slice(0, -1).concat("?").join(" ");
  const checkedSearch = await client.searchWallet({
    container: missingChecked,
    password: PASSWORD,
    reference: { walletCheck: true },
    passphrase: "TREZOR",
  });
  expectEqual(
    fieldsOf(checkedSearch, ["found", "container", "words"]),
    {
      found: true,
      container: made.checked,
      words: [{ position: 24, word: made.checked.split(" ").at(-1) }],
    },
    "searchWallet restores the checked wallet's container with its passphrase",
  );
  let searchCancelled = false;
  await expectRejection(
    client.searchWallet({
      container: missingReduced,
      password: PASSWORD,
      reference: { fingerprint: FINGERPRINTS.phrase },
      onProgress: ({ candidate, round }) => {
        if (candidate === 1 && round === 2) {
          searchCancelled = true;
          client.cancel();
        }
      },
    }),
    "CANCELLED",
    "cancel during a candidate recovery stops searchWallet",
  );
  expect(searchCancelled, "searchWallet reaches the candidate where the page cancels");
  await expectRejection(
    client.searchWallet({
      container: missingLast.replace(/^\S+/, "?"),
      password: PASSWORD,
      reference: { builtInCheck: true },
    }),
    "TOO_MANY_MISSING_WORDS",
    "searchWallet refuses two missing words before any round",
  );
}

/** MhfeClient.cancel, one long operation at a time, and the page's callbacks that fail. */
export async function checkCancelAndCallbacks(client) {
  group("MhfeClient.cancel and the page's callbacks");
  const container = REDUCED_COST_CONTAINER;
  const cancelledAtOnce = client.decrypt({ container, password: PASSWORD });
  client.cancel();
  await expectRejection(
    cancelledAtOnce,
    "CANCELLED",
    "cancel() before the first round refuses with CANCELLED",
  );
  const cancelledLater = client.decrypt({
    container,
    password: PASSWORD,
    onProgress: ({ round }) => {
      if (round === 2) client.cancel();
    },
  });
  await expectRejection(
    cancelledLater,
    "CANCELLED",
    "cancel() in the second round refuses with CANCELLED",
  );
  expect(
    (await rejectionOf(cancelledLater)) instanceof MhfeCancelledError,
    "a cancelled operation rejects with MhfeCancelledError",
  );
  expect(
    (await client.readContainer(container)).container === container,
    "a new operation runs after a cancel",
  );

  const running = client.decrypt({ container, password: PASSWORD });
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    }),
    "BUSY",
    "a second long operation is refused while one runs",
  );
  expect(
    (await client.readPhrase(PHRASE)).phrase === PHRASE,
    "reading words does not wait for the long operation",
  );
  expect((await running).candidates[0].phrase === PHRASE, "the first operation still ends");

  const pageError = new Error("synthetic page error");
  await expectRejection(
    client.decrypt({
      container,
      password: PASSWORD,
      onProgress: () => {
        throw pageError;
      },
    }),
    "CALLBACK_FAILED",
    "a throwing onProgress stops the operation",
    pageError,
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
      onUnverified: () => {
        throw pageError;
      },
    }),
    "CALLBACK_FAILED",
    "a throwing onUnverified stops the operation",
    pageError,
  );
  await expectRejection(
    client.decrypt({
      container,
      password: PASSWORD,
      onProgress: async () => {
        throw pageError;
      },
    }),
    "CALLBACK_FAILED",
    "an async onProgress that rejects stops the operation",
    pageError,
  );
  expect(
    (await client.readPhrase(PHRASE)).phrase === PHRASE,
    "a new operation runs after a callback failed",
  );
  await expectTypeError(
    client.decrypt({ container, password: PASSWORD, onProgress: "show" }),
    "onProgress must be a function.",
    "an onProgress that is not a function is refused",
  );
  await expectTypeError(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
      onUnverified: "show",
    }),
    "onUnverified must be a function.",
    "an onUnverified that is not a function is refused",
  );
}

/** MhfeClient's operations when the browser cannot give the Argon2 memory. */
export async function checkMemoryFailures(client) {
  group("MhfeClient: memory the browser cannot give");
  // The core reports the 2 GiB of memory level 0 that it asked for, not the reduced cost.
  const message = "The computer could not reserve 2 GiB of memory for Argon2";
  const failed = (error) => error?.code === "MEMORY_ALLOCATION_FAILED" && error.message === message;
  const log = progressLog();
  const recovery = await rejectionOf(
    client.decrypt({
      container: REDUCED_COST_CONTAINER,
      password: MEMORY_FAILURE_PASSWORD,
      onProgress: log.onProgress,
    }),
  );
  expect(
    failed(recovery) && sameValue(log.lines, ["recover 1/12"]),
    `a recovery fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${recovery?.code}`,
  );
  const encryptionLog = progressLog();
  const encryption = await rejectionOf(
    client.encrypt({
      phrase: PHRASE,
      password: MEMORY_FAILURE_PASSWORD,
      passwordRepeat: MEMORY_FAILURE_PASSWORD,
      walletHasPassphrase: false,
      onProgress: encryptionLog.onProgress,
    }),
  );
  expect(
    failed(encryption) && sameValue(encryptionLog.lines, ["encrypt 1/24"]),
    `an encryption fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${encryption?.code}`,
  );

  const sessionStart = await rejectionOf(
    client.openHiddenWallets({ container: MEMORY_FAILURE_CONTAINER, mainPassphrase: "" }),
  );
  expect(
    failed(sessionStart),
    `a session of hidden wallets fails at its start, when it reserves its work area -> ${sessionStart?.code}`,
  );
  const session = await client.openHiddenWallets({
    container: REDUCED_COST_CONTAINER,
    mainPassphrase: "",
  });
  const openLog = progressLog();
  const opening = await rejectionOf(
    session.open({
      password: MEMORY_FAILURE_PASSWORD,
      passwordRepeat: MEMORY_FAILURE_PASSWORD,
      onProgress: openLog.onProgress,
    }),
  );
  expect(
    failed(opening) && sameValue(openLog.lines, ["recover 1/12"]),
    `the session after it reserved its area fails in a wallet's round 1 -> ${opening?.code}`,
  );
  await expectRejection(
    session.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
    "SESSION_CLOSED",
    "a memory failure is no refusal: it ends the session",
  );
  expect(
    (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD })).candidates[0]
      .verified,
    "the slot is free after each memory failure",
  );
}

/** Workers that fail, unpaired surrogates, and the wiping of secrets when nothing can start. */
export async function checkRuntime(client, passwords, wallet, compiled) {
  group("Runtime");
  await checkFailingWorkers(client, compiled);
  await checkWipedCopies(client, passwords, wallet);
}

/** WebAssembly and worker scripts that fail, and passwords with an unpaired surrogate. */
export async function checkFailingWorkers(client, compiled) {
  await expectRejection(
    new MhfeRepair({
      workerSource: WORKER_SOURCE,
      wasm: new Uint8Array([0, 97, 115, 109]),
    }).parameters(),
    "WORKER_FAILED",
    "WebAssembly that does not compile rejects with WORKER_FAILED",
  );
  await expectRejection(
    new MhfeRepair({ workerSource: "this is not JavaScript (", wasm: compiled }).parameters(),
    "WORKER_FAILED",
    "a worker whose script does not parse rejects with WORKER_FAILED",
  );
  await expectRejection(
    new MhfePasswords({
      workerSource: 'throw new Error("stopped");',
      wasm: compiled,
    }).parameters(),
    "WORKER_FAILED",
    "a worker whose script throws rejects with WORKER_FAILED",
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "a\uD800",
      passwordRepeat: "a\uD800",
      walletHasPassphrase: false,
    }),
    "INVALID_PASSWORD_TEXT",
    "a password with an unpaired surrogate is refused",
  );
  await expectRejection(
    new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled }).review({
      password: "\uDC00 test",
    }),
    "INVALID_PASSWORD_TEXT",
    "the passwords module refuses an unpaired surrogate too",
  );
  expect(
    (await client.readPhrase(PHRASE)).phrase === PHRASE,
    "the client works after workers that failed",
  );
}

/** The client's byte copies of secrets are wiped when the browser refuses the Blob URL. */
export async function checkWipedCopies(client, passwords, wallet) {
  // The client's own byte copies of secrets, seen through the page's TextEncoder, must be wiped
  // when an operation cannot start: here the browser refuses the worker's Blob URL.
  const copies = [];
  const RealTextEncoder = globalThis.TextEncoder;
  globalThis.TextEncoder = class extends RealTextEncoder {
    encode(text) {
      const encoded = super.encode(text);
      if (text === PASSWORD || text === "TREZOR") copies.push(encoded);
      return encoded;
    }
  };
  // The property rather than the method alone: the very function is put back, and the method is
  // never held unbound.
  const realObjectURLProperty = Object.getOwnPropertyDescriptor(URL, "createObjectURL");
  const wiped = () => copies.every((copy) => copy.every((byte) => byte === 0));
  try {
    URL.createObjectURL = () => {
      throw new Error("refused by the page");
    };
    const refusedCheck = () =>
      client.check({
        container: REDUCED_COST_CONTAINER,
        password: PASSWORD,
        reference: { fingerprint: FINGERPRINT },
        passphrase: "TREZOR",
      });
    await expectRejection(
      refusedCheck(),
      "WORKER_FAILED",
      "a Blob URL the browser refuses rejects with WORKER_FAILED",
    );
    await expectRejection(
      refusedCheck(),
      "WORKER_FAILED",
      "the refused operation freed its slot: the next is not BUSY",
    );
    Object.defineProperty(URL, "createObjectURL", realObjectURLProperty);
    expect(
      copies.length === 4 && wiped(),
      "the copies of the password and the passphrase were wiped",
    );
    copies.length = 0;
    await expectTypeError(
      passwords.review({ password: PASSWORD, passwordRepeat: 5 }),
      "repeated password must be a string or a Uint8Array.",
      "a repetition that is not text is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "\uD800", walletCheck: true }),
      "INVALID_PASSWORD_TEXT",
      "a passphrase repetition with an unpaired surrogate is refused",
    );
    // A repetition of the wrong type is refused before anything is copied (AUD-016-API003);
    // the unpaired surrogate is refused after the passphrase was copied, and that copy is wiped.
    expect(
      copies.length === 1 && wiped(),
      "the first entry's copy is wiped when its repetition is refused",
    );
  } finally {
    Object.defineProperty(URL, "createObjectURL", realObjectURLProperty);
    globalThis.TextEncoder = RealTextEncoder;
  }
}
