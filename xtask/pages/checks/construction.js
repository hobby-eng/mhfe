async function checkConstruction(client, compiled) {
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
      version: VERSION,
      suiteId: SUITE_3,
      sameLengthSuiteId: SUITE_4,
      rounds: 12,
      maxPim: 1023,
      maxMemoryLevel: 21,
      highestBrowserMemoryLevel: 0,
      wordCounts: [12, 15, 18, 21, 24],
      builtInCheckWordCounts: [12, 15, 18, 21],
      repairWordCounts: [2, 4, 6, 8],
      recommendedRepairWords: 4,
      repairCapacities: [
        { count: 2, unreadable: 2, wrong: 1 },
        { count: 4, unreadable: 4, wrong: 2 },
        { count: 6, unreadable: 6, wrong: 3 },
        { count: 8, unreadable: 8, wrong: 4 },
      ],
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

async function checkReading(client) {
  group("MhfeClient.readPhrase and readContainer");
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
    long.containers.length === 1
      && long.containers[0].sameLength === false
      && long.containers[0].words === 24,
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
