async function checkArgon2Build(name, createModule) {
  const engine = argon2Engine(await createModule());
  // What reached the engine, in order: "known answer" or "round".
  const derives = [];
  const reduced = {
    derive: (password, salt, memoryKib, passes, key) => {
      if (KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)) {
        derives.push("known answer");
        engine.derive(password, salt, memoryKib, passes, key);
        return;
      }
      assert.deepEqual(
        [memoryKib, passes],
        [2097152, 12],
        "the core asks for the suite 3 defaults",
      );
      derives.push("round");
      engine.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key);
    },
    reserve: (memoryKib) => assert.equal(memoryKib, 2097152, "a session reserves 2 GiB"),
  };
  const steps = [];
  const onRound = (round, rounds, stage) => steps.push(`${stage} ${round}/${rounds}`);
  const created = operations.encrypt(PHRASE, PASSWORD, reduced, {
    onRound,
    repairWordCount: 4,
    onUnverified: (json) => steps.push(`unverified ${JSON.parse(json).container}`),
  });
  assert.equal(created.container, REDUCED_COST_CONTAINER, `${name}: same container as native`);
  // The build gives its known answer before the first round and again after the last.
  assert.deepEqual(derives, [
    "known answer",
    ...Array.from({ length: 24 }, () => "round"),
    "known answer",
  ]);
  assert.equal(created.suiteId, SUITE_3);
  assert.equal(created.builtInCheck, true, "a 12-word phrase in 24 words has a built-in check");
  assert.deepEqual(created.otherLengths, []);
  assert.equal(created.repairWords.split(" ").length, 4);
  assert.equal(created.repairProfile, "MHFE-REPAIR-1");
  assert.deepEqual(created.keep, [
    { item: "containerWords", words: 24 },
    { item: "password" },
    { item: "repairWords" },
  ]);
  // Twelve rounds of encryption, the unchecked container, then twelve more that check it.
  const expected = Array.from(
    { length: 24 },
    (_, index) => `${index < 12 ? "encrypt" : "check"} ${index + 1}/24`,
  );
  expected.splice(12, 0, `unverified ${REDUCED_COST_CONTAINER}`);
  assert.deepEqual(steps, expected);
  steps.length = 0;
  // A wallet with a BIP39 passphrase keeps it after the password and before the repair words.
  const withPassphrase = operations.encrypt(PHRASE, PASSWORD, reduced, {
    repairWordCount: 2,
    walletHasPassphrase: true,
  });
  assert.equal(withPassphrase.container, REDUCED_COST_CONTAINER);
  assert.deepEqual(withPassphrase.keep, [
    { item: "containerWords", words: 24 },
    { item: "password" },
    { item: "passphrase" },
    { item: "repairWords" },
  ]);
  await checkEncryptAnswers(created, onRound, reduced, steps);
  const missingLast = await checkRecoveryLengths(created, onRound, reduced, steps);
  await checkReferences(created, missingLast, reduced);
  await checkEarlyRefusals(created, reduced);
  const { rekeyStating, contradicted, ownerAgain } = await checkRekeyAnswers(
    created,
    onRound,
    reduced,
    steps,
  );
  const ownerOfContradicted = await checkRekeyEndings(
    contradicted,
    ownerAgain,
    reduced,
    rekeyStating,
  );
  await checkDetectedLength(ownerOfContradicted, rekeyStating);
  const same = await checkSameLengthRekeys(created, onRound, reduced, steps);
  await checkOwnerComparison(name, created, derives, onRound, reduced, same, steps);
}

/**
 * The answer whether the wallet has a passphrase in encrypt, and the recoveries of its
 * container.
 */
async function checkEncryptAnswers(created, onRound, reduced, steps) {
  // Without an answer, undefined or null, what to keep names any passphrase of the wallet in its
  // place: a page need not ask.
  for (const value of [undefined, null]) {
    const unknown = operations.encrypt(PHRASE, PASSWORD, reduced, {
      repairWordCount: 2,
      walletHasPassphrase: value,
    });
    assert.equal(unknown.container, REDUCED_COST_CONTAINER);
    assert.deepEqual(
      unknown.keep,
      [
        { item: "containerWords", words: 24 },
        { item: "password" },
        { item: "passphraseIfAny" },
        { item: "repairWords" },
      ],
      `encrypt with walletHasPassphrase ${value} names any passphrase of the wallet`,
    );
  }
  // An answer given is a boolean and nothing else, refused before any Argon2 round: no other value
  // is read as a truth value.
  for (const value of NOT_BOOLEAN_ANSWERS) {
    expectMessage(PASSPHRASE_ANSWER_NOT_BOOLEAN, () =>
      operations.encrypt(PHRASE, PASSWORD, reduced, { walletHasPassphrase: value, onRound }),
    );
  }
  assert.deepEqual(steps, [], "encrypt refuses an answer that is not a boolean before Argon2");

  const recovery = operations.decrypt(created.container, PASSWORD, reduced, { onRound });
  assert.deepEqual(
    steps,
    Array.from({ length: 12 }, (_, index) => `recover ${index + 1}/12`),
  );
  assert.deepEqual(recovery, {
    kind: "phrase",
    candidates: [
      {
        words: 12,
        verified: true,
        status: "verified",
        phrase: PHRASE,
        suiteId: SUITE_3,
        fingerprintWithoutPassphrase: PHRASE_FINGERPRINT,
        walletCheck: null,
        statedWords: null,
        otherLengths: [],
      },
    ],
  });
  // The length rules of recovery (AUD-015-FUN001): a check that passes takes precedence over a
  // stated length, which the reading names; 24 stated words give both readings, the checked one
  // first; a stated short length that no check passes is refused.
  const statedOther = operations.decrypt(created.container, PASSWORD, reduced, { words: 15 });
  assert.deepEqual(
    [statedOther.kind, statedOther.candidates[0].words, statedOther.candidates[0].statedWords],
    ["phrase", 12, 15],
  );
  assert.equal(statedOther.candidates[0].phrase, PHRASE);
  const stated24 = operations.decrypt(created.container, PASSWORD, reduced, { words: 24 });
  assert.deepEqual(
    stated24.candidates.map(({ words, verified, statedWords }) => [words, verified, statedWords]),
    [
      [12, true, 24],
      [24, false, null],
    ],
  );
  assert.equal(stated24.kind, "ambiguous");
  expectMessage(
    "VERIFIER_MISMATCH: the recovered phrase passes no built-in check: the password, PIM, " +
      "memory level or container is probably wrong, or the original seed phrase has 24 words",
    () => operations.decrypt(created.container, encode("wrong"), reduced, { words: 12 }),
  );
  const wrong = operations.decrypt(created.container, encode("wrong"), reduced);
  assert.deepEqual(
    [wrong.candidates[0].words, wrong.candidates[0].status],
    [24, "readAs24"],
    "a wrong password reads as 24 words, not verified",
  );
  assert.equal(typeof wrong.candidates[0].walletCheck, "boolean");
  // Every 24-word reading gets the 16-bit source check with the passphrase given, or none: the
  // published wallet-check phrase ("abandon" 21 times, "above proof fatigue") passes with
  // "TREZOR" and fails without a passphrase.
  const checkedPhrase = `${"abandon ".repeat(21)}above proof fatigue`;
  const checkedContainer = operations.encrypt(checkedPhrase, PASSWORD, reduced).container;
  const readWith = (passphrase) =>
    operations.decrypt(checkedContainer, PASSWORD, reduced, { passphrase }).candidates[0];
  assert.deepEqual(
    [readWith("TREZOR").words, readWith("TREZOR").walletCheck, readWith("").walletCheck],
    [24, true, false],
  );
}

/** A check at a stated length and the length detected, and what each recovery offers next. */
async function checkRecoveryLengths(created, onRound, reduced, steps) {
  steps.length = 0;
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "words", "12", { onRound }).matches,
    true,
  );
  assert.deepEqual(steps.slice(-2), ["recover 12/12", "compare 12/12"]);
  // A check at a stated length that the built-in check contradicts matches at the length found,
  // which the evidence names (AUD-015-FUN001).
  const checkedOther = operations.check(created.container, PASSWORD, reduced, "words", "15");
  assert.deepEqual([checkedOther.matches, checkedOther.evidence.builtInCheck], [true, 12]);
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT)
      .matches,
    true,
  );
  assert.deepEqual(
    operations.check(created.container, PASSWORD, reduced, "address", BIP84_ADDRESS, {
      coin: "bitcoin",
    }),
    { matches: true, path: "m/84'/0'/0'/0/0", evidence: { builtInCheck: 12, walletCheck: null } },
  );
  // The length detected: the 12-word original passes its own checks, and one recovery is
  // compared again, as a page that asks for the length when detection finds none compares it.
  assert.deepEqual(operations.check(created.container, PASSWORD, reduced, "words", "0"), {
    matches: true,
    path: null,
    evidence: { builtInCheck: 12, walletCheck: null },
  });
  const checkSession = new core.CheckSession(
    created.container,
    PASSWORD,
    "",
    0,
    0,
    0,
    "words",
    "0",
    "",
    "",
    noBytes(),
    reduced,
    () => {},
  );
  // A stated length the built-in check contradicts matches at the length found (AUD-015-FUN001);
  // a fingerprint of another wallet does not.
  const atFifteen = JSON.parse(checkSession.compare("words", "15", "", "", noBytes()));
  assert.deepEqual([atFifteen.matches, atFifteen.evidence.builtInCheck], [true, 12]);
  assert.equal(
    JSON.parse(checkSession.compare("fingerprint", "00000000", "", "", noBytes())).matches,
    false,
  );
  assert.equal(
    JSON.parse(checkSession.compare("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes())).matches,
    true,
    "a recovery is compared again without its rounds",
  );
  checkSession.free();
  // The search for missing words: the candidates, the decoy wallet without Argon2, and the
  // owner's wallet, each candidate recovered at the reduced cost.
  const missingLast = REDUCED_COST_CONTAINER.split(" ")
    .map((word, index) => (index === 23 ? "?" : word))
    .join(" ");
  assert.deepEqual(JSON.parse(core.searchCandidates(missingLast)), {
    missing: [24],
    candidates: 8,
    offersWalletSearch: true,
    offersOwnChecks: true,
  });
  // Two missing words leave only the decoy search; a same-length container has no own checks.
  const twoMarked = missingLast.replace(/^\w+/u, "?");
  assert.deepEqual(
    fieldsOf(JSON.parse(core.searchCandidates(twoMarked)), ["missing", "offersWalletSearch"]),
    { missing: [1, 24], offersWalletSearch: false },
  );
  assert.equal(JSON.parse(core.searchCandidates(twoMarked)).offersOwnChecks, false);
  const sameLengthMissing = REDUCED_COST_SAME_LENGTH_CONTAINER.replace(/\w+$/u, "?");
  assert.deepEqual(
    fieldsOf(JSON.parse(core.searchCandidates(sameLengthMissing)), [
      "offersWalletSearch",
      "offersOwnChecks",
    ]),
    { offersWalletSearch: true, offersOwnChecks: false },
  );
  const decoyFingerprint = core.walletFingerprint(encode(REDUCED_COST_CONTAINER), noBytes());
  const decoyFound = JSON.parse(
    core.searchDecoy(missingLast, "fingerprint", decoyFingerprint, "", "", noBytes(), 20, () => {}),
  );
  assert.equal(decoyFound.container, REDUCED_COST_CONTAINER);
  assert.deepEqual(decoyFound.words, [{ position: 24, word: "sweet" }]);
  const decoyMissed = JSON.parse(
    core.searchDecoy(missingLast, "fingerprint", "00000000", "", "", noBytes(), 20, () => {}),
  );
  assert.deepEqual([decoyMissed.found, decoyMissed.container], [false, null]);
  return missingLast;
}

/**
 * The owner's fingerprint and the other references of a recovery, and the library's refusals
 * before any round.
 */
async function checkReferences(created, missingLast, reduced) {
  // The owner's fingerprint, and the original seed phrase's own checks without and with its
  // passphrase: a 12-word phrase passes its built-in check either way.
  for (const [kind, reference, passphrase] of [
    ["fingerprint", PHRASE_FINGERPRINT, ""],
    ["builtInCheck", "", ""],
    ["walletCheck", "", "TREZOR"],
  ]) {
    const seen = [];
    const searched = JSON.parse(
      core.searchWallet(
        missingLast,
        PASSWORD,
        "",
        0,
        0,
        0,
        kind,
        reference,
        "",
        "",
        encode(passphrase),
        reduced,
        (candidate, candidates) => seen.push(`${candidate}/${candidates}`),
        () => {},
      ),
    );
    assert.equal(searched.container, REDUCED_COST_CONTAINER, `searchWallet with ${kind}`);
    assert.equal(seen[0], "1/8", `searchWallet with ${kind} tells each candidate`);
  }
  const twoMissing = missingLast.replace(/^\S+/, "?");
  expectCode("TOO_MANY_MISSING_WORDS", () =>
    core.searchWallet(
      twoMissing,
      PASSWORD,
      "",
      0,
      0,
      0,
      "fingerprint",
      PHRASE_FINGERPRINT,
      "",
      "",
      noBytes(),
      reduced,
      () => {},
      () => {},
    ),
  );
  expectCode("INVALID_REQUEST", () => core.searchCandidates(REDUCED_COST_CONTAINER));
  // An Ethereum address of the same wallet, on Ethereum's path.
  assert.deepEqual(
    operations.check(
      created.container,
      PASSWORD,
      reduced,
      "address",
      "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
      { coin: "ethereum" },
    ),
    { matches: true, path: "m/44'/60'/0'/0/0", evidence: { builtInCheck: 12, walletCheck: null } },
  );
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT, {
      passphrase: encode("TREZOR"),
    }).matches,
    false,
  );
  expectCode("INVALID_COIN", () =>
    operations.check(created.container, PASSWORD, reduced, "address", "bc1q", { coin: "doge" }),
  );
  // The library's refusal, before any round: the binding has none of its own.
  expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
    operations.check(created.container, PASSWORD, reduced, "walletCheck", "", {
      onRound: noRoundExpected,
    }),
  );
}

/**
 * The refusals before any Argon2 call: the numbers of the raw API, and a refused password's
 * passphrase wiped.
 */
async function checkEarlyRefusals(created, reduced) {
  // Refusals happen before any Argon2 call.
  expectCode("MEMORY_LEVEL_NOT_SUPPORTED_HERE", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { memoryLevel: 1 }),
  );
  expectCode("INVALID_PIM", () => operations.encrypt(PHRASE, PASSWORD, reduced, { pim: 1024 }));
  expectCode("INVALID_PHRASE", () => operations.encrypt("abandon about", PASSWORD, reduced));
  expectCode("INVALID_REPAIR_WORDS", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { repairWordCount: 3 }),
  );
  expectCode("PASSWORDS_DIFFER", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { repeat: encode("other") }),
  );
  // Numbers the raw API gets straight from JavaScript are refused unless they are whole numbers
  // in range; a u32 parameter would have turned 2^32 into 0 and -1 into 4294967295.
  for (const value of [2 ** 32, 2 ** 32 + 1, -1, 0.5, NaN, Infinity]) {
    expectCode("INVALID_PIM", () => operations.encrypt(PHRASE, PASSWORD, reduced, { pim: value }));
    expectCode("INVALID_MEMORY_LEVEL", () =>
      operations.decrypt(created.container, PASSWORD, reduced, { memoryLevel: value }),
    );
    expectCode("INVALID_WORD_COUNT", () =>
      operations.decrypt(created.container, PASSWORD, reduced, { words: value }),
    );
  }
  // A refused password must not leave the separately given BIP39 passphrase in the core's memory.
  const sentinel = encode("public sentinel passphrase 7f3a9c");
  expectCode("EMPTY_PASSWORD", () =>
    operations.check(created.container, noBytes(), reduced, "fingerprint", PHRASE_FINGERPRINT, {
      passphrase: sentinel.slice(),
    }),
  );
  assert.equal(
    Buffer.from(coreMemory.buffer).indexOf(Buffer.from(sentinel)),
    -1,
    "the passphrase was wiped",
  );
  // The words are read back written out, whatever case and short forms were typed.
  const typed = created.container
    .toUpperCase()
    .split(" ")
    .map((word) => word.slice(0, 4))
    .join("  ");
  const facts = JSON.parse(core.describeContainer(typed));
  assert.equal(facts.container, created.container);
  assert.deepEqual(facts.phraseLengths, [12, 15, 18, 21, 24]);
  assert.equal(facts.confirmationFor["12"], "builtInCheck");
  assert.equal(facts.confirmationFor["24"], "walletOrOwner");
  // With the length detected, the wallet or its owner confirms a rekey, whatever length is found:
  // a 24-word original may pass a short check by chance (AUD-017-FUN001).
  assert.equal(facts.confirmationFor["0"], "walletOrOwner");
  assert.equal(facts.hiddenWallets, true);
  assert.equal(facts.offersWalletCheck, true);
  const phraseFacts = JSON.parse(
    core.describePhrase(encode(PHRASE.toUpperCase().replaceAll(" ", "\t"))),
  );
  assert.equal(phraseFacts.phrase, PHRASE);
  assert.deepEqual(phraseFacts.otherLengths, []);
  assert.deepEqual(phraseFacts.containers, [
    { sameLength: false, words: 24, wrongWordPassesOneIn: 256, otherLengths: [] },
    { sameLength: true, words: 12, wrongWordPassesOneIn: 16, otherLengths: [] },
  ]);
  // A public 12-word phrase whose packed state also passes the 21-word check (src/packing.rs):
  // a 24-word container of it can be misread, a same-length one cannot, as the command-line tool
  // warns only for the first.
  const ambiguous = JSON.parse(core.describePhrase(encode(AMBIGUOUS_12_WORDS)));
  assert.deepEqual(ambiguous.otherLengths, [21]);
  assert.deepEqual(
    ambiguous.containers.map((choice) => choice.otherLengths),
    [[21], []],
  );
  expectCode("UNASSIGNED_CHARACTER", () => core.checkPassword(encode("a͸")));
  expectCode("INVALID_PASSWORD_UTF8", () => core.checkPassword(new Uint8Array([0xff])));
  expectCode("CONTROL_CHARACTER_IN_PASSWORD", () => core.checkPassword(encode("first\r\nsecond")));
  // A progress callback that throws stops the operation.
  expectCode("CANCELLED", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, {
      onRound: () => {
        throw new Error("stop");
      },
    }),
  );
  // A container of the phrase's own length, only when asked for.
  const sameLength = operations.encrypt(PHRASE, PASSWORD, reduced, { sameLength: true });
  assert.equal(sameLength.container, REDUCED_COST_SAME_LENGTH_CONTAINER);
  assert.equal(sameLength.suiteId, SUITE_4);
  assert.equal(sameLength.builtInCheck, false);
  assert.deepEqual(
    operations.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced).candidates[0].status,
    "noBuiltInCheck",
  );
  expectCode("NO_BUILT_IN_CHECK", () =>
    operations.check(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, "words", "12"),
  );
  // A same-length container has no wallet check, with a passphrase or without one: the library's
  // order, the same as through the command line, puts this refusal before the empty passphrase's.
  for (const passphrase of [encode("TREZOR"), noBytes()]) {
    expectCode("NO_WALLET_CHECK", () =>
      operations.check(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, "walletCheck", "", {
        passphrase,
        onRound: noRoundExpected,
      }),
    );
  }
  expectCode("SAME_LENGTH_NEEDS_SHORT_PHRASE", () =>
    operations.encrypt(ZERO_24, PASSWORD, reduced, { sameLength: true }),
  );
  expectCode("LENGTH_CHOICE_NOT_APPLICABLE", () =>
    operations.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, { words: 15 }),
  );
}
