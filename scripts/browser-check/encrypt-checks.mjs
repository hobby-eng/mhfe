// The page's checks of MhfeClient.encrypt (page code, scripts/browser-check/harness.mjs). They keep
// the containers they make in `made`, for the checks of the other methods.

/** MhfeClient.encrypt: its rounds, its results with every option, and its refusals and faults. */
export async function checkEncrypt(client, repair, made) {
  group("MhfeClient.encrypt");
  const sealPhrase = (options) =>
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
      ...options,
    });
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "a\tb",
      passwordRepeat: "a\tb",
      walletHasPassphrase: false,
    }),
    "CONTROL_CHARACTER_IN_PASSWORD",
    "a password with a TAB is refused",
  );

  const { sealed, cards } = await checkEncryptRounds(client, repair, sealPhrase);
  await checkEncryptPasswordForms(client, sealPhrase, sealed, cards);
  await checkEncryptPasswordRepair(client, sealPhrase, made);
  await checkEncryptLengths(client, sealPhrase, made);
  await checkEncryptRepetitions(client, sealPhrase);
  await checkEncryptPassphraseAnswers(client, sealPhrase);
  await checkEncryptRefusals(client, sealPhrase);
  await checkEncryptFaults(client, sealPhrase);
}

/** The rounds and callbacks of an encryption, and its result with the repair module's card. */
export async function checkEncryptRounds(client, repair, sealPhrase) {
  const log = progressLog();
  const shown = [];
  const sealed = await sealPhrase({
    repairWordCount: 4,
    onProgress: log.onProgress,
    onUnverified: (result) => {
      log.lines.push("unverified");
      shown.push(result);
    },
  });
  expectEqual(
    log.lines,
    [...roundLines("encrypt", 1, 12, 24), "unverified", ...roundLines("check", 13, 24, 24)],
    "encrypt runs 12 rounds, shows the container unverified, then checks it in 12 more",
  );
  expectEqual(
    shown,
    [
      {
        container: REDUCED_COST_CONTAINER,
        containerFingerprint: FINGERPRINTS.reducedCostContainer,
      },
    ],
    "onUnverified receives the native container and its fingerprint",
  );
  const cards = {};
  for (const count of REPAIR_WORD_CHOICES) {
    cards[count] = (await repair.repairWords({ container: REDUCED_COST_CONTAINER, count })).words;
  }
  expectEqual(
    sealed,
    {
      container: REDUCED_COST_CONTAINER,
      suiteId: SUITE_3,
      containerFingerprint: FINGERPRINTS.reducedCostContainer,
      builtInCheck: true,
      otherLengths: [],
      repairWords: cards[4],
      repairProfile: REPAIR_PROFILE,
      keep: [...KEEP_24, { item: "repairWords", apart: true }],
    },
    "encrypt resolves to the native container with every field and the repair module's card",
  );
  return { sealed, cards };
}

/** A password as bytes or text, the passphrase's answer and repair words of every count. */
export async function checkEncryptPasswordForms(client, sealPhrase, sealed, cards) {
  const passwordBytes = encode(PASSWORD);
  const repeatBytes = encode(PASSWORD);
  const asTyped = await client.encrypt({
    phrase: PHRASE,
    password: passwordBytes,
    passwordRepeat: repeatBytes,
    passwordRepair: "asTyped",
    repairWordCount: 2,
    walletHasPassphrase: false,
  });
  expect(
    asTyped.container === REDUCED_COST_CONTAINER &&
      asTyped.repairWords === cards[2] &&
      asTyped.repairProfile === REPAIR_PROFILE,
    "a password as bytes, kept as typed, gives the same container, with two repair words",
  );
  const decoder = new TextDecoder();
  expect(
    decoder.decode(passwordBytes) === PASSWORD && decoder.decode(repeatBytes) === PASSWORD,
    "the page's password bytes are copied, neither emptied nor wiped",
  );
  const withPassphrase = await sealPhrase({ walletHasPassphrase: true, repairWordCount: 6 });
  expectEqual(
    withPassphrase,
    {
      ...sealed,
      repairWords: cards[6],
      keep: [...KEEP_24, { item: "passphrase" }, { item: "repairWords", apart: true }],
    },
    "walletHasPassphrase adds the passphrase to what to keep; six repair words and their profile",
  );
  // Without callbacks, as for output to a file: the result comes only after the check.
  const quiet = await sealPhrase({ repairWordCount: 8 });
  expectEqual(
    quiet,
    { ...sealed, repairWords: cards[8] },
    "encrypt without callbacks resolves to the checked container, eight repair words and profile",
  );
  expectEqual(
    await client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: repeatBytes,
      walletHasPassphrase: false,
    }),
    { ...sealed, repairWords: null, repairProfile: null, keep: KEEP_24 },
    "a password as text and its repetition as the same bytes are the same password",
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: passwordBytes,
      passwordRepeat: WRONG_PASSWORD,
      walletHasPassphrase: false,
    }),
    "PASSWORDS_DIFFER",
    "a password as bytes and a repetition as other text differ",
  );
}

/** The password's repair: the written form and a restored word encrypt as the full password. */
export async function checkEncryptPasswordRepair(client, sealPhrase, made) {
  const checkWord = await client.encrypt({
    phrase: PHRASE,
    password: CHECK_WORD_PASSWORD,
    passwordRepeat: CHECK_WORD_PASSWORD,
    walletHasPassphrase: false,
  });
  made.checkWord = checkWord.container;
  const corrected = await client.encrypt({
    phrase: PHRASE,
    password: CHECK_WORD_CAPITALS,
    passwordRepeat: CHECK_WORD_CAPITALS,
    passwordRepair: "corrected",
    walletHasPassphrase: false,
  });
  expect(
    corrected.container === made.checkWord,
    'passwordRepair "corrected" encrypts with the written form of the password',
  );
  const restored = await client.encrypt({
    phrase: PHRASE,
    password: CHECK_WORD_MISSING,
    passwordRepeat: CHECK_WORD_MISSING,
    passwordRepair: { repair: 3 },
    walletHasPassphrase: false,
  });
  expect(
    restored.container === made.checkWord,
    "passwordRepair { repair: 3 } encrypts with the restored third word",
  );
  await expectRejection(
    sealPhrase({ passwordRepair: "corrected" }),
    "PASSWORD_REPAIR_NOT_OFFERED",
    '"corrected" is refused for a password the review does not correct',
  );
}

/** The containers of a same-length phrase, of an ambiguous one and of 24-word phrases. */
export async function checkEncryptLengths(client, sealPhrase, made) {
  const same = await sealPhrase({ sameLength: true });
  expectEqual(
    same,
    {
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      suiteId: SUITE_4,
      containerFingerprint: FINGERPRINTS.sameLengthContainer,
      builtInCheck: false,
      otherLengths: [],
      repairWords: null,
      repairProfile: null,
      keep: [{ item: "containerWords", words: 12 }, { item: "password" }],
    },
    "encrypt with sameLength gives the native 12-word container with every field",
  );
  const ambiguous = await client.encrypt({
    phrase: AMBIGUOUS_12_WORDS,
    password: PASSWORD,
    passwordRepeat: PASSWORD,
    walletHasPassphrase: false,
  });
  made.ambiguous = ambiguous.container;
  expectEqual(
    fieldsOf(ambiguous, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
    {
      suiteId: SUITE_3,
      builtInCheck: true,
      otherLengths: [21],
      keep: [...KEEP_24, { item: "wordCount", words: 12, apart: true }],
    },
    "a phrase that detection could also read as 21 words adds its word count to what to keep",
  );
  const checked = await client.encrypt({
    phrase: CHECKED_PHRASE,
    password: PASSWORD,
    passwordRepeat: PASSWORD,
    walletHasPassphrase: false,
  });
  made.checked = checked.container;
  expectEqual(
    fieldsOf(checked, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
    { suiteId: SUITE_3, builtInCheck: false, otherLengths: [], keep: KEEP_24 },
    "a 24-word phrase gets a 24-word container without a built-in check",
  );
  made.emptyChecked = (
    await client.encrypt({
      phrase: EMPTY_CHECKED_PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    })
  ).container;
}

/** A repetition that differs or is missing, and the password's own rules before it. */
export async function checkEncryptRepetitions(client, sealPhrase) {
  await expectRejection(
    sealPhrase({ passwordRepeat: WRONG_PASSWORD }),
    "PASSWORDS_DIFFER",
    "a repetition that differs is refused",
  );
  await expectRejection(
    client.encrypt({ phrase: PHRASE, password: PASSWORD, walletHasPassphrase: false }),
    "PASSWORDS_DIFFER",
    "a password without its repetition is refused",
  );
  await expectRejection(
    client.encrypt({ phrase: PHRASE, password: encode(PASSWORD), walletHasPassphrase: false }),
    "PASSWORDS_DIFFER",
    "a password as bytes without its repetition is refused the same way",
  );
  // The password's own rules come before the comparison, as in the command-line tool, where a
  // script's first line is refused before its second is read.
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "a\tb",
      passwordRepeat: "a\tc",
      walletHasPassphrase: false,
    }),
    "CONTROL_CHARACTER_IN_PASSWORD",
    "a password that breaks a rule is refused for it, before its repetition is compared",
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "",
      passwordRepeat: "x",
      walletHasPassphrase: false,
    }),
    "EMPTY_PASSWORD",
    "an empty password is refused before its repetition is compared",
  );
}

/** The answer whether the wallet has a passphrase: left out, null, or not a boolean. */
export async function checkEncryptPassphraseAnswers(client, sealPhrase) {
  // Without an answer, left out or null, what to keep names any passphrase of the wallet in its
  // place: a page need not ask.
  for (const [description, value] of [
    ["left out", undefined],
    ["null", null],
  ]) {
    expectEqual(
      fieldsOf(
        await client.encrypt({
          phrase: PHRASE,
          password: PASSWORD,
          passwordRepeat: PASSWORD,
          repairWordCount: 2,
          ...(value === undefined ? {} : { walletHasPassphrase: value }),
        }),
        ["container", "keep"],
      ),
      {
        container: REDUCED_COST_CONTAINER,
        keep: [...KEEP_24, PASSPHRASE_IF_ANY, { item: "repairWords", apart: true }],
      },
      `encrypt with walletHasPassphrase ${description} names any passphrase of the wallet`,
    );
  }
  for (const value of ["no", 0]) {
    await expectExactTypeError(
      sealPhrase({ walletHasPassphrase: value }),
      WALLET_PASSPHRASE_REQUIRED,
      `a walletHasPassphrase of ${JSON.stringify(value)}, not a boolean, is refused`,
    );
  }
}

/** Refusals before any Argon2 round, of the settings, and the cost PIM 1 asks for. */
export async function checkEncryptRefusals(client, sealPhrase) {
  const refusalLog = progressLog();
  await expectRejection(
    client.encrypt({
      phrase: ZERO_24,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      sameLength: true,
      walletHasPassphrase: false,
      onProgress: refusalLog.onProgress,
    }),
    "SAME_LENGTH_NEEDS_SHORT_PHRASE",
    "a same-length container of a 24-word phrase is refused",
  );
  await expectRejection(
    client.encrypt({
      phrase: "abandon about",
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
      onProgress: refusalLog.onProgress,
    }),
    "INVALID_PHRASE",
    "an invalid phrase is refused",
  );
  expect(refusalLog.lines.length === 0, "both refusals came before any Argon2 round");
  await expectRejection(
    sealPhrase({ memoryLevel: 1 }),
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    "memory level 1 (4 GiB) is refused in a browser",
  );
  // In the library's words for the same value, as the command-line tool prints them.
  await expectRejection(
    sealPhrase({ memoryLevel: 22 }),
    "INVALID_MEMORY_LEVEL",
    "memory level 22 is refused",
    undefined,
    "The memory level must be a whole number from 0 to 21, not 22",
  );
  await expectRejection(
    sealPhrase({ pim: 1024 }),
    "INVALID_PIM",
    "PIM 1024 is refused",
    undefined,
    "The PIM must be a whole number from 0 to 1023, not 1024",
  );
  await expectRejection(
    sealPhrase({ repairWordCount: 3 }),
    "INVALID_REPAIR_WORDS",
    "three repair words are refused",
    undefined,
    "The repair words cannot be used: a card has 2, 4, 6 or 8 repair words, not 3",
  );
  const pimError = await rejectionOf(sealPhrase({ pim: 1 }));
  expect(
    pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
    "PIM 1 asks Argon2 for 24 passes, which the reduced-cost wrapper refuses",
  );
}

/** A fault in the rounds of the check, and a cancel in them. */
export async function checkEncryptFaults(client, sealPhrase) {
  const faultyLog = progressLog();
  const faultyShown = [];
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: FAULTY_CHECK_PASSWORD,
      passwordRepeat: FAULTY_CHECK_PASSWORD,
      repairWordCount: 4,
      walletHasPassphrase: false,
      onProgress: faultyLog.onProgress,
      onUnverified: ({ container }) => faultyShown.push(container),
    }),
    "VERIFICATION_FAILED",
    "a fault in the rounds of the check rejects with VERIFICATION_FAILED",
  );
  expect(
    faultyShown.length === 1 && faultyLog.lines.at(-1) === "check 24/24",
    "the unverified container was shown, and the check ran its rounds before it failed",
  );
  const cancelShown = [];
  await expectRejection(
    sealPhrase({
      onUnverified: ({ container }) => cancelShown.push(container),
      onProgress: ({ stage }) => {
        if (stage === "check") client.cancel();
      },
    }),
    "CANCELLED",
    "cancel() in the check stops an encryption",
  );
  expect(
    cancelShown[0] === REDUCED_COST_CONTAINER,
    "the container cancelled in its check had been shown unverified",
  );
}
