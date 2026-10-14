// The page's checks of MhfeClient.check, the rehearsal of a container against its wallet (page
// code, scripts/browser-check/harness.mjs), on the containers that the encryption checks made.

/** MhfeClient.check: matches, results that are not verified, and refusals. */
export async function checkRehearsal(client, made) {
  group("MhfeClient.check");
  const helpers = rehearsalHelpers(client, made);
  await checkRehearsalReferences(helpers);
  await checkRehearsalLengths(helpers);
  await checkRehearsalOtherContainers(helpers);
  await checkRehearsalWalletCheck(helpers);
  await checkRehearsalRefusals(helpers);
  await checkRehearsalReferenceTypes(helpers);
}

/** What the steps of checkRehearsal share: the checks they make, and the outcomes they expect. */
export function rehearsalHelpers(client, made) {
  const fullCheck = (reference, options = {}) =>
    client.check({
      container: REDUCED_COST_CONTAINER,
      password: PASSWORD,
      reference,
      ...options,
    });
  const check = async (reference, options = {}) =>
    fieldsOf(await fullCheck(reference, options), ["outcome", "path"]);
  const matched = (path = null) => ({ outcome: "matches", path });
  const notMatched = { outcome: "doesNotMatch", path: null };
  const notVerified = { outcome: "notVerified", path: null };
  const onChecked = async (reference, options) =>
    fieldsOf(
      await client.check({ container: made.checked, password: PASSWORD, reference, ...options }),
      ["outcome", "path"],
    );
  return { client, made, fullCheck, check, matched, notMatched, notVerified, onChecked };
}

/** The evidence of a match, and matches by fingerprint, address and path, with a passphrase. */
export async function checkRehearsalReferences(helpers) {
  const { fullCheck, check, matched, notMatched } = helpers;
  // The original seed phrase's own checks come with a match: the built-in check of the 12-word
  // phrase, and the phrase + passphrase check, which a phrase drawn without it fails.
  expectEqual(
    (await fullCheck({ fingerprint: FINGERPRINT })).evidence,
    {
      builtInCheck: 12,
      matchingLengths: [12],
      passed: [{ check: "builtInCheck", words: 12 }],
      walletCheck: null,
    },
    "a check lists the built-in check of a 12-word phrase, no wallet check without a passphrase",
  );
  const log = progressLog();
  expectEqual(
    await check({ fingerprint: FINGERPRINT }, { onProgress: log.onProgress }),
    matched(),
    "check matches the master key fingerprint",
  );
  expectEqual(
    log.lines,
    [...roundLines("recover", 1, 12, 12), "compare 12/12"],
    "a check reports 12 rounds, then compare once",
  );
  expectEqual(
    await check({ fingerprint: "00000000" }),
    notMatched,
    "another fingerprint does not match",
  );
  expectEqual(
    await check({ fingerprint: FINGERPRINT }, { password: encode(PASSWORD) }),
    matched(),
    "a check takes the password as bytes",
  );
  expectEqual(
    await check({ address: BIP84_ADDRESS, coin: "bitcoin" }),
    matched(BIP84_PATH),
    "a Bitcoin address is found at BIP84's first path",
  );
  expectEqual(
    await check({ address: BIP84_ACCOUNT_3_CHANGE_7, coin: "bitcoin" }),
    matched("m/84'/0'/3'/1/7"),
    "the standard search finds change address 7 of account 3",
  );
  expectEqual(
    await check({ address: ETHEREUM_ADDRESS, coin: "ethereum" }),
    matched(ETHEREUM_PATH),
    "an Ethereum address is found on Ethereum's path",
  );
  expectEqual(
    await check({ address: BIP84_ADDRESS, coin: "bitcoin", path: BIP84_PATH }),
    matched(BIP84_PATH),
    "an address at its own path matches",
  );
  expectEqual(
    await check({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/0'/0'/0/1" }),
    notMatched,
    "an address at another path does not match",
  );
  expectEqual(
    await check({ address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" }, { passphrase: "TREZOR" }),
    matched(BIP84_PATH),
    "with the passphrase, the passphrase wallet's address matches",
  );
  expectEqual(
    await check({ fingerprint: FINGERPRINTS.phraseWithTrezor }, { passphrase: encode("TREZOR") }),
    matched(),
    "with the passphrase as bytes, the passphrase wallet's fingerprint matches",
  );
  expectEqual(
    await check({ fingerprint: FINGERPRINT }, { passphrase: "TREZOR" }),
    notMatched,
    "the fingerprint without the passphrase does not match a wallet with one",
  );
  expectEqual(await check({ words: 12 }), matched(), "the built-in check of 12 words matches");
  expectEqual(await check({ words: 0 }), matched(), "the length detected matches as 12 words");
}

/** The built-in check of a length stated where a shorter one passes, and of 24 words. */
export async function checkRehearsalLengths(helpers) {
  const { fullCheck, check } = helpers;
  // The length rules of recovery: a short length whose check passes takes precedence over the
  // stated one, so 15 stated words match, and the evidence names the 12 found (AUD-015-FUN001).
  expectEqual(
    await fullCheck({ words: 15 }),
    {
      outcome: "matches",
      path: null,
      evidence: {
        builtInCheck: 12,
        matchingLengths: [12],
        passed: [{ check: "builtInCheck", words: 12 }],
        walletCheck: null,
      },
    },
    "the built-in check of 15 stated words matches at the 12 found, which the evidence names",
  );
  expectEqual(
    await fullCheck({ words: 15 }, { password: WRONG_PASSWORD }),
    {
      outcome: "doesNotMatch",
      path: null,
      evidence: { builtInCheck: null, matchingLengths: [], passed: [], walletCheck: null },
    },
    "where no short check passes, as with the wrong password, the built-in check of 15 words " +
      "does not match",
  );
  await expectRejection(
    check({ words: 24 }),
    "INVALID_WORD_COUNT",
    "24 words have no built-in check",
  );
}

/** The containers of the check-word password, of the same length and of an ambiguous phrase. */
export async function checkRehearsalOtherContainers(helpers) {
  const { client, made, matched } = helpers;
  expectEqual(
    fieldsOf(
      await client.check({
        container: made.checkWord,
        password: CHECK_WORD_MISSING,
        passwordRepair: { repair: 3 },
        reference: { fingerprint: FINGERPRINT },
      }),
      ["outcome", "path"],
    ),
    matched(),
    "passwordRepair { repair: 3 } restores the password of a check",
  );
  expectEqual(
    fieldsOf(
      await client.check({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        reference: { address: BIP84_ADDRESS, coin: "bitcoin" },
      }),
      ["outcome", "path"],
    ),
    matched(BIP84_PATH),
    "a same-length container is checked against an address",
  );
  // Several lengths pass and none is stated, or a stated one does not: not verified, with every
  // length that passes; a stated length among them matches (AUD-023-FUN002).
  const onAmbiguous = (reference) =>
    client.check({ container: made.ambiguous, password: PASSWORD, reference });
  for (const words of [0, 15]) {
    expectEqual(
      await onAmbiguous({ words }),
      {
        outcome: "notVerified",
        path: null,
        evidence: {
          builtInCheck: null,
          matchingLengths: [12, 21],
          passed: [{ check: "builtInChecks", lengths: [12, 21] }],
          // With the length detected the 24-word reading comes out too, and gets the 16-bit
          // check, which this phrase, drawn without it, fails; a stated length has none.
          walletCheck: words === 0 ? false : null,
        },
      },
      `the ambiguous phrase with ${words === 0 ? "the length detected" : "15 stated words"} ` +
        "is not verified and names 12 and 21",
    );
  }
  expectEqual(
    fieldsOf(await onAmbiguous({ words: 21 }), ["outcome", "path"]),
    matched(),
    "the ambiguous phrase with 21 stated words matches",
  );
}

/** The wallet check of a 24-word phrase, and the length the page gives when none is detected. */
export async function checkRehearsalWalletCheck(helpers) {
  const { client, made, matched, notMatched, notVerified, onChecked } = helpers;
  let emptyEvidence;
  const emptyChecked = await client.check({
    container: made.emptyChecked,
    password: PASSWORD,
    reference: { words: 0 },
    onNoLength: (evidence) => {
      emptyEvidence = evidence;
      return null;
    },
  });
  const expectedEmptyEvidence = {
    builtInCheck: null,
    matchingLengths: [],
    walletCheck: true,
    passed: [{ check: "walletCheck" }],
  };
  expectEqual(
    emptyChecked,
    { outcome: "notVerified", path: null, evidence: expectedEmptyEvidence },
    "a wallet check with no passphrase stays in the unverified rehearsal's evidence",
  );
  expectEqual(
    emptyEvidence,
    expectedEmptyEvidence,
    "onNoLength receives the wallet check with no passphrase",
  );
  // A pass of the 16-bit check is a fact beside the result, not a verification of the reading.
  expectEqual(
    await client.check({
      container: made.checked,
      password: PASSWORD,
      reference: { walletCheck: true },
      passphrase: "TREZOR",
    }),
    {
      outcome: "notVerified",
      path: null,
      evidence: {
        builtInCheck: null,
        matchingLengths: [],
        passed: [{ check: "walletCheck" }],
        walletCheck: true,
      },
    },
    "the wallet check with its passphrase passes and leaves the reading not verified",
  );
  expectEqual(
    await onChecked({ walletCheck: true }, { passphrase: "trezor" }),
    notMatched,
    "the wallet check with another passphrase does not",
  );
  expectEqual(
    await onChecked(
      { fingerprint: FINGERPRINTS.checkedPhraseWithTrezor },
      { passphrase: "TREZOR" },
    ),
    matched(),
    "a 24-word phrase's passphrase wallet matches its fingerprint",
  );
  // The length detected: a 24-word reading is not verified, its 16-bit pass with the passphrase
  // a fact beside it; the page is asked for the length, with what detection found, and the
  // fingerprint it gives is compared on the same recovery.
  expectEqual(
    await onChecked({ words: 0 }, { passphrase: "TREZOR" }),
    notVerified,
    "the length detected leaves a 24-word phrase drawn with the 16-bit check not verified",
  );
  let lengthAsked = 0;
  let detected = null;
  const askedLog = progressLog();
  expectEqual(
    await onChecked(
      { words: 0 },
      {
        onProgress: askedLog.onProgress,
        onNoLength: (evidence) => {
          lengthAsked += 1;
          detected = evidence;
          return { fingerprint: FINGERPRINTS.checkedPhraseWithTrezor, passphrase: "TREZOR" };
        },
      },
    ),
    matched(),
    "with no length detected, the fingerprint the page gives matches",
  );
  expect(
    lengthAsked === 1 && askedLog.lines.filter((line) => line.startsWith("recover")).length === 12,
    "the page is asked once, and the recovery runs once",
  );
  expectEqual(
    detected,
    { builtInCheck: null, matchingLengths: [], passed: [], walletCheck: false },
    "the page is told what detection found",
  );
  expectEqual(
    await onChecked({ words: 0 }, { onNoLength: () => null }),
    notVerified,
    "without an answer the result stays",
  );
}

/** Refusals before any Argon2 round. */
export async function checkRehearsalRefusals(helpers) {
  const { client, check, onChecked } = helpers;
  const refusalLog = progressLog();
  const onProgress = refusalLog.onProgress;
  await expectRejection(
    onChecked({ walletCheck: true }, { onProgress }),
    "WALLET_CHECK_NEEDS_PASSPHRASE",
    "the wallet check without a passphrase is refused",
  );
  await expectRejection(
    client.check({
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      password: PASSWORD,
      reference: { walletCheck: true },
      passphrase: "TREZOR",
      onProgress,
    }),
    "NO_WALLET_CHECK",
    "a same-length container has no wallet check",
  );
  // The library's order, the same as through the command line: no wallet check before the
  // empty passphrase.
  await expectRejection(
    client.check({
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      password: PASSWORD,
      reference: { walletCheck: true },
      onProgress,
    }),
    "NO_WALLET_CHECK",
    "a same-length container has no wallet check, also without a passphrase",
  );
  await expectRejection(
    client.check({
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      password: PASSWORD,
      reference: { words: 12 },
      onProgress,
    }),
    "NO_BUILT_IN_CHECK",
    "a same-length container has no built-in check",
  );
  await expectRejection(
    check({ address: BIP84_ADDRESS, coin: "doge" }, { onProgress }),
    "INVALID_COIN",
    "an unknown coin is refused",
  );
  await expectRejection(
    check({ address: DAMAGED_ADDRESS, coin: "bitcoin" }, { onProgress }),
    "INVALID_ADDRESS",
    "an address whose checksum fails is refused",
  );
  await expectRejection(
    check({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/x" }, { onProgress }),
    "INVALID_DERIVATION_PATH",
    "a malformed path is refused",
  );
  await expectRejection(
    check({ fingerprint: "73c5da0" }, { onProgress }),
    "INVALID_FINGERPRINT",
    "a fingerprint of seven digits is refused",
  );
  await expectRejection(
    check({ fingerprint: FINGERPRINT }, { passwordRepair: "corrected", onProgress }),
    "PASSWORD_REPAIR_NOT_OFFERED",
    '"corrected" is refused for a password the review does not correct',
  );
  await expectRejection(
    check({ fingerprint: FINGERPRINT }, { memoryLevel: 1, onProgress }),
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    "a check at memory level 1 is refused in a browser",
  );
  expect(refusalLog.lines.length === 0, "each of these refusals came before any Argon2 round");
}

/** References of no kind, of two kinds, or with fields of another kind. */
export async function checkRehearsalReferenceTypes(helpers) {
  const { check } = helpers;
  const oneKind = "reference must be exactly one of";
  await expectTypeError(
    check({ address: BIP84_ADDRESS }),
    "reference.coin must name the coin of the address",
    "an address without its coin is refused: no coin is the default",
  );
  await expectTypeError(check(undefined), oneKind, "a check without a reference is refused");
  await expectTypeError(
    check({ fingerprint: FINGERPRINT, address: BIP84_ADDRESS }),
    oneKind,
    "a reference of two kinds is refused",
  );
  await expectTypeError(
    check({ fingerprint: FINGERPRINT, coin: "bitcoin" }),
    "reference.coin belongs only to an address reference.",
    "a coin without an address is refused",
  );
  await expectTypeError(
    check({ words: 12, path: BIP84_PATH }),
    "reference.path belongs only to an address reference.",
    "a path without an address is refused",
  );
  await expectTypeError(
    check({ walletCheck: false }),
    "reference.walletCheck must be true.",
    "walletCheck must be true",
  );
  await expectTypeError(
    check({ address: 42 }),
    "reference.address must be a string.",
    "an address that is not text is refused",
  );
}
