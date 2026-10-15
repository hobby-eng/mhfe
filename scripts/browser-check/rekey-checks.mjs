// The page's checks of MhfeClient.rekey (page code, scripts/browser-check/harness.mjs): what a
// rekey gives, its confirmation by the built-in check, the fingerprint or the owner of a length
// found or detected, and its passwords. The owner's confirmations are in rekey-owner-checks.mjs,
// those of a same-length container in rekey-same-length-checks.mjs, and the refusals in
// rekey-refusal-checks.mjs.

/** MhfeClient.rekey: its rounds and results, its confirmations, and its refusals. */
export async function checkRekey(client, repair, wallet, made) {
  group("MhfeClient.rekey");
  await checkKeepingOldContainer(client);
  const helpers = await rekeyHelpers(client, made);
  await checkRekeyResult(helpers, wallet);
  await checkRekeyDetectedLength(helpers);
  await checkRekeyAmbiguousLength(helpers);
  await checkRekeyPasswords(helpers, repair);
  await checkRekeyOwner(helpers);
  await checkRekeyOwnerLengths(helpers);
  await checkRekeyOwnerCallbacks(helpers);
  const sameLength = await checkRekeySameLength(helpers);
  await checkRekeySameLengthPassphrase(helpers, sameLength);
  await checkRekeySameLengthAddresses(helpers, sameLength);
  await checkRekeySameLengthOwner(helpers, sameLength);
  await checkRekeyLengthDiffers(helpers);
  await checkRekeyEarlyRefusals(helpers);
  await checkRekeyAnswerRefusals(helpers);
  await checkRekeyPassphraseRefusals(helpers);
  await checkRekeyConfirmationTypes(helpers);
  await checkRekeyNewSettings(helpers);
}

/** keepOldContainer lists the exact old-backup settings, even above the browser's memory limit. */
export async function checkKeepingOldContainer(client) {
  for (const { options, expected } of KEEP_OLD_CASES) {
    expectEqual(
      await client.keepOldContainer(options),
      expected,
      `keepOldContainer preserves the old backup with settings ${JSON.stringify(options ?? {})}`,
    );
  }
  await expectRejection(
    client.keepOldContainer({ pim: 1024 }),
    "INVALID_PIM",
    "keepOldContainer refuses an invalid PIM",
    undefined,
    "The PIM must be a whole number from 0 to 1023, not 1024",
  );
}

/** What checkRekey's steps share: the requests they vary, encrypt's result, early refusals. */
export async function rekeyHelpers(client, made) {
  const base = {
    container: REDUCED_COST_CONTAINER,
    words: 12,
    password: PASSWORD,
    newPassword: NEW_PASSWORD,
    newPasswordRepeat: NEW_PASSWORD,
    confirmation: { builtInCheck: true },
    walletHasPassphrase: false,
  };
  // A rekey must give what encrypt gives for the same phrase with the new password.
  const sealWithNew = (phrase, options = {}) =>
    client.encrypt({
      phrase,
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
      walletHasPassphrase: false,
      ...options,
    });
  const sealedWithNew = await sealWithNew(PHRASE);
  const ownerBase = {
    ...base,
    container: made.checked,
    words: 24,
  };
  // A same-length container has no built-in check: the wallet confirms its phrase. A reference
  // with an empty passphrase matches the phrase's wallet without one and proves nothing about
  // funds under a passphrase, so these rekeys keep base's answer, false, unless they say other.
  const sameBase = {
    ...base,
    container: REDUCED_COST_SAME_LENGTH_CONTAINER,
    words: undefined,
  };
  /** A refusal with `code` and exactly `message`, which must come before any Argon2 round. */
  const expectEarlyRefusal = async (options, code, message, description) => {
    const rounds = progressLog();
    await expectExactRefusal(
      client.rekey({ ...options, onProgress: rounds.onProgress }),
      code,
      message,
      description,
    );
    expect(rounds.lines.length === 0, `${description}: before any Argon2 round`);
  };
  /** A refusal of the passphrase's answer. */
  const expectPassphraseRefusal = (options, message, description) =>
    expectEarlyRefusal(options, "INVALID_REQUEST", message, description);
  return {
    client,
    made,
    base,
    ownerBase,
    sameBase,
    sealWithNew,
    sealedWithNew,
    expectEarlyRefusal,
    expectPassphraseRefusal,
  };
}

/**
 * What a rekey resolves to: what encrypt gives for the confirmed phrase, with `walletCheck`,
 * the 16-bit wallet check of a recovered 24-word reading with the reference's passphrase or
 * none, null for every other length, and `rehearsal`, what the new container is rehearsed
 * with: the built-in check of a short phrase unless said otherwise (AUD-023-ARC010).
 */
export function asRekeyResult(sealed, walletCheck = null, rehearsal = { kind: "builtInCheck" }) {
  return { ...sealed, walletCheck, rehearsal };
}

/** The library's refusal of a stated length the built-in check contradicts (src/error.rs). */
export function lengthDiffers(found, stated) {
  return (
    `The built-in check finds a ${found}-word original seed phrase, not the ${stated} words ` +
    "stated: confirm it with a receiving address or the master key fingerprint of the wallet"
  );
}

/** The rounds, the callbacks and the result of a rekey confirmed by the built-in check. */
export async function checkRekeyResult(helpers, wallet) {
  const { client, base, sealedWithNew } = helpers;
  const log = progressLog();
  const shown = [];
  const rekeyed = await client.rekey({
    ...base,
    onProgress: log.onProgress,
    onUnverified: (result) => {
      log.lines.push("unverified");
      shown.push(result);
    },
  });
  expectEqual(
    log.lines,
    rekeyLines([], ["unverified"]),
    "a rekey reports 36 rounds: recover, encrypt, the unverified container, check",
  );
  expectEqual(
    shown,
    [
      {
        container: sealedWithNew.container,
        containerFingerprint: sealedWithNew.containerFingerprint,
      },
    ],
    "onUnverified receives the new container and its fingerprint",
  );
  expectEqual(
    rekeyed,
    asRekeyResult(sealedWithNew),
    "a rekey resolves to what encrypt gives with the new password, every field, and no wallet " +
      "check for 12 words",
  );
  expect(
    rekeyed.containerFingerprint === (await wallet.fingerprint({ phrase: rekeyed.container })),
    "the new container's fingerprint is the wallet module's",
  );
  expectEqual(
    fieldsOf(rekeyed, [
      "suiteId",
      "builtInCheck",
      "otherLengths",
      "repairWords",
      "repairProfile",
      "keep",
    ]),
    {
      suiteId: SUITE_3,
      builtInCheck: true,
      otherLengths: [],
      repairWords: null,
      repairProfile: null,
      keep: KEEP_24,
    },
    "a rekey resolves as encrypt does, with every field",
  );
  const afterRekey = await client.decrypt({
    container: rekeyed.container,
    password: NEW_PASSWORD,
  });
  expect(
    afterRekey.candidates[0].phrase === PHRASE && afterRekey.candidates[0].verified,
    "a rekey seals the phrase with the new password",
  );
  expect(
    (await client.rekey({ ...base, newPasswordRepeat: encode(NEW_PASSWORD) })).container ===
      sealedWithNew.container,
    "a new password as text and its repetition as the same bytes are the same password",
  );
}

/** The length detected, confirmed by the fingerprint or the owner, and two lengths that pass. */
export async function checkRekeyDetectedLength(helpers) {
  const { client, made, base, sealWithNew, sealedWithNew } = helpers;
  // The length detected: a 24-word original may pass a short check by chance, so the built-in
  // check alone confirms no detected length (REFERENCE_REQUIRED before any round, in
  // checkRekeyAnswerRefusals). The fingerprint, an address or the owner does, and a reference is
  // compared with every reading (AUD-017-FUN001).
  expectEqual(
    await client.rekey({ ...base, words: 0, confirmation: { fingerprint: FINGERPRINT } }),
    asRekeyResult(sealedWithNew),
    "a rekey with the length detected, confirmed by the fingerprint, seals the 12-word phrase: " +
      "what encrypt gives, every field",
  );
  let detectedOwnerSaw = null;
  const byDetectedOwner = await client.rekey({
    ...base,
    words: 0,
    confirmation: {
      owner: (check) => {
        detectedOwnerSaw = check;
        return true;
      },
    },
  });
  expectEqual(
    detectedOwnerSaw,
    {
      phrase: PHRASE,
      words: 12,
      fingerprintWithoutPassphrase: FINGERPRINT,
      rehearsalNeedsPassphrase: false,
    },
    "with the length detected the owner is shown the 12 words found, and no length stated",
  );
  expect(
    byDetectedOwner.container === sealedWithNew.container,
    "the owner's yes confirms the length detected",
  );
  expectEqual(
    await client.rekey({
      ...base,
      container: made.ambiguous,
      words: 0,
      confirmation: { fingerprint: FINGERPRINTS.ambiguous12Words },
    }),
    asRekeyResult(await sealWithNew(AMBIGUOUS_12_WORDS)),
    "a detection that finds two lengths is told apart by the fingerprint, compared with each " +
      "reading: what encrypt gives the 12 words, every field",
  );
  await expectRejection(
    client.rekey({ ...base, container: made.ambiguous, words: 12 }),
    "AMBIGUOUS_LENGTH",
    "a length stated among two that pass does not let the built-in check alone confirm a rekey",
  );
}

/** After AMBIGUOUS_LENGTH, the owner confirms a length on the same recovery. */
export async function checkRekeyAmbiguousLength(helpers) {
  const { client, made, base, sealWithNew } = helpers;
  // On the same recovery (AUD-017-UI002): the page is given the lengths the owner can tell
  // apart, the owner states one and compares its reading.
  const ambiguousAsked = [];
  let ambiguousShown = null;
  expectEqual(
    await client.rekey({
      ...base,
      container: made.ambiguous,
      words: 12,
      onConfirmAgain: ({ error, ownerLengths }) => {
        ambiguousAsked.push([error.code, ownerLengths]);
        return {
          owner: (check) => {
            ambiguousShown = check;
            return true;
          },
          words: 12,
        };
      },
    }),
    asRekeyResult(await sealWithNew(AMBIGUOUS_12_WORDS)),
    "after AMBIGUOUS_LENGTH the owner confirms the 12-word reading on the same recovery: what " +
      "encrypt gives, every field",
  );
  expectEqual(
    [ambiguousAsked, ambiguousShown],
    [
      [["AMBIGUOUS_LENGTH", [12, 21]]],
      {
        phrase: AMBIGUOUS_12_WORDS,
        words: 12,
        fingerprintWithoutPassphrase: FINGERPRINTS.ambiguous12Words,
        rehearsalNeedsPassphrase: false,
      },
    ],
    "the page was given both lengths, and the owner was shown the reading of the one stated",
  );
}

/** The new password's repetition and repair, the old password's repair, and a passphrase. */
export async function checkRekeyPasswords(helpers, repair) {
  const { client, made, base, sealWithNew } = helpers;
  await expectRejection(
    client.rekey({
      ...base,
      newPassword: encode(NEW_PASSWORD),
      newPasswordRepeat: "another public test passwore",
    }),
    "PASSWORDS_DIFFER",
    "a new password as bytes and a repetition as other text differ",
  );

  const toCheckWord = await client.rekey({
    ...base,
    newPassword: CHECK_WORD_MISSING,
    newPasswordRepeat: CHECK_WORD_MISSING,
    newPasswordRepair: { repair: 3 },
    repairWordCount: 4,
  });
  const card = await repair.repairWords({ container: toCheckWord.container, count: 4 });
  expect(
    toCheckWord.container === made.checkWord,
    "newPasswordRepair restores the new password: the container its encryption gives",
  );
  expectEqual(
    fieldsOf(toCheckWord, ["repairWords", "repairProfile", "keep"]),
    {
      repairWords: card.words,
      repairProfile: REPAIR_PROFILE,
      keep: [...KEEP_24, { item: "repairWords", apart: true }],
    },
    "a rekey with repairWordCount 4 gives the repair module's card",
  );
  const back = await client.rekey({
    ...base,
    container: made.checkWord,
    password: CHECK_WORD_MISSING,
    passwordRepair: { repair: 3 },
    newPassword: PASSWORD,
    newPasswordRepeat: PASSWORD,
  });
  expect(
    back.container === REDUCED_COST_CONTAINER,
    "passwordRepair restores the old password: rekeyed back, the native container again",
  );
  // The built-in check shows nothing of a BIP39 passphrase, so the page states it; a wallet that
  // has one keeps it after the password, before the repair words.
  const withPassphrase = await client.rekey({
    ...base,
    walletHasPassphrase: true,
    repairWordCount: 2,
  });
  expectEqual(
    withPassphrase.keep,
    [...KEEP_24, PASSPHRASE, { item: "repairWords", apart: true }],
    "a rekey stated to have a passphrase keeps it after the password, before the repair words",
  );
  expectEqual(
    withPassphrase,
    asRekeyResult(await sealWithNew(PHRASE, { walletHasPassphrase: true, repairWordCount: 2 })),
    "it is what encrypt gives with the same answer and repair words, every field",
  );
}
