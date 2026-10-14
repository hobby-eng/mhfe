// The page's checks of the refusals of a rekey (page code, scripts/browser-check/harness.mjs; the
// rekey's helpers, with the requests these checks vary, are in rekey-checks.mjs).

/** A stated length that the built-in check contradicts, refused late or confirmed again. */
export async function checkRekeyLengthDiffers(helpers) {
  const { client, base, sealedWithNew } = helpers;
  // A late refusal: the built-in check finds 12 words, not the 15 stated. It takes precedence,
  // but only the wallet confirms the phrase then, so the rekey stops once the recovery's rounds
  // have found the length, before anything is sealed (AUD-015-FUN001).
  const lengthLog = progressLog();
  await expectExactRefusal(
    client.rekey({ ...base, words: 15, onProgress: lengthLog.onProgress }),
    "LENGTH_DIFFERS",
    lengthDiffers(12, 15),
    "a stated length that the built-in check contradicts needs the wallet's confirmation",
  );
  expectEqual(
    lengthLog.lines,
    roundLines("recover", 1, 12, 36),
    "it is refused after the recovery's rounds, before anything is sealed",
  );
  expectEqual(
    await client.rekey({ ...base, words: 15, confirmation: { fingerprint: FINGERPRINT } }),
    asRekeyResult(sealedWithNew),
    "the fingerprint confirms the 12-word reading the check found: what encrypt gives, every " +
      "field",
  );
  // The fingerprint given after the refusal confirms on the same recovery: the rounds of the
  // recovery run once (AUD-017-UI002). A null answer ends the rekey with the refusal.
  const againLog = progressLog();
  const againAsked = [];
  expectEqual(
    await client.rekey({
      ...base,
      words: 15,
      onProgress: againLog.onProgress,
      onConfirmAgain: ({ error, ownerLengths }) => {
        againAsked.push([error.code, error.message, ownerLengths]);
        return { fingerprint: FINGERPRINT };
      },
    }),
    asRekeyResult(sealedWithNew),
    "after LENGTH_DIFFERS the fingerprint confirms on the same recovery: what encrypt gives, " +
      "every field",
  );
  expectEqual(
    againAsked,
    [["LENGTH_DIFFERS", lengthDiffers(12, 15), [15]]],
    "the page was given the refusal and the stated length for the owner",
  );
  expectEqual(
    againLog.lines,
    [
      ...roundLines("recover", 1, 12, 36),
      "compare 12/36",
      ...roundLines("encrypt", 13, 24, 36),
      ...roundLines("check", 25, 36, 36),
    ],
    "the recovery's rounds ran once",
  );
  await expectExactRefusal(
    client.rekey({ ...base, words: 15, onConfirmAgain: () => null }),
    "LENGTH_DIFFERS",
    lengthDiffers(12, 15),
    "a page that gives no other confirmation ends the rekey with the refusal",
  );
}

/** Refusals of the new password, the length and the memory level before any Argon2 round. */
export async function checkRekeyEarlyRefusals(helpers) {
  const { client, base, sameBase } = helpers;
  // Early refusals, before any Argon2 round.
  const refusalLog = progressLog();
  await expectRejection(
    client.rekey({
      ...base,
      newPassword: PASSWORD,
      newPasswordRepeat: PASSWORD,
      onProgress: refusalLog.onProgress,
    }),
    "NEW_PASSWORD_SAME_AS_OLD",
    "the old password and settings are refused as the new ones",
  );
  await expectExactRefusal(
    client.rekey({ ...base, words: 24, onProgress: refusalLog.onProgress }),
    "REFERENCE_REQUIRED",
    REFERENCE_REQUIRED,
    "a 24-word phrase has no built-in check to confirm it",
  );
  await expectRejection(
    client.rekey({
      ...sameBase,
      words: 15,
      confirmation: { fingerprint: FINGERPRINT },
      onProgress: refusalLog.onProgress,
    }),
    "LENGTH_CHOICE_NOT_APPLICABLE",
    "a same-length container refuses another word count",
  );
  await expectRejection(
    client.rekey({ ...base, memoryLevel: 1, onProgress: refusalLog.onProgress }),
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    "an old memory level 1 is refused in a browser",
  );
  expect(refusalLog.lines.length === 0, "these refusals came before any Argon2 round");
}

/** Lengths the built-in check cannot confirm, and a rekey without the passphrase's answer. */
export async function checkRekeyAnswerRefusals(helpers) {
  const { base, ownerBase, sameBase, expectEarlyRefusal, expectPassphraseRefusal } = helpers;
  // A length without a built-in check refuses that check first, before the answer is judged:
  // without the answer, it is still REFERENCE_REQUIRED. So does the length detected on a 24-word
  // container, where a 24-word original may pass a short check by chance (AUD-017-FUN001).
  for (const { options, description } of [
    { options: { ...base, words: 24 }, description: "a 24-word phrase" },
    {
      options: { ...sameBase, confirmation: { builtInCheck: true } },
      description: "a same-length container",
    },
    { options: { ...base, words: 0 }, description: "the length detected" },
  ]) {
    for (const walletHasPassphrase of [undefined, false, true]) {
      await expectEarlyRefusal(
        { ...options, walletHasPassphrase },
        "REFERENCE_REQUIRED",
        REFERENCE_REQUIRED,
        `${description} refuses the built-in check with the answer ${walletHasPassphrase}`,
      );
    }
  }
  await expectPassphraseRefusal(
    { ...base, walletHasPassphrase: undefined },
    PASSPHRASE_UNSTATED,
    "the built-in check shows nothing of a passphrase: a rekey without the answer is refused",
  );
  let ownerAskedUnstated = false;
  await expectPassphraseRefusal(
    {
      ...ownerBase,
      walletHasPassphrase: undefined,
      confirmation: {
        owner: () => {
          ownerAskedUnstated = true;
          return true;
        },
      },
    },
    PASSPHRASE_UNSTATED,
    "nor does the owner's comparison: an owner's rekey without the answer is refused",
  );
  expect(!ownerAskedUnstated, "the owner was not asked: the refusal came before the recovery");
}

/** References whose passphrase shows nothing or contradicts the answer, and passphrases refused. */
export async function checkRekeyPassphraseRefusals(helpers) {
  const { client, base, ownerBase, sameBase, expectPassphraseRefusal } = helpers;
  // A reference with an empty passphrase matches the phrase's wallet without one, as it does
  // here, and proves nothing about funds under a passphrase: without the answer it is refused.
  for (const { confirmation, description } of [
    { confirmation: { fingerprint: FINGERPRINT }, description: "a fingerprint" },
    { confirmation: { address: BIP84_ADDRESS, coin: "bitcoin" }, description: "an address" },
  ]) {
    for (const passphrase of [undefined, "", encode("")]) {
      await expectPassphraseRefusal(
        { ...sameBase, confirmation, passphrase, walletHasPassphrase: undefined },
        PASSPHRASE_UNSTATED,
        `${description} with ${passphrase === undefined ? "no" : "an empty"} passphrase` +
          `${passphrase instanceof Uint8Array ? " as bytes" : ""} shows nothing: a rekey ` +
          "without the answer is refused",
      );
    }
  }
  for (const [confirmation, passphrase, description] of [
    [
      { fingerprint: FINGERPRINTS.phraseWithTrezor },
      "TREZOR",
      "a fingerprint with a passphrase, stated to be of a wallet without one, is refused",
    ],
    [
      { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
      encode("TREZOR"),
      "an address with a passphrase as bytes, stated to be of a wallet without one, is refused",
    ],
  ]) {
    await expectPassphraseRefusal(
      { ...sameBase, confirmation, passphrase, walletHasPassphrase: false },
      PASSPHRASE_CONTRADICTED,
      description,
    );
  }
  // A passphrase belongs only to an address or a fingerprint: with the built-in check or the
  // owner, the client refuses it, and the owner is not asked.
  let ownerAskedWithPassphrase = false;
  for (const { options, description } of [
    { options: base, description: "the built-in check" },
    {
      options: {
        ...ownerBase,
        confirmation: {
          owner: () => {
            ownerAskedWithPassphrase = true;
            return true;
          },
        },
      },
      description: "the owner",
    },
  ]) {
    for (const passphrase of ["TREZOR", encode("TREZOR")]) {
      await expectExactTypeError(
        client.rekey({ ...options, passphrase, walletHasPassphrase: true }),
        REKEY_PASSPHRASE_ONLY_WITH_REFERENCE,
        `a passphrase${typeof passphrase === "string" ? "" : " as bytes"} with ${description} ` +
          "is refused",
      );
    }
  }
  expect(!ownerAskedWithPassphrase, "the owner was not asked with a passphrase given");
}

/** Answers that are not booleans, and confirmations of no kind, two kinds or another kind. */
export async function checkRekeyConfirmationTypes(helpers) {
  const { client, base, sameBase } = helpers;
  // The answer may be left out of a rekey, but one given is a boolean: null is not.
  for (const walletHasPassphrase of ["no", 1, 0, {}, null]) {
    await expectExactTypeError(
      client.rekey({ ...base, walletHasPassphrase }),
      WALLET_PASSPHRASE_REQUIRED,
      `a walletHasPassphrase of ${JSON.stringify(walletHasPassphrase)}, not a boolean, is ` +
        "refused in a rekey too",
    );
  }
  await expectRejection(
    client.rekey({ ...base, newPasswordRepeat: "another public test passwore" }),
    "PASSWORDS_DIFFER",
    "a new password whose repetition differs is refused",
  );
  await expectRejection(
    client.rekey({ ...base, newMemoryLevel: 1 }),
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    "a new memory level 1 is refused in a browser",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { walletCheck: true } }),
    "not by the wallet check",
    "the wallet check never confirms a rekey",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { words: 12 } }),
    "not by a word count",
    "a word count does not confirm a rekey",
  );
  const builtInCheckAlone = "confirmation must be exactly one kind; builtInCheck must be true.";
  await expectTypeError(
    client.rekey({ ...base, confirmation: { owner: () => true, builtInCheck: true } }),
    builtInCheckAlone,
    "an owner callback together with another kind is refused",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { builtInCheck: true, fingerprint: FINGERPRINT } }),
    builtInCheckAlone,
    "the built-in check together with a fingerprint is refused",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { owner: () => true, fingerprint: FINGERPRINT } }),
    "confirmation must be exactly one kind; owner must be a function.",
    "an owner callback together with a fingerprint is refused",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: undefined }),
    "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
      "{ fingerprint } or { owner }.",
    "a rekey without a confirmation is refused, naming what a rekey takes",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { coin: "bitcoin" } }),
    "confirmation must be one of { builtInCheck: true }",
    "a confirmation of no kind is refused, naming what a rekey takes",
  );
  await expectTypeError(
    client.rekey({ ...base, confirmation: { builtInCheck: false } }),
    builtInCheckAlone,
    "builtInCheck must be true",
  );
  await expectTypeError(
    client.rekey({ ...sameBase, confirmation: { fingerprint: FINGERPRINT, path: BIP84_PATH } }),
    "confirmation.path belongs only to an address confirmation.",
    "a path without an address is refused in a confirmation",
  );
}

/** The new settings as the seal uses them, and the old PIM in the recovery. */
export async function checkRekeyNewSettings(helpers) {
  const { client, base } = helpers;
  // The new settings are judged as the seal uses them: the old password with PIM 1 is a new
  // container, and the seal, not the recovery, asks Argon2 for PIM 1's cost.
  const newPimLog = progressLog();
  const newPimError = await rejectionOf(
    client.rekey({
      ...base,
      newPassword: PASSWORD,
      newPasswordRepeat: PASSWORD,
      newPim: 1,
      onProgress: newPimLog.onProgress,
    }),
  );
  expect(
    newPimError?.code === "ARGON2_FAILED" &&
      newPimError.message.includes(PIM_1_COST) &&
      newPimLog.lines.at(-1) === "encrypt 13/36",
    "newPim 1 with the old password is accepted, and the seal asks for 24 passes",
  );
  const oldPimLog = progressLog();
  const oldPimError = await rejectionOf(
    client.rekey({ ...base, pim: 1, onProgress: oldPimLog.onProgress }),
  );
  expect(
    oldPimError?.code === "ARGON2_FAILED" &&
      oldPimError.message.includes(PIM_1_COST) &&
      sameValue(oldPimLog.lines, ["recover 1/36"]),
    "the old PIM 1 makes the recovery ask for 24 passes",
  );
}
