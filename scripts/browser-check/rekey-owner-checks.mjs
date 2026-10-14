// The page's checks of a rekey that the owner confirms by comparing the recovered phrase with the
// backup (page code, scripts/browser-check/harness.mjs; the rekey's helpers are in
// rekey-checks.mjs).

/** The owner's yes, from a promise, of a 24-word phrase, and of a wallet with a passphrase. */
export async function checkRekeyOwner(helpers) {
  const { client, ownerBase, sealWithNew } = helpers;
  let ownerSaw = null;
  const ownerSealed = await client.rekey({
    ...ownerBase,
    confirmation: {
      owner: async (check) => {
        ownerSaw = check;
        return true;
      },
    },
  });
  expectEqual(
    ownerSaw,
    {
      phrase: CHECKED_PHRASE,
      words: 24,
      fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
      rehearsalNeedsPassphrase: false,
    },
    "the owner is shown the recovered phrase and its fingerprint",
  );
  expectEqual(
    fieldsOf(ownerSealed, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
    { suiteId: SUITE_3, builtInCheck: false, otherLengths: [], keep: KEEP_24 },
    "the owner's yes, from a promise, seals the 24-word phrase",
  );
  // CHECKED_PHRASE fails the 16-bit wallet check without its passphrase "TREZOR", as
  // page-values.mjs checks before the page runs.
  expectEqual(
    ownerSealed,
    asRekeyResult(await sealWithNew(CHECKED_PHRASE), false, {
      kind: "fingerprint",
      fingerprint: FINGERPRINTS.checkedPhrase,
    }),
    "the container the owner confirmed is what encrypt gives with the new password, with the " +
      "24-word reading's wallet check, every field",
  );
  const ownerRecovery = await client.decrypt({
    container: ownerSealed.container,
    password: NEW_PASSWORD,
  });
  expect(
    ownerRecovery.candidates[0].phrase === CHECKED_PHRASE,
    "the container the owner confirmed opens with the new password",
  );
  // A wallet with a passphrase: the owner's yes brings it, for the fingerprint the new
  // container's rehearsal compares, which is known before the seal (AUD-023-ARC010).
  let needsPassphrase = null;
  const ownerWithPassphrase = await client.rekey({
    ...ownerBase,
    walletHasPassphrase: true,
    confirmation: {
      owner: (check) => {
        needsPassphrase = check.rehearsalNeedsPassphrase;
        return { passphrase: "TREZOR" };
      },
    },
  });
  expectEqual(
    fieldsOf(ownerWithPassphrase, ["container", "keep", "rehearsal"]),
    {
      container: ownerSealed.container,
      keep: [...KEEP_24, PASSPHRASE],
      rehearsal: { kind: "fingerprint", fingerprint: FINGERPRINTS.checkedPhraseWithTrezor },
    },
    "the owner's rekey stated to have a passphrase keeps it, and its rehearsal compares the " +
      "fingerprint with it; the container is the same",
  );
  expect(needsPassphrase === true, "the owner is told that the rehearsal needs the passphrase");
  await expectRejection(
    client.rekey({
      ...ownerBase,
      walletHasPassphrase: true,
      confirmation: { owner: () => true },
    }),
    "INVALID_REQUEST",
    "a yes without the passphrase the rehearsal needs stops the rekey before the seal",
  );
}

/** The owner's no, a stated length beside the reading found, and anything but true. */
export async function checkRekeyOwnerLengths(helpers) {
  const { client, base, ownerBase, sealedWithNew } = helpers;
  // A stated short length that the check contradicts: the owner may confirm the reading the
  // check found, and is shown the length stated beside it, which the page names first.
  const ownerNo = [];
  await expectRejection(
    client.rekey({
      ...base,
      words: 15,
      confirmation: {
        owner: (check) => {
          ownerNo.push(check);
          return false;
        },
      },
    }),
    "NOT_CONFIRMED_BY_OWNER",
    "the owner's no stops a rekey",
  );
  expectEqual(
    ownerNo,
    [
      {
        phrase: PHRASE,
        words: 12,
        statedWords: 15,
        fingerprintWithoutPassphrase: FINGERPRINT,
        rehearsalNeedsPassphrase: false,
      },
    ],
    "the owner of 15 stated words saw the 12-word reading the check found, with the 15 stated",
  );
  // 24 words stated beside a 12-word reading whose check passes: the owner cannot tell the two
  // readings apart, so the library refuses once the recovery has found them, before the owner
  // is asked, even an owner with a yes ready; an address or the fingerprint confirms one
  // (AUD-015-FUN001, AUD-016-BLD002).
  const ownerOf24 = [];
  const ownerOf24Log = progressLog();
  await expectExactRefusal(
    client.rekey({
      ...base,
      words: 24,
      onProgress: ownerOf24Log.onProgress,
      confirmation: {
        owner: (check) => {
          ownerOf24.push(check);
          return true;
        },
      },
    }),
    "LENGTH_DIFFERS",
    lengthDiffers(12, 24),
    "24 words stated beside a 12-word reading whose check passes cannot reach the owner",
  );
  expectEqual(ownerOf24, [], "the owner was not asked");
  expectEqual(
    ownerOf24Log.lines,
    roundLines("recover", 1, 12, 36),
    "it is refused after the recovery's rounds, before anything is sealed",
  );
  expectEqual(
    await client.rekey({ ...base, words: 24, confirmation: { fingerprint: FINGERPRINT } }),
    asRekeyResult(sealedWithNew),
    "the fingerprint confirms the 12-word reading beside 24 stated words: what encrypt gives, " +
      "every field",
  );
  await expectRejection(
    client.rekey({ ...ownerBase, confirmation: { owner: () => "yes" } }),
    "NOT_CONFIRMED_BY_OWNER",
    "anything but true from the owner stops a rekey",
  );
}

/** An owner callback that throws, a cancel while the owner is asked, and onUnverified. */
export async function checkRekeyOwnerCallbacks(helpers) {
  const { client, base, ownerBase } = helpers;
  const ownerError = new Error("synthetic owner error");
  await expectRejection(
    client.rekey({
      ...ownerBase,
      confirmation: {
        owner: () => {
          throw ownerError;
        },
      },
    }),
    "CALLBACK_FAILED",
    "an owner callback that throws stops a rekey",
    ownerError,
  );
  // An MhfeError of another call, here the BUSY of a recovery started while the rekey holds the
  // slot, must not pass for the rekey's own error.
  let busy = null;
  const ownerBusy = await rejectionOf(
    client.rekey({
      ...ownerBase,
      confirmation: {
        owner: async () => {
          busy = await rejectionOf(
            client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }),
          );
          throw busy;
        },
      },
    }),
  );
  expect(
    busy?.code === "BUSY" && ownerBusy?.code === "CALLBACK_FAILED" && ownerBusy.cause === busy,
    `an MhfeError thrown by the owner ends the rekey with CALLBACK_FAILED, it as the cause -> ${ownerBusy?.code}`,
  );
  let ownerAsked;
  let answerOwner;
  const asked = new Promise((resolve) => {
    ownerAsked = resolve;
  });
  const awaitingOwner = client.rekey({
    ...ownerBase,
    confirmation: {
      owner: () => {
        ownerAsked();
        return new Promise((resolve) => {
          answerOwner = resolve;
        });
      },
    },
  });
  await asked;
  client.cancel();
  expect(
    (await rejectionOf(awaitingOwner)) instanceof MhfeCancelledError,
    "client.cancel() while a rekey awaits the owner's answer stops it",
  );
  answerOwner(true);
  expect(
    (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD })).candidates[0]
      .verified,
    "the owner's late yes goes nowhere, and the slot is free",
  );
  const unverifiedError = new Error("synthetic page error");
  const unverifiedLog = progressLog();
  await expectRejection(
    client.rekey({
      ...base,
      onProgress: unverifiedLog.onProgress,
      onUnverified: () => {
        throw unverifiedError;
      },
    }),
    "CALLBACK_FAILED",
    "a throwing onUnverified stops a rekey",
    unverifiedError,
  );
  expect(
    unverifiedLog.lines.at(-1) === "encrypt 24/36",
    "it stops where the new container is shown, before its check",
  );
}
