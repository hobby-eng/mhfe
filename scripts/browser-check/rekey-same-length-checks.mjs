// The page's checks of a rekey of a same-length container, which has no built-in check: the wallet
// or the owner confirms its phrase (page code, scripts/browser-check/harness.mjs; the rekey's
// helpers, with the requests these checks vary, are in rekey-checks.mjs).

/** A same-length rekey confirmed by the fingerprint or an address of the wallet without one. */
export async function checkRekeySameLength(helpers) {
  const { client, sameBase, sealWithNew } = helpers;
  const sameSealed = await sealWithNew(PHRASE, { sameLength: true });
  const sameSealedWithPassphrase = await sealWithNew(PHRASE, {
    sameLength: true,
    walletHasPassphrase: true,
  });
  const sameRekey = await client.rekey({
    ...sameBase,
    confirmation: { fingerprint: FINGERPRINT },
  });
  expectEqual(
    fieldsOf(sameRekey, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
    {
      suiteId: SUITE_4,
      builtInCheck: false,
      otherLengths: [],
      keep: KEEP_SAME_LENGTH,
    },
    "a same-length rekey confirmed by the fingerprint, stated without a passphrase, seals a " +
      "same-length container and keeps no passphrase",
  );
  expectEqual(
    sameRekey,
    asRekeyResult(sameSealed, null, { kind: "confirmingReference" }),
    "it is what encrypt with sameLength gives with the new password, every field, and no " +
      "wallet check",
  );
  const sameRecovery = await client.decrypt({
    container: sameRekey.container,
    password: NEW_PASSWORD,
  });
  expect(
    sameRecovery.candidates[0].phrase === PHRASE &&
      sameRecovery.candidates[0].status === "noBuiltInCheck",
    "the rekeyed same-length container opens with the new password",
  );
  const sameContainer = (result) => result.container === sameSealed.container;
  expect(
    sameContainer(
      await client.rekey({ ...sameBase, words: 12, confirmation: { fingerprint: FINGERPRINT } }),
    ),
    "a same-length container takes its own length, 12, as the word count",
  );
  const addressLog = progressLog();
  const byAddress = await client.rekey({
    ...sameBase,
    confirmation: { address: BIP84_ADDRESS, coin: "bitcoin" },
    onProgress: addressLog.onProgress,
  });
  expect(
    sameContainer(byAddress) && sameValue(byAddress.keep, KEEP_SAME_LENGTH),
    "a rekey confirmed by a Bitcoin address without a passphrase, stated without one, gives " +
      "the same container and keeps no passphrase",
  );
  expectEqual(
    addressLog.lines,
    rekeyLines(["compare 12/36"], []),
    "a rekey confirmed by the wallet compares once after the recovery",
  );
  const byEthereum = await client.rekey({
    ...sameBase,
    confirmation: { address: ETHEREUM_ADDRESS, coin: "ethereum", path: ETHEREUM_PATH },
  });
  expect(
    sameContainer(byEthereum),
    "a rekey confirmed by an Ethereum address at its path gives the same container",
  );
  return { sameSealedWithPassphrase, sameContainer };
}

/** A wallet stated to have a passphrase, and a reference compared with one. */
export async function checkRekeySameLengthPassphrase(helpers, sameLength) {
  const { client, sameBase } = helpers;
  const { sameSealedWithPassphrase, sameContainer } = sameLength;
  // A wallet stated to have a passphrase is compared with it: a reference without it would
  // match the phrase's wallet without one and say nothing about the funds under the passphrase
  // (the specification's re-encryption rules), so it is refused before any round.
  for (const { confirmation, description } of REFERENCES_WITHOUT_PASSPHRASE) {
    for (const passphrase of [undefined, ""]) {
      await expectRejection(
        client.rekey({ ...sameBase, confirmation, passphrase, walletHasPassphrase: true }),
        "INVALID_REQUEST",
        `${description} with ${passphrase === undefined ? "no" : "an empty"} passphrase, ` +
          "stated to be of a wallet with one, is refused",
      );
    }
  }
  // Only a reference compared with a non-empty passphrase shows that the wallet has one: the
  // answer may be left out.
  const byPassphrase = await client.rekey({
    ...sameBase,
    confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
    passphrase: "TREZOR",
    walletHasPassphrase: undefined,
  });
  expect(
    sameContainer(byPassphrase),
    "a rekey confirmed by the passphrase wallet's fingerprint, with the passphrase, as well",
  );
  // The reference's passphrase shows that the wallet has one, stated or not.
  expectEqual(
    byPassphrase.keep,
    [...KEEP_SAME_LENGTH, PASSPHRASE],
    "the fingerprint's passphrase, unstated, puts the passphrase in what to keep",
  );
  expectEqual(
    await client.rekey({
      ...sameBase,
      confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
      passphrase: "TREZOR",
      walletHasPassphrase: true,
    }),
    // A same-length container has no built-in check: the fingerprint that confirmed it
    // rehearses the new one too.
    asRekeyResult(sameSealedWithPassphrase, null, { kind: "confirmingReference" }),
    "the fingerprint's passphrase, stated as well, gives what encrypt gives with it, every field",
  );
}

/** The passphrase wallet's address, and passwords, repetition and passphrase as bytes. */
export async function checkRekeySameLengthAddresses(helpers, sameLength) {
  const { client, sameBase } = helpers;
  const { sameContainer } = sameLength;
  const byTrezorAddress = await client.rekey({
    ...sameBase,
    confirmation: { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
    passphrase: "TREZOR",
    walletHasPassphrase: undefined,
  });
  expect(
    sameContainer(byTrezorAddress),
    "a rekey confirmed by the passphrase wallet's address, with the passphrase, as well",
  );
  expectEqual(
    byTrezorAddress.keep,
    [...KEEP_SAME_LENGTH, PASSPHRASE],
    "the address's passphrase, unstated, puts the passphrase in what to keep",
  );
  expectEqual(
    fieldsOf(
      await client.rekey({
        ...sameBase,
        confirmation: { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
        passphrase: "TREZOR",
        walletHasPassphrase: true,
      }),
      ["container", "keep"],
    ),
    { container: byTrezorAddress.container, keep: [...KEEP_SAME_LENGTH, PASSPHRASE] },
    "the address's passphrase, stated as well, keeps it",
  );
  const fromBytes = await client.rekey({
    ...sameBase,
    password: encode(PASSWORD),
    newPassword: encode(NEW_PASSWORD),
    newPasswordRepeat: encode(NEW_PASSWORD),
    confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
    passphrase: encode("TREZOR"),
    walletHasPassphrase: undefined,
  });
  expect(
    sameContainer(fromBytes) && sameValue(fromBytes.keep, [...KEEP_SAME_LENGTH, PASSPHRASE]),
    "a rekey takes the passwords, the repetition and the passphrase as bytes; the passphrase " +
      "as bytes shows the wallet's too",
  );
}

/** The owner of a same-length container, and a fingerprint of another wallet. */
export async function checkRekeySameLengthOwner(helpers, sameLength) {
  const { client, sameBase } = helpers;
  const { sameContainer } = sameLength;
  let sameOwnerSaw = null;
  const bySameOwner = await client.rekey({
    ...sameBase,
    walletHasPassphrase: false,
    confirmation: {
      owner: (check) => {
        sameOwnerSaw = check;
        return true;
      },
    },
  });
  expectEqual(
    sameOwnerSaw,
    {
      phrase: PHRASE,
      words: 12,
      fingerprintWithoutPassphrase: FINGERPRINT,
      rehearsalNeedsPassphrase: false,
    },
    "the owner of a same-length container is shown its 12-word phrase",
  );
  expect(sameContainer(bySameOwner), "the owner's yes seals the same container");
  expectEqual(
    bySameOwner.rehearsal,
    { kind: "fingerprint", fingerprint: FINGERPRINT },
    "a same-length phrase the owner confirmed is rehearsed with its fingerprint",
  );
  const mismatchLog = progressLog();
  await expectRejection(
    client.rekey({
      ...sameBase,
      confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
      onProgress: mismatchLog.onProgress,
    }),
    "REFERENCE_MISMATCH",
    "a fingerprint of another wallet, stated without a passphrase, stops the rekey",
  );
  expect(
    mismatchLog.lines.at(-1) === "compare 12/36",
    "it stops after the comparison, before anything is sealed",
  );
}
