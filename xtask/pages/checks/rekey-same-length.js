  /**
   * MhfeClient.rekey of a same-length container, confirmed by the wallet and its address, with and
   * without a passphrase.
   */
  async function checkRekeySameLength(client, asRekeyResult, base, sealWithNew) {
    // A same-length container has no built-in check: the wallet confirms its phrase. A reference
    // with an empty passphrase matches the phrase's wallet without one and proves nothing about
    // funds under a passphrase, so these rekeys keep base's answer, false, unless they say other.
    const sameBase = {
      ...base,
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      words: undefined,
    };
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
      asRekeyResult(sameSealed),
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
      [
        ...roundLines("recover", 1, 12, 36),
        "compare 12/36",
        ...roundLines("encrypt", 13, 24, 36),
        ...roundLines("check", 25, 36, 36),
      ],
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
    // A wallet stated to have a passphrase is compared with it: a reference without it would
    // match the phrase's wallet without one and say nothing about the funds under the passphrase
    // (the specification's re-encryption rules), so it is refused before any round.
    for (const [confirmation, description] of [
      [{ fingerprint: FINGERPRINT }, "a fingerprint"],
      [{ address: BIP84_ADDRESS, coin: "bitcoin" }, "an address"],
    ]) {
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
      asRekeyResult(sameSealedWithPassphrase),
      "the fingerprint's passphrase, stated as well, gives what encrypt gives with it, every field",
    );
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
    return { sameBase, sameContainer, byTrezorAddress };
  }

  /**
   * MhfeClient.rekey of a same-length container: what its owner is shown, and a page that gives no
   * other confirmation.
   */
  async function checkRekeySameLengthOwner(
    client,
    asRekeyResult,
    base,
    byTrezorAddress,
    sameBase,
    sameContainer,
    sealedWithNew,
  ) {
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
      { phrase: PHRASE, words: 12, fingerprintWithoutPassphrase: FINGERPRINT },
      "the owner of a same-length container is shown its 12-word phrase",
    );
    expect(sameContainer(bySameOwner), "the owner's yes seals the same container");
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
