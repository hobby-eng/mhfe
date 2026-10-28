  async function checkRekey(client, repair, wallet, made) {
    group("MhfeClient.rekey");
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
    /**
     * What a rekey resolves to: what encrypt gives for the confirmed phrase, with `walletCheck`,
     * the 16-bit source check of a recovered 24-word reading with the reference's passphrase or
     * none, null for every other length.
     */
    const asRekeyResult = (sealed, walletCheck = null) => ({ ...sealed, walletCheck });
    const sealedWithNew = await sealWithNew(PHRASE);
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
      [
        ...roundLines("recover", 1, 12, 36),
        ...roundLines("encrypt", 13, 24, 36),
        "unverified",
        ...roundLines("check", 25, 36, 36),
      ],
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
    // The length detected: a 24-word original may pass a short check by chance, so the built-in
    // check alone confirms no detected length (REFERENCE_REQUIRED before any round, below). The
    // fingerprint, an address or the owner does, and a reference is compared with every reading
    // (AUD-017-FUN001).
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
      { phrase: PHRASE, words: 12, fingerprintWithoutPassphrase: FINGERPRINT },
      "with the length detected the owner is shown the 12 words found, and no length stated",
    );
    expect(
      byDetectedOwner.container === sealedWithNew.container,
      "the owner's yes confirms the length detected",
    );
    await checkRekeyResults(client, repair, made, asRekeyResult, base, sealWithNew);
    const ownerBase = await checkRekeyOwner(
      client,
      made,
      asRekeyResult,
      base,
      sealWithNew,
      sealedWithNew,
    );
    await checkRekeyCancelled(client, base, ownerBase);
    const { sameBase, sameContainer, byTrezorAddress } = await checkRekeySameLength(
      client,
      asRekeyResult,
      base,
      sealWithNew,
    );
    await checkRekeySameLengthOwner(
      client,
      asRekeyResult,
      base,
      byTrezorAddress,
      sameBase,
      sameContainer,
      sealedWithNew,
    );
    await checkRekeyEarlyRefusals(client, base, ownerBase, sameBase);
    await checkRekeySettings(client, base, sameBase);
  }

  /**
   * MhfeClient.rekey: its results against encrypt's, what the owner is shown of both lengths, and
   * a passphrase kept.
   */
  async function checkRekeyResults(client, repair, made, asRekeyResult, base, sealWithNew) {
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
        },
      ],
      "the page was given both lengths, and the owner was shown the reading of the one stated",
    );
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
        keep: [...KEEP_24, { item: "repairWords" }],
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
      [...KEEP_24, PASSPHRASE, { item: "repairWords" }],
      "a rekey stated to have a passphrase keeps it after the password, before the repair words",
    );
    expectEqual(
      withPassphrase,
      asRekeyResult(await sealWithNew(PHRASE, { walletHasPassphrase: true, repairWordCount: 2 })),
      "it is what encrypt gives with the same answer and repair words, every field",
    );
  }

  /**
   * MhfeClient.rekey with the owner's confirmation: what the owner is shown, a yes, and the
   * answers that stop it.
   */
  async function checkRekeyOwner(client, made, asRekeyResult, base, sealWithNew, sealedWithNew) {
    let ownerSaw = null;
    const ownerBase = {
      ...base,
      container: made.checked,
      words: 24,
    };
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
      },
      "the owner is shown the recovered phrase and its fingerprint",
    );
    expectEqual(
      fieldsOf(ownerSealed, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
      { suiteId: SUITE_3, builtInCheck: false, otherLengths: [], keep: KEEP_24 },
      "the owner's yes, from a promise, seals the 24-word phrase",
    );
    // CHECKED_PHRASE fails the 16-bit wallet check without its passphrase "TREZOR", as the script
    // checks before the page runs.
    expectEqual(
      ownerSealed,
      asRekeyResult(await sealWithNew(CHECKED_PHRASE), false),
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
    const ownerWithPassphrase = await client.rekey({
      ...ownerBase,
      walletHasPassphrase: true,
      confirmation: { owner: () => true },
    });
    expectEqual(
      fieldsOf(ownerWithPassphrase, ["container", "keep"]),
      { container: ownerSealed.container, keep: [...KEEP_24, PASSPHRASE] },
      "the owner's rekey stated to have a passphrase keeps it; the container is the same",
    );
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
      [{ phrase: PHRASE, words: 12, statedWords: 15, fingerprintWithoutPassphrase: FINGERPRINT }],
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
    return ownerBase;
  }

  /** MhfeClient.rekey cancelled while it awaits the owner's answer. */
  async function checkRekeyCancelled(client, base, ownerBase) {
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
      (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
        .candidates[0].verified,
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
