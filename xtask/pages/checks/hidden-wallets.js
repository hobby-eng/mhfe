  async function checkHiddenWallets(client, wallet, made) {
    group("MhfeClient.openHiddenWallets");
    const wallets = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    await expectRejection(
      client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }),
      "BUSY",
      "an open session holds the long-operation slot",
    );
    expect(
      (await client.readContainer(REDUCED_COST_CONTAINER)).hiddenWallets,
      "reading words runs while a session is open",
    );
    const log = progressLog();
    const opening = wallets.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
      onProgress: log.onProgress,
    });
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "BUSY",
      "a second wallet does not open while one opens",
    );
    const hidden = await opening;
    await expectTypeError(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD, onProgress: 1 }),
      "onProgress must be a function.",
      "an onProgress that is not a function is refused",
    );
    expectEqual(log.lines, roundLines("recover", 1, 12, 12), "opening one reports 12 rounds");
    expect(
      hidden.fingerprintWithoutPassphrase === (await wallet.fingerprint({ phrase: hidden.phrase })),
      "a hidden wallet's fingerprint is the wallet module's",
    );
    await expectRejection(
      wallets.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "PASSWORD_ALREADY_USED",
      "a password opens one hidden wallet only",
    );
    await expectRejection(
      wallets.open({ password: PASSWORD, passwordRepeat: PASSWORD }),
      "HIDDEN_WALLET_PASSES_CHECK",
      "the main password's reading passes the built-in check, so it is no hidden wallet",
    );
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "PASSWORDS_DIFFER",
      "a repetition that differs is refused",
    );
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: encode(NEW_PASSWORD) }),
      "PASSWORDS_DIFFER",
      "a repetition as bytes of another password is refused",
    );
    await expectRejection(
      wallets.open({
        password: CHECK_WORD_MISSING,
        passwordRepeat: CHECK_WORD_MISSING,
        passwordRepair: { repair: 2 },
      }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      "a repair the review did not offer is refused",
    );
    // Nothing is sent for a repair position that is not a word number, so the session stays open.
    const repairPosition = "a word number from 1.";
    for (const position of [-1, 0, 2 ** 32]) {
      await expectTypeError(
        wallets.open({
          password: CHECK_WORD_MISSING,
          passwordRepeat: CHECK_WORD_MISSING,
          passwordRepair: { repair: position },
        }),
        repairPosition,
        `passwordRepair { repair: ${position} } is refused`,
      );
    }
    const restored = await wallets.open({
      password: CHECK_WORD_MISSING,
      passwordRepeat: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
    });
    await expectRejection(
      wallets.open({ password: CHECK_WORD_PASSWORD, passwordRepeat: CHECK_WORD_PASSWORD }),
      "PASSWORD_ALREADY_USED",
      "passwordRepair { repair: 3 } opened the wallet of the restored password",
    );
    // Every password the core refuses before any work leaves the session open: the wallet of
    // THIRD_PASSWORD opens below.
    for (const [password, code] of [
      ["public\ttest password", "CONTROL_CHARACTER_IN_PASSWORD"],
      [new Uint8Array([0x70, 0xff]), "INVALID_PASSWORD_UTF8"],
      ["public \u0378 test password", "UNASSIGNED_CHARACTER"],
      ["a".repeat(1025), "PASSWORD_TOO_LONG"],
    ]) {
      await expectRejection(
        wallets.open({ password, passwordRepeat: password }),
        code,
        `a password refused with ${code} leaves the session open`,
      );
    }
    await expectRejection(
      wallets.open({ password: encode(THIRD_PASSWORD) }),
      "PASSWORDS_DIFFER",
      "a password without its repetition leaves the session open",
    );
    const second = await wallets.open({
      password: encode(THIRD_PASSWORD),
      passwordRepeat: encode(THIRD_PASSWORD),
    });
    await wallets.close();
    await expectRejection(
      wallets.open({ password: "x", passwordRepeat: "x" }),
      "SESSION_CLOSED",
      "a closed session refuses to open a wallet",
    );
    expect(
      (await outcomeWithin(wallets.close(), 5000)) === "resolved",
      "closing a closed session resolves at once",
    );
    const closedTwice = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const firstClose = closedTwice.close();
    const secondClose = closedTwice.close();
    expect(firstClose === secondClose, "a second close() returns the first one's promise");
    await secondClose;
    const afterClose = await client.decrypt({
      container: REDUCED_COST_CONTAINER,
      password: PASSWORD,
    });
    expect(
      afterClose.candidates[0].phrase === PHRASE,
      "once the second close() resolves, the session has freed the long-operation slot",
    );
    await checkHiddenWalletReadings(client, made, hidden, restored, second);
    await checkHiddenWalletSessions(client);
  }

  /**
   * MhfeClient.openHiddenWallets: the wallets of the container's readings and passwords, and
   * close() during an open.
   */
  async function checkHiddenWalletReadings(client, made, hidden, restored, second) {
    // A hidden wallet is the container read as 24 words with its password.
    const readAs24 = async (password) => {
      const [reading] = (
        await client.decrypt({ container: REDUCED_COST_CONTAINER, password, words: 24 })
      ).candidates;
      return {
        phrase: reading.phrase,
        words: 24,
        fingerprintWithoutPassphrase: reading.fingerprintWithoutPassphrase,
      };
    };
    const newPasswordWallet = await readAs24(NEW_PASSWORD);
    const checkWordWallet = await readAs24(CHECK_WORD_PASSWORD);
    const thirdWallet = await readAs24(THIRD_PASSWORD);
    expectEqual(
      hidden,
      newPasswordWallet,
      "after close the slot is free; a hidden wallet is the container read as 24 words",
    );
    expectEqual(
      restored,
      checkWordWallet,
      "the restored password's wallet is the container read with the full password",
    );
    expectEqual(
      second,
      thirdWallet,
      "the session stayed open after the refusals; a password as bytes opens its own wallet",
    );

    const again = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    expectEqual(
      await again.open({
        password: CHECK_WORD_CAPITALS,
        passwordRepeat: CHECK_WORD_CAPITALS,
        passwordRepair: "corrected",
      }),
      checkWordWallet,
      'passwordRepair "corrected" opens the wallet of the written form',
    );
    expectEqual(
      await again.open({ password: THIRD_PASSWORD, passwordRepeat: encode(THIRD_PASSWORD) }),
      thirdWallet,
      "a password as text and its repetition as the same bytes are the same password",
    );
    expectEqual(
      await again.open({ password: encode(NEW_PASSWORD), passwordRepeat: NEW_PASSWORD }),
      newPasswordWallet,
      "and so are a password as bytes and its repetition as the same text",
    );
    expect(
      (await outcomeWithin(again.close(), 5000)) === "resolved",
      "close() while the session waits resolves once the worker has ended",
    );

    // A failing onProgress of an open ends the whole session.
    const failing = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const progressError = new Error("synthetic page error");
    await expectRejection(
      failing.open({
        password: NEW_PASSWORD,
        passwordRepeat: NEW_PASSWORD,
        onProgress: () => {
          throw progressError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onProgress stops the open",
      progressError,
    );
    await expectRejection(
      failing.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "a failing onProgress ends the whole session",
    );

    // The main wallet's passphrase counts: a reading that passes the wallet check with it is
    // refused, and without it the same password opens that reading.
    const withPassphrase = await client.openHiddenWallets({
      container: made.checked,
      mainPassphrase: "TREZOR",
    });
    await expectRejection(
      withPassphrase.open({ password: PASSWORD, passwordRepeat: PASSWORD }),
      "HIDDEN_WALLET_PASSES_CHECK",
      "a reading that passes the wallet check with the main passphrase is refused",
    );
    const interrupted = withPassphrase.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
    });
    client.cancel();
    await expectRejection(interrupted, "CANCELLED", "client.cancel() during an open stops it");
    await expectRejection(
      withPassphrase.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "client.cancel() ends the session",
    );
    const withoutPassphrase = await client.openHiddenWallets({
      container: made.checked,
      mainPassphrase: new Uint8Array(0),
    });
    expectEqual(
      await withoutPassphrase.open({
        password: encode(PASSWORD),
        passwordRepeat: encode(PASSWORD),
      }),
      {
        phrase: CHECKED_PHRASE,
        words: 24,
        fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
      },
      "with an empty main passphrase as bytes, the same password opens that reading",
    );
    const closedDuringOpen = withoutPassphrase.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
    });
    expect(
      (await outcomeWithin(withoutPassphrase.close(), 5000)) === "resolved",
      "close() during an open resolves once the session has ended",
    );
    expect(
      (await rejectionOf(closedDuringOpen)) instanceof MhfeCancelledError,
      "close() during an open stops it with MhfeCancelledError",
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE &&
        (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
          .candidates[0].verified,
      "after close() during an open the slot is free",
    );
  }

  /** MhfeClient.openHiddenWallets: a session that waits, one at PIM 1, and what ends a session. */
  async function checkHiddenWalletSessions(client) {
    const waiting = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    client.cancel();
    await expectRejection(
      waiting.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "SESSION_CLOSED",
      "client.cancel() while the session waits ends it",
    );
    const atPim1 = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      pim: 1,
      mainPassphrase: "",
    });
    const pimError = await rejectionOf(
      atPim1.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
    );
    expect(
      pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
      "a session at PIM 1 asks Argon2 for 24 passes",
    );
    await expectRejection(
      atPim1.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "a failure that is no refusal ends the session",
    );
    await expectRejection(
      client.openHiddenWallets({
        container: REDUCED_COST_CONTAINER,
        memoryLevel: 1,
        mainPassphrase: "",
      }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a session at memory level 1 is refused in a browser",
    );
    await expectRejection(
      client.openHiddenWallets({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        mainPassphrase: "",
      }),
      "NO_HIDDEN_WALLETS",
      "hidden wallets open on a 24-word container only",
    );
    await expectTypeError(
      client.openHiddenWallets({ container: REDUCED_COST_CONTAINER }),
      "mainPassphrase is required",
      "the main passphrase is required",
    );
  }

