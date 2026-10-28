  async function checkCancelAndCallbacks(client) {
    group("MhfeClient.cancel and the page's callbacks");
    const container = REDUCED_COST_CONTAINER;
    const cancelledAtOnce = client.decrypt({ container, password: PASSWORD });
    client.cancel();
    await expectRejection(cancelledAtOnce, "CANCELLED", "cancel before the first round");
    const cancelledLater = client.decrypt({
      container,
      password: PASSWORD,
      onProgress: ({ round }) => {
        if (round === 2) client.cancel();
      },
    });
    await expectRejection(cancelledLater, "CANCELLED", "cancel in the second round");
    expect(
      (await rejectionOf(cancelledLater)) instanceof MhfeCancelledError,
      "a cancelled operation rejects with MhfeCancelledError",
    );
    expect(
      (await client.readContainer(container)).container === container,
      "a new operation runs after a cancel",
    );

    const running = client.decrypt({ container, password: PASSWORD });
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
      }),
      "BUSY",
      "a second long operation is refused while one runs",
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE,
      "reading words does not wait for the long operation",
    );
    expect((await running).candidates[0].phrase === PHRASE, "the first operation still ends");

    const pageError = new Error("synthetic page error");
    await expectRejection(
      client.decrypt({
        container,
        password: PASSWORD,
        onProgress: () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onProgress stops the operation",
      pageError,
    );
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        onUnverified: () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onUnverified stops the operation",
      pageError,
    );
    await expectRejection(
      client.decrypt({
        container,
        password: PASSWORD,
        onProgress: async () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "an async onProgress that rejects stops the operation",
      pageError,
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE,
      "a new operation runs after a callback failed",
    );
    await expectTypeError(
      client.decrypt({ container, password: PASSWORD, onProgress: "show" }),
      "onProgress must be a function.",
      "an onProgress that is not a function is refused",
    );
    await expectTypeError(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        onUnverified: "show",
      }),
      "onUnverified must be a function.",
      "an onUnverified that is not a function is refused",
    );
  }

  async function checkMemoryFailures(client) {
    group("MhfeClient: memory the browser cannot give");
    // The core reports the 2 GiB of memory level 0 that it asked for, not the reduced cost.
    const message = "The computer could not reserve 2 GiB of memory for Argon2";
    const failed = (error) =>
      error?.code === "MEMORY_ALLOCATION_FAILED" && error.message === message;
    const log = progressLog();
    const recovery = await rejectionOf(
      client.decrypt({
        container: REDUCED_COST_CONTAINER,
        password: MEMORY_FAILURE_PASSWORD,
        onProgress: log.onProgress,
      }),
    );
    expect(
      failed(recovery) && sameValue(log.lines, ["recover 1/12"]),
      `a recovery fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${recovery?.code}`,
    );
    const encryptionLog = progressLog();
    const encryption = await rejectionOf(
      client.encrypt({
        phrase: PHRASE,
        password: MEMORY_FAILURE_PASSWORD,
        passwordRepeat: MEMORY_FAILURE_PASSWORD,
        walletHasPassphrase: false,
        onProgress: encryptionLog.onProgress,
      }),
    );
    expect(
      failed(encryption) && sameValue(encryptionLog.lines, ["encrypt 1/24"]),
      `an encryption fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${encryption?.code}`,
    );

    const sessionStart = await rejectionOf(
      client.openHiddenWallets({ container: MEMORY_FAILURE_CONTAINER, mainPassphrase: "" }),
    );
    expect(
      failed(sessionStart),
      `a session of hidden wallets fails at its start, when it reserves its work area -> ${sessionStart?.code}`,
    );
    const session = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const openLog = progressLog();
    const opening = await rejectionOf(
      session.open({
        password: MEMORY_FAILURE_PASSWORD,
        passwordRepeat: MEMORY_FAILURE_PASSWORD,
        onProgress: openLog.onProgress,
      }),
    );
    expect(
      failed(opening) && sameValue(openLog.lines, ["recover 1/12"]),
      `the session after it reserved its area fails in a wallet's round 1 -> ${opening?.code}`,
    );
    await expectRejection(
      session.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "SESSION_CLOSED",
      "a memory failure is no refusal: it ends the session",
    );
    expect(
      (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
        .candidates[0].verified,
      "the slot is free after each memory failure",
    );
  }

