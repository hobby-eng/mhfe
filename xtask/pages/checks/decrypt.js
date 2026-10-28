  async function checkDecrypt(client, wallet, made) {
    group("MhfeClient.decrypt");
    const container = REDUCED_COST_CONTAINER;
    const verified = {
      words: 12,
      verified: true,
      status: "verified",
      phrase: PHRASE,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINT,
      walletCheck: null,
      statedWords: null,
      otherLengths: [],
    };
    const log = progressLog();
    expectEqual(
      await client.decrypt({ container, password: PASSWORD, onProgress: log.onProgress }),
      { kind: "phrase", candidates: [verified] },
      "decrypt recovers the verified 12-word phrase with every field",
    );
    expectEqual(log.lines, roundLines("recover", 1, 12, 12), "a recovery reports 12 rounds");
    expectEqual(
      await client.decrypt({ container, password: encode(PASSWORD), words: 12 }),
      { kind: "phrase", candidates: [verified] },
      "the chosen length 12 with the password as bytes gives the same",
    );
    /** A 24-word reading of a state, with the values computed independently in the script. */
    const readAs24 = (name, status, otherLengths = []) => ({
      words: 24,
      verified: false,
      status,
      phrase: READINGS[name],
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS[name],
      walletCheck: WALLET_CHECKS[name],
      statedWords: null,
      otherLengths,
    });
    // 24 words stated beside a 12-word reading whose check passes: both readings, the checked one
    // first, naming the length stated, as the length rules of recovery say (AUD-015-FUN001).
    const as24 = await client.decrypt({ container, password: PASSWORD, words: 24 });
    expectEqual(
      as24,
      {
        kind: "ambiguous",
        candidates: [
          { ...verified, statedWords: 24 },
          readAs24("phraseAs24", "readAs24Chosen", [12]),
        ],
      },
      "the chosen length 24 gives the checked 12 words first, then the whole state: the entropy " +
        "and its SHA-256, with every field",
    );
    const walletFingerprints = [];
    for (const { phrase } of as24.candidates) {
      walletFingerprints.push(await wallet.fingerprint({ phrase }));
    }
    expectEqual(
      as24.candidates.map((candidate) => candidate.fingerprintWithoutPassphrase),
      walletFingerprints,
      "each candidate's fingerprint is the wallet module's",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, memoryLevel: 1 }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a recovery at memory level 1 is refused in a browser",
    );
    // A stated short length whose check fails while another's passes: the check takes precedence,
    // and the reading names the length stated (AUD-015-FUN001).
    expectEqual(
      await client.decrypt({ container, password: PASSWORD, words: 15 }),
      { kind: "phrase", candidates: [{ ...verified, statedWords: 15 }] },
      "a chosen length whose check fails gives the 12 words whose check passes, naming the 15 " +
        "stated, with every field",
    );
    // The wrong password's state passes no short check (it reads as 24 words below).
    await expectRejection(
      client.decrypt({ container, password: WRONG_PASSWORD, words: 15 }),
      "VERIFIER_MISMATCH",
      "a chosen length whose check fails, where no other passes, is refused",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, words: 13 }),
      "INVALID_WORD_COUNT",
      "a word count of 13 is refused",
    );
    const wrong = await client.decrypt({ container, password: WRONG_PASSWORD });
    expectEqual(
      wrong,
      { kind: "phrase", candidates: [readAs24("wrongPasswordAs24", "readAs24")] },
      "a wrong password reads as 24 unverified words (status readAs24), with every field",
    );
    expect(
      (
        await client.encrypt({
          phrase: wrong.candidates[0].phrase,
          password: WRONG_PASSWORD,
          passwordRepeat: WRONG_PASSWORD,
          walletHasPassphrase: false,
        })
      ).container === container,
      "those 24 words, encrypted again with the wrong password, give the container back",
    );

    const sameLength = {
      ...verified,
      verified: false,
      status: "noBuiltInCheck",
      suiteId: SUITE_4,
    };
    expectEqual(
      await client.decrypt({ container: REDUCED_COST_SAME_LENGTH_CONTAINER, password: PASSWORD }),
      { kind: "phrase", candidates: [sameLength] },
      "a same-length container recovers the phrase, not verified, with every field",
    );
    expectEqual(
      await client.decrypt({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        words: 12,
      }),
      { kind: "phrase", candidates: [sameLength] },
      "a same-length container takes its own length",
    );
    await expectRejection(
      client.decrypt({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        words: 15,
      }),
      "LENGTH_CHOICE_NOT_APPLICABLE",
      "a same-length container refuses another length",
    );
    await checkDecryptAmbiguous(client, made, readAs24);
    await checkDecryptRepairs(client, made, container);
  }

  /** MhfeClient.decrypt of an ambiguous container, by a stated length and by the wallet check. */
  async function checkDecryptAmbiguous(client, made, readAs24) {
    const ambiguousOriginal = (statedWords = null) => ({
      words: 12,
      verified: true,
      status: "verified",
      phrase: AMBIGUOUS_12_WORDS,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS.ambiguous12Words,
      walletCheck: null,
      statedWords,
      otherLengths: [21],
    });
    const ambiguousAs21 = (statedWords = null) => ({
      words: 21,
      verified: true,
      status: "verified",
      phrase: READINGS.ambiguousAs21,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS.ambiguousAs21,
      walletCheck: null,
      statedWords,
      otherLengths: [12],
    });
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD }),
      {
        kind: "ambiguous",
        candidates: [
          ambiguousOriginal(),
          ambiguousAs21(),
          readAs24("ambiguousAs24", "readAs24", [12, 21]),
        ],
      },
      "an ambiguous container lists the 12 and 21 verified words and the 24-word reading in full",
    );
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD, words: 12 }),
      { kind: "phrase", candidates: [ambiguousOriginal()] },
      "a length stated among those that pass resolves the ambiguity",
    );
    // 24 words stated beside lengths that pass: every reading, the checked ones first, as the
    // length rules of recovery say (AUD-015-FUN001).
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD, words: 24 }),
      {
        kind: "ambiguous",
        candidates: [
          ambiguousOriginal(24),
          ambiguousAs21(24),
          readAs24("ambiguousAs24", "readAs24Chosen", [12, 21]),
        ],
      },
      "24 stated words give the checked readings first and the 24-word reading in full",
    );

    expectEqual(
      await client.decrypt({ container: made.checked, password: PASSWORD }),
      {
        kind: "phrase",
        candidates: [
          {
            words: 24,
            verified: false,
            status: "readAs24",
            phrase: CHECKED_PHRASE,
            suiteId: SUITE_3,
            fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
            walletCheck: false,
            statedWords: null,
            otherLengths: [],
          },
        ],
      },
      "a 24-word phrase that passes the wallet check only with its passphrase does not pass without",
    );
    expectEqual(
      (await client.decrypt({ container: made.checked, password: PASSWORD, passphrase: "TREZOR" }))
        .candidates[0].walletCheck,
      true,
      "with its passphrase, the same 24-word reading passes the 16-bit check",
    );
    expectEqual(
      await client.decrypt({ container: made.emptyChecked, password: PASSWORD }),
      {
        kind: "phrase",
        candidates: [
          {
            words: 24,
            verified: false,
            status: "readAs24",
            phrase: EMPTY_CHECKED_PHRASE,
            suiteId: SUITE_3,
            fingerprintWithoutPassphrase: FINGERPRINTS.emptyCheckedPhrase,
            walletCheck: true,
            statedWords: null,
            otherLengths: [],
          },
        ],
      },
      "a 24-word phrase that passes the wallet check without a passphrase is reported so",
    );
  }

  /** MhfeClient.decrypt with a repaired password, one typed in capitals, and at PIM 1. */
  async function checkDecryptRepairs(client, made, container) {
    const restored = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
    });
    expect(
      restored.candidates[0].phrase === PHRASE && restored.candidates[0].verified,
      "passwordRepair { repair: 3 } opens the container of the check-word password",
    );
    const corrected = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_CAPITALS,
      passwordRepair: "corrected",
    });
    expect(
      corrected.candidates[0].phrase === PHRASE && corrected.candidates[0].verified,
      'passwordRepair "corrected" opens it with the written form',
    );
    const capitals = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_CAPITALS,
    });
    expect(
      capitals.candidates.every((candidate) => candidate.phrase !== PHRASE),
      "kept as typed, the password with capitals is another password",
    );
    await expectRejection(
      client.decrypt({
        container: made.checkWord,
        password: CHECK_WORD_MISSING,
        passwordRepair: { repair: 2 },
      }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      "a repair the review did not offer is refused",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, passwordRepair: "corrected" }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      '"corrected" is refused for a password the review does not correct',
    );
    const pimError = await rejectionOf(client.decrypt({ container, password: PASSWORD, pim: 1 }));
    expect(
      pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
      "a recovery with PIM 1 asks Argon2 for 24 passes",
    );
  }

