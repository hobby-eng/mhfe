  async function checkWallet(wallet) {
    group("MhfeWallet");
    expectThrownTypeError(
      () => new MhfeWallet({ workerSource: WORKER_SOURCE }),
      "wasm must be a Uint8Array or a WebAssembly.Module.",
      "a wallet module without the WebAssembly is refused",
    );
    const coin = (id, name, addressForms) => ({ id, name, addressForms });
    expectEqual(
      await wallet.parameters(),
      {
        version: VERSION,
        coins: [
          coin("bitcoin", "Bitcoin", "1…, 3…, bc1q… or bc1p…"),
          coin("bitcoin-cash", "Bitcoin Cash", "bitcoincash:q… or 1…"),
          coin("cosmos", "Cosmos", "cosmos1…"),
          coin("dash", "Dash", "X… or dash1k…"),
          coin("dogecoin", "Dogecoin", "D…"),
          coin("ethereum", "Ethereum and EVM networks", "0x…"),
          coin("ethereum-classic", "Ethereum Classic", "0x…"),
          coin("injective", "Injective", "inj1…"),
          coin("litecoin", "Litecoin", "L…, M…, 3… or ltc1q…"),
          coin("tron", "Tron", "T…"),
          coin("xrp", "XRP", "r…"),
          coin("zcash", "Zcash", "t1…"),
        ],
        walletCheckBits: 16,
        drawReportInterval: 1024,
        maxChosenWords: 1,
        maxNeverUseWords: 1,
        recommendedRandomBits: 240,
      },
      "parameters gives the version, the twelve coins of an address check with their names and " +
        "address forms, 16 bits of wallet check, a report every 1,024 draws, and the limits of " +
        "the wishes: 1 chosen word, 1 word never to use, 240 random bits recommended",
    );

    expect(
      (await wallet.fingerprint({ phrase: PHRASE })) === FINGERPRINT,
      "the wallet module gives the master key fingerprint",
    );
    expect(
      (await wallet.fingerprint({ phrase: PHRASE, passphrase: "TREZOR" })) ===
        FINGERPRINTS.phraseWithTrezor &&
        (await wallet.fingerprint({ phrase: PHRASE, passphrase: encode("TREZOR") })) ===
          FINGERPRINTS.phraseWithTrezor,
      "the fingerprint with a passphrase, as text or bytes",
    );
    await expectRejection(
      wallet.fingerprint({ phrase: "abandon about" }),
      "INVALID_PHRASE",
      "an invalid phrase has no fingerprint",
    );

    expect(
      await wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: "TREZOR" }),
      "the wallet module confirms the published wallet check",
    );
    expect(
      (await wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: encode("trezor") })) ===
        false &&
        (await wallet.walletCheck({ phrase: EMPTY_CHECKED_PHRASE, passphrase: "TREZOR" })) ===
          false,
      "the wallet check fails with another passphrase and for another phrase",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: "" }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check with an empty passphrase is refused",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: CHECKED_PHRASE }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check without a passphrase is refused",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: PHRASE, passphrase: "TREZOR" }),
      "INVALID_WORD_COUNT",
      "the wallet check of a 12-word phrase is refused",
    );

    // The default search: ten accounts, two chains and the first hundred addresses of each.
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin" }),
      {
        type: "native SegWit (BIP84)",
        search: "m/84'/0'/0'-9'/0-1/0-99",
        addresses: 2000,
        onlyPath: false,
      },
      "describeAddress states Bitcoin's standard search: 2,000 addresses",
    );
    // The decoy search of two missing words: the first account, as far as the gap.
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", scanGap: 20 }),
      {
        type: "native SegWit (BIP84)",
        search: "m/84'/0'/0'-0'/0-1/0-19",
        addresses: 40,
        onlyPath: false,
      },
      "describeAddress with a scan gap states the first account's first 20 of each chain",
    );
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", path: BIP84_PATH }),
      { type: "native SegWit (BIP84)", search: BIP84_PATH, addresses: 1, onlyPath: true },
      "describeAddress with a path searches that path only",
    );
    expectEqual(
      await wallet.describeAddress({ address: ETHEREUM_ADDRESS, coin: "ethereum" }),
      { type: null, search: "m/44'/60'/0'-9'/0-1/0-99", addresses: 2000, onlyPath: false },
      "an Ethereum address has no type of its own",
    );
    await expectTypeError(
      wallet.describeAddress({ address: BIP84_ADDRESS }),
      "coin must name the coin of the address",
      "describeAddress without a coin is refused: no coin is the default",
    );
    await expectRejection(
      wallet.describeAddress({ address: BIP84_ADDRESS, coin: "doge" }),
      "INVALID_COIN",
      "an unknown coin is refused",
    );
    await expectRejection(
      wallet.describeAddress({ address: DAMAGED_ADDRESS, coin: "bitcoin" }),
      "INVALID_ADDRESS",
      "an address whose checksum fails is refused",
    );
    await expectRejection(
      wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/x" }),
      "INVALID_DERIVATION_PATH",
      "a malformed path is refused",
    );
    const countingWorkers = await checkDrawPhrase(wallet);
    await checkCheckedDraws(wallet, countingWorkers);
  }

  /**
   * MhfeWallet.drawPhrase from the browser's randomness, with and without the wallet check, and
   * its workers.
   */
  async function checkDrawPhrase(wallet) {
    const drawn = await wallet.drawPhrase();
    expect(
      drawn.words === 24 && drawn.phrase.split(" ").length === 24,
      "the wallet module draws a phrase from the browser's randomness",
    );
    expect(
      drawn.walletCheck === false &&
        drawn.workers === 1 &&
        drawn.fingerprintWithPassphrase === (await wallet.fingerprint({ phrase: drawn.phrase })),
      "a phrase without a passphrase gets no wallet check, from one worker, with its fingerprint",
    );
    // A chosen word: its cost as the library rates it, and a phrase that meets it.
    const oneFixed = await wallet.describeDraw({
      chosen: [{ word: "happy", position: 1 }],
      walletCheck: true,
    });
    expect(
      oneFixed.randomBits === 229 &&
        oneFixed.randomness === "notRecommended" &&
        oneFixed.recognisable === true &&
        oneFixed.fixedPosition === true,
      "a word at a fixed position with the wallet check keeps 229 bits: allowed, not " +
        "recommended, and recognisable",
    );
    const hint = await wallet.wordHints({ typed: "abandon ZO" });
    expect(
      hint.hint === "words" && hint.words.join(" ") === "zone zoo",
      "the hint below BIP39 words lists the words that begin with the last two letters",
    );
    await expectRejection(
      wallet.describeDraw({
        chosen: [
          { word: "happy", position: 1 },
          { word: "zoo", position: 5 },
        ],
      }),
      "INVALID_WORD_WISH",
      "a second chosen word is refused",
    );
    const wished = await wallet.drawPhrase({
      chosen: [{ word: "zoo", position: 24 }],
      neverUse: ["abandon"],
    });
    const wishedWords = wished.phrase.split(" ");
    expect(
      wishedWords[23] === "zoo" && !wishedWords.includes("abandon"),
      "a drawn phrase has the chosen word at its position and no word never to use",
    );
    await expectRejection(
      wallet.drawPhrase({ chosen: [{ word: "notaword", position: 1 }] }),
      "INVALID_WORD_WISH",
      "a chosen word that is not a BIP39 word is refused",
    );
    const withPassphrase = await wallet.drawPhrase({
      passphrase: "TREZOR",
      passphraseRepeat: encode("TREZOR"),
      walletCheck: false,
    });
    expect(
      withPassphrase.walletCheck === false &&
        withPassphrase.workers === 1 &&
        withPassphrase.fingerprintWithPassphrase ===
          (await wallet.fingerprint({ phrase: withPassphrase.phrase, passphrase: "TREZOR" })),
      "a phrase with a passphrase and no check has the fingerprint with that passphrase",
    );
    await expectTypeError(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "TREZOR" }),
      "walletCheck must be true or false when a passphrase is given.",
      "with a passphrase, walletCheck must be chosen",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "trezor", walletCheck: true }),
      "PASSPHRASES_DIFFER",
      "a passphrase whose repetition differs is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", walletCheck: false }),
      "PASSPHRASES_DIFFER",
      "a passphrase without its repetition is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ walletCheck: true }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check without a passphrase is refused",
    );
    await expectTypeError(
      wallet.drawPhrase({
        passphrase: "TREZOR",
        passphraseRepeat: "TREZOR",
        walletCheck: true,
        workers: 0,
      }),
      "workers must be a whole number from 1 to 256.",
      "no workers are refused",
    );
    // Counts the workers a drawing really starts, through the page's Worker constructor.
    const countingWorkers = async (draw) => {
      const RealWorker = globalThis.Worker;
      let workersStarted = 0;
      globalThis.Worker = class extends RealWorker {
        constructor(...options) {
          super(...options);
          workersStarted += 1;
        }
      };
      try {
        return { result: await draw(), workersStarted };
      } finally {
        globalThis.Worker = RealWorker;
      }
    };
    const { result: unchecked, workersStarted: uncheckedWorkers } = await countingWorkers(() =>
      wallet.drawPhrase({ workers: 3 }),
    );
    expect(
      unchecked.walletCheck === false && unchecked.workers === 1 && uncheckedWorkers === 1,
      "a phrase without the wallet check is drawn by one worker, whatever workers says",
    );
    return countingWorkers;
  }

  /**
   * MhfeWallet.drawPhrase with the wallet check: failing workers, cancellation and progress
   * reports.
   */
  async function checkCheckedDraws(wallet, countingWorkers) {
    const checkedDraw = {
      passphrase: "TREZOR",
      passphraseRepeat: "TREZOR",
      walletCheck: true,
    };
    // Every worker of a checked draw failing at once, here from a random source of zeros, must
    // not take the page down: Firefox crashed the page when a worker was terminated while it
    // loaded the WebAssembly (reported by wallet-tools, 2026-10-08).
    const zeros = new MhfeWallet({
      workerSource:
        'Object.defineProperty(crypto, "getRandomValues", { value: (b) => b.fill(0) });\n' +
        WORKER_SOURCE,
      wasm: await WebAssembly.compile(bytes(WASM_BASE64)),
    });
    await expectRejection(
      zeros.drawPhrase({ ...checkedDraw, workers: 8 }),
      "RANDOM_FAILED",
      "eight workers that all fail at once end the drawing with RANDOM_FAILED, the page alive",
    );
    const running = wallet.drawPhrase({ ...checkedDraw, workers: 2 });
    await expectRejection(wallet.drawPhrase(), "BUSY", "a second drawing waits for none: BUSY");
    wallet.cancel();
    await expectRejection(running, "CANCELLED", "cancel() stops a drawing");
    expect(
      (await rejectionOf(running)) instanceof MhfeCancelledError,
      "a cancelled drawing rejects with MhfeCancelledError",
    );

    /** Whether a drawn phrase passes the wallet check with "TREZOR" and has that fingerprint. */
    const passesWithTrezor = async (drawnPhrase) =>
      drawnPhrase.words === 24 &&
      drawnPhrase.walletCheck === true &&
      (await wallet.walletCheck({ phrase: drawnPhrase.phrase, passphrase: "TREZOR" })) &&
      drawnPhrase.fingerprintWithPassphrase ===
        (await wallet.fingerprint({ phrase: drawnPhrase.phrase, passphrase: "TREZOR" }));
    // The two checked drawings of the page, about 65,536 BIP39 seeds each: one on the default
    // workers, one on a count given.
    const reports = [];
    const checked = await wallet.drawPhrase({
      ...checkedDraw,
      onProgress: (progress) => reports.push(progress),
    });
    const defaultWorkers = Math.min(navigator.hardwareConcurrency || 1, 8);
    expect(
      checked.workers === defaultWorkers && (await passesWithTrezor(checked)),
      `a checked phrase passes the wallet check, drawn on the default ${defaultWorkers} workers`,
    );
    // Whether a report comes at all is chance here: the phrase may be found before 1,024 draws.
    // The drawing stopped after three reports below checks that they come.
    expect(
      reports.every(
        (report, index) => report.stage === "draw" && report.draws === (index + 1) * 1024,
      ),
      `each of the ${reports.length} reports of the drawing adds the 1,024 draws of one worker`,
    );
    const givenWorkers = defaultWorkers > 1 ? defaultWorkers - 1 : 2;
    const { result: onGiven, workersStarted: givenStarted } = await countingWorkers(() =>
      wallet.drawPhrase({ ...checkedDraw, workers: givenWorkers }),
    );
    expect(
      onGiven.workers === givenWorkers &&
        givenStarted === givenWorkers &&
        (await passesWithTrezor(onGiven)),
      `a checked phrase drawn on ${givenWorkers} workers, as asked, passes the wallet check`,
    );

    // Each worker reports every 1,024 of its draws, so the total grows by 1,024 a report. A phrase
    // found before the third report (about one drawing in 21) ends the drawing first, so it is
    // tried again.
    let stoppedReports = [];
    let stopped = null;
    for (let attempt = 0; attempt < 5 && !(stopped instanceof MhfeCancelledError); attempt += 1) {
      const seen = [];
      stopped = await rejectionOf(
        wallet.drawPhrase({
          ...checkedDraw,
          workers: 2,
          onProgress: (progress) => {
            seen.push(progress);
            if (seen.length === 3) wallet.cancel();
          },
        }),
      );
      stoppedReports = seen;
    }
    expectEqual(
      stoppedReports,
      [
        { stage: "draw", draws: 1024 },
        { stage: "draw", draws: 2048 },
        { stage: "draw", draws: 3072 },
      ],
      "a drawing reports the draws of all workers, 1,024 more each time, until it is cancelled",
    );

    // The first report comes after 1,024 draws of a worker; a phrase found before it (about one
    // drawing in 32 on two workers) ends without one, so the drawing is tried again.
    const pageError = new Error("synthetic page error");
    let failure = null;
    let firstReport = null;
    for (let attempt = 0; attempt < 5 && failure === null; attempt += 1) {
      failure = await rejectionOf(
        wallet.drawPhrase({
          ...checkedDraw,
          workers: 2,
          onProgress: (progress) => {
            firstReport ??= progress;
            return Promise.reject(pageError);
          },
        }),
      );
    }
    expect(
      failure?.code === "CALLBACK_FAILED" &&
        failure.cause === pageError &&
        sameValue(firstReport, { stage: "draw", draws: 1024 }),
      "an onProgress whose promise rejects stops the drawing at the first report",
    );
    const after = await wallet.drawPhrase({
      passphrase: encode("TREZOR"),
      passphraseRepeat: "TREZOR",
      walletCheck: false,
    });
    expect(
      after.words === 24 &&
        after.workers === 1 &&
        after.fingerprintWithPassphrase ===
          (await wallet.fingerprint({ phrase: after.phrase, passphrase: "TREZOR" })),
      "a new drawing runs after one stopped; a passphrase as bytes is read",
    );
  }

