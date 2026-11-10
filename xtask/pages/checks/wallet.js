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
    },
    "parameters gives the version, the twelve coins of an address check with their names and "
      + "address forms, and 16 bits of wallet check",
  );

  expect(
    (await wallet.fingerprint({ phrase: PHRASE })) === FINGERPRINT,
    "the wallet module gives the master key fingerprint",
  );
  expect(
    (await wallet.fingerprint({ phrase: PHRASE, passphrase: "TREZOR" }))
        === FINGERPRINTS.phraseWithTrezor
      && (await wallet.fingerprint({ phrase: PHRASE, passphrase: encode("TREZOR") }))
        === FINGERPRINTS.phraseWithTrezor,
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
    (await wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: encode("trezor") }))
        === false
      && (await wallet.walletCheck({ phrase: EMPTY_CHECKED_PHRASE, passphrase: "TREZOR" }))
        === false,
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
      coins: ["bitcoin"],
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
      coins: ["bitcoin"],
      type: "native SegWit (BIP84)",
      search: "m/84'/0'/0'-0'/0-1/0-19",
      addresses: 40,
      onlyPath: false,
    },
    "describeAddress with a scan gap states the first account's first 20 of each chain",
  );
  expectEqual(
    await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", path: BIP84_PATH }),
    {
      coins: ["bitcoin"],
      type: "native SegWit (BIP84)",
      search: BIP84_PATH,
      addresses: 1,
      onlyPath: true,
    },
    "describeAddress with a path searches that path only",
  );
  expectEqual(
    await wallet.describeAddress({ address: ETHEREUM_ADDRESS, coin: "ethereum" }),
    {
      coins: ["ethereum"],
      type: null,
      search: "m/44'/60'/0'-9'/0-1/0-99",
      addresses: 2000,
      onlyPath: false,
    },
    "an Ethereum address has no type of its own",
  );
  expectEqual(
    await wallet.describeAddress({ address: ETHEREUM_ADDRESS }),
    {
      coins: ["ethereum", "ethereum-classic"],
      type: null,
      search: "m/44'/{60,61}'/0'-9'/0-1/0-99",
      addresses: 4000,
      onlyPath: false,
    },
    "describeAddress without a coin names every coin of the address's form, a shared path once",
  );
  expectEqual(
    await wallet.describeAddress({ address: LEGACY_ADDRESS }),
    {
      coins: ["bitcoin", "bitcoin-cash"],
      type: "legacy (BIP44)",
      search: "m/44'/{0,145}'/0'-9'/0-1/0-99",
      addresses: 4000,
      onlyPath: false,
    },
    "a 1… address without a coin is searched as Bitcoin and Bitcoin Cash",
  );
  expectEqual(
    await wallet.describeAddress({ address: NESTED_SEGWIT_ADDRESS }),
    {
      coins: ["bitcoin", "litecoin"],
      type: "nested SegWit (BIP49)",
      search: "m/49'/{0,2}'/0'-9'/0-1/0-99",
      addresses: 4000,
      onlyPath: false,
    },
    "a 3… address without a coin is searched as Bitcoin and Litecoin",
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
}
