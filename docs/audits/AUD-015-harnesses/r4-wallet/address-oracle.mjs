// AUD-015 R4: an independent oracle for the wallet addresses of src/wallet.rs.
//
// It derives keys with @scure/bip39 and @scure/bip32 and encodes every address form by hand from
// @noble/hashes, @noble/curves and @scure/base primitives (read-only, from the node_modules of
// ../multi-chain-wallet-tools). The oracle first proves itself on literal published values (BIP44,
// BIP49, BIP84 and BIP86 vectors, the CashAddr specification, EIP-55, the XRP genesis account and
// @scure/btc-signer's own P2TR), then:
//   1. recomputes every row of the 43-row ADDRESSES table in src/wallet.rs (read from the source
//      text, never imported) and fails on any difference;
//   2. writes extra public cases (other phrases, passphrases, accounts, chains and indexes) to
//      docs/audits/AUD-015-evidence/r4-wallet-cases.json for the Rust probe, which checks that
//      mhfe finds each address at its path and by its search.
//
//   node docs/audits/AUD-015-harnesses/r4-wallet/address-oracle.mjs
//
// Exits non-zero on the first mismatch. Public test data only.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ROOT = new URL("../../../../", import.meta.url);
const MODULES = new URL("../multi-chain-wallet-tools/node_modules/", ROOT);
const load = (path) => import(new URL(path, MODULES).href);

const { mnemonicToSeedSync } = await load("@scure/bip39/index.js");
const { HDKey } = await load("@scure/bip32/index.js");
const { sha256 } = await load("@noble/hashes/sha2.js");
const { ripemd160 } = await load("@noble/hashes/legacy.js");
const { keccak_256 } = await load("@noble/hashes/sha3.js");
const { secp256k1 } = await load("@noble/curves/secp256k1.js");
const base = await load("@scure/base/index.js");
const btc = await load("@scure/btc-signer/index.js");

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const hash160 = (bytes) => ripemd160(sha256(bytes));
const base58check = base.createBase58check(sha256);
// XRP: Base58Check (double SHA-256, four bytes) written with the XRP alphabet (XRPL docs,
// "Base58 Encodings"); @scure/base's base58xrp is the bare alphabet.
const xrpBase58 = {
  encode: (payload) =>
    base.base58xrp.encode(concat(payload, sha256(sha256(payload)).slice(0, 4))),
};

// --- Address encoders, written from the specifications, not from mhfe ---------------------------

const p2pkh = (version, key) => base58check.encode(concat(version, hash160(key)));
const p2shP2wpkh = (version, key) =>
  base58check.encode(concat(version, hash160(concat([0x00, 0x14], hash160(key)))));
const segwit = (hrp, version, program) => {
  const coder = version === 0 ? base.bech32 : base.bech32m;
  return coder.encode(hrp, [version, ...coder.toWords(program)]);
};
// BIP340 tagged hash and BIP86 output key.
const taggedHash = (tag, data) => {
  const t = sha256(new TextEncoder().encode(tag));
  return sha256(concat(t, t, data));
};
const taprootOutputKey = (compressed) => {
  const P0 = secp256k1.Point.fromBytes(compressed);
  const even = P0.toAffine().y % 2n === 0n ? P0 : P0.negate();
  const x = even.toBytes(true).slice(1);
  const t = BigInt("0x" + hex(taggedHash("TapTweak", x)));
  assert.ok(t < secp256k1.Point.Fn.ORDER, "TapTweak out of range");
  return even.add(secp256k1.Point.BASE.multiply(t)).toBytes(true).slice(1);
};
const keccakAddress = (compressed) => {
  const uncompressed = secp256k1.Point.fromBytes(compressed).toBytes(false);
  return keccak_256(uncompressed.slice(1)).slice(12);
};
// EIP-55 mixed-case checksum.
const eip55 = (bytes) => {
  const lower = hex(bytes);
  const digest = hex(keccak_256(new TextEncoder().encode(lower)));
  return (
    "0x" +
    [...lower].map((c, i) => (parseInt(digest[i], 16) >= 8 ? c.toUpperCase() : c)).join("")
  );
};
// CashAddr (spec: github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md).
const CASH_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const cashPolymod = (values) => {
  const G = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i += 1) if ((c0 >> BigInt(i)) & 1n) c ^= G[i];
  }
  return c ^ 1n;
};
const cashaddr = (prefix, version, hash) => {
  const payload = base.bech32.toWords(concat([version], hash));
  const prefixValues = [...prefix].map((ch) => ch.charCodeAt(0) & 0x1f);
  const checksum = cashPolymod([...prefixValues, 0, ...payload, 0, 0, 0, 0, 0, 0, 0, 0]);
  const check = [];
  for (let i = 0; i < 8; i += 1) check.push(Number((checksum >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:` + [...payload, ...check].map((v) => CASH_CHARSET[v]).join("");
};

// --- The oracle proves itself on published literal values first --------------------------------

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const keyAt = (phrase, passphrase, path) =>
  HDKey.fromMasterSeed(mnemonicToSeedSync(phrase, passphrase)).derive(path).publicKey;

// BIP32 fingerprint of the BIP84 test phrase (published "73c5da0a"; also the parent fingerprint in
// BIP84's account key derivation listing).
const masterFingerprint = (phrase, passphrase) =>
  hex(hash160(HDKey.fromMasterSeed(mnemonicToSeedSync(phrase, passphrase)).publicKey).slice(0, 4));
assert.equal(masterFingerprint(ABANDON, ""), "73c5da0a", "BIP32 fingerprint of the BIP84 phrase");
// BIP84 published vectors.
assert.equal(
  segwit("bc", 0, hash160(keyAt(ABANDON, "", "m/84'/0'/0'/0/0"))),
  "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
);
assert.equal(
  segwit("bc", 0, hash160(keyAt(ABANDON, "", "m/84'/0'/0'/0/1"))),
  "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
);
assert.equal(
  segwit("bc", 0, hash160(keyAt(ABANDON, "", "m/84'/0'/0'/1/0"))),
  "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
);
// BIP86 published vectors.
for (const [path, address] of [
  ["m/86'/0'/0'/0/0", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"],
  ["m/86'/0'/0'/0/1", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"],
  ["m/86'/0'/0'/1/0", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"],
]) {
  const key = keyAt(ABANDON, "", path);
  assert.equal(segwit("bc", 1, taprootOutputKey(key)), address, `BIP86 ${path}`);
  // A second, separate implementation of P2TR.
  assert.equal(btc.p2tr(key.slice(1)).address, address, `btc-signer P2TR ${path}`);
}
// BIP49 published testnet vector.
assert.equal(
  p2shP2wpkh([0xc4], keyAt(ABANDON, "", "m/49'/1'/0'/0/0")),
  "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
);
// CashAddr specification example: P2PKH of 76a04053bda0a88bda5177b86a15c3b29f559873.
assert.equal(
  cashaddr("bitcoincash", 0, fromHex("76a04053bda0a88bda5177b86a15c3b29f559873")),
  "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
);
// EIP-55 published example.
assert.equal(
  eip55(fromHex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")),
  "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
);
// XRP genesis account (XRPL docs): account ID b5f762798a53d543a014caf8b297cff8f2f937e8.
assert.equal(
  xrpBase58.encode(concat([0x00], fromHex("b5f762798a53d543a014caf8b297cff8f2f937e8"))),
  "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
);

// --- Every coin and form, as mhfe's Coin and AddressType name them -----------------------------

/** form -> [coin id, path purpose, coin type(s) searched first, encoder(compressed key)] */
const FORMS = {
  "bitcoin-p2pkh": ["bitcoin", 44, 0, (k) => p2pkh([0x00], k)],
  "bitcoin-p2sh-p2wpkh": ["bitcoin", 49, 0, (k) => p2shP2wpkh([0x05], k)],
  "bitcoin-p2wpkh": ["bitcoin", 84, 0, (k) => segwit("bc", 0, hash160(k))],
  "bitcoin-p2tr": ["bitcoin", 86, 0, (k) => segwit("bc", 1, taprootOutputKey(k))],
  "bitcoin-testnet-p2pkh": ["bitcoin", 44, 1, (k) => p2pkh([0x6f], k)],
  "bitcoin-testnet-p2sh-p2wpkh": ["bitcoin", 49, 1, (k) => p2shP2wpkh([0xc4], k)],
  "bitcoin-testnet-p2wpkh": ["bitcoin", 84, 1, (k) => segwit("tb", 0, hash160(k))],
  "bitcoin-testnet-p2tr": ["bitcoin", 86, 1, (k) => segwit("tb", 1, taprootOutputKey(k))],
  "litecoin-p2pkh": ["litecoin", 44, 2, (k) => p2pkh([0x30], k)],
  "litecoin-p2sh-p2wpkh": ["litecoin", 49, 2, (k) => p2shP2wpkh([0x32], k)],
  "litecoin-p2sh-p2wpkh-3": ["litecoin", 49, 2, (k) => p2shP2wpkh([0x05], k)],
  "litecoin-p2wpkh": ["litecoin", 84, 2, (k) => segwit("ltc", 0, hash160(k))],
  dogecoin: ["dogecoin", 44, 3, (k) => p2pkh([0x1e], k)],
  "dash-core": ["dash", 44, 5, (k) => p2pkh([0x4c], k)],
  zcash: ["zcash", 44, 133, (k) => base58check.encode(concat([0x1c, 0xb8], hash160(k)))],
  "bitcoin-cash": ["bitcoin-cash", 44, 145, (k) => cashaddr("bitcoincash", 0, hash160(k))],
  "bitcoin-cash-legacy": ["bitcoin-cash", 44, 145, (k) => p2pkh([0x00], k)],
  xrp: ["xrp", 44, 144, (k) => xrpBase58.encode(concat([0x00], hash160(k)))],
  tron: ["tron", 44, 195, (k) => base58check.encode(concat([0x41], keccakAddress(k)))],
  ethereum: ["ethereum", 44, 60, (k) => eip55(keccakAddress(k))],
  "ethereum-classic": ["ethereum-classic", 44, 61, (k) => eip55(keccakAddress(k))],
  cosmos: ["cosmos", 44, 118, (k) => base.bech32.encode("cosmos", base.bech32.toWords(hash160(k)))],
  injective: [
    "injective",
    44,
    60,
    (k) => base.bech32.encode("inj", base.bech32.toWords(keccakAddress(k))),
  ],
  // DIP18: Bech32m, hrp "dash"/"tdash", payload 0xb0 || HASH160.
  "dash-platform": [
    "dash",
    9,
    5,
    (k) => base.bech32m.encode("dash", base.bech32m.toWords(concat([0xb0], hash160(k)))),
  ],
  "dash-platform-testnet": [
    "dash",
    9,
    1,
    (k) => base.bech32m.encode("tdash", base.bech32m.toWords(concat([0xb0], hash160(k)))),
  ],
};

/** The encoders that can produce `address` for `coin` at `path`, by its form. */
function oracleAddress(coin, passphrase, path, phrase = ABANDON) {
  const key = keyAt(phrase, passphrase, path);
  const steps = path.split("/");
  const purpose = Number.parseInt(steps[1], 10);
  const coinType = Number.parseInt(steps[2], 10);
  return Object.entries(FORMS)
    .filter(([, [id, formPurpose]]) => id === coin && formPurpose === purpose)
    .map(([form, [, , formCoin, encode]]) => ({ form, formCoin, address: encode(key), coinType }));
}

// --- 1. The ADDRESSES table of src/wallet.rs, read as text ------------------------------------

const COIN_IDS = {
  Bitcoin: "bitcoin",
  Ethereum: "ethereum",
  Xrp: "xrp",
  Tron: "tron",
  Zcash: "zcash",
  Dogecoin: "dogecoin",
  BitcoinCash: "bitcoin-cash",
  Litecoin: "litecoin",
  EthereumClassic: "ethereum-classic",
  Cosmos: "cosmos",
  Injective: "injective",
  Dash: "dash",
};
const source = readFileSync(new URL("src/wallet.rs", ROOT), "utf8");
const table = source.slice(source.indexOf("const ADDRESSES:"), source.indexOf("fn addresses_are_found"));
const rows = [
  ...table.matchAll(/\(\s*Coin::(\w+),\s*"([^"]*)",\s*"([^"]+)",\s*"([^"]+)",?\s*\)/g),
].map(([, coin, passphrase, path, address]) => ({
  coin: COIN_IDS[coin],
  passphrase,
  path,
  address,
}));
const declared = Number(/const ADDRESSES: \[\(Coin, &str, &str, &str\); (\d+)\]/.exec(source)[1]);
assert.equal(rows.length, declared, "every row of the ADDRESSES table was read");
let tableChecked = 0;
for (const row of rows) {
  const computed = oracleAddress(row.coin, row.passphrase, row.path).map((entry) => entry.address);
  // EIP-55 addresses compare case-sensitively as written; the others are canonical already.
  assert.ok(
    computed.includes(row.address),
    `src/wallet.rs ADDRESSES ${row.coin} ${row.path} ${JSON.stringify(row.passphrase)}: ` +
      `${row.address} not in ${JSON.stringify(computed)}`,
  );
  tableChecked += 1;
}

// --- 2. Extra cases for the Rust probe ---------------------------------------------------------

/** Public phrases: BIP39's own English test vectors (Trezor's vectors.json), 12 and 24 words. */
const PHRASES = [
  ABANDON,
  "legal winner thank year wave sausage worth useful legal winner thank yellow",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
];
// Public synthetic passphrases; the third changes under NFKD (é composed, the ligature ﬁ).
const PASSPHRASES = ["", "TREZOR", "Café ﬁ"];
/** Paths inside the default limits (10 accounts, 100 indexes), and one outside. */
const SPOTS = [
  [0, 0, 0],
  [9, 1, 99],
  [4, 0, 57],
];
const cases = [];
for (const [phraseIndex, phrase] of PHRASES.entries()) {
  for (const passphrase of PASSPHRASES) {
    for (const [form, [coin, purpose, coinType, encode]] of Object.entries(FORMS)) {
      for (const [account, chain, index] of SPOTS) {
        const hardenedChain = purpose === 9;
        const prefix = purpose === 9 ? `m/9'/${coinType}'/17'` : `m/${purpose}'/${coinType}'`;
        const path = `${prefix}/${account}'/${chain}${hardenedChain ? "'" : ""}/${index}`;
        const key = keyAt(phrase, passphrase, path);
        cases.push({ coin, form, phraseIndex, passphrase, path, address: encode(key) });
      }
    }
  }
}
// Second roots: a Bitcoin Cash wallet on coin type 0 and an Ethereum Classic one on 60.
for (const [coin, path, encode] of [
  ["bitcoin-cash", "m/44'/0'/2'/0/3", FORMS["bitcoin-cash"][3]],
  ["ethereum-classic", "m/44'/60'/2'/1/3", FORMS["ethereum-classic"][3]],
]) {
  cases.push({ coin, form: `${coin}-second-root`, phraseIndex: 0, passphrase: "", path, address: encode(keyAt(ABANDON, "", path)) });
}
// Just outside the default limits: account 10 and index 100.
for (const path of ["m/84'/0'/10'/0/0", "m/84'/0'/0'/0/100"]) {
  cases.push({
    coin: "bitcoin",
    form: "outside-default-limits",
    phraseIndex: 0,
    passphrase: "",
    path,
    address: FORMS["bitcoin-p2wpkh"][3](keyAt(ABANDON, "", path)),
  });
}

const fingerprints = [];
for (const [phraseIndex, phrase] of PHRASES.entries()) {
  for (const passphrase of PASSPHRASES) {
    fingerprints.push({ phraseIndex, passphrase, fingerprint: masterFingerprint(phrase, passphrase) });
  }
}

const evidence = new URL("docs/audits/AUD-015-evidence/", ROOT);
mkdirSync(evidence, { recursive: true });
const out = new URL("r4-wallet-cases.json", evidence);
writeFileSync(out, JSON.stringify({ phrases: PHRASES, cases, fingerprints }, null, 1) + "\n");
console.log(
  `oracle self-checks passed; ${tableChecked} of ${rows.length} src/wallet.rs ADDRESSES rows ` +
    `reproduced; ${cases.length} extra cases and ${fingerprints.length} fingerprints written to ` +
    `${out.pathname}`,
);
