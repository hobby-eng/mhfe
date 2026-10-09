// AUD-015 R4: an independent computation of MHFE-WALLET-CHECK-SEED-1 (mhfe_spec README, "Optional
// source profile: a recovery check for new 24-word phrases"), from the specification's text only:
//
//   seed = PBKDF2-HMAC-SHA512(NFKD(M(E)), "mnemonic" || NFKD(Q), 2048, 64)
//   T    = SHA-256(ASCII("MHFE-WALLET-CHECK-SEED-1") || BE32(256) || seed); passes iff T[0..2] == 0
//
// with Node's OpenSSL PBKDF2 and SHA-256 and @scure/bip39's English mnemonic (read-only from
// ../multi-chain-wallet-tools/node_modules). It first reproduces every published digest of
// mhfe_spec/vectors/profiles/README.md, passing and failing, then searches the first passing
// counter for a fresh public passphrase that NFKD changes ("Café ﬁ": a composed e-acute
// and the fi ligature), and writes it to docs/audits/AUD-015-evidence/r4-wallet-check-vector.json
// for the Rust probe. About 65,536 PBKDF2 seeds on one thread, under a minute.
//
//   node docs/audits/AUD-015-harnesses/r4-wallet/wallet-check-oracle.mjs
import assert from "node:assert/strict";
import { createHash, pbkdf2Sync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

const ROOT = new URL("../../../../", import.meta.url);
const MODULES = new URL("../multi-chain-wallet-tools/node_modules/", ROOT);
const { entropyToMnemonic } = await import(new URL("@scure/bip39/index.js", MODULES).href);
const { wordlist } = await import(new URL("@scure/bip39/wordlists/english.js", MODULES).href);

const TAG = Buffer.from("MHFE-WALLET-CHECK-SEED-1", "ascii");
assert.equal(TAG.length, 24);

function entropyOf(counter) {
  const entropy = new Uint8Array(32);
  new DataView(entropy.buffer).setBigUint64(24, BigInt(counter));
  return entropy;
}

function digest(entropy, passphrase, { withLength = true } = {}) {
  const mnemonic = entropyToMnemonic(entropy, wordlist);
  const seed = pbkdf2Sync(
    Buffer.from(mnemonic.normalize("NFKD"), "utf8"),
    Buffer.from("mnemonic" + passphrase.normalize("NFKD"), "utf8"),
    2048,
    64,
    "sha512",
  );
  const length = Buffer.from([0x00, 0x00, 0x01, 0x00]);
  const parts = withLength ? [TAG, length, seed] : [TAG, seed];
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

const passes = (hex) => hex.startsWith("0000");

// The published vectors, passing and failing (mhfe_spec/vectors/profiles/README.md).
assert.equal(
  digest(entropyOf(76562), "TREZOR"),
  "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853",
);
assert.equal(
  digest(entropyOf(98918), ""),
  "0000ede77b44fbd62025e1d36a45ebe3846cf48f7b3e76ca6a91495fdadc1fb2",
);
assert.ok(digest(entropyOf(76562), "").startsWith("ebd07f71"));
assert.ok(digest(entropyOf(98918), "TREZOR").startsWith("8d2b97fb"));
assert.ok(digest(entropyOf(76562), "TREZOR", { withLength: false }).startsWith("f2c9f765"));
assert.equal(
  entropyToMnemonic(entropyOf(98918), wordlist).split(" ").slice(-3).join(" "),
  "absorb another spoil",
);

// A fresh vector: the first passing counter from 1 for a passphrase that NFKD changes.
const PASSPHRASE = "Café ﬁ";
assert.notEqual(PASSPHRASE.normalize("NFKD"), PASSPHRASE);
const LIMIT = 2_000_000;
let counter = 1;
while (!passes(digest(entropyOf(counter), PASSPHRASE))) {
  counter += 1;
  assert.ok(counter < LIMIT, "no passing counter found");
}
const found = digest(entropyOf(counter), PASSPHRASE);
const mnemonic = entropyToMnemonic(entropyOf(counter), wordlist);
const record = {
  passphrase: PASSPHRASE,
  passphraseNfkd: PASSPHRASE.normalize("NFKD"),
  counter,
  entropyHex: Buffer.from(entropyOf(counter)).toString("hex"),
  mnemonic,
  digest: found,
  // The same entropy with the passphrase's NFC form and with a plain ASCII look-alike.
  nfcDigest: digest(entropyOf(counter), PASSPHRASE.normalize("NFC")),
  asciiLookalikeDigest: digest(entropyOf(counter), "Cafe fi"),
  emptyDigest: digest(entropyOf(counter), ""),
  previousDigest: digest(entropyOf(counter - 1), PASSPHRASE),
};
assert.ok(passes(record.nfcDigest), "NFC and NFKD forms give the same seed");
const evidence = new URL("docs/audits/AUD-015-evidence/", ROOT);
mkdirSync(evidence, { recursive: true });
writeFileSync(
  new URL("r4-wallet-check-vector.json", evidence),
  JSON.stringify(record, null, 1) + "\n",
);
console.log(`published vectors reproduced; first passing counter ${counter}: ${found}`);
console.log(JSON.stringify(record));
