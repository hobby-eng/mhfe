// The constants of the page of scripts/verify-browsers.mjs: public test data, and known values
// computed here from their definitions, independently of mhfe. The runner declares every export of
// this module in the page script under its own name, as JSON (scripts/browser-check/harness.mjs).
import { createECDH, createHash, createHmac, pbkdf2Sync } from "node:crypto";

import {
  AMBIGUOUS_12_WORDS,
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_CONTAINER,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
  SELF_CHECK_PARTS,
} from "../public-test-data.mjs";

// The page's data of scripts/public-test-data.mjs.
export {
  AMBIGUOUS_12_WORDS,
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_CONTAINER,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
  SELF_CHECK_PARTS as SELF_CHECK,
};

// The page's public test data beside scripts/public-test-data.mjs.
// Passes the wallet check with the passphrase "TREZOR" (TREZOR_COUNTER in src/wallet_check.rs).
export const CHECKED_PHRASE = "abandon ".repeat(21) + "above proof fatigue";
// Passes the wallet check without a passphrase (EMPTY_COUNTER in src/wallet_check.rs).
export const EMPTY_CHECKED_PHRASE = "abandon ".repeat(21) + "absorb another spoil";
// The wrong password of the page, one letter off PASSWORD.
export const WRONG_PASSWORD = "public test passwore";
// The 256-bit states of PHRASE and of AMBIGUOUS_12_WORDS read as other lengths. A state is the
// phrase's entropy followed by the first bytes of the entropy's SHA-256 (src/packing.rs): for
// PHRASE 16 zero bytes and the first 16 bytes of their SHA-256, for AMBIGUOUS_12_WORDS
// 4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad. These phrases were computed
// from those bytes with the BIP39 English list (SHA-256 of english.txt 2f5eed53...3b24dbda),
// independently of mhfe; the 21 words are the first 28 bytes, the 24 words all 32.
//
// wrongPasswordAs24 is what WRONG_PASSWORD reads from REDUCED_COST_CONTAINER as 24 words. It
// depends on the reduced cost, so it was taken once from this page; the page also encrypts it
// again with WRONG_PASSWORD, which must give REDUCED_COST_CONTAINER, the container of the native
// tests, back. The cipher is a permutation, so only the right 24 words do that.
export const READINGS = {
  phraseAs24:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about inner love zone until oven protect tray movie front reopen emerge bachelor",
  ambiguousAs21:
    "essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock",
  ambiguousAs24:
    "essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock simple dress sand",
  wrongPasswordAs24:
    "wash humor junk coil author glide void dynamic donor patrol beach outdoor result subject piece mix aim juice raise enjoy pattern name miracle pact",
};

/** The BIP39 seed of a phrase: PBKDF2-HMAC-SHA512, 2,048 iterations, salt "mnemonic" + passphrase. */
function bip39Seed(phrase, passphrase) {
  const BIP39_ITERATIONS = 2048;
  const SEED_BYTES = 64;
  return pbkdf2Sync(
    phrase.normalize("NFKD"),
    `mnemonic${passphrase}`.normalize("NFKD"),
    BIP39_ITERATIONS,
    SEED_BYTES,
    "sha512",
  );
}

/**
 * The BIP32 master key fingerprint of a BIP39 phrase, computed here with Node's crypto from BIP39
 * and BIP32 alone, independently of mhfe: the seed, the master key (HMAC-SHA512 keyed "Bitcoin
 * seed"), its compressed secp256k1 public key, and the first four bytes of RIPEMD-160 of SHA-256
 * of that key.
 */
function masterFingerprint(phrase, passphrase) {
  // The master private key is the left half of the HMAC; the right half is its chain code.
  const masterKey = createHmac("sha512", "Bitcoin seed")
    .update(bip39Seed(phrase, passphrase))
    .digest()
    .subarray(0, 32);
  const curve = createECDH("secp256k1");
  curve.setPrivateKey(masterKey);
  const publicKey = curve.getPublicKey(null, "compressed");
  const keyHash = createHash("ripemd160")
    .update(createHash("sha256").update(publicKey).digest())
    .digest();
  return keyHash.subarray(0, 4).toString("hex");
}

/**
 * Whether a 24-word phrase passes the wallet check MHFE-WALLET-CHECK-SEED-1 with a passphrase,
 * computed here from its definition in src/wallet_check.rs, independently of mhfe: SHA-256 of the
 * ASCII tag, the entropy's 256 bits as a 4-byte big-endian number and the BIP39 seed starts with
 * two zero bytes, 16 bits.
 */
function passesWalletCheck(phrase, passphrase) {
  const ENTROPY_BITS = 256;
  const bits = Buffer.alloc(4);
  bits.writeUInt32BE(ENTROPY_BITS);
  const digest = createHash("sha256")
    .update("MHFE-WALLET-CHECK-SEED-1")
    .update(bits)
    .update(bip39Seed(phrase, passphrase))
    .digest();
  return digest[0] === 0 && digest[1] === 0;
}

// The computations above must first give the published 73c5da0a and the b4e3f5ed of
// src/wallet.rs, both of the BIP39 test phrase, and the two public counters of the wallet check,
// before their other values are trusted.
if (
  masterFingerprint(PHRASE, "") !== "73c5da0a" ||
  masterFingerprint(PHRASE, "TREZOR") !== "b4e3f5ed"
) {
  throw new Error("The independent fingerprint computation does not give the published values.");
}
if (
  !passesWalletCheck(CHECKED_PHRASE, "TREZOR") ||
  passesWalletCheck(CHECKED_PHRASE, "") ||
  !passesWalletCheck(EMPTY_CHECKED_PHRASE, "")
) {
  throw new Error("The independent wallet check does not give the published values.");
}
export const FINGERPRINTS = {
  phrase: "73c5da0a",
  phraseWithTrezor: "b4e3f5ed",
  reducedCostContainer: masterFingerprint(REDUCED_COST_CONTAINER, ""),
  sameLengthContainer: masterFingerprint(REDUCED_COST_SAME_LENGTH_CONTAINER, ""),
  fullSizeContainer: masterFingerprint(FULL_SIZE_CONTAINER, ""),
  checkedPhrase: masterFingerprint(CHECKED_PHRASE, ""),
  checkedPhraseWithTrezor: masterFingerprint(CHECKED_PHRASE, "TREZOR"),
  emptyCheckedPhrase: masterFingerprint(EMPTY_CHECKED_PHRASE, ""),
  ambiguous12Words: masterFingerprint(AMBIGUOUS_12_WORDS, ""),
};
for (const [name, phrase] of Object.entries(READINGS)) {
  FINGERPRINTS[name] = masterFingerprint(phrase, "");
}
// Whether each 24-word reading passes the wallet check without a passphrase.
export const WALLET_CHECKS = {
  phraseAs24: passesWalletCheck(READINGS.phraseAs24, ""),
  ambiguousAs24: passesWalletCheck(READINGS.ambiguousAs24, ""),
  wrongPasswordAs24: passesWalletCheck(READINGS.wrongPasswordAs24, ""),
};

// The page's own test data.
export const PASSWORD = "public test password";
export const NEW_PASSWORD = "another public test password";
export const THIRD_PASSWORD = "a third public test password";
// "abandon" 23 times and "art": the 24-word phrase of zero entropy.
export const ZERO_24 = "abandon ".repeat(23) + "art";
// The public check word vector of the specification (src/check_word.rs), typed in other ways.
export const CHECK_WORD_PASSWORD = "jovial trailing chokehold pavilion cresting ninth";
export const CHECK_WORD_DICE = "35214 62431 15543 44126 21365";
export const CHECK_WORD_MISSING = "jovial trailing ? pavilion cresting ninth";
export const CHECK_WORD_CAPITALS = "JOVIAL Trailing chokehold pavilion cresting ninth";
// Addresses of PHRASE's wallet (src/wallet.rs): BIP84's published first address, the change
// address 7 of account 3, the first address with the passphrase "TREZOR" and Ethereum's first.
export const BIP84_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
export const BIP84_PATH = "m/84'/0'/0'/0/0";
export const BIP84_ACCOUNT_3_CHANGE_7 = "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry";
export const BIP84_TREZOR_ADDRESS = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";
export const ETHEREUM_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
export const ETHEREUM_PATH = "m/44'/60'/0'/0/0";
// The same BIP84 address with its last character changed: its checksum fails.
export const DAMAGED_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv";
export const FINGERPRINT = FINGERPRINTS.phrase;
export const SUITE_3 = "MHFE-BIP39-256-EXPERIMENTAL-3";
export const SUITE_4 = "MHFE-BIP39-LP-EXPERIMENTAL-4";
export const REPAIR_PROFILE = "MHFE-REPAIR-1";
// The repair words of FULL_SIZE_CONTAINER for each count, from an independent implementation
// (src/repair.rs).
export const FULL_SIZE_REPAIR_WORDS = {
  2: "labor extra",
  4: "shaft pupil patient jewel",
  6: "credit buzz orbit tired sail coffee",
  8: "appear include vicious move uphold tiger song satoshi",
};
// What PIM 1 asks Argon2 for, as the reduced-cost wrapper reports it when it refuses it: the
// memory of level 0 and 12 x (PIM + 1) passes (src/suite.rs).
export const PIM_1_COST = "2097152 KiB and 24 passes";
export const REPAIR_WORD_CHOICES = [2, 4, 6, 8];
export const KEEP_24 = [{ item: "containerWords", words: 24 }, { item: "password" }];
export const KEEP_SAME_LENGTH = [{ item: "containerWords", words: 12 }, { item: "password" }];
export const PASSPHRASE = { item: "passphrase" };
export const PASSPHRASE_IF_ANY = { item: "passphraseIfAny" };
// The client's TypeErrors for a walletHasPassphrase that is not a boolean and for a passphrase
// with the built-in check or the owner (web/client.js), and the library's refusals of a rekey
// whose passphrase is not stated or stated against its reference (src/rekey.rs) and of the
// built-in check where the length has none or is detected (src/error.rs), exactly as the page
// gets them.
export const WALLET_PASSPHRASE_REQUIRED =
  "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
export const REKEY_PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address or a fingerprint.";
export const PASSPHRASE_UNSTATED = "Invalid request: say whether the wallet has a BIP39 passphrase";
export const PASSPHRASE_CONTRADICTED =
  "Invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows";
export const REFERENCE_REQUIRED =
  "The built-in check alone does not confirm this recovery: a 24-word original seed phrase, a " +
  "same-length container and a detected length need a receiving address or the master key " +
  "fingerprint of the wallet, or the owner's comparison with the backup, before the phrase is " +
  "encrypted again";
// The parts a page adds to a self-check, before the library's (PAGE_PARTS in web/runtime.js).
export const PAGE_PARTS = ["browser-features", "package-parts", "page-encoding"];
