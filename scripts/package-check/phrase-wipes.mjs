// Part 2 of the checks of the browser package, continued (scripts/verify-browser-package.mjs).
// Phrases reach the WebAssembly as UTF-8 bytes, which the bindings wipe (SecretText in
// src/wasm_api/mod.rs), as they wipe passwords: wasm-bindgen's own copy of a text argument stays
// in the module's memory after the call (AUD-010). Each case runs in a fresh instance with the
// phrase as a person may type it, in capitals with two spaces between the words, a form the
// library never writes itself, so that a copy found can only be the argument's. None may be left,
// whether the call succeeds or is refused.
import assert from "node:assert/strict";

import { PHRASE, REDUCED_COST_CONTAINER } from "../public-test-data.mjs";
import { expectMessage } from "./expect.mjs";
import {
  bindings,
  drawWithoutWishes,
  instanceOver,
  noop,
  packageWasm,
  realArgon2,
  testRandom,
} from "./package.mjs";
import {
  CHECKED_PHRASE,
  KNOWN_ANSWER_COSTS,
  PASSWORD,
  PHRASE_TREZOR_FINGERPRINT,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  encode,
  noBytes,
  typedForm,
} from "./test-values.mjs";

// The core's and the wallet's bindings are the bindings of the package's one WebAssembly.
const core = bindings;
const wallet = bindings;

/** Twelve words whose checksum fails: an invalid phrase as long as a valid one. */
const INVALID_CHECKSUM = `${"abandon ".repeat(11)}abandon`;
/**
 * The allocator of the WebAssembly writes its own records over the first bytes of a block it
 * frees, so a copy left in a freed block is sought by the rest of the text.
 */
const FREED_BLOCK_RECORD_BYTES = 16;
/**
 * Runs `call(instance, bytes, copies)` with the UTF-8 bytes of `text` in a fresh instance of the
 * package's bindings and returns what it returned or threw and the copies of `text` left in its
 * memory; `copies()` counts them during the call.
 */
function copiesLeftBy(text, call) {
  const { instance, memory } = instanceOver(packageWasm);
  const needle = Buffer.from(text).subarray(FREED_BLOCK_RECORD_BYTES);
  assert.ok(needle.length >= FREED_BLOCK_RECORD_BYTES, `${JSON.stringify(text)} is long enough`);
  const copies = () => {
    // The memory may have grown during the call, which replaces its buffer.
    const heap = Buffer.from(memory.buffer);
    let found = 0;
    for (let at = heap.indexOf(needle); at !== -1; at = heap.indexOf(needle, at + 1)) found += 1;
    return found;
  };
  assert.equal(copies(), 0, `a fresh instance holds no copy of ${JSON.stringify(text)}`);
  let outcome;
  try {
    outcome = call(instance, encode(text), copies);
  } catch (error) {
    outcome = error;
  }
  return { outcome, copies: copies() };
}
/** The core's Argon2 at the reduced cost of part 1, its known answers unchanged. */
const reducedArgon2 = {
  derive: (password, salt, memoryKib, passes, key) =>
    KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)
      ? realArgon2.derive(password, salt, memoryKib, passes, key)
      : realArgon2.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key),
  reserve: noop,
};
const encryptBytes = (instance, phrase, repeat = PASSWORD.slice(), onRound = noop) =>
  JSON.parse(
    instance.encrypt(
      phrase,
      PASSWORD.slice(),
      repeat,
      "",
      0,
      0,
      0,
      false,
      0,
      false,
      reducedArgon2,
      onRound,
      noop,
    ),
  );
const refusedWith = (code) => (outcome) => outcome?.message?.startsWith(`${code}: `);
/** Each call that takes a phrase or another secret text, with what it must give. */
const PHRASE_CASES = [
  {
    name: "describePhrase",
    text: typedForm(PHRASE),
    call: (instance, bytes) => JSON.parse(instance.describePhrase(bytes)).phrase,
    expected: (outcome) => outcome === PHRASE,
  },
  {
    name: "describePhrase, refused",
    text: typedForm(INVALID_CHECKSUM),
    call: (instance, bytes) => instance.describePhrase(bytes),
    expected: refusedWith("INVALID_PHRASE"),
  },
  {
    name: "walletFingerprint",
    text: typedForm(PHRASE),
    call: (instance, bytes) => instance.walletFingerprint(bytes, encode("TREZOR")),
    expected: (outcome) => outcome === PHRASE_TREZOR_FINGERPRINT,
  },
  {
    name: "walletFingerprint, its passphrase refused",
    text: typedForm(PHRASE),
    call: (instance, bytes) => instance.walletFingerprint(bytes, new Uint8Array([0xff])),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  {
    name: "walletCheck",
    text: typedForm(CHECKED_PHRASE),
    call: (instance, bytes) => instance.walletCheck(bytes, encode("TREZOR")),
    expected: (outcome) => outcome === true,
  },
  {
    name: "walletCheck, refused without a passphrase",
    text: typedForm(CHECKED_PHRASE),
    call: (instance, bytes) => instance.walletCheck(bytes, noBytes()),
    expected: refusedWith("WALLET_CHECK_NEEDS_PASSPHRASE"),
  },
  {
    name: "encrypt",
    text: typedForm(PHRASE),
    // The measure finds the phrase while the binding holds it, from the first round's callback:
    // its absence afterwards is the wipe, not a copy the measure cannot see.
    call: (instance, bytes, copies) => {
      let during = null;
      const { container } = encryptBytes(instance, bytes, PASSWORD.slice(), (round) => {
        if (round === 1) during = copies();
      });
      return { container, during };
    },
    expected: ({ container, during }) => container === REDUCED_COST_CONTAINER && during === 1,
  },
  {
    name: "encrypt, refused before the phrase is read",
    text: typedForm(PHRASE),
    call: (instance, bytes) => encryptBytes(instance, bytes, encode("another password")),
    expected: refusedWith("PASSWORDS_DIFFER"),
  },
  {
    name: "encrypt, its phrase refused",
    text: typedForm(INVALID_CHECKSUM),
    call: (instance, bytes) => encryptBytes(instance, bytes),
    expected: refusedWith("INVALID_PHRASE"),
  },
  // The two passphrases of a new phrase are both held for wiping before either is read: a first
  // one that is not UTF-8 leaves no copy of its repetition (AUD-013-SEC001), and the other way
  // round.
  {
    name: "drawPhrase, its passphrase refused before its repetition is read",
    text: "public test passphrase repeated for the draw",
    call: (instance, bytes) =>
      drawWithoutWishes(instance, new Uint8Array([0xff]), bytes, true, testRandom),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  {
    name: "drawPhrase, its repetition refused",
    text: "public test passphrase typed first for the draw",
    call: (instance, bytes) =>
      drawWithoutWishes(instance, bytes, new Uint8Array([0xff]), true, testRandom),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  // A line for a hint may be part of a password or a seed phrase: wiped, and so is the result's
  // buffer, which tells its last letters.
  {
    name: "wordHints, its line",
    text: "public test line typed for a hint below it",
    // The words that begin with "it", which the result's wiped buffer held.
    call: (instance, bytes) => JSON.parse(instance.wordHints("eff", bytes)).hint,
    expected: (outcome) => outcome === "words",
  },
  // A chosen word is part of the new phrase: wiped after a description, a draw and a refusal,
  // also when the passphrase is refused before it is read. The padding makes the text long enough
  // to be sought; the word is read without the spaces around it.
  {
    name: "describeDraw, its chosen word",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      JSON.parse(instance.describeDraw(bytes, Uint32Array.from([1]), "", false)).randomness,
    expected: (outcome) => outcome === "ample",
  },
  {
    name: "drawPhrase, its chosen word",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      JSON.parse(
        instance.drawPhrase(
          noBytes(),
          noBytes(),
          bytes,
          Uint32Array.from([1]),
          "",
          false,
          testRandom,
          noop,
        ),
      ).words,
    expected: (outcome) => outcome === 24,
  },
  {
    name: "drawPhrase, its chosen word refused",
    text: "Notaword".padStart(40),
    call: (instance, bytes) =>
      instance.drawPhrase(
        noBytes(),
        noBytes(),
        bytes,
        Uint32Array.from([1]),
        "",
        false,
        testRandom,
        noop,
      ),
    expected: refusedWith("INVALID_WORD_WISH"),
  },
  {
    name: "drawPhrase, its chosen word after a refused passphrase",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      instance.drawPhrase(
        new Uint8Array([0xff]),
        noBytes(),
        bytes,
        Uint32Array.from([1]),
        "",
        false,
        testRandom,
        noop,
      ),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
];

/** Phrases reach the WebAssembly as bytes, and no copy of them stays in its memory. */
export function checkPhraseWipes() {
  for (const { name, text, call, expected } of PHRASE_CASES) {
    const { outcome, copies } = copiesLeftBy(text, call);
    assert.ok(expected(outcome), `${name}: ${outcome?.message ?? JSON.stringify(outcome)}`);
    assert.equal(copies, 0, `${name}: the phrase was wiped`);
  }
  // A phrase that is not UTF-8 is an invalid phrase, before any other work.
  const PHRASE_NOT_UTF8 =
    "INVALID_PHRASE: the seed phrase is not a valid English BIP39 phrase: it is not UTF-8 text";
  const notUtf8 = () => new Uint8Array([0x61, 0xff]);
  expectMessage(PHRASE_NOT_UTF8, () => core.describePhrase(notUtf8()));
  expectMessage(PHRASE_NOT_UTF8, () => wallet.walletFingerprint(notUtf8(), noBytes()));
  expectMessage(PHRASE_NOT_UTF8, () => wallet.walletCheck(notUtf8(), encode("TREZOR")));
  expectMessage(PHRASE_NOT_UTF8, () => encryptBytes(core, notUtf8()));
  console.log("Phrases reach the WebAssembly as bytes, and no copy of them stays in its memory.");
}
