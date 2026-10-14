// The public test values of the checks of the browser package (scripts/verify-browser-package.mjs)
// and the texts they expect, exactly as the core, the worker and the classes give them. Only
// public data: the test passwords and passphrases, and the published values of BIP32 and BIP84.

/** The UTF-8 bytes of `text`, as a page passes a secret. */
export const encode = (text) => new TextEncoder().encode(text);
/** No bytes: an empty passphrase or repetition. */
export const noBytes = () => new Uint8Array();

/** What a rekey's recovery returns when the owner has nothing to answer: no phrase to compare, no
 * wallet check, and no passphrase for the new container's rehearsal. */
export const NOTHING_TO_ASK = {
  ownerCheck: null,
  walletCheck: null,
  rehearsalNeedsPassphrase: false,
};

/** The test password of the reduced-cost containers (REDUCED_COST_CONTAINER). */
export const PASSWORD = encode("public test password");
/** The new password of the rekeys. */
export const NEW_PASSWORD = encode("another public test password");
/** The same test password as text, as a page may pass it. */
export const TEST_PASSWORD = "public test password";
/** A public test passphrase, as text. */
export const TEST_PASSPHRASE = "public test passphrase";
/** Four Argon2 lanes need at least 32 KiB; 256 KiB and one pass match the native test. */
export const REDUCED_MEMORY_KIB = 256;
/** The passes of Argon2 at the reduced cost. */
export const REDUCED_PASSES = 1;
/** The master key fingerprint of PHRASE without a passphrase (BIP32 test vectors). */
export const PHRASE_FINGERPRINT = "73c5da0a";
/** The same with the BIP39 test passphrase "TREZOR" (src/wallet.rs). */
export const PHRASE_TREZOR_FINGERPRINT = "b4e3f5ed";
/** BIP84's published first address of PHRASE without a passphrase. */
export const PHRASE_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/** BIP84's first address of PHRASE with the passphrase "TREZOR" (src/wallet.rs). */
export const PHRASE_TREZOR_ADDRESS = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";
/**
 * "abandon" 21 times and "above proof fatigue", which passes the wallet check with "TREZOR" and
 * fails without a passphrase (TREZOR_COUNTER in src/wallet_check.rs).
 */
export const CHECKED_PHRASE = `${"abandon ".repeat(21)}above proof fatigue`;
// The core's refusals of the answer whether the wallet has a BIP39 passphrase, exactly as the
// WebAssembly throws them: the answer not given where nothing shows the passphrase, given against
// the reference's passphrase, or not a boolean (src/rekey.rs, src/wasm_api/core.rs).
/** The answer not given where nothing shows the passphrase. */
export const PASSPHRASE_UNSTATED =
  "INVALID_REQUEST: invalid request: say whether the wallet has a BIP39 passphrase";
/** The answer given against the passphrase the reference was compared with. */
export const PASSPHRASE_CONTRADICTED =
  "INVALID_REQUEST: invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows";
/** A reference without the passphrase for a wallet stated to have one (src/rekey.rs). */
export const PASSPHRASE_NOT_COMPARED =
  "INVALID_REQUEST: invalid request: the reference must be compared with the wallet's BIP39 passphrase, which it has";
/** An answer that is not a boolean. */
export const PASSPHRASE_ANSWER_NOT_BOOLEAN =
  "INVALID_REQUEST: invalid request: walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase";
// The refusal of a passphrase with the built-in check in a search, and with the built-in check or
// the owner in a rekey, naming the references that take one there
// (rehearsal::refuse_unused_passphrase).
/** A passphrase with the built-in check in a search. */
export const SEARCH_PASSPHRASE_WITHOUT_REFERENCE =
  "INVALID_REQUEST: invalid request: a BIP39 passphrase belongs only to an address, a fingerprint or the wallet check";
/** A passphrase with the built-in check or the owner in a rekey. */
export const REKEY_PASSPHRASE_WITHOUT_REFERENCE =
  "INVALID_REQUEST: invalid request: a BIP39 passphrase belongs only to an address or a fingerprint";
/**
 * The refusal of a count with the check word, one wording in the WebAssembly and in the class,
 * which adds a period (AUD-023-ARC007).
 */
export const CHECK_WORD_TAKES_NO_COUNT =
  'count belongs only to the kinds "words" and "characters": "checkWord" always gives 5 words ' +
  "and their check word";
/** A length without a built-in check confirmed by the built-in check (src/error.rs). */
export const REFERENCE_REQUIRED =
  "REFERENCE_REQUIRED: the built-in check alone does not confirm this recovery: a 24-word original seed phrase, a same-length container and a detected length need a receiving address or the master key fingerprint of the wallet, or the owner's comparison with the backup, before the phrase is encrypted again";
/**
 * The client's TypeError for a walletHasPassphrase given but not a boolean, where encrypt takes
 * undefined and null as no answer and a rekey only undefined (web/client.js).
 */
export const WALLET_PASSPHRASE_REQUIRED =
  "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
// The client's TypeErrors for a passphrase with the built-in check in a search and with the
// built-in check or the owner in a rekey (web/client.js), in the words of the core's refusals
// above, which they copy.
/** A passphrase with the built-in check in a search, as the client refuses it. */
export const SEARCH_PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address, a fingerprint or the wallet check.";
/** A passphrase with the built-in check or the owner in a rekey, as the client refuses it. */
export const REKEY_PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address or a fingerprint.";
/** Values that are not a boolean, which no answer whether the wallet has a passphrase may be. */
export const NOT_BOOLEAN_ANSWERS = ["no", "true", 1, 0, {}];
/**
 * The cost of the known answer of the page's Argon2 build, which every Argon2 operation runs before
 * its first round and after its last (src/engine/known_answers.rs), and of its larger ones at 64
 * and 256 MiB in the full self-check: these reach the real build unchanged.
 */
export const KNOWN_ANSWER_COSTS = ["1024/1", "65536/3", "262144/2"];
/** The self-test's fault where a round's published input gave another key (src/self_test.rs). */
export const argon2KeyFault = (round) => ({
  kind: "argon2-key",
  round,
  message: `first wrong round ${round} of 24: Argon2id returned another key for the published input, so the fault is in Argon2id`,
});
/** The error of an operation whose Argon2 build gave another answer (src/error.rs). */
export const argon2Refused = (detail) =>
  `SELF_CHECK_FAILED: the self-test failed: Argon2id: ${detail}. ` +
  "Do not use this program on this computer";
/** The suite of a 24-word container. */
export const SUITE_3 = "MHFE-BIP39-256-EXPERIMENTAL-3";
/** The suite of a container of the phrase's own length. */
export const SUITE_4 = "MHFE-BIP39-LP-EXPERIMENTAL-4";

/**
 * A phrase as a person may type it, in capitals with two spaces between the words: a form the
 * library never writes itself, so that a copy of it found in memory can only be the argument's.
 */
export const typedForm = (phrase) => phrase.toUpperCase().split(" ").join("  ");
