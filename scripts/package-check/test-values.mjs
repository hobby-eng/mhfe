import { TEST_PASSWORD, NEW_PASSWORD as NEW_PASSWORD_TEXT } from "../public-test-data.mjs";
export {
  TEST_PASSWORD,
  TEST_PASSPHRASE,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  PHRASE_FINGERPRINT,
  PHRASE_TREZOR_FINGERPRINT,
  PHRASE_ADDRESS,
  PHRASE_TREZOR_ADDRESS,
  CHECKED_PHRASE,
  WALLET_PASSPHRASE_REQUIRED,
  SEARCH_PASSPHRASE_ONLY_WITH_REFERENCE,
  REKEY_PASSPHRASE_ONLY_WITH_REFERENCE,
  KNOWN_ANSWER_COSTS,
  SUITE_3,
  SUITE_4,
} from "../public-test-data.mjs";

// The public test values of the checks of the browser package (scripts/verify-browser-package.mjs)
// and the texts they expect, exactly as the core, the worker and the classes give them. Only
// public data: the test passwords and passphrases, and the published values of BIP32 and BIP84.

/** The UTF-8 bytes of `text`, as a page passes a secret. */
export const encode = (text) => new TextEncoder().encode(text);
/** No bytes: an empty passphrase or repetition. */
export const noBytes = () => new Uint8Array();

/** Complete synthetic evidence of a recovery whose checks found no length. */
export const NO_LENGTH_EVIDENCE = {
  builtInCheck: null,
  matchingLengths: [],
  walletCheck: null,
  passed: [],
};

/** What a rekey's recovery returns when the owner has nothing to answer: no phrase to compare, no
 * wallet check, and no passphrase for the new container's rehearsal. */
export const NOTHING_TO_ASK = {
  ownerCheck: null,
  walletCheck: null,
  rehearsalNeedsPassphrase: false,
};

/** The test password of the reduced-cost containers (REDUCED_COST_CONTAINER). */
export const PASSWORD = encode(TEST_PASSWORD);
/** The new password of the rekeys. */
export const NEW_PASSWORD = encode(NEW_PASSWORD_TEXT);
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
// The client's TypeErrors for a passphrase with the built-in check in a search and with the
// built-in check or the owner in a rekey (web/client.js), in the words of the core's refusals
// above, which they copy.
/** Values that are not a boolean, which no answer whether the wallet has a passphrase may be. */
export const NOT_BOOLEAN_ANSWERS = ["no", "true", 1, 0, {}];
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

/**
 * A phrase as a person may type it, in capitals with two spaces between the words: a form the
 * library never writes itself, so that a copy of it found in memory can only be the argument's.
 */
export const typedForm = (phrase) => phrase.toUpperCase().split(" ").join("  ");
