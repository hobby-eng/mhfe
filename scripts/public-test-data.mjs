// The public test data that the checks of the browser package, the browser tests and the
// comparison of the command-line tool with the package share. Only public data: BIP39's all-zero
// phrases and containers of them under the public test password, and the self-checks' parts.

/** BIP39's all-zero 12-word phrase. */
export const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/** BIP39's all-zero 24-word phrase. */
export const ZERO_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/**
 * The container of PHRASE under "public test password" at the reduced cost of the tests, 256 KiB
 * and one pass (REDUCED_COST_CONTAINER in src/mhfe.rs).
 */
export const REDUCED_COST_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
/** The same at the same cost as a container of the phrase's own length (suite 4). */
export const REDUCED_COST_SAME_LENGTH_CONTAINER =
  "program adjust rain raven flip eternal spider bulb under soup enrich ensure";

/** Exact old-backup lists, including settings that a browser cannot execute. */
export const KEEP_OLD_CASES = [
  { options: undefined, expected: [{ item: "oldContainer" }, { item: "oldPasswords" }] },
  { options: {}, expected: [{ item: "oldContainer" }, { item: "oldPasswords" }] },
  {
    options: { pim: 3, memoryLevel: 0 },
    expected: [{ item: "oldContainer" }, { item: "oldPasswords" }, { item: "pim", value: 3 }],
  },
  {
    options: { pim: 0, memoryLevel: 2 },
    expected: [
      { item: "oldContainer" },
      { item: "oldPasswords" },
      { item: "memoryLevel", value: 2 },
    ],
  },
  {
    options: { pim: 3, memoryLevel: 2 },
    expected: [
      { item: "oldContainer" },
      { item: "oldPasswords" },
      { item: "pim", value: 3 },
      { item: "memoryLevel", value: 2 },
    ],
  },
];
/**
 * The same phrase and password at full size: the public vector zero-12, whose repair words an
 * independent implementation computed.
 */
export const FULL_SIZE_CONTAINER =
  "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
/** Packs to the first state of AMBIGUOUS_STATES in src/packing.rs, which also passes the 21-word check. */
export const AMBIGUOUS_12_WORDS =
  "essence drama mule dolphin bitter rain abandon abandon able human mule relax";

/**
 * The parts of each module's self-check in the order the library runs them, and the name it gives
 * each (src/self_check/sets.rs), with the parts a page adds (web/runtime.js): what the checks of
 * the browser package and the browser tests expect.
 */
export const SELF_CHECK_PARTS = {
  repair: ["bip39-words", "repair-words", "wallet-hashes", "bip39-seed", "bip32"],
  passwords: [
    "password-unicode",
    "password-check-word",
    "password-generator",
    "password-strength",
    "word-hints",
    "random-source",
  ],
  wallet: [
    "bip39-words",
    "wallet-hashes",
    "bip39-seed",
    "bip32",
    "addresses",
    "address-search",
    "wallet-check",
    "word-wishes",
    "word-hints",
    "random-source",
  ],
  core: [
    "cipher-hashes",
    "argon2",
    "cipher-rounds",
    "formats",
    "container-facts",
    "keep-advice",
    "password-unicode",
    "bip39-words",
    "repair-words",
    "container-search",
    "password-check-word",
    "wallet-hashes",
    "bip39-seed",
    "bip32",
    "addresses",
    "wallet-check",
    "hidden-wallets",
    "rekey",
    "rehearsal",
  ],
  labels: {
    "cipher-hashes": "Cipher hashes",
    argon2: "Argon2id",
    "argon2-sizes": "Argon2id at 64 and 256 MiB",
    "cipher-rounds": "Cipher rounds",
    formats: "Formats",
    "container-facts": "Container facts",
    "keep-advice": "Keep advice",
    "password-unicode": "Passwords (Unicode 17)",
    "bip39-words": "BIP39 words",
    "repair-words": "Repair words (MHFE-REPAIR-1)",
    "container-search": "Search for missing words",
    "password-check-word": "Password check word (MHFE-PASSWORD-CHECK-1)",
    "wallet-hashes": "Wallet hashes",
    "bip39-seed": "BIP39 seeds",
    bip32: "BIP32 keys",
    addresses: "Address encodings",
    "address-search": "Address search",
    "wallet-check": "Wallet check (MHFE-WALLET-CHECK-SEED-1)",
    "word-wishes": "Chosen word of a new phrase",
    "word-hints": "Word hints",
    "hidden-wallets": "Hidden wallets",
    rekey: "Rekey",
    rehearsal: "Rehearsal",
    "password-generator": "Password generator",
    "password-strength": "Password strength estimate",
    "random-source": "Random source",
    "memory-locking": "Locked memory",
    "core-dumps": "Core dumps",
    isolation: "Isolation",
    "hidden-input": "Hidden input",
    "browser-features": "Browser features",
    "package-parts": "Package parts",
    "page-encoding": "Text encoding of the page",
  },
};

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
/**
 * The client's TypeError for a walletHasPassphrase given but not a boolean, where encrypt takes
 * undefined and null as no answer and a rekey only undefined (web/client.js).
 */
export const WALLET_PASSPHRASE_REQUIRED =
  "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
/** A passphrase with the built-in check in a search, as the client refuses it. */
export const SEARCH_PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address, a fingerprint or the wallet check.";
/** A passphrase with the built-in check or the owner in a rekey, as the client refuses it. */
export const REKEY_PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address or a fingerprint.";
/**
 * The cost of the known answer of the page's Argon2 build, which every Argon2 operation runs before
 * its first round and after its last (src/engine/known_answers.rs), and of its larger ones at 64
 * and 256 MiB in the full self-check: these reach the real build unchanged.
 */
export const KNOWN_ANSWER_COSTS = ["1024/1", "65536/3", "262144/2"];
/** The suite of a 24-word container. */
export const SUITE_3 = "MHFE-BIP39-256-EXPERIMENTAL-3";
/** The suite of a container of the phrase's own length. */
export const SUITE_4 = "MHFE-BIP39-LP-EXPERIMENTAL-4";

/** The public replacement password used by native/browser rekey checks. */
export const NEW_PASSWORD = "another public test password";
/** BIP84's first receiving path for the all-zero test phrase. */
export const BIP84_PATH = "m/84'/0'/0'/0/0";
/** Page-owned self-check parts, before the library's component checks. */
export const PAGE_PARTS = ["browser-features", "package-parts", "page-encoding"];
