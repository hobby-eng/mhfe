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
  repair: ["bip39-words", "repair-words"],
  passwords: [
    "password-unicode",
    "password-check-word",
    "password-generator",
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
    "random-source": "Random source",
    "browser-features": "Browser features",
    "package-parts": "Package parts",
    "page-encoding": "Text encoding of the page",
  },
};
