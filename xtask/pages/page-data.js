// The fixed data of the browser check page, as the page's own `const` lines: public test data
// only. The page gets these lines between the package's classes and its checks (page.rs), and the
// reduced-cost wrapper of the worker takes FAULTY_CHECK_PASSWORD, MEMORY_FAILURE_PASSWORD and
// MEMORY_FAILURE_CONTAINER from here. The values are those of scripts/public-test-data.mjs and
// scripts/verify-browsers.mjs at commit f68d6c7 (2026-10-28). `cargo xtask package-check`, `cargo
// xtask parity` and `cargo xtask browser-check-page` take theirs from here too.
// The parts of each module's self-check in the order the library runs them, and the name it gives
// each (src/self_check/sets.rs), with the parts a page adds (web/runtime.js).
const SELF_CHECK = {"repair":["bip39-words","repair-words"],"passwords":["password-unicode","password-check-word","password-generator","word-hints","random-source"],"wallet":["bip39-words","wallet-hashes","bip39-seed","bip32","addresses","address-search","wallet-check","word-wishes","word-hints","random-source"],"core":["cipher-hashes","argon2","cipher-rounds","formats","container-facts","keep-advice","password-unicode","bip39-words","repair-words","container-search","password-check-word","wallet-hashes","bip39-seed","bip32","addresses","wallet-check","hidden-wallets","rekey","rehearsal"],"labels":{"cipher-hashes":"Cipher hashes","argon2":"Argon2id","argon2-sizes":"Argon2id at 64 and 256 MiB","cipher-rounds":"Cipher rounds","formats":"Formats","container-facts":"Container facts","keep-advice":"Keep advice","password-unicode":"Passwords (Unicode 18)","bip39-words":"BIP39 words","repair-words":"Repair words (MHFE-REPAIR-1)","container-search":"Search for missing words","password-check-word":"Password check word (MHFE-PASSWORD-CHECK-1)","wallet-hashes":"Wallet hashes","bip39-seed":"BIP39 seeds","bip32":"BIP32 keys","addresses":"Address encodings","address-search":"Address search","wallet-check":"Wallet check (MHFE-WALLET-CHECK-SEED-1)","word-wishes":"Chosen word of a new phrase","word-hints":"Word hints","hidden-wallets":"Hidden wallets","rekey":"Rekey","rehearsal":"Rehearsal","password-generator":"Password generator","random-source":"Random source","browser-features":"Browser features","package-parts":"Package parts","page-encoding":"Text encoding of the page"}};
// BIP39's all-zero 24-word phrase.
const ZERO_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
// BIP39's all-zero 12-word phrase.
const PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// The container of PHRASE under "public test password" at the reduced cost of the tests, 256 KiB
// and one pass (REDUCED_COST_CONTAINER in src/mhfe.rs).
const REDUCED_COST_CONTAINER = "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
// The same at the same cost as a container of the phrase's own length (suite 4).
const REDUCED_COST_SAME_LENGTH_CONTAINER = "program adjust rain raven flip eternal spider bulb under soup enrich ensure";
// The same phrase and password at full size: the public vector zero-12, whose repair words an
// independent implementation computed.
const FULL_SIZE_CONTAINER = "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
// The password of those containers.
const TEST_PASSWORD = "public test password";
// BIP84's published first address of PHRASE without a passphrase.
const BIP84_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
// Passes the wallet check with the passphrase "TREZOR" (TREZOR_COUNTER in src/wallet_check.rs).
const CHECKED_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon above proof fatigue";
// Passes the wallet check without a passphrase (EMPTY_COUNTER in src/wallet_check.rs).
const EMPTY_CHECKED_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb another spoil";
// Packs to the first state of AMBIGUOUS_STATES in src/packing.rs, which also passes the 21-word
// check.
const AMBIGUOUS_12_WORDS = "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
// The wrong password of the page, one letter off PASSWORD.
const WRONG_PASSWORD = "public test passwore";
// The 256-bit states of PHRASE and of AMBIGUOUS_12_WORDS read as other lengths. A state is the
// phrase's entropy followed by the first bytes of the entropy's SHA-256 (src/packing.rs): for
// PHRASE 16 zero bytes and the first 16 bytes of their SHA-256, for AMBIGUOUS_12_WORDS
// 4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad. These phrases were computed
// from those bytes with the BIP39 English list (SHA-256 of english.txt 2f5eed53...3b24dbda),
// independently of mhfe; the 21 words are the first 28 bytes, the 24 words all 32.
//
// wrongPasswordAs24 is what WRONG_PASSWORD reads from REDUCED_COST_CONTAINER as 24 words. It
// depends on the reduced cost, so it was taken once from the page; the page also encrypts it again
// with WRONG_PASSWORD, which must give REDUCED_COST_CONTAINER, the container of the native tests,
// back. The cipher is a permutation, so only the right 24 words do that.
const READINGS = {"phraseAs24":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about inner love zone until oven protect tray movie front reopen emerge bachelor","ambiguousAs21":"essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock","ambiguousAs24":"essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock simple dress sand","wrongPasswordAs24":"wash humor junk coil author glide void dynamic donor patrol beach outdoor result subject piece mix aim juice raise enjoy pattern name miracle pact"};
// The password whose encryption check the reduced-cost wrapper spoils.
const FAULTY_CHECK_PASSWORD = "public test password, faulty check";
// The password and the container for which the wrapper fails as a browser does that cannot give
// the Argon2 memory: in every round of the password, and when a session of hidden wallets on the
// container reserves its work area. The container is the public vector zero-12.
const MEMORY_FAILURE_PASSWORD = "public test password, memory refused";
const MEMORY_FAILURE_CONTAINER = "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
// The fingerprints and wallet checks of fixed public inputs, computed once, independently of
// mhfe's crates, from BIP39 and BIP32 alone with Node's crypto (Node v26.12.1, OpenSSL 3.5.9,
// scripts/verify-browsers.mjs lines 102-189 at commit f68d6c7, 2026-10-28): the computation first
// gave the published 73c5da0a and the b4e3f5ed of src/wallet.rs, both of the BIP39 test phrase.
// The wallet checks follow the definition of MHFE-WALLET-CHECK-SEED-1 in src/wallet_check.rs; that
// computation first gave the two public counters: CHECKED_PHRASE passes with "TREZOR" and not
// without, and EMPTY_CHECKED_PHRASE passes without.
const FINGERPRINTS = {"phrase":"73c5da0a","phraseWithTrezor":"b4e3f5ed","reducedCostContainer":"4eb1e81f","sameLengthContainer":"ac540b68","fullSizeContainer":"487a156e","checkedPhrase":"f219dad9","checkedPhraseWithTrezor":"bd7744bb","emptyCheckedPhrase":"3dbdb252","ambiguous12Words":"a58e92b5","phraseAs24":"b61c9f21","ambiguousAs21":"1d376894","ambiguousAs24":"16ee844f","wrongPasswordAs24":"09e6cccd"};
const WALLET_CHECKS = {"phraseAs24":false,"ambiguousAs24":false,"wrongPasswordAs24":false};
