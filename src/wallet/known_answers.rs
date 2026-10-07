//! Known answers of the wallet: the self-checks `wallet-hashes`, `bip39-seed`, `bip32`,
//! `addresses` and `address-search`.
//!
//! The hashes the wallet code uses, BIP39 seeds with and without a passphrase that NFKD changes,
//! BIP32 derivation, one receiving address of each encoding at its path with a damaged copy of
//! each checksum that must be refused, and what an address check states it will search. The coin
//! vectors stay in this Rust code: a self-check's label and detail never name a coin or an
//! address, so that no page text carries them.

use bip39::{Language, Mnemonic};
use bitcoin_hashes::{hash160, Hash};

use super::{
    bip39_seed, find_address, master_fingerprint, parse_fingerprint, program_for, Address, Coin,
    DerivationPath, ExtendedKey, SearchLimits, HARDENED,
};
use crate::phrase::known_answers::TREZOR_ENGLISH;
use crate::self_check::{
    digest_outcome, expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, DigestCase,
    Findings, Tier,
};

fn sha512(_: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha512::digest(message).to_vec()
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::{KeyInit, Mac};
    let mut mac = <hmac::Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key)
        .expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn ripemd160(_: &[u8], message: &[u8]) -> Vec<u8> {
    bitcoin_hashes::ripemd160::Hash::hash(message)
        .to_byte_array()
        .to_vec()
}

fn bitcoin_sha256(_: &[u8], message: &[u8]) -> Vec<u8> {
    bitcoin_hashes::sha256::Hash::hash(message)
        .to_byte_array()
        .to_vec()
}

fn keccak256(_: &[u8], message: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    sha3::Keccak256::digest(message).to_vec()
}

/// RFC 4231 test case 6: a key longer than the block, which HMAC hashes first.
const LONG_KEY: [u8; 131] = [0xaa; 131];

const WALLET_DIGESTS: [DigestCase; 7] = [
    // FIPS 180-4, example "abc".
    DigestCase {
        algorithm: "SHA-512",
        function: sha512,
        key: b"",
        message: b"abc",
        expected: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                   2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
    // FIPS 180-4, the 896-bit message, which needs a second block.
    DigestCase {
        algorithm: "SHA-512",
        function: sha512,
        key: b"",
        message: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                   ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        expected: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                   501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    },
    // RFC 4231, test case 2.
    DigestCase {
        algorithm: "HMAC-SHA-512",
        function: hmac_sha512,
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                   9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    // RFC 4231, test case 6.
    DigestCase {
        algorithm: "HMAC-SHA-512",
        function: hmac_sha512,
        key: &LONG_KEY,
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                   6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
    // The RIPEMD-160 authors' test vector "abc".
    DigestCase {
        algorithm: "RIPEMD-160",
        function: ripemd160,
        key: b"",
        message: b"abc",
        expected: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    },
    // FIPS 180-4's SHA-256("abc") through bitcoin_hashes, which HASH160 uses.
    DigestCase {
        algorithm: "SHA-256",
        function: bitcoin_sha256,
        key: b"",
        message: b"abc",
        expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    // Keccak-256 of the empty string, the Keccak team's value, which @noble/hashes 2.4.0 gives
    // too; it differs from SHA3-256 (a7ffc6f8...) in its padding.
    DigestCase {
        algorithm: "Keccak-256",
        function: keccak256,
        key: b"",
        message: b"",
        expected: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    },
];

/// The `wallet-hashes` check: SHA-512, HMAC-SHA-512, RIPEMD-160, the SHA-256 of bitcoin_hashes
/// and Keccak-256 against their published values.
pub(crate) struct WalletHashesCheck {
    cases: &'static [DigestCase],
}

impl WalletHashesCheck {
    pub(crate) fn new() -> Self {
        Self {
            cases: &WALLET_DIGESTS,
        }
    }
}

impl ComponentCheck for WalletHashesCheck {
    fn id(&self) -> &'static str {
        "wallet-hashes"
    }

    fn label(&self) -> &'static str {
        "Wallet hashes"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        digest_outcome(self.cases)
    }
}

/// The public test phrase of BIP-0039, BIP-0084 and many wallets: "abandon" 11 times, "about".
const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon about";
/// The passphrase of the published vector unicode-password, which NFKD changes: Python's
/// unicodedata gives the bytes 43616665cc81206669205041cc8a3120f09f949020d0b8cc86.
const UNICODE_PASSPHRASE: &str = "Caf\u{e9} \u{fb01} \u{ff30}\u{212b}\u{2460} \u{1f510} \u{439}";

/// A BIP39 seed: phrase, passphrase and the 64-byte seed.
#[derive(Clone, Copy)]
struct SeedCase {
    phrase: &'static str,
    passphrase: &'static str,
    seed: &'static str,
}

const SEEDS: [SeedCase; 2] = [
    // BIP-0039's first English test vector, with the passphrase "TREZOR".
    SeedCase {
        phrase: ABANDON,
        passphrase: "TREZOR",
        seed: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
               1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    },
    // PBKDF2-HMAC-SHA512 of the same phrase with the salt "mnemonic" and the passphrase after
    // NFKD, computed with Python's hashlib, which first gave the vector above.
    SeedCase {
        phrase: ABANDON,
        passphrase: UNICODE_PASSPHRASE,
        seed: "d0d474bd6da672ba723cdaad52638bca7e0230db2de5b219bfc46d15b759148a\
               56fd39c552ea030a354311a0c67cb131c59ba19a44e5d870964b5cf1c5120fc7",
    },
];

/// The seeds of BIP-0039's 24 English test vectors with the passphrase "TREZOR", in the order of
/// [`TREZOR_ENGLISH`], reproduced with Python's hashlib.
const TREZOR_SEEDS: [&str; 24] = [
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
    "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
    "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
    "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
    "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
    "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
    "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
    "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
    "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
    "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
];

/// The master key fingerprint of [`ABANDON`] with "TREZOR", computed with a pure Python BIP32 that
/// first reproduced BIP-0032's test vectors; without a passphrase it is the published 73c5da0a.
const TREZOR_FINGERPRINT: [u8; 4] = [0xb4, 0xe3, 0xf5, 0xed];

/// The `bip39-seed` check.
pub(crate) struct SeedCheck {
    seeds: &'static [SeedCase],
    trezor_seeds: &'static [&'static str],
}

impl SeedCheck {
    pub(crate) fn new() -> Self {
        Self {
            seeds: &SEEDS,
            trezor_seeds: &TREZOR_SEEDS,
        }
    }

    fn seed(phrase: &str, passphrase: &str, expected: &str) -> Result<(), String> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| "the built-in cases are damaged".to_owned())?;
        let seed = bip39_seed(&mnemonic, passphrase);
        expect(hex::encode(&seed[..]) == expected, "differs")
    }
}

impl ComponentCheck for SeedCheck {
    fn id(&self) -> &'static str {
        "bip39-seed"
    }

    fn label(&self) -> &'static str {
        "BIP39 seeds"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("seed", self.seeds, |case| {
            Self::seed(case.phrase, case.passphrase, case.seed)
        });
        findings.one(|| {
            let fingerprint = master_fingerprint(ABANDON, "TREZOR").map_err(stopped)?;
            expect(
                fingerprint == TREZOR_FINGERPRINT,
                "a master key fingerprint differs",
            )
        });
        if tier == Tier::Full {
            let cases: Vec<(&str, &str)> = TREZOR_ENGLISH
                .iter()
                .map(|vector| vector.phrase)
                .zip(self.trezor_seeds.iter().copied())
                .collect();
            findings.one(|| {
                expect(
                    cases.len() == TREZOR_ENGLISH.len(),
                    "the built-in cases are damaged",
                )
            });
            findings.each("test vector seed", &cases, |&(phrase, seed)| {
                Self::seed(phrase, "TREZOR", seed)
            });
        }
        findings.outcome()
    }
}

/// A BIP-0032 test vector: the seed, the master key with its chain code, and one derived key.
#[derive(Clone, Copy)]
struct Bip32Case {
    seed: &'static str,
    master_key: &'static str,
    master_chain_code: &'static str,
    /// The master key's fingerprint, the first four bytes of HASH160 of its public key; empty
    /// when not checked.
    master_fingerprint: &'static str,
    path: &'static [u32],
    key: &'static str,
    chain_code: &'static str,
    /// The compressed public key of the derived key; empty when not checked.
    public_key: &'static str,
}

/// BIP-0032's test vectors 1 and 3, every value recomputed with a pure Python secp256k1. Vector 3
/// keeps the leading zero of its master key, which some implementations dropped.
const BIP32: [Bip32Case; 2] = [
    Bip32Case {
        seed: "000102030405060708090a0b0c0d0e0f",
        master_key: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        master_chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        master_fingerprint: "3442193e",
        // m/0H/1/2H/2/1000000000
        path: &[HARDENED, 1, 2 | HARDENED, 2, 1_000_000_000],
        key: "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        chain_code: "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
        public_key: "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
    },
    Bip32Case {
        seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac\
               ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        master_key: "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
        master_chain_code: "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f",
        master_fingerprint: "",
        // m/0H
        path: &[HARDENED],
        key: "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
        chain_code: "e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd",
        public_key: "",
    },
];

/// The `bip32` check.
pub(crate) struct Bip32Check {
    cases: &'static [Bip32Case],
}

impl Bip32Check {
    pub(crate) fn new() -> Self {
        Self { cases: &BIP32 }
    }

    fn vector(case: &Bip32Case) -> Result<(), String> {
        let seed =
            hex::decode(case.seed).map_err(|_| "the built-in cases are damaged".to_owned())?;
        let master = ExtendedKey::from_hmac(b"Bitcoin seed", &[&seed]).map_err(stopped)?;
        expect(
            hex::encode(&master.key[..]) == case.master_key
                && hex::encode(&master.chain_code[..]) == case.master_chain_code,
            "gives another master key",
        )?;
        if !case.master_fingerprint.is_empty() {
            let public_key = master.public_key().map_err(stopped)?;
            let fingerprint = &hash160::Hash::hash(&public_key).to_byte_array()[..4];
            expect(
                hex::encode(fingerprint) == case.master_fingerprint,
                "gives another fingerprint",
            )?;
        }
        let key = master.derive(case.path).map_err(stopped)?;
        expect(
            hex::encode(&key.key[..]) == case.key
                && hex::encode(&key.chain_code[..]) == case.chain_code,
            "gives another key",
        )?;
        if !case.public_key.is_empty() {
            expect(
                hex::encode(key.public_key().map_err(stopped)?) == case.public_key,
                "gives another public key",
            )?;
        }
        Ok(())
    }
}

impl ComponentCheck for Bip32Check {
    fn id(&self) -> &'static str {
        "bip32"
    }

    fn label(&self) -> &'static str {
        "BIP32 keys"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("test vector", self.cases, Self::vector);
        findings.one(|| {
            expect_refusal(parse_fingerprint("73c5da0g"), "INVALID_FINGERPRINT")
                .map_err(|what| format!("a fingerprint that is not hexadecimal {what}"))
        });
        findings.outcome()
    }
}

/// A receiving address of the test phrase [`ABANDON`] at its path.
#[derive(Clone, Copy)]
struct AddressCase {
    coin: Coin,
    passphrase: &'static str,
    path: &'static str,
    address: &'static str,
    /// One of each encoding, checked at every start; the others in the full self-test.
    startup: bool,
}

const fn at(coin: Coin, path: &'static str, address: &'static str, startup: bool) -> AddressCase {
    AddressCase {
        coin,
        passphrase: "",
        path,
        address,
        startup,
    }
}

/// Where the wallets of [`ABANDON`] put each address (the table of the wallet's unit tests). The
/// Bitcoin mainnet values at index 0 are the published vectors of BIP44, BIP49, BIP84 and BIP86,
/// and the Dash Platform values the official DIP17/DIP18 vectors; the other Bitcoin values were
/// computed with Python's hashlib, and the other coins with the audited JavaScript libraries
/// @scure/bip32, @noble/hashes, @noble/curves and @scure/base, and ethers for EIP-55, each of
/// which first reproduced BIP84's vector.
const ADDRESSES: [AddressCase; 43] = [
    at(
        Coin::Bitcoin,
        "m/44'/0'/0'/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/0'/0'/0/0",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/0/0",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/0/1",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/1/0",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/0'/0/0",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/0'/1/0",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/44'/0'/3'/1/7",
        "12DCYXCcRpBJ5VoWDvSijepPu8mshEihvX",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/0'/3'/1/7",
        "3K7gGbTWfdq3kyBgkVTMbhfftnrhxB6jpW",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/3'/1/7",
        "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/3'/1/7",
        "bc1preq6saz8z9zrn3clx9eaen0dcsynwseakek7nwqlrj52wd2dsfsqlfsyut",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/44'/1'/0'/0/0",
        "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/1'/0'/0/0",
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/1'/0'/0/0",
        "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/1'/0'/0/0",
        "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
        false,
    ),
    AddressCase {
        coin: Coin::Bitcoin,
        passphrase: "TREZOR",
        path: "m/84'/0'/0'/0/0",
        address: "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu",
        startup: false,
    },
    at(
        Coin::Ethereum,
        "m/44'/60'/0'/0/0",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        true,
    ),
    at(
        Coin::Ethereum,
        "m/44'/60'/3'/1/7",
        "0xc1A30611797762aea209daC2aC7E900f0cE95f9e",
        false,
    ),
    at(
        Coin::Xrp,
        "m/44'/144'/0'/0/0",
        "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        true,
    ),
    at(
        Coin::Xrp,
        "m/44'/144'/3'/1/7",
        "rnU3BdqhZk8DL3FKjQcaAyf3DJSoUZD8eM",
        false,
    ),
    at(
        Coin::Tron,
        "m/44'/195'/0'/0/0",
        "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        true,
    ),
    at(
        Coin::Tron,
        "m/44'/195'/3'/1/7",
        "TTD7MudE8L26nvnrEf2LHzXm6stKRpFZH1",
        false,
    ),
    at(
        Coin::Zcash,
        "m/44'/133'/0'/0/0",
        "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F",
        true,
    ),
    at(
        Coin::Zcash,
        "m/44'/133'/3'/1/7",
        "t1Pii1UXFrpcFucY5NBEFa664pymr7boHq4",
        false,
    ),
    at(
        Coin::Dogecoin,
        "m/44'/3'/0'/0/0",
        "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
        true,
    ),
    at(
        Coin::Dogecoin,
        "m/44'/3'/3'/1/7",
        "DNuJKZiVoQ6t67t8dE4NuBDhd2FNpMBsg6",
        false,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/0'/0/0",
        "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
        true,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/3'/1/7",
        "bitcoincash:qrhejavdmlfh9eajjxra3s3mn8gxls9hkvsq2yd62y",
        false,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/0'/0/0",
        "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg",
        false,
    ),
    // A wallet of this coin on another coin's type, under the coin's second root.
    at(
        Coin::BitcoinCash,
        "m/44'/0'/0'/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        false,
    ),
    at(
        Coin::Litecoin,
        "m/44'/2'/0'/0/0",
        "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
        true,
    ),
    at(
        Coin::Litecoin,
        "m/49'/2'/0'/0/0",
        "M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM",
        true,
    ),
    at(
        Coin::Litecoin,
        "m/84'/2'/3'/1/7",
        "ltc1qnnphcvq5zgyf4f0uepust6d7gyt2zl69vftnz2",
        false,
    ),
    at(
        Coin::EthereumClassic,
        "m/44'/61'/0'/0/0",
        "0xFA22515E43658ce56A7682B801e9B5456f511420",
        false,
    ),
    // A wallet of this coin on another coin's type, under the coin's second root.
    at(
        Coin::EthereumClassic,
        "m/44'/60'/0'/0/0",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        false,
    ),
    at(
        Coin::Cosmos,
        "m/44'/118'/0'/0/0",
        "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
        true,
    ),
    at(
        Coin::Cosmos,
        "m/44'/118'/3'/1/7",
        "cosmos1j8dc8g9sux68h924yj646shrsjmkd7g6fwevky",
        false,
    ),
    at(
        Coin::Injective,
        "m/44'/60'/0'/0/0",
        "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
        true,
    ),
    at(
        Coin::Dash,
        "m/44'/5'/0'/0/0",
        "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
        true,
    ),
    at(
        Coin::Dash,
        "m/44'/5'/3'/1/7",
        "XbAei18dD6mdL9LR6sTmbFJTQAJBcpxuxL",
        false,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/0'/0",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
        true,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/0'/1",
        "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw",
        false,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/1'/0",
        "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28",
        false,
    ),
];

/// Addresses of the table above with one character changed, one for each checksum: each must be
/// refused, never read as another address.
const DAMAGED: [(Coin, &str); 9] = [
    // Base58Check
    (Coin::Bitcoin, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB"),
    // Bech32 (BIP173)
    (Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv"),
    // Bech32m (BIP350)
    (
        Coin::Bitcoin,
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcs",
    ),
    // EIP-55: one capital made small.
    (Coin::Ethereum, "0x9858efFD232B4033E47d90003D41EC34EcaEda94"),
    // Base58Check with the other alphabet
    (Coin::Xrp, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4"),
    // CashAddr
    (
        Coin::BitcoinCash,
        "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q7",
    ),
    // Bech32 of an account
    (
        Coin::Cosmos,
        "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5",
    ),
    // Bech32m of DIP18
    (Coin::Dash, "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rt"),
    // Base58Check of a Keccak hash
    (Coin::Tron, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdJ"),
];

/// The master key fingerprint of [`ABANDON`] without a passphrase, the published 73c5da0a.
const ABANDON_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// Searches the full self-test runs: an address found under the second root of its coin, and one
/// at account 3, the change chain and index 7, within 4 accounts and 8 indexes.
const SEARCHES: [(usize, &str); 2] = [(29, "m/44'/0'/0'/0/0"), (9, "m/84'/0'/3'/1/7")];

/// The `addresses` check: the published master fingerprint, each address at its path derived from
/// one master key per passphrase, and the damaged addresses refused. The full self-test adds every
/// address of the table and two searches.
pub(crate) struct AddressesCheck {
    addresses: &'static [AddressCase],
    damaged: &'static [(Coin, &'static str)],
}

impl AddressesCheck {
    pub(crate) fn new() -> Self {
        Self {
            addresses: &ADDRESSES,
            damaged: &DAMAGED,
        }
    }

    fn address(case: &AddressCase, masters: &[(&str, ExtendedKey)]) -> Result<(), String> {
        let address = Address::parse(case.coin, case.address).map_err(stopped)?;
        let path: DerivationPath = case
            .path
            .parse()
            .map_err(|_| "the built-in cases are damaged".to_owned())?;
        let master = masters
            .iter()
            .find(|(passphrase, _)| *passphrase == case.passphrase)
            .map(|(_, master)| master)
            .ok_or_else(|| "the built-in cases are damaged".to_owned())?;
        let key = master.derive(&path.0).map_err(stopped)?;
        let program = program_for(&key, address.address_type).map_err(stopped)?;
        expect(program == address.program, "differs")
    }
}

impl ComponentCheck for AddressesCheck {
    fn id(&self) -> &'static str {
        "addresses"
    }

    fn label(&self) -> &'static str {
        "Address encodings"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let full = tier == Tier::Full;
        let mut findings = Findings::new();
        findings.one(|| {
            let fingerprint = master_fingerprint(ABANDON, "").map_err(stopped)?;
            expect(
                fingerprint == ABANDON_FINGERPRINT,
                "the master key fingerprint differs",
            )
        });
        let cases: Vec<AddressCase> = self
            .addresses
            .iter()
            .filter(|case| full || case.startup)
            .copied()
            .collect();
        // One master key for each passphrase, derived once: a BIP39 seed takes 2,048 rounds.
        let mut masters: Vec<(&str, ExtendedKey)> = Vec::new();
        for case in &cases {
            if masters
                .iter()
                .all(|(passphrase, _)| *passphrase != case.passphrase)
            {
                match ExtendedKey::master(ABANDON, case.passphrase) {
                    Ok(master) => masters.push((case.passphrase, master)),
                    Err(error) => findings.one(|| Err(stopped(error))),
                }
            }
        }
        findings.each("address", &cases, |case| Self::address(case, &masters));
        findings.each("damaged address", self.damaged, |&(coin, text)| {
            expect_refusal(Address::parse(coin, text), "INVALID_ADDRESS")
        });
        if full {
            findings.each("search", &SEARCHES, |&(index, expected)| {
                let case = self
                    .addresses
                    .get(index)
                    .ok_or_else(|| "the built-in cases are damaged".to_owned())?;
                let address = Address::parse(case.coin, case.address).map_err(stopped)?;
                let limits = SearchLimits::new(4, 8).map_err(stopped)?;
                let found = find_address(ABANDON, case.passphrase, &address, None, limits)
                    .map_err(stopped)?;
                expect(
                    found.map(|path| path.to_string()).as_deref() == Some(expected),
                    "finds the address elsewhere",
                )
            });
        }
        findings.outcome()
    }
}

/// The `address-search` check, built only where a program states an address search: natively and
/// in the browser's wallet module.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-wallet"))]
pub(crate) use address_search::AddressSearchCheck;

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-wallet"))]
mod address_search {
    use crate::self_check::{
        expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
    };
    use crate::wallet::{AddressSearch, Coin};

    /// What an address check states before it runs ([`AddressSearch::describe`]): the address type
    /// and the paths it searches with the default limits, ten accounts of a hundred receiving and a
    /// hundred change addresses, or the one path given.
    #[derive(Clone, Copy)]
    struct SearchCase {
        coin: Coin,
        address: &'static str,
        path: &'static str,
        type_description: Option<&'static str>,
        pattern: &'static str,
        addresses: u64,
        only_path: bool,
    }

    /// The paths come from the standards the addresses follow, each step written out: BIP44, BIP84
    /// and DIP17 give the purpose and coin type of the root, under which the accounts 0' to 9', the
    /// two chains and the indexes 0 to 99 lie. The addresses are those of [`super::ADDRESSES`].
    const SEARCHES_STATED: [SearchCase; 5] = [
        // BIP-0084's published first receiving address: purpose 84', coin type 0', 2 chains × 10
        // accounts × 100 indexes.
        SearchCase {
            coin: Coin::Bitcoin,
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            path: "",
            type_description: Some("native SegWit (BIP84)"),
            pattern: "m/84'/0'/0'-9'/0-1/0-99",
            addresses: 2_000,
            only_path: false,
        },
        // The same address at its one path, as BIP-0084 publishes it.
        SearchCase {
            coin: Coin::Bitcoin,
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            path: "m/84'/0'/0'/0/0",
            type_description: Some("native SegWit (BIP84)"),
            pattern: "m/84'/0'/0'/0/0",
            addresses: 1,
            only_path: true,
        },
        // A test network address: every Bitcoin test network uses coin type 1' (SLIP-0044).
        SearchCase {
            coin: Coin::Bitcoin,
            address: "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
            path: "",
            type_description: Some("testnet, native SegWit (BIP84)"),
            pattern: "m/84'/1'/0'-9'/0-1/0-99",
            addresses: 2_000,
            only_path: false,
        },
        // A coin with two coin types, 145' and Bitcoin's 0', searched under both roots: 4,000.
        SearchCase {
            coin: Coin::BitcoinCash,
            address: "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
            path: "",
            type_description: None,
            pattern: "m/44'/{145,0}'/0'-9'/0-1/0-99",
            addresses: 4_000,
            only_path: false,
        },
        // DIP17's feature path m/9'/5'/17'/account'/key class'/index, whose two key classes are
        // hardened.
        SearchCase {
            coin: Coin::Dash,
            address: "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
            path: "",
            type_description: Some("Platform payment (DIP17)"),
            pattern: "m/9'/5'/17'/0'-9'/0'-1'/0-99",
            addresses: 2_000,
            only_path: false,
        },
    ];

    /// A search an address check must refuse, as its texts are given, and the error code.
    #[derive(Clone, Copy)]
    struct RefusedSearch {
        coin: &'static str,
        address: &'static str,
        path: &'static str,
        code: &'static str,
    }

    /// An index of 2^31 without the hardened mark, which would name another path, an address of
    /// another coin, and a coin the check does not know.
    const SEARCHES_REFUSED: [RefusedSearch; 3] = [
        RefusedSearch {
            coin: "bitcoin",
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            path: "m/84'/0'/0'/0/2147483648",
            code: "INVALID_DERIVATION_PATH",
        },
        RefusedSearch {
            coin: "bitcoin",
            address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            path: "",
            code: "INVALID_ADDRESS",
        },
        RefusedSearch {
            coin: "no-such-coin",
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            path: "",
            code: "INVALID_COIN",
        },
    ];

    /// The `address-search` check: what an address check states it will search, compared whole, and
    /// the searches it must refuse. No key is derived, so every case runs at every start.
    pub(crate) struct AddressSearchCheck {
        stated: &'static [SearchCase],
        refused: &'static [RefusedSearch],
    }

    impl AddressSearchCheck {
        pub(crate) fn new() -> Self {
            Self {
                stated: &SEARCHES_STATED,
                refused: &SEARCHES_REFUSED,
            }
        }

        fn stated(case: &SearchCase) -> Result<(), String> {
            let search = AddressSearch::describe(case.coin.id(), case.address, case.path)
                .map_err(stopped)?;
            expect(
                search.type_description() == case.type_description
                    && search.pattern() == case.pattern
                    && search.addresses() == case.addresses
                    && search.only_path() == case.only_path,
                "is stated otherwise",
            )
        }
    }

    impl ComponentCheck for AddressSearchCheck {
        fn id(&self) -> &'static str {
            "address-search"
        }

        fn label(&self) -> &'static str {
            "Address search"
        }

        fn run(&mut self, _: Tier) -> ComponentOutcome {
            let mut findings = Findings::new();
            findings.each("search", self.stated, Self::stated);
            findings.each("wrong search", self.refused, |case| {
                expect_refusal(
                    AddressSearch::describe(case.coin, case.address, case.path),
                    case.code,
                )
            });
            findings.outcome()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_address_search_is_stated_as_known() {
            let mut check = AddressSearchCheck::new();
            for tier in [Tier::Startup, Tier::Full] {
                assert_eq!(check.run(tier), ComponentOutcome::Passed);
            }
            assert_eq!(
                (check.id(), check.label()),
                ("address-search", "Address search")
            );
            // Every address stated is one of the address table.
            for case in SEARCHES_STATED {
                assert!(super::super::ADDRESSES
                    .iter()
                    .any(|known| known.address == case.address));
            }
        }

        #[test]
        fn a_search_stated_otherwise_or_accepted_fails() {
            let mut stated = SEARCHES_STATED;
            // Nine accounts instead of ten.
            stated[0].pattern = "m/84'/0'/0'-8'/0-1/0-99";
            let mut check = AddressSearchCheck {
                stated: Box::leak(Box::new(stated)),
                ..AddressSearchCheck::new()
            };
            assert_eq!(
                check.run(Tier::Startup),
                ComponentOutcome::Failed("search 1 of 5 is stated otherwise".to_owned())
            );
            let mut stated = SEARCHES_STATED;
            stated[1].only_path = false;
            let mut check = AddressSearchCheck {
                stated: Box::leak(Box::new(stated)),
                ..AddressSearchCheck::new()
            };
            assert_eq!(
                check.run(Tier::Startup),
                ComponentOutcome::Failed("search 2 of 5 is stated otherwise".to_owned())
            );
            // The highest ordinary index is a valid path: a search there is accepted.
            let mut refused = SEARCHES_REFUSED;
            refused[0].path = "m/84'/0'/0'/0/2147483647";
            let mut check = AddressSearchCheck {
                refused: Box::leak(Box::new(refused)),
                ..AddressSearchCheck::new()
            };
            assert_eq!(
                check.run(Tier::Startup),
                ComponentOutcome::Failed(
                    "wrong search 1 of 3 is accepted instead of refused with \
                     INVALID_DERIVATION_PATH"
                        .to_owned()
                )
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wallet_checks_pass() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(WalletHashesCheck::new().run(tier), ComponentOutcome::Passed);
            assert_eq!(SeedCheck::new().run(tier), ComponentOutcome::Passed);
            assert_eq!(Bip32Check::new().run(tier), ComponentOutcome::Passed);
            assert_eq!(
                AddressesCheck::new().run(tier),
                ComponentOutcome::Passed,
                "{tier:?}"
            );
        }
        assert_eq!(ADDRESSES.iter().filter(|case| case.startup).count(), 18);
        assert_eq!(SEARCHES[0].1, ADDRESSES[SEARCHES[0].0].path);
        assert_eq!(SEARCHES[1].1, ADDRESSES[SEARCHES[1].0].path);
    }

    #[test]
    fn a_wrong_hash_function_fails() {
        fn sha3_256(_: &[u8], message: &[u8]) -> Vec<u8> {
            use sha3::Digest;
            sha3::Sha3_256::digest(message).to_vec()
        }
        let mut cases = WALLET_DIGESTS;
        cases[6].function = sha3_256;
        let mut check = WalletHashesCheck {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("Keccak-256 gives another digest".to_owned())
        );
    }

    #[test]
    fn a_corrupted_seed_or_key_fails() {
        let mut seeds = SEEDS;
        seeds[1].passphrase = "Caf\u{e9} \u{fb01} \u{ff30}\u{c5}\u{2460} \u{1f510} \u{439}";
        let mut check = SeedCheck {
            seeds: Box::leak(Box::new(seeds)),
            ..SeedCheck::new()
        };
        // U+00C5 and U+212B have the same NFKD: the seed stays the same.
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut seeds = SEEDS;
        seeds[1].passphrase = "Cafe \u{fb01} \u{ff30}\u{212b}\u{2460} \u{1f510} \u{439}";
        let mut check = SeedCheck {
            seeds: Box::leak(Box::new(seeds)),
            ..SeedCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("seed 2 of 2 differs".to_owned())
        );
        let mut trezor = TREZOR_SEEDS;
        trezor[23] = trezor[22];
        let mut check = SeedCheck {
            trezor_seeds: Box::leak(Box::new(trezor)),
            ..SeedCheck::new()
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        assert_eq!(
            check.run(Tier::Full),
            ComponentOutcome::Failed("test vector seed 24 of 24 differs".to_owned())
        );

        let mut cases = BIP32;
        cases[1].master_key = "ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae3200";
        let mut check = Bip32Check {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("test vector 2 of 2 gives another master key".to_owned())
        );
        let mut cases = BIP32;
        cases[0].path = &[HARDENED, 1, 2 | HARDENED, 2, 1_000_000_001];
        let mut check = Bip32Check {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("test vector 1 of 2 gives another key".to_owned())
        );
    }

    #[test]
    fn a_corrupted_or_accepted_address_fails() {
        let mut addresses = ADDRESSES;
        // The address of the next index, where the wallet does not put the case's path.
        addresses[2].path = "m/84'/0'/0'/0/1";
        let mut check = AddressesCheck {
            addresses: Box::leak(Box::new(addresses)),
            ..AddressesCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("address 3 of 18 differs".to_owned())
        );
        let mut damaged = DAMAGED;
        damaged[4].1 = "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3";
        let mut check = AddressesCheck {
            damaged: Box::leak(Box::new(damaged)),
            ..AddressesCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "damaged address 5 of 9 is accepted instead of refused with INVALID_ADDRESS"
                    .to_owned()
            )
        );
    }

    /// A self-check's detail never carries a coin's name or an address.
    #[test]
    fn details_name_no_coin() {
        let mut addresses = ADDRESSES;
        addresses[16].address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda95";
        let mut check = AddressesCheck {
            addresses: Box::leak(Box::new(addresses)),
            ..AddressesCheck::new()
        };
        let outcome = check.run(Tier::Startup);
        let detail = outcome.detail().unwrap();
        assert_eq!(detail, "address 7 of 18 stops with INVALID_ADDRESS");
        for coin in Coin::ALL {
            assert!(!detail.to_lowercase().contains(&coin.name().to_lowercase()));
            assert!(!detail.contains(coin.id()));
        }
        assert!(!check.label().contains("Bitcoin"));
    }
}
