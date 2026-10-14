//! The fixed public inputs of the test vectors and negative cases: BIP39 test phrases and public
//! passwords, the only ones vectors are ever made from.

use super::{NegativeInput, PublicInput};

/// BIP39's all-zero 12-word phrase.
pub(crate) const ZERO_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP39's all-zero 24-word phrase.
pub(crate) const ZERO_24: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art";
pub(super) const ZERO_15: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon address";
const ZERO_18: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon agent";
const ZERO_21: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon admit";
/// BIP39's 12-word phrase of 0x7f bytes.
pub(crate) const NONZERO_12: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NONZERO_21: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice \
                          cage absurd amount doctor acoustic avoid letter advice cage absurd apart";
/// NFKD changes all but the spaces and the emoji: e + U+0301, "fi", "P", "A" + U+030A, "1",
/// and U+0438 U+0306.
pub(crate) const UNICODE_PASSWORD: &str =
    "Caf\u{E9} \u{FB01} \u{FF30}\u{212B}\u{2460} \u{1F510} \u{439}";
/// NFKD bytes of UNICODE_PASSWORD, independently reproduced with Python Unicode 17.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
pub(crate) const UNICODE_PASSWORD_NFKD: &str = "43616665cc81206669205041cc8a3120f09f949020d0b8cc86";
/// The BIP84 master fingerprint of ZERO_12 without a passphrase.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) const ZERO_12_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
/// One bit changed in the public fingerprint, for refusal cases.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) const WRONG_FINGERPRINT: [u8; 4] = {
    let mut fingerprint = ZERO_12_FINGERPRINT;
    fingerprint[3] ^= 1;
    fingerprint
};
/// The password of the public test vectors.
pub(crate) const TEST_PASSWORD: &str = "public test password";
/// A 12-word phrase whose packed state passes the 21-word built-in check too, by chance.
pub(crate) const AMBIGUOUS_12_21: &str =
    "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
const OTHER_PASSWORD: &str = "audit probe password 2026";

pub(super) const fn input(
    name: &'static str,
    phrase: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
) -> PublicInput {
    PublicInput {
        name,
        phrase,
        password,
        pim,
        memory_level,
    }
}

/// The suite 3 vector set: every phrase length with zero and non-zero entropy, a non-zero PIM, a
/// non-zero memory level and both together, a password that NFKD changes, a password with
/// leading, repeated and trailing spaces, and a phrase whose state passes two short checks.
pub const PUBLIC_INPUTS: [PublicInput; 17] = [
    input("zero-12", ZERO_12, TEST_PASSWORD, 0, 0),
    input("zero-15", ZERO_15, TEST_PASSWORD, 0, 0),
    input("zero-18", ZERO_18, TEST_PASSWORD, 0, 0),
    input("zero-21", ZERO_21, TEST_PASSWORD, 0, 0),
    input("zero-24", ZERO_24, TEST_PASSWORD, 0, 0),
    input("nonzero-12", NONZERO_12, OTHER_PASSWORD, 0, 0),
    input(
        "nonzero-15",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage \
         wise",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input(
        "nonzero-18",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount \
         doctor acoustic avoid letter always",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input("nonzero-21", NONZERO_21, OTHER_PASSWORD, 0, 0),
    input(
        "nonzero-24",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage \
         worth useful legal winner thank year wave sausage worth title",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input("zero-12-pim-1", ZERO_12, TEST_PASSWORD, 1, 0),
    input("zero-12-memory-level-1", ZERO_12, TEST_PASSWORD, 0, 1),
    input("zero-12-pim-1-memory-level-1", ZERO_12, TEST_PASSWORD, 1, 1),
    input("zero-24-pim-1-memory-level-1", ZERO_24, TEST_PASSWORD, 1, 1),
    input("unicode-password", ZERO_12, UNICODE_PASSWORD, 0, 0),
    // Leading, repeated and trailing spaces are part of the password: nothing is trimmed.
    input(
        "spaces-password",
        ZERO_12,
        "  public   test password  ",
        0,
        0,
    ),
    // Its state passes both the 12- and the 21-word check, so recovery lists both and the
    // 24-word reading.
    input("ambiguous-12-21", AMBIGUOUS_12_21, TEST_PASSWORD, 0, 0),
];

const fn negative(
    name: &'static str,
    container_of: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
    words: usize,
) -> NegativeInput {
    NegativeInput {
        name,
        container_of,
        password,
        pim,
        memory_level,
        words,
    }
}

/// Wrong password, PIM and memory level for a 12-word container; a wrong password for a 24-word
/// container, which has no check and yields another valid phrase; and the right password with
/// 24 words stated for a 12-word container: `selected-24-words`, the historical record of the
/// unverified 24-word reading alone, and `stated-24-words`, the recovery under the length rules,
/// the verified 12-word reading first and the 24-word one after it.
pub const NEGATIVE_INPUTS: [NegativeInput; 7] = [
    negative(
        "wrong-password-detect",
        "zero-12",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative(
        "wrong-password-12-words",
        "zero-12",
        "public test passworD",
        0,
        0,
        12,
    ),
    negative("wrong-pim", "zero-12", TEST_PASSWORD, 1, 0, 0),
    negative("wrong-memory-level", "zero-12", TEST_PASSWORD, 0, 1, 0),
    negative(
        "wrong-password-24-words",
        "zero-24",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative("selected-24-words", "zero-12", TEST_PASSWORD, 0, 0, 24),
    negative("stated-24-words", "zero-12", TEST_PASSWORD, 0, 0, 24),
];

/// The suite 4 vector set: every short length at the defaults, zero and non-zero entropy, a
/// non-zero PIM, memory level 1, both together, and a password that NFKD changes.
pub const SAME_LENGTH_INPUTS: [PublicInput; 10] = [
    input("same-length-zero-12", ZERO_12, TEST_PASSWORD, 0, 0),
    input("same-length-zero-15", ZERO_15, TEST_PASSWORD, 0, 0),
    input("same-length-zero-18", ZERO_18, TEST_PASSWORD, 0, 0),
    input("same-length-zero-21", ZERO_21, TEST_PASSWORD, 0, 0),
    input("same-length-nonzero-12", NONZERO_12, OTHER_PASSWORD, 0, 0),
    input("same-length-nonzero-21", NONZERO_21, OTHER_PASSWORD, 0, 0),
    input("same-length-zero-12-pim-1", ZERO_12, TEST_PASSWORD, 1, 0),
    input(
        "same-length-zero-12-memory-level-1",
        ZERO_12,
        TEST_PASSWORD,
        0,
        1,
    ),
    input(
        "same-length-zero-12-pim-1-memory-level-1",
        ZERO_12,
        TEST_PASSWORD,
        1,
        1,
    ),
    input(
        "same-length-unicode-password",
        ZERO_15,
        UNICODE_PASSWORD,
        0,
        0,
    ),
];

/// Suite 4 recoveries with a wrong password, PIM or memory level, which give another valid
/// phrase of the same length without any error, and with another length chosen, which is refused
/// before any Argon2 work.
pub const SAME_LENGTH_NEGATIVE_INPUTS: [NegativeInput; 4] = [
    negative(
        "same-length-wrong-password",
        "same-length-zero-12",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative(
        "same-length-wrong-pim",
        "same-length-zero-12",
        TEST_PASSWORD,
        1,
        0,
        0,
    ),
    negative(
        "same-length-wrong-memory-level",
        "same-length-zero-12",
        TEST_PASSWORD,
        0,
        1,
        0,
    ),
    negative(
        "same-length-other-length-chosen",
        "same-length-zero-12",
        TEST_PASSWORD,
        0,
        0,
        15,
    ),
];
