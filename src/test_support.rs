//! What the unit tests of several modules share: the real C engine at a tiny cost, which is the
//! code path of every release at full cost, the stand-ins for it, and the public test phrases,
//! states and password, so that each test builds its setting from one place.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::engine::{Argon2Cost, Argon2Engine, NativeEngine, KEY_BYTES, SALT_BYTES};
use crate::memory::LockedBytes;
use crate::packing::State;
use crate::{Mhfe, MhfeError, Password, Suite, WorkFactor};

/// 256 KiB and one pass: four Argon2 lanes need at least 32 KiB. The reduced-cost containers of
/// src/mhfe.rs and of the browser tests are made at the same cost.
pub(crate) const REDUCED_COST: Argon2Cost = Argon2Cost {
    memory_kib: 256,
    passes: 1,
};
/// BIP39's all-zero 12-word phrase.
pub(crate) const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP39's 12-word phrase of 0x7f bytes.
pub(crate) const LEGAL_12: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// The password of the public test vectors.
pub(crate) const TEST_PASSWORD: &str = "public test password";
/// One letter off [`TEST_PASSWORD`].
pub(crate) const WRONG_PASSWORD: &str = "public test passwore";
/// The master key fingerprint of [`ABANDON_12`] without a passphrase (BIP32 test vectors).
pub(crate) const ABANDON_12_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// Public states that pass two short checks at once. Each packs a short phrase whose state
/// happens to carry a valid 21-word verifier too, which occurs for about one state in 2^32;
/// they were found by searching counters after the ASCII text "MHFE ambiguous".
pub(crate) const AMBIGUOUS_STATES: [(&str, [usize; 2]); 3] = [
    (
        "4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad",
        [12, 21],
    ),
    (
        "4d48464520616d626967756f00000000d7215b3cc350c32cc955fd4e3e272edf",
        [15, 21],
    ),
    (
        "4d48464520616d626967756f7573207400000000643a0b3e565fd3c1659f6749",
        [18, 21],
    ),
];

pub(crate) fn state_from_hex(text: &str) -> State {
    hex::decode(text).unwrap().try_into().unwrap()
}

/// A packed state as the fixed array that `unpack` and detection read.
pub(crate) fn state_of(packed: &LockedBytes) -> &State {
    packed[..].try_into().unwrap()
}

/// Public test entropy of `length` bytes, every byte different.
pub(crate) fn entropy(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
        .collect()
}

/// An engine that must never run: a refusal must come before any Argon2 work.
pub(crate) struct NoArgon2Calls;

impl Argon2Engine for NoArgon2Calls {
    fn argon2id(
        &mut self,
        _: &[u8],
        _: &[u8; SALT_BYTES],
        _: u32,
        _: u32,
        _: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        panic!("Argon2 ran where a refusal should have come first");
    }
}

/// A stand-in for Argon2 in structural tests: a key that depends on password and salt.
pub(crate) struct HashEngine;

// A deliberate copy of the trait's signature, which an implementation repeats.
impl Argon2Engine for HashEngine {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        _: u32,
        _: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        key.copy_from_slice(&Sha256::digest([password, &salt[..]].concat()));
        Ok(())
    }
}

/// Present only in test builds. A release binary or WebAssembly module that contains this text
/// would contain the reduced test engine, and the release check fails.
#[used]
static REDUCED_COST_MARKER: &str = "MHFE-TEST-ONLY-REDUCED-ARGON2-COST";

/// The real C engine for fast unit tests: every call runs at [`REDUCED_COST`], whatever cost it
/// asks for. It exists only in test builds; the release check
/// `scripts/check-release-artifacts.sh` looks for [`REDUCED_COST_MARKER`] to prove it.
pub(crate) struct ReducedEngine(NativeEngine);

// A deliberate copy of the trait's signature, which an implementation repeats.
impl Argon2Engine for ReducedEngine {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        _: u32,
        _: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        let Argon2Cost { memory_kib, passes } = REDUCED_COST;
        self.0.argon2id(password, salt, memory_kib, passes, key)
    }
}

/// The real C engine at [`REDUCED_COST`] under the settings `work`.
pub(crate) fn reduced_at(work: WorkFactor) -> Mhfe<ReducedEngine> {
    assert!(!REDUCED_COST_MARKER.is_empty());
    let engine = NativeEngine::allocate(REDUCED_COST.memory_bytes()).unwrap();
    Mhfe::with_engine(work, ReducedEngine(engine))
}

/// [`reduced_at`] the default settings.
pub(crate) fn reduced() -> Mhfe<ReducedEngine> {
    reduced_at(WorkFactor::default())
}

/// [`TEST_PASSWORD`] as a password.
pub(crate) fn test_password() -> Password {
    Password::new(TEST_PASSWORD).unwrap()
}

/// [`WRONG_PASSWORD`] as a password.
pub(crate) fn wrong_password() -> Password {
    Password::new(WRONG_PASSWORD).unwrap()
}

/// The container of `phrase` in `suite` under [`TEST_PASSWORD`], made by `mhfe`.
pub(crate) fn container_of(
    mhfe: &mut Mhfe<ReducedEngine>,
    phrase: &str,
    suite: Suite,
) -> Zeroizing<String> {
    mhfe.encrypt(
        phrase,
        &test_password(),
        suite,
        &mut |_, _| Ok(()),
        &mut |_| Ok(()),
    )
    .unwrap()
}

/// The public container of the suite 3 vector zero-12: [`ABANDON_12`] under [`TEST_PASSWORD`] at
/// full cost.
pub(crate) fn zero_12_container() -> String {
    crate::self_check::ZERO_12_CONTAINER.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zero_12_container_is_the_vectors() {
        let json = include_str!("../tests/spec/vectors/suite3/zero-12.json");
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(value["container"].as_str().unwrap(), zero_12_container());
    }
}
