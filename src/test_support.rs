//! What the unit tests of several modules share: the real C engine at a tiny cost, which is the
//! code path of every release at full cost, and the public test phrases and password, so that
//! each test builds its setting from one place.

use zeroize::Zeroizing;

use crate::engine::{Argon2Cost, Argon2Engine, NativeEngine};
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

/// An engine that must never run: a refusal must come before any Argon2 work.
pub(crate) struct NoArgon2Calls;

impl Argon2Engine for NoArgon2Calls {
    fn derive(&mut self, _: &[u8], _: &[u8; 16], _: &mut [u8; 32]) -> Result<(), MhfeError> {
        panic!("Argon2 ran where a refusal should have come first");
    }
}

/// The real C engine at [`REDUCED_COST`] under the settings `work`.
pub(crate) fn reduced_at(work: WorkFactor) -> Mhfe<NativeEngine> {
    Mhfe::with_engine(work, NativeEngine::reduced_for_tests(REDUCED_COST).unwrap())
}

/// [`reduced_at`] the default settings.
pub(crate) fn reduced() -> Mhfe<NativeEngine> {
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
    mhfe: &mut Mhfe<NativeEngine>,
    phrase: &str,
    suite: Suite,
) -> Zeroizing<String> {
    mhfe.encrypt(phrase, &test_password(), suite, &mut |_, _| Ok(()))
        .unwrap()
}

/// The public container of the suite 3 vector zero-12: [`ABANDON_12`] under [`TEST_PASSWORD`] at
/// full cost.
pub(crate) fn zero_12_container() -> String {
    crate::self_check::ZERO_12_CONTAINER.to_owned()
}

#[test]
fn the_zero_12_container_is_the_vectors() {
    let json = include_str!("../tests/fixtures/suite3-vectors/zero-12.json");
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(value["container"].as_str().unwrap(), zero_12_container());
}
