//! Hidden wallets (specification supplement: "A hidden wallet behind an honest disclosure"): every
//! other password opens another wallet on the same container, `H = D_P(Y)`, read at the state
//! width. Nothing records which passwords were used or how many, so the container alone tells
//! nothing about them.

use crate::engine::Argon2Engine;
use crate::mhfe::{read_as, suite_3_state, RecoveredPhrase};
use crate::packing;
use crate::suite::Suite;
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback};

/// The width a hidden wallet is read at on a 24-word container: the whole state.
const STATE_WORDS: usize = 24;

impl<E: Argon2Engine> Mhfe<E> {
    /// The wallet that `password` opens on a 24-word container, read as 24 words. It has no
    /// built-in check. A password whose reading passes the check of a 12- to 21-word phrase, about
    /// once in a billion, is refused (rule I29): recovery would take the hidden wallet for that
    /// short phrase and call it verified. So is one whose reading passes the wallet check with
    /// `passphrase`, the main wallet's BIP39 passphrase, once in 65,536, which would make it look
    /// like the main wallet; without a passphrase there is no wallet check to pass. Only 24-word
    /// containers are taken for now; the same derivation on a same-length container would give
    /// wallets of its length.
    pub fn derive_wallet(
        &mut self,
        container: &str,
        password: &Password,
        passphrase: &str,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        let (_, x) = self.recover_state(
            container,
            password,
            Some(Suite::TwentyFourWords),
            on_progress,
        )?;
        let x = suite_3_state(&x)?;
        if passes_a_check(&x, passphrase)? {
            return Err(MhfeError::HiddenWalletPassesCheck);
        }
        read_as(&x, STATE_WORDS)
    }
}

/// Whether a state would be read as a checked phrase: a short one that passes its built-in check,
/// or a new 24-word one that passes the wallet check with `passphrase`. The 24-word reading of a
/// state is the state itself.
fn passes_a_check(x: &packing::State, passphrase: &str) -> Result<bool, MhfeError> {
    if !packing::matching_short_lengths(x).is_empty() {
        return Ok(true);
    }
    if passphrase.is_empty() {
        return Ok(false);
    }
    wallet_check::passes(&x[..], passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Argon2Cost, NativeEngine};
    use crate::{PhraseLength, Recovery, WorkFactor};

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn reduced() -> Mhfe<NativeEngine> {
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        Mhfe::with_engine(
            WorkFactor::default(),
            NativeEngine::reduced_for_tests(cost).unwrap(),
        )
    }

    #[test]
    fn another_password_opens_another_24_word_wallet() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = Password::new("public test password").unwrap();
        let hidden = Password::new("another public test password").unwrap();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::TwentyFourWords, none)
            .unwrap();

        let wallet = mhfe.derive_wallet(&container, &hidden, "", none).unwrap();
        assert_eq!(wallet.words, 24);
        assert!(!wallet.verified);
        assert_ne!(*wallet.phrase, ABANDON);
        // Recovery with the hidden password gives the same wallet, unverified.
        let Recovery::Phrase(recovered) = mhfe
            .decrypt(&container, &hidden, PhraseLength::Detect, none)
            .unwrap()
        else {
            panic!("one reading expected");
        };
        assert_eq!(*recovered.phrase, *wallet.phrase);
        assert!(!recovered.verified);
        // The same password gives the same wallet again: nothing needs to be written down.
        assert_eq!(
            *mhfe
                .derive_wallet(&container, &hidden, "", none)
                .unwrap()
                .phrase,
            *wallet.phrase
        );
    }

    /// Rule I29: the main password of a short phrase passes its check, so it is refused here.
    #[test]
    fn a_reading_that_passes_a_short_check_is_refused() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = Password::new("public test password").unwrap();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::TwentyFourWords, none)
            .unwrap();
        assert!(matches!(
            mhfe.derive_wallet(&container, &main, "", none),
            Err(MhfeError::HiddenWalletPassesCheck)
        ));
    }

    #[test]
    fn a_state_that_passes_the_wallet_check_is_refused() {
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut state = [0u8; packing::STATE_BYTES];
        state[24..].copy_from_slice(&76_562u64.to_be_bytes());
        assert!(passes_a_check(&state, "TREZOR").unwrap());
        // Without the main wallet's passphrase there is no wallet check to pass.
        assert!(!passes_a_check(&state, "").unwrap());
        state[24..].copy_from_slice(&76_561u64.to_be_bytes());
        assert!(!passes_a_check(&state, "TREZOR").unwrap());
    }

    #[test]
    fn a_same_length_container_is_not_taken_yet() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = Password::new("public test password").unwrap();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::SameLength, none)
            .unwrap();
        assert!(matches!(
            mhfe.derive_wallet(&container, &main, "", none),
            Err(MhfeError::InvalidContainer(_))
        ));
    }
}
