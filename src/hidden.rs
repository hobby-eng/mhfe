//! Hidden wallets (specification supplement: "A hidden wallet behind an honest disclosure"): every
//! other password opens another wallet on the same container, `H = D_P(Y)`, read at the state
//! width. Nothing records which passwords were used or how many, so the container alone tells
//! nothing about them.

use crate::engine::Argon2Engine;
use crate::mhfe::{read_as, suite_3_state, RecoveredPhrase};
use crate::packing;
use crate::suite::Suite;
use crate::{Mhfe, MhfeError, Password, ProgressCallback};

/// The width a hidden wallet is read at on a 24-word container: the whole state.
const STATE_WORDS: usize = 24;

impl<E: Argon2Engine> Mhfe<E> {
    /// The wallet that `password` opens on a 24-word container, read as 24 words. It has no
    /// built-in check. A password whose reading passes the check of a 12- to 21-word phrase, about
    /// once in a billion, is refused (rule I29): recovery would take the hidden wallet for that
    /// short phrase and call it verified. Only 24-word containers are taken for now; the same
    /// derivation on a same-length container would give wallets of its length.
    pub fn derive_wallet(
        &mut self,
        container: &str,
        password: &Password,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        let (_, x) = self.recover_state(
            container,
            password,
            Some(Suite::TwentyFourWords),
            on_progress,
        )?;
        let x = suite_3_state(&x)?;
        if !packing::matching_short_lengths(&x).is_empty() {
            return Err(MhfeError::HiddenWalletPassesCheck);
        }
        read_as(&x, STATE_WORDS)
    }
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

        let wallet = mhfe.derive_wallet(&container, &hidden, none).unwrap();
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
                .derive_wallet(&container, &hidden, none)
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
            mhfe.derive_wallet(&container, &main, none),
            Err(MhfeError::HiddenWalletPassesCheck)
        ));
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
            mhfe.derive_wallet(&container, &main, none),
            Err(MhfeError::InvalidContainer(_))
        ));
    }
}
