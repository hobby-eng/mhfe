//! Hidden wallets (specification supplement: "A hidden wallet behind an honest disclosure"): every
//! other password opens another wallet on the same container, `H = D_P(Y)`, read at the state
//! width. Nothing records which passwords were used or how many, so the container alone tells
//! nothing about them.

use crate::container::ContainerFacts;
use crate::detection::LengthDetection;
use crate::engine::Argon2Engine;
use crate::memory::LockedText;
use crate::mhfe::{read_as, suite_3_state, RecoveredPhrase};
use crate::suite::Suite;
use crate::{Mhfe, MhfeError, Password, ProgressCallback};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

impl<E: Argon2Engine> Mhfe<E> {
    /// The wallet that `password` opens on a 24-word container, read as 24 words. It has no
    /// built-in check. A password whose reading passes the check of a 12- to 21-word phrase, about
    /// once in a billion, is refused (rule I29): recovery would take the hidden wallet for that
    /// short phrase and call it verified. So is one whose reading passes the wallet check with
    /// `passphrase`, the main wallet's BIP39 passphrase, or without a passphrase, each once in
    /// 65,536, which would make it look like the main wallet or a checked one. Only 24-word
    /// containers are taken for now; the same derivation on a same-length container would give
    /// wallets of its length.
    pub fn derive_wallet(
        &mut self,
        container: &str,
        password: &Password,
        passphrase: &str,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        ContainerFacts::read(container)?.require_hidden_wallets()?;
        let (_, x) = self.recover_state(
            container,
            password,
            Some(Suite::TwentyFourWords),
            on_progress,
        )?;
        let x = suite_3_state(&x)?;
        if LengthDetection::of(x).reads_as_checked(passphrase)? {
            return Err(MhfeError::HiddenWalletPassesCheck);
        }
        // Read at the whole state's width, as 24 words.
        read_as(x, crate::packing::STATE_WORDS)
    }
}

/// A session of hidden wallets on one 24-word container: each password opens its own wallet, none
/// twice. The main wallet's BIP39 passphrase is given once, every time, so that asking for it tells
/// nothing about the main wallet. Nothing is created or stored: the container and each password
/// give the same wallet every time.
pub struct HiddenWallets {
    container: String,
    passphrase: LockedText,
    /// The passwords of this session, kept as the Password itself, whose buffer stays locked
    /// until it is wiped: a copy of its bytes would not be (AUD-008-SEC003).
    used: Vec<Password>,
}

impl HiddenWallets {
    /// The error codes of [`Self::open`] after which a session stays open for another password: a
    /// password used already, one whose wallet would pass a check, and a password refused before
    /// any work. Any other error ends the session.
    pub const KEEPS_SESSION_OPEN: [&'static str; 9] = [
        "PASSWORD_ALREADY_USED",
        "HIDDEN_WALLET_PASSES_CHECK",
        "PASSWORDS_DIFFER",
        "PASSWORD_REPAIR_NOT_OFFERED",
        "EMPTY_PASSWORD",
        "PASSWORD_TOO_LONG",
        "INVALID_PASSWORD_UTF8",
        "CONTROL_CHARACTER_IN_PASSWORD",
        "UNASSIGNED_CHARACTER",
    ];

    /// A session on `container`, which must have 24 words, with the main wallet's passphrase,
    /// empty for a wallet without one. Refused before any Argon2 work otherwise.
    pub fn new(container: &str, main_passphrase: &str) -> Result<Self, MhfeError> {
        let facts = ContainerFacts::read(container)?;
        facts.require_hidden_wallets()?;
        Ok(Self {
            container: facts.words().to_owned(),
            passphrase: LockedText::copy_of(main_passphrase),
            used: Vec::new(),
        })
    }

    /// Whether `password` opened a wallet of this session already, compared after normalization,
    /// as the cipher takes it: "é" typed either way is one password.
    pub fn was_used(&self, password: &Password) -> bool {
        self.used
            .iter()
            .any(|other| other.as_bytes() == password.as_bytes())
    }

    /// Opens the wallet of `password`, read as 24 words. A password used already is refused
    /// before any Argon2 work (PASSWORD_ALREADY_USED); one whose wallet would pass a check is
    /// refused after it (HIDDEN_WALLET_PASSES_CHECK, rule I29) and may be replaced by another.
    pub fn open<E: Argon2Engine>(
        &mut self,
        mhfe: &mut Mhfe<E>,
        password: Password,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        if self.was_used(&password) {
            return Err(MhfeError::PasswordAlreadyUsed);
        }
        let wallet =
            mhfe.derive_wallet(&self.container, &password, &self.passphrase, on_progress)?;
        self.used.push(password);
        Ok(wallet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{reduced, test_password, ABANDON_12 as ABANDON};
    use crate::{PhraseLength, Recovery};

    #[test]
    fn another_password_opens_another_24_word_wallet() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = test_password();
        let hidden = Password::new("another public test password").unwrap();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::TwentyFourWords, none)
            .unwrap();

        let wallet = mhfe.derive_wallet(&container, &hidden, "", none).unwrap();
        assert_eq!(wallet.words(), 24);
        assert!(!wallet.verified());
        assert_ne!(wallet.phrase(), ABANDON);
        // Recovery with the hidden password gives the same wallet, unverified.
        let Recovery::Phrase(recovered) = mhfe
            .decrypt(&container, &hidden, PhraseLength::Detect, none)
            .unwrap()
        else {
            panic!("one reading expected");
        };
        assert_eq!(recovered.phrase(), wallet.phrase());
        assert!(!recovered.verified());
        // The same password gives the same wallet again: nothing needs to be written down.
        assert_eq!(
            mhfe.derive_wallet(&container, &hidden, "", none)
                .unwrap()
                .phrase(),
            wallet.phrase()
        );
    }

    /// Rule I29: the main password of a short phrase passes its check, so it is refused here.
    #[test]
    fn a_reading_that_passes_a_short_check_is_refused() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = test_password();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::TwentyFourWords, none)
            .unwrap();
        assert!(matches!(
            mhfe.derive_wallet(&container, &main, "", none),
            Err(MhfeError::HiddenWalletPassesCheck)
        ));
    }

    #[test]
    fn a_same_length_container_is_not_taken_yet() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let main = test_password();
        let container = mhfe
            .encrypt(ABANDON, &main, Suite::SameLength, none)
            .unwrap();
        assert!(matches!(
            mhfe.derive_wallet(&container, &main, "", none),
            Err(MhfeError::NoHiddenWallets {
                container_words: 12
            })
        ));
    }
}
