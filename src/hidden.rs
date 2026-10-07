//! Hidden wallets (specification supplement: "A hidden wallet behind an honest disclosure"): every
//! other password opens another wallet on the same container, `H = D_P(Y)`, read at the state
//! width. Nothing records which passwords were used or how many, so the container alone tells
//! nothing about them.

use crate::container::ContainerFacts;
use crate::engine::Argon2Engine;
use crate::memory::LockedText;
use crate::mhfe::{read_as, suite_3_state, RecoveredPhrase};
use crate::packing;
use crate::suite::Suite;
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// The width a hidden wallet is read at on a 24-word container: the whole state.
const STATE_WORDS: usize = 24;

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
        let (_, x) = self.recover_state(
            container,
            password,
            Some(Suite::TwentyFourWords),
            on_progress,
        )?;
        let x = suite_3_state(&x)?;
        if passes_a_check(x, passphrase)? {
            return Err(MhfeError::HiddenWalletPassesCheck);
        }
        read_as(x, STATE_WORDS)
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
    /// A session on `container`, which must have 24 words, with the main wallet's passphrase,
    /// empty for a wallet without one. Refused before any Argon2 work otherwise.
    pub fn new(container: &str, main_passphrase: &str) -> Result<Self, MhfeError> {
        let facts = ContainerFacts::read(container)?;
        if !facts.opens_hidden_wallets() {
            return Err(MhfeError::InvalidContainer(
                "hidden wallets are opened on a 24-word container only".to_owned(),
            ));
        }
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

/// Whether a state would be read as a checked phrase: a short one that passes its built-in check,
/// or a new 24-word one that passes the wallet check with `passphrase`. The 24-word reading of a
/// state is the state itself.
fn passes_a_check(x: &packing::State, passphrase: &str) -> Result<bool, MhfeError> {
    if !packing::matching_short_lengths(x).is_empty() || wallet_check::passes(&x[..], passphrase)? {
        return Ok(true);
    }
    // mhfe decrypt reports a pass without a passphrase, so a hidden wallet must not pass that
    // either, whatever the main wallet's passphrase.
    Ok(!passphrase.is_empty() && wallet_check::passes(&x[..], "")?)
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
        // The same reading with the main wallet's empty passphrase is another seed, which fails.
        assert!(!passes_a_check(&state, "").unwrap());
        state[24..].copy_from_slice(&76_561u64.to_be_bytes());
        assert!(!passes_a_check(&state, "TREZOR").unwrap());
        // A reading that passes the check without a passphrase is refused as well, also when the
        // main wallet has one: mhfe decrypt would report that pass.
        state[24..].copy_from_slice(&98_918u64.to_be_bytes());
        assert!(passes_a_check(&state, "").unwrap());
        assert!(passes_a_check(&state, "TREZOR").unwrap());
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
