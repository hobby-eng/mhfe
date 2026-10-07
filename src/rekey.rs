//! Rekey: a container recovered with the old password and settings and sealed again with new ones
//! (the specification's re-encryption rules). The guard of a rekey lives here, for every front
//! end: the length of the phrase, the confirmation that the recovered phrase is the wallet's (rule
//! I14), and a new password or settings that actually change the container.

use std::cell::RefCell;

use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::engine::Argon2Engine;
use crate::mhfe::RecoveredPhrase;
use crate::operation::{Encryption, RoundCounter, Sealed, Stage, StageCallback};
use crate::rehearsal::{Confirmation, Reference};
use crate::{Mhfe, MhfeError, Password, WordCount, WorkFactor, ROUNDS};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// Rounds of a whole rekey: a recovery of 12, then an encryption with its check of 24.
const REKEY_ROUNDS: u32 = 3 * ROUNDS;

/// A phrase recovered for a rekey and confirmed, with whether its wallet has a BIP39 passphrase,
/// which the new container's keep list names.
pub struct ConfirmedPhrase {
    phrase: RecoveredPhrase,
    wallet_has_passphrase: bool,
}

impl ConfirmedPhrase {
    pub fn phrase(&self) -> &RecoveredPhrase {
        &self.phrase
    }

    /// What [`crate::operation::Sealed::keep`] takes for the wallet's passphrase.
    pub fn wallet_has_passphrase(&self) -> bool {
        self.wallet_has_passphrase
    }
}

/// One rekey of one container.
pub struct Rekey {
    container: ContainerFacts,
    words: WordCount,
    old_password: Password,
    old_work: WorkFactor,
}

impl Rekey {
    /// A rekey of `container`, whose phrase has `words` words: required for a 24-word container,
    /// which may hold any length, and optional for a same-length container, whose own length it
    /// must then be. `other_wallets_moved` is the owner's answer to the warning that the wallets
    /// other passwords open on this container change with the new one: only a yes lets it go on.
    /// Everything is checked here, before any Argon2 work.
    pub fn new(
        container: &str,
        words: Option<usize>,
        old_password: Password,
        old_work: WorkFactor,
        other_wallets_moved: bool,
    ) -> Result<Self, MhfeError> {
        if !other_wallets_moved {
            return Err(MhfeError::OtherWalletsNotConfirmed);
        }
        let container = ContainerFacts::read(container)?;
        let words = match (words, container.phrase_lengths()) {
            (Some(words), _) => WordCount::new(words)?,
            (None, [only]) => WordCount::new(*only)?,
            (None, _) => {
                return Err(MhfeError::InvalidRequest(
                    "the word count of the phrase is needed for a 24-word container".to_owned(),
                ))
            }
        };
        // Refuses a length the container cannot have.
        container.confirmation_needed(words)?;
        Ok(Self {
            container,
            words,
            old_password,
            old_work,
        })
    }

    pub fn words(&self) -> WordCount {
        self.words
    }

    /// How the recovered phrase must be confirmed: by its built-in check, or by the wallet or its
    /// owner.
    pub fn confirmation_needed(&self) -> ConfirmationNeeded {
        self.container
            .confirmation_needed(self.words)
            .expect("the length was checked when the rekey was made")
    }

    /// Refuses a new password and settings that would give the old container again: with the same
    /// settings the password must differ, compared after normalization, as the cipher takes it.
    pub fn check_new(
        &self,
        new_password: &Password,
        new_work: WorkFactor,
    ) -> Result<(), MhfeError> {
        if new_work == self.old_work && new_password.as_bytes() == self.old_password.as_bytes() {
            return Err(MhfeError::NewPasswordSameAsOld);
        }
        Ok(())
    }

    /// Recovers the phrase with the old password (rounds 1 to 12 of 36), confirmed as
    /// `confirmation` says. Where the length has a built-in check, only that check is taken, as
    /// the command-line tool offers only it. [`Confirmation::Owner`] returns the phrase for the
    /// owner to compare with their backup; the caller goes on only if the owner confirms it.
    ///
    /// `wallet_has_passphrase` is what the caller states about the wallet's BIP39 passphrase. A
    /// reference compared with a passphrase shows that the wallet has one, and a statement that
    /// says otherwise is refused. Nothing else shows it, so there it must be stated: not the
    /// built-in check, not the owner, and not a reference without a passphrase, which matches the
    /// phrase's wallet without one even when the owner's funds are under a passphrase. Both are
    /// judged before any Argon2 work.
    pub fn recover<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        confirmation: Confirmation<'_>,
        wallet_has_passphrase: Option<bool>,
        progress: StageCallback<'_>,
    ) -> Result<ConfirmedPhrase, MhfeError> {
        if mhfe.work_factor() != self.old_work {
            return Err(MhfeError::InvalidRequest(
                "the recovery must run at the old container's settings".to_owned(),
            ));
        }
        if self.confirmation_needed() == ConfirmationNeeded::BuiltInCheck
            && !matches!(confirmation, Confirmation::BuiltInCheck)
        {
            return Err(MhfeError::InvalidRequest(
                "this length has a built-in check, which confirms the phrase".to_owned(),
            ));
        }
        // A length without a built-in check needs a reference or the owner: refused first, as the
        // recovery would refuse it, so that the passphrase's answer is judged only after.
        if self.confirmation_needed() == ConfirmationNeeded::WalletOrOwner
            && matches!(
                confirmation,
                Confirmation::BuiltInCheck
                    | Confirmation::Wallet(
                        Reference::BuiltInCheck { .. } | Reference::WalletCheck { .. }
                    )
            )
        {
            return Err(MhfeError::ReferenceRequired);
        }
        let wallet_has_passphrase = wallet_passphrase(&confirmation, wallet_has_passphrase)?;
        let rounds = RoundCounter::starting_after(0, REKEY_ROUNDS);
        // Both callbacks report to the one progress of the caller, never at the same time.
        let progress = RefCell::new(progress);
        let phrase = mhfe.recover_confirmed_reporting(
            self.container.words(),
            &self.old_password,
            self.words,
            confirmation,
            &mut |round, _| rounds.report(Stage::Recover, round, &mut **progress.borrow_mut()),
            &mut || rounds.report(Stage::Compare, ROUNDS, &mut **progress.borrow_mut()),
        )?;
        Ok(ConfirmedPhrase {
            phrase,
            wallet_has_passphrase,
        })
    }

    /// Seals the recovered and confirmed `phrase` with the new password at the settings of `mhfe`
    /// (rounds 13 to 36), in a container of the old one's kind, with `repair_word_count` repair
    /// words if given. The settings are the engine's own, so that the refusal of the old password
    /// and settings judges what the encryption really uses. The old `Mhfe` should be dropped
    /// before `mhfe` is made, so that both work areas are never reserved at once.
    pub fn seal<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        confirmed: &ConfirmedPhrase,
        new_password: &Password,
        repair_word_count: Option<usize>,
        progress: StageCallback<'_>,
        on_unverified: &mut dyn FnMut(&str) -> Result<(), MhfeError>,
    ) -> Result<Sealed, MhfeError> {
        self.check_new(new_password, mhfe.work_factor())?;
        // A container of the old one's kind: 24 words, or the same length as the phrase.
        let suite = self.container.suite();
        let rounds = RoundCounter::starting_after(ROUNDS, REKEY_ROUNDS);
        let phrase = &confirmed.phrase.phrase;
        Encryption::new(phrase, suite, repair_word_count)?.run(
            mhfe,
            phrase,
            new_password,
            &mut |stage, round, _| rounds.report(stage, round, &mut *progress),
            on_unverified,
        )
    }
}

/// Whether the wallet has a BIP39 passphrase, from the confirmation and the caller's statement
/// (see [`Rekey::recover`]).
fn wallet_passphrase(
    confirmation: &Confirmation<'_>,
    stated: Option<bool>,
) -> Result<bool, MhfeError> {
    // Only a passphrase shows something: a reference without one proves nothing about another.
    let shown = match confirmation {
        Confirmation::Wallet(reference) => {
            reference.passphrase().is_some_and(|text| !text.is_empty())
        }
        Confirmation::BuiltInCheck | Confirmation::Owner => false,
    };
    match (shown, stated) {
        (true, Some(false)) => Err(MhfeError::InvalidRequest(
            "the wallet's BIP39 passphrase is stated otherwise than the reference shows".to_owned(),
        )),
        (true, _) => Ok(true),
        (false, Some(stated)) => Ok(stated),
        (false, None) => Err(MhfeError::InvalidRequest(
            "say whether the wallet has a BIP39 passphrase".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container_24() -> String {
        // Any valid 24-word phrase serves as a container's words for the checks before Argon2.
        crate::phrase::phrase_from_entropy(&[7u8; 32])
            .unwrap()
            .to_string()
    }

    fn password(text: &str) -> Password {
        Password::new(text).unwrap()
    }

    #[test]
    fn the_owner_must_confirm_that_other_wallets_are_safe() {
        let refused = Rekey::new(
            &container_24(),
            Some(24),
            password("old password"),
            WorkFactor::default(),
            false,
        );
        assert!(matches!(refused, Err(MhfeError::OtherWalletsNotConfirmed)));
    }

    #[test]
    fn a_24_word_container_needs_the_phrase_length() {
        let refused = Rekey::new(
            &container_24(),
            None,
            password("old password"),
            WorkFactor::default(),
            true,
        );
        assert!(matches!(refused, Err(MhfeError::InvalidRequest(_))));
        let rekey = Rekey::new(
            &container_24(),
            Some(12),
            password("old password"),
            WorkFactor::default(),
            true,
        )
        .unwrap();
        assert_eq!(
            rekey.confirmation_needed(),
            ConfirmationNeeded::BuiltInCheck
        );
    }

    #[test]
    fn the_same_password_and_settings_are_refused() {
        let rekey = Rekey::new(
            &container_24(),
            Some(24),
            password("old password"),
            WorkFactor::default(),
            true,
        )
        .unwrap();
        assert!(matches!(
            rekey.check_new(&password("old password"), WorkFactor::default()),
            Err(MhfeError::NewPasswordSameAsOld)
        ));
        assert!(rekey
            .check_new(&password("new password"), WorkFactor::default())
            .is_ok());
        assert!(rekey
            .check_new(&password("old password"), WorkFactor::new(1, 0).unwrap())
            .is_ok());
    }

    fn reduced(work: WorkFactor) -> Mhfe<crate::engine::NativeEngine> {
        use crate::engine::{Argon2Cost, NativeEngine};
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        Mhfe::with_engine(work, NativeEngine::reduced_for_tests(cost).unwrap())
    }

    /// The settings judged are the engine's own: a recovery at other settings than the old
    /// container's is refused, and so is sealing with the old password on an engine at the old
    /// settings, which would give the old container again.
    #[test]
    fn the_engines_settings_are_the_ones_judged() {
        const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";
        let none = &mut |_, _| Ok(());
        let old = password("public test password");
        let old_work = WorkFactor::default();
        let container = reduced(old_work)
            .encrypt(ABANDON, &old, crate::Suite::TwentyFourWords, none)
            .unwrap();
        let rekey = Rekey::new(
            &container,
            Some(12),
            password("public test password"),
            old_work,
            true,
        )
        .unwrap();
        let other_work = WorkFactor::new(1, 0).unwrap();
        assert!(matches!(
            rekey.recover(
                &mut reduced(other_work),
                Confirmation::BuiltInCheck,
                Some(false),
                &mut |_, _, _| { Ok(()) }
            ),
            Err(MhfeError::InvalidRequest(_))
        ));
        let phrase = rekey
            .recover(
                &mut reduced(old_work),
                Confirmation::BuiltInCheck,
                Some(false),
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        assert_eq!(
            *phrase.phrase().phrase,
            ABANDON.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        let unchanged = rekey.seal(
            &mut reduced(old_work),
            &phrase,
            &old,
            None,
            &mut |_, _, _| Ok(()),
            &mut |_| Ok(()),
        );
        assert!(matches!(unchanged, Err(MhfeError::NewPasswordSameAsOld)));
        let sealed = rekey
            .seal(
                &mut reduced(other_work),
                &phrase,
                &old,
                None,
                &mut |_, _, _| Ok(()),
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_ne!(sealed.container(), &*container);
    }

    /// An engine that must never run: the refusals below come before any Argon2 work.
    struct NoArgon2Calls;

    impl Argon2Engine for NoArgon2Calls {
        fn derive(&mut self, _: &[u8], _: &[u8; 16], _: &mut [u8; 32]) -> Result<(), MhfeError> {
            panic!("Argon2 ran for a rekey that should have been refused first");
        }
    }

    /// The wallet's passphrase, for the keep list: a reference with a passphrase shows it, a
    /// statement that says otherwise is refused, and everything else needs it stated.
    #[test]
    fn the_wallet_passphrase_is_shown_or_stated() {
        let fingerprint = |passphrase| Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase,
        };
        let without = fingerprint("");
        let with = fingerprint("TREZOR");
        let unstated = |result: Result<bool, MhfeError>| matches!(result, Err(MhfeError::InvalidRequest(text)) if text.contains("say whether"));
        let contradicted = |result: Result<bool, MhfeError>| matches!(result, Err(MhfeError::InvalidRequest(text)) if text.contains("stated otherwise"));
        // A reference without a passphrase shows nothing: the answer must be stated.
        assert!(unstated(wallet_passphrase(
            &Confirmation::Wallet(&without),
            None
        )));
        assert!(!wallet_passphrase(&Confirmation::Wallet(&without), Some(false)).unwrap());
        assert!(wallet_passphrase(&Confirmation::Wallet(&without), Some(true)).unwrap());
        // A reference with one shows it; a statement that says otherwise is refused.
        for stated in [None, Some(true)] {
            assert!(wallet_passphrase(&Confirmation::Wallet(&with), stated).unwrap());
        }
        assert!(contradicted(wallet_passphrase(
            &Confirmation::Wallet(&with),
            Some(false)
        )));
        for confirmation in [Confirmation::BuiltInCheck, Confirmation::Owner] {
            assert!(unstated(wallet_passphrase(&confirmation, None)));
            assert!(wallet_passphrase(&confirmation, Some(true)).unwrap());
            assert!(!wallet_passphrase(&confirmation, Some(false)).unwrap());
        }
    }

    #[test]
    fn a_missing_or_contradicting_statement_is_refused_before_any_work() {
        let rekey = Rekey::new(
            &container_24(),
            Some(12),
            password("old password"),
            WorkFactor::default(),
            true,
        )
        .unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        let refused = rekey.recover(
            &mut mhfe,
            Confirmation::BuiltInCheck,
            None,
            &mut |_, _, _| Ok(()),
        );
        assert!(matches!(refused, Err(MhfeError::InvalidRequest(_))));
        let same_length = Rekey::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            None,
            password("old password"),
            WorkFactor::default(),
            true,
        )
        .unwrap();
        let without = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "",
        };
        let unstated = same_length.recover(
            &mut mhfe,
            Confirmation::Wallet(&without),
            None,
            &mut |_, _, _| Ok(()),
        );
        assert!(
            matches!(unstated, Err(MhfeError::InvalidRequest(text)) if text.contains("say whether"))
        );
        let with = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "TREZOR",
        };
        let contradicted = same_length.recover(
            &mut mhfe,
            Confirmation::Wallet(&with),
            Some(false),
            &mut |_, _, _| Ok(()),
        );
        assert!(matches!(
            contradicted,
            Err(MhfeError::InvalidRequest(text)) if text.contains("stated otherwise")
        ));
        // A length without a built-in check refuses the built-in check first.
        let no_check = same_length.recover(
            &mut mhfe,
            Confirmation::BuiltInCheck,
            None,
            &mut |_, _, _| Ok(()),
        );
        assert!(matches!(no_check, Err(MhfeError::ReferenceRequired)));
    }

    /// A rekey confirmed by the fingerprint of a wallet with a passphrase lists the passphrase
    /// in what to keep, after the words and the password, with or without repair words.
    #[test]
    fn a_wallet_with_a_passphrase_keeps_it_after_a_rekey() {
        use crate::operation::KeepItem;
        const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";
        let work = WorkFactor::default();
        let old = password("public test password");
        let container = reduced(work)
            .encrypt(ABANDON, &old, crate::Suite::SameLength, &mut |_, _| Ok(()))
            .unwrap();
        let rekey = Rekey::new(&container, None, old, work, true).unwrap();
        let fingerprint = crate::wallet::master_fingerprint(ABANDON, "TREZOR").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "TREZOR",
        };
        let confirmed = rekey
            .recover(
                &mut reduced(work),
                Confirmation::Wallet(&reference),
                None,
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        assert!(confirmed.wallet_has_passphrase());
        for repair_words in [None, Some(4)] {
            let sealed = rekey
                .seal(
                    &mut reduced(work),
                    &confirmed,
                    &password("another public test password"),
                    repair_words,
                    &mut |_, _, _| Ok(()),
                    &mut |_| Ok(()),
                )
                .unwrap();
            let keep = sealed.keep(work, confirmed.wallet_has_passphrase());
            let mut expected = vec![
                KeepItem::ContainerWords(12),
                KeepItem::Password,
                KeepItem::Passphrase,
            ];
            if repair_words.is_some() {
                expected.push(KeepItem::RepairWords);
            }
            assert_eq!(keep.items(), expected.as_slice());
        }
    }
}
