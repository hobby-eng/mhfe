//! Rekey: a container recovered with the old password and settings and sealed again with new ones
//! (the specification's re-encryption rules). The guard of a rekey lives here, for every front
//! end: the length of the phrase, the confirmation that the recovered phrase is the wallet's (rule
//! I14), and a new password or settings that actually change the container.

use std::cell::RefCell;

use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::engine::Argon2Engine;
use crate::mhfe::RecoveredPhrase;
use crate::operation::{Encryption, RoundCounter, Sealed, Stage, StageCallback};
use crate::rehearsal::{Confirmation, RecoveredForRekey};
use crate::{Mhfe, MhfeError, Password, PhraseLength, WorkFactor, ROUNDS};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// Rounds of a whole rekey: a recovery of 12, then an encryption with its check of 24.
const REKEY_ROUNDS: u32 = 3 * ROUNDS;

/// A phrase recovered for a rekey and confirmed, with whether its wallet has a BIP39 passphrase,
/// which the new container's keep list names. One confirmed by [`Confirmation::Owner`] awaits the
/// owner's explicit yes, given with [`ConfirmedPhrase::confirmed_by_owner`], and is not sealed
/// before it (the specification's re-encryption rules).
pub struct ConfirmedPhrase {
    phrase: RecoveredPhrase,
    wallet_has_passphrase: bool,
    awaits_owner: bool,
}

impl ConfirmedPhrase {
    pub fn phrase(&self) -> &RecoveredPhrase {
        &self.phrase
    }

    /// Whether the phrase still waits for the owner, who compares it with their backup or enters
    /// it into their wallet.
    pub fn awaits_owner(&self) -> bool {
        self.awaits_owner
    }

    /// The phrase once the owner has answered yes, explicitly: only then may it be sealed.
    pub fn confirmed_by_owner(self) -> Self {
        Self {
            awaits_owner: false,
            ..self
        }
    }

    /// Whether the wallet has a BIP39 passphrase, always known after a rekey's recovery;
    /// [`crate::operation::Sealed::keep`] takes it as a [`crate::operation::WalletPassphrase`].
    pub fn wallet_has_passphrase(&self) -> bool {
        self.wallet_has_passphrase
    }
}

/// One rekey of one container.
pub struct Rekey {
    container: ContainerFacts,
    length: PhraseLength,
    old_password: Password,
    old_work: WorkFactor,
}

impl Rekey {
    /// A rekey of `container`, whose phrase has the given `length`: a stated word count, or
    /// [`PhraseLength::Detect`] to detect it after the recovery (`detection`). A
    /// same-length container has its own length only. Nothing is destroyed: the old container
    /// keeps opening every wallet with its old passwords, so that a front end warns that funds at
    /// the old addresses of the wallets other passwords open on it are moved before the old
    /// container and its passwords are deleted. Everything is checked here, before any Argon2
    /// work.
    pub fn new(
        container: &str,
        length: PhraseLength,
        old_password: Password,
        old_work: WorkFactor,
    ) -> Result<Self, MhfeError> {
        let container = ContainerFacts::read(container)?;
        // Refuses a length the container cannot have.
        container.require_length(length)?;
        Ok(Self {
            container,
            length,
            old_password,
            old_work,
        })
    }

    /// The same rekey with the length stated, as after a detection that found several
    /// ([`MhfeError::AmbiguousLength`]): checked before any Argon2 work, as [`Rekey::new`] does.
    pub fn with_length(self, length: PhraseLength) -> Result<Self, MhfeError> {
        self.container.require_length(length)?;
        Ok(Self { length, ..self })
    }

    /// How the recovered phrase must be confirmed: by its built-in check at a stated 12- to 21-word
    /// length, or by the wallet or its owner, also for a detected length.
    pub fn confirmation_needed(&self) -> ConfirmationNeeded {
        self.container
            .confirmation_needed(self.length)
            .expect("the length was checked when the rekey was made")
    }

    /// Whether the owner can confirm the phrase of the rekey's length from `recovered` by
    /// comparing it with their backup ([`RecoveredForRekey::owner_can_confirm`]): a front end
    /// offers that answer only then.
    pub fn owner_can_confirm(&self, recovered: &RecoveredForRekey) -> Result<bool, MhfeError> {
        recovered.owner_can_confirm(self.length)
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
    /// `confirmation` says, under the length rules of recovery: [`Rekey::recover_state`], then
    /// [`Rekey::confirm`]. A front end that asks again after a refused confirmation calls the two
    /// itself, so that the rounds run once.
    pub fn recover<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        confirmation: Confirmation<'_>,
        wallet_has_passphrase: Option<bool>,
        progress: StageCallback<'_>,
    ) -> Result<ConfirmedPhrase, MhfeError> {
        // Judged before any Argon2 work: the confirmation first, as the recovery would refuse it,
        // then the passphrase's answer.
        confirmation.refuse_for(self.confirmation_needed())?;
        wallet_passphrase(&confirmation, wallet_has_passphrase)?;
        let progress = RefCell::new(progress);
        let recovered = self.recover_state(mhfe, confirmation, &mut |stage, round, total| {
            (*progress.borrow_mut())(stage, round, total)
        })?;
        self.confirm(
            &recovered,
            confirmation,
            wallet_has_passphrase,
            &mut |stage, round, total| (*progress.borrow_mut())(stage, round, total),
        )
    }

    /// The recovery of a rekey (rounds 1 to 12 of 36): the old container's state, from which
    /// [`Rekey::confirm`] takes the phrase once confirmed, as often as a confirmation is refused,
    /// without the rounds again. `confirmation` is the first one the caller will give, refused
    /// here before any Argon2 work if it cannot confirm a phrase of the rekey's length.
    pub fn recover_state<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        confirmation: Confirmation<'_>,
        progress: StageCallback<'_>,
    ) -> Result<RecoveredForRekey, MhfeError> {
        if mhfe.work_factor() != self.old_work {
            return Err(MhfeError::InvalidRequest(
                "the recovery must run at the old container's settings".to_owned(),
            ));
        }
        let rounds = RoundCounter::starting_after(0, REKEY_ROUNDS);
        mhfe.recover_for_rekey(
            self.container.words(),
            &self.old_password,
            self.length,
            confirmation,
            &mut |round, _| rounds.report(Stage::Recover, round, progress),
        )
    }

    /// The phrase of the rekey's length from `recovered`, once `confirmation` confirms it
    /// ([`RecoveredForRekey::confirm`]). The built-in check confirms a short phrase at the length
    /// it finds only when that length was stated; else the rekey is refused with
    /// [`MhfeError::LengthDiffers`], and a receiving address or the fingerprint must confirm it,
    /// which tells every reading apart (AUD-015-FUN001). With the length detected the built-in
    /// check alone is refused (AUD-017-FUN001). [`Confirmation::Owner`] returns the phrase for the
    /// owner to compare with their backup, awaiting the owner ([`ConfirmedPhrase::awaits_owner`]):
    /// it is sealed only after [`ConfirmedPhrase::confirmed_by_owner`], an explicit yes. The
    /// caller says first when the check found another length than the one stated
    /// ([`crate::RecoveredPhrase::stated_words`]).
    ///
    /// `wallet_has_passphrase` is what the caller states about the wallet's BIP39 passphrase. A
    /// reference compared with a passphrase shows that the wallet has one, and a statement that
    /// says otherwise is refused. Nothing else shows it, so there it must be stated: not the
    /// built-in check, not the owner, and not a reference without a passphrase, which matches the
    /// phrase's wallet without one even when the owner's funds are under a passphrase.
    pub fn confirm(
        &self,
        recovered: &RecoveredForRekey,
        confirmation: Confirmation<'_>,
        wallet_has_passphrase: Option<bool>,
        progress: StageCallback<'_>,
    ) -> Result<ConfirmedPhrase, MhfeError> {
        let wallet_has_passphrase = wallet_passphrase(&confirmation, wallet_has_passphrase)?;
        let rounds = RoundCounter::starting_after(0, REKEY_ROUNDS);
        let phrase = recovered.confirm(self.length, confirmation, &mut || {
            rounds.report(Stage::Compare, ROUNDS, progress)
        })?;
        Ok(ConfirmedPhrase {
            phrase,
            wallet_has_passphrase,
            awaits_owner: matches!(confirmation, Confirmation::Owner),
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
        // The owner's comparison is a confirmation only once the owner has said yes.
        if confirmed.awaits_owner {
            return Err(MhfeError::NotConfirmedByOwner);
        }
        self.check_new(new_password, mhfe.work_factor())?;
        // A container of the old one's kind: 24 words, or the same length as the phrase.
        let suite = self.container.suite();
        let rounds = RoundCounter::starting_after(ROUNDS, REKEY_ROUNDS);
        let phrase = &confirmed.phrase.phrase();
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
        Confirmation::Wallet(reference) => reference.given_passphrase().is_some(),
        Confirmation::BuiltInCheck | Confirmation::Owner => false,
    };
    let reference_without_passphrase = matches!(
        confirmation,
        Confirmation::Wallet(reference) if reference.given_passphrase().is_none()
    );
    match (shown, stated) {
        (true, Some(false)) => Err(MhfeError::InvalidRequest(
            "the wallet's BIP39 passphrase is stated otherwise than the reference shows".to_owned(),
        )),
        // A reference is compared with the wallet's passphrase when it has one (the
        // specification's re-encryption rules): without it, it would match the phrase's wallet
        // without one, which says nothing about the funds under the passphrase.
        (false, Some(true)) if reference_without_passphrase => Err(MhfeError::InvalidRequest(
            "the reference must be compared with the wallet's BIP39 passphrase, which it has"
                .to_owned(),
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
    use crate::rehearsal::Reference;

    fn container_24() -> String {
        // Any valid 24-word phrase serves as a container's words for the checks before Argon2.
        crate::phrase::phrase_from_entropy(&[7u8; 32])
            .unwrap()
            .to_string()
    }

    fn password(text: &str) -> Password {
        Password::new(text).unwrap()
    }

    fn words(count: usize) -> PhraseLength {
        PhraseLength::Words(crate::WordCount::new(count).unwrap())
    }

    #[test]
    fn a_24_word_container_takes_a_stated_or_detected_length() {
        let made = |length| {
            Rekey::new(
                &container_24(),
                length,
                password("old password"),
                WorkFactor::default(),
            )
            .unwrap()
            .confirmation_needed()
        };
        assert_eq!(made(words(12)), ConfirmationNeeded::BuiltInCheck);
        assert_eq!(made(words(24)), ConfirmationNeeded::WalletOrOwner);
        assert_eq!(
            made(PhraseLength::Detect),
            ConfirmationNeeded::WalletOrOwner
        );
    }

    #[test]
    fn the_same_password_and_settings_are_refused() {
        let rekey = Rekey::new(
            &container_24(),
            words(24),
            password("old password"),
            WorkFactor::default(),
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

    use crate::test_support::reduced_at as reduced;

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
            words(12),
            password("public test password"),
            old_work,
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
            phrase.phrase().phrase(),
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

    use crate::test_support::NoArgon2Calls;

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
        // A wallet said to have a passphrase is compared with it, never without.
        assert!(matches!(
            wallet_passphrase(&Confirmation::Wallet(&without), Some(true)),
            Err(MhfeError::InvalidRequest(text)) if text.contains("compared with the wallet's")
        ));
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
            words(12),
            password("old password"),
            WorkFactor::default(),
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
            PhraseLength::Detect,
            password("old password"),
            WorkFactor::default(),
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
        let rekey = Rekey::new(&container, PhraseLength::Detect, old, work).unwrap();
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
            let keep = sealed.keep(work, confirmed.wallet_has_passphrase().into());
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

    const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon about";

    /// A 24-word container of `phrase` under a public password at the reduced cost, with the
    /// rekey of it for `length`, stated or detected.
    fn rekey_of(phrase: &str, length: PhraseLength) -> Rekey {
        let old = password("public test password");
        let container = reduced(WorkFactor::default())
            .encrypt(phrase, &old, crate::Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        Rekey::new(&container, length, old, WorkFactor::default()).unwrap()
    }

    fn detected(phrase: &str) -> Rekey {
        rekey_of(phrase, PhraseLength::Detect)
    }

    fn stated(phrase: &str, length: usize) -> Rekey {
        rekey_of(phrase, words(length))
    }

    fn recover_detected(
        rekey: &Rekey,
        confirmation: Confirmation<'_>,
    ) -> Result<ConfirmedPhrase, MhfeError> {
        rekey.recover(
            &mut reduced(WorkFactor::default()),
            confirmation,
            Some(false),
            &mut |_, _, _| Ok(()),
        )
    }

    /// A stated length that the built-in check contradicts (AUD-015-FUN001): the check's reading
    /// takes precedence, but the built-in check alone does not confirm it; the wallet does, at a
    /// short length too, and the owner sees the reading with the length stated beside it.
    #[test]
    fn a_stated_length_the_check_contradicts_needs_the_wallet() {
        let fingerprint = Reference::Fingerprint {
            fingerprint: crate::wallet::master_fingerprint(ABANDON_12, "").unwrap(),
            passphrase: "",
        };
        let rekey = stated(ABANDON_12, 15);
        assert_eq!(
            recover_detected(&rekey, Confirmation::BuiltInCheck).err(),
            Some(MhfeError::LengthDiffers {
                stated: 15,
                found: 12
            })
        );
        let confirmed = recover_detected(&rekey, Confirmation::Wallet(&fingerprint)).unwrap();
        assert_eq!(confirmed.phrase().phrase(), ABANDON_12);
        let shown = recover_detected(&rekey, Confirmation::Owner).unwrap();
        assert_eq!(
            (shown.phrase().words(), shown.phrase().stated_words()),
            (12, Some(15))
        );

        // 24 words stated beside a passing check: the built-in check is refused before any work,
        // the owner cannot tell the two readings apart, and the fingerprint finds the 12-word one.
        let rekey = stated(ABANDON_12, 24);
        assert!(matches!(
            recover_detected(&rekey, Confirmation::BuiltInCheck),
            Err(MhfeError::ReferenceRequired)
        ));
        assert_eq!(
            recover_detected(&rekey, Confirmation::Owner).err(),
            Some(MhfeError::LengthDiffers {
                stated: 24,
                found: 12
            })
        );
        let confirmed = recover_detected(&rekey, Confirmation::Wallet(&fingerprint)).unwrap();
        assert_eq!(confirmed.phrase().phrase(), ABANDON_12);

        // The right length stated: the built-in check confirms it, and a reference may too.
        let rekey = stated(ABANDON_12, 12);
        assert!(recover_detected(&rekey, Confirmation::BuiltInCheck).is_ok());
        assert!(recover_detected(&rekey, Confirmation::Wallet(&fingerprint)).is_ok());
    }

    /// With the length detected the built-in check alone confirms nothing, before any Argon2 work
    /// (AUD-017-FUN001): a 24-word original may pass a short check by chance. A reference is
    /// compared with every reading: the right fingerprint finds the 12-word phrase, which passed
    /// its built-in check as well, and another is refused.
    #[test]
    fn a_detected_length_needs_the_wallet_or_the_owner() {
        let rekey = detected(ABANDON_12);
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        assert!(matches!(
            rekey.recover(
                &mut mhfe,
                Confirmation::BuiltInCheck,
                Some(false),
                &mut |_, _, _| Ok(())
            ),
            Err(MhfeError::ReferenceRequired)
        ));
        let fingerprint = |fingerprint| Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let right = fingerprint(crate::wallet::master_fingerprint(ABANDON_12, "").unwrap());
        let confirmed = recover_detected(&rekey, Confirmation::Wallet(&right)).unwrap();
        assert_eq!(confirmed.phrase().words(), 12);
        assert!(confirmed.phrase().verified());
        let other = fingerprint([0, 0, 0, 0]);
        assert!(matches!(
            recover_detected(&rekey, Confirmation::Wallet(&other)),
            Err(MhfeError::ReferenceMismatch)
        ));
    }

    /// With the length detected, a 24-word phrase has no built-in check: its fingerprint or the
    /// owner confirms it.
    #[test]
    fn a_detected_24_word_phrase_is_confirmed_by_the_wallet_or_the_owner() {
        let phrase = crate::phrase::phrase_from_entropy(&[7u8; 32])
            .unwrap()
            .to_string();
        let rekey = detected(&phrase);
        let reference = Reference::Fingerprint {
            fingerprint: crate::wallet::master_fingerprint(&phrase, "").unwrap(),
            passphrase: "",
        };
        let confirmed = recover_detected(&rekey, Confirmation::Wallet(&reference)).unwrap();
        assert_eq!(confirmed.phrase().phrase(), phrase);
        assert!(!confirmed.phrase().verified());
        let shown = recover_detected(&rekey, Confirmation::Owner).unwrap();
        assert_eq!(shown.phrase().words(), 24);

        // The owner's comparison confirms only after an explicit yes: before it nothing is sealed.
        assert!(shown.awaits_owner());
        let seal = |confirmed: &ConfirmedPhrase| {
            rekey.seal(
                &mut reduced(WorkFactor::new(1, 0).unwrap()),
                confirmed,
                &password("another public test password"),
                None,
                &mut |_, _, _| Ok(()),
                &mut |_| Ok(()),
            )
        };
        assert!(matches!(seal(&shown), Err(MhfeError::NotConfirmedByOwner)));
        let yes = shown.confirmed_by_owner();
        assert!(!yes.awaits_owner());
        assert!(seal(&yes).is_ok());
    }

    /// The phrase's own checks never confirm a rekey, and are refused before any Argon2 work.
    #[test]
    fn a_detected_length_refuses_the_own_checks_as_a_reference() {
        let rekey = Rekey::new(
            &container_24(),
            PhraseLength::Detect,
            password("old password"),
            WorkFactor::default(),
        )
        .unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        for reference in [
            Reference::WalletCheck {
                passphrase: "TREZOR",
            },
            Reference::OwnChecks { passphrase: None },
        ] {
            let refused = rekey.recover(
                &mut mhfe,
                Confirmation::Wallet(&reference),
                Some(true),
                &mut |_, _, _| Ok(()),
            );
            assert!(matches!(refused, Err(MhfeError::ReferenceRequired)));
        }
    }

    /// A phrase that detection reads as two short lengths, the published ambiguous-12-21 vector:
    /// one phrase is sealed, and the built-in check cannot tell the readings apart, also with a
    /// length stated among them; a fingerprint compares every reading and finds the phrase.
    #[test]
    fn an_ambiguous_detection_needs_the_wallet() {
        const AMBIGUOUS: &str =
            "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
        let fingerprint = Reference::Fingerprint {
            fingerprint: crate::wallet::master_fingerprint(AMBIGUOUS, "").unwrap(),
            passphrase: "",
        };
        let ambiguous = Some(MhfeError::AmbiguousLength {
            readings: vec![12, 21, 24],
        });
        let rekey = detected(AMBIGUOUS);
        let confirmed = recover_detected(&rekey, Confirmation::Wallet(&fingerprint)).unwrap();
        assert_eq!(confirmed.phrase().phrase(), AMBIGUOUS);
        let stated = stated(AMBIGUOUS, 12);
        assert_eq!(
            recover_detected(&stated, Confirmation::BuiltInCheck).err(),
            ambiguous
        );
        let shown = recover_detected(&stated, Confirmation::Owner).unwrap();
        assert_eq!(
            (shown.phrase().phrase(), shown.phrase().other_lengths()),
            (AMBIGUOUS, &[21][..])
        );
    }

    /// One recovery, several confirmations (AUD-017-UI002): a refused confirmation is followed by
    /// another without the rounds again, and the owner is offered only the lengths the library
    /// lets them confirm, never 24 words beside a short length that passes.
    #[test]
    fn a_refused_confirmation_is_followed_by_another_on_the_same_recovery() {
        const AMBIGUOUS: &str =
            "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
        let rekey = stated(AMBIGUOUS, 12);
        let state = rekey
            .recover_state(
                &mut reduced(WorkFactor::default()),
                Confirmation::BuiltInCheck,
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        let confirm = |rekey: &Rekey, state: &RecoveredForRekey, confirmation| {
            rekey.confirm(state, confirmation, Some(false), &mut |_, _, _| Ok(()))
        };
        assert!(matches!(
            confirm(&rekey, &state, Confirmation::BuiltInCheck),
            Err(MhfeError::AmbiguousLength { .. })
        ));
        assert_eq!(state.lengths_the_owner_can_confirm().unwrap(), [12, 21]);
        assert!(rekey.owner_can_confirm(&state).unwrap());
        let shown = confirm(&rekey, &state, Confirmation::Owner).unwrap();
        assert_eq!(shown.phrase().phrase(), AMBIGUOUS);
        let as_24 = stated(AMBIGUOUS, 24);
        assert!(!as_24.owner_can_confirm(&state).unwrap());

        // A stated length the check contradicts: the owner may confirm a short one, never 24.
        let rekey = stated(ABANDON_12, 15);
        let state = rekey
            .recover_state(
                &mut reduced(WorkFactor::default()),
                Confirmation::BuiltInCheck,
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        assert_eq!(
            confirm(&rekey, &state, Confirmation::BuiltInCheck).err(),
            Some(MhfeError::LengthDiffers {
                stated: 15,
                found: 12
            })
        );
        assert!(rekey.owner_can_confirm(&state).unwrap());
        assert!(!stated(ABANDON_12, 24).owner_can_confirm(&state).unwrap());
        assert_eq!(
            state.lengths_the_owner_can_confirm().unwrap(),
            [12, 15, 18, 21]
        );
    }
}
