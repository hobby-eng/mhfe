//! The re-encryption guard: a phrase recovered to be encrypted again comes out only once it is
//! confirmed, by its built-in check, by the wallet, or by its owner.

#[cfg(test)]
use crate::wallet::Fingerprint;

use std::sync::Arc;

use k256::elliptic_curve::subtle::ConstantTimeEq;

use super::{compare, Reference};
use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::engine::Argon2Engine;
use crate::memory::LockedBytes;
use crate::mhfe::{
    every_reading, read_same_length, recover, suite_3_state, PhraseLength, RecoveredPhrase,
    Recovery,
};
use crate::packing::STATE_WORDS;
use crate::suite::Suite;
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount, WorkFactor};

/// Private credentials of a recovered rekey capability, retained until its last token drops.
pub(crate) struct RekeyOrigin {
    facts: ContainerFacts,
    password: LockedBytes,
    work: WorkFactor,
}

impl RekeyOrigin {
    pub(crate) fn matches(
        &self,
        facts: &ContainerFacts,
        password: &Password,
        work: WorkFactor,
    ) -> bool {
        self.facts.words() == facts.words()
            && self.work == work
            && bool::from(self.password.ct_eq(password.as_bytes()))
    }
}

/// How a phrase recovered to be encrypted again is confirmed (the re-encryption guard).
#[derive(Clone, Copy)]
pub enum Confirmation<'a> {
    /// Its built-in check at the stated length: a 12- to 21-word original of a 24-word container
    /// only.
    BuiltInCheck,
    /// A receiving address or the fingerprint of the wallet, compared as the rehearsal check
    /// compares them.
    Wallet(&'a Reference<'a>),
    /// The owner compares the phrase with their backup and confirms it. The library cannot tell:
    /// the caller must show the phrase and go on only if the owner confirms it.
    Owner,
}

impl<'a> Confirmation<'a> {
    /// The reference of the wallet that confirms the phrase: an address or the fingerprint. The
    /// built-in check, the phrase's own checks given as a reference and the owner give none.
    pub fn wallet_reference(&self) -> Option<&'a Reference<'a>> {
        match self {
            Self::Wallet(reference) if reference.identifies_wallet() => Some(reference),
            _ => None,
        }
    }

    /// Refuses, before any Argon2 work, a confirmation that cannot confirm a phrase that needs
    /// `needed` (`REFERENCE_REQUIRED`): the built-in check where the length is not stated as one
    /// that has it, and the phrase's own checks given as a reference, which confirm no 24-word
    /// reading. With the length detected the built-in check alone is refused too: a 24-word
    /// original that passes a short check by chance, which encryption warns of, would be sealed
    /// again as that shorter phrase, another wallet (AUD-017-FUN001).
    pub fn refuse_for(&self, needed: ConfirmationNeeded) -> Result<(), MhfeError> {
        // A passphrase too long for any seed, before any work (AUD-024-API019).
        if let Some(passphrase) = self
            .wallet_reference()
            .and_then(|reference| reference.passphrase())
        {
            crate::wallet::require_passphrase_size(passphrase)?;
        }
        let refused = match needed {
            ConfirmationNeeded::BuiltInCheck => false,
            ConfirmationNeeded::WalletOrOwner => {
                matches!(self, Self::BuiltInCheck) || self.gives_own_checks()
            }
        };
        if refused {
            return Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceRequired,
            ));
        }
        Ok(())
    }

    /// A reference that does not identify the wallet, given where one should.
    fn gives_own_checks(&self) -> bool {
        matches!(self, Self::Wallet(reference) if !reference.identifies_wallet())
    }
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Recovers the phrase of `container` to encrypt it again under a new password or settings,
    /// and gives it only once it is confirmed (the re-encryption guard), as `confirmation` says:
    /// a 12- to 21-word original of a 24-word container passes its built-in check at the length
    /// `words` the owner states in every case, and a 24-word original or a same-length container,
    /// which have none, need a wallet reference or the owner. Encrypting the phrase again under the
    /// old password and comparing proves nothing, as that gives the same container for every
    /// password, so it is not a confirmation. Everything is checked before the first Argon2 call.
    pub fn recover_confirmed(
        &mut self,
        container: &str,
        password: &Password,
        words: WordCount,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        self.recover_confirmed_reporting(
            container,
            password,
            PhraseLength::Words(words),
            confirmation,
            on_progress,
            &mut || Ok(()),
        )
    }

    /// [`Mhfe::recover_confirmed`] for a `length` that may be detected, calling `before_compare`
    /// once the recovery's rounds are done and before a wallet reference is compared, which for an
    /// address can take seconds ([`RecoveredForRekey::confirm`]).
    pub(crate) fn recover_confirmed_reporting(
        &mut self,
        container: &str,
        password: &Password,
        length: PhraseLength,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
        before_compare: &mut dyn FnMut() -> Result<(), MhfeError>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        self.recover_for_rekey(container, password, length, confirmation, on_progress)?
            .confirm(length, confirmation, before_compare)
    }

    /// Recovers the state of `container` to confirm a phrase from it, once or again after a
    /// confirmation was refused, without the rounds again ([`RecoveredForRekey`]). `length` and
    /// `confirmation` are those of the first confirmation, which is refused here, before any
    /// Argon2 work, if it cannot confirm a phrase of that length.
    pub(crate) fn recover_for_rekey(
        &mut self,
        container: &str,
        password: &Password,
        length: PhraseLength,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredForRekey, MhfeError> {
        let facts = ContainerFacts::read(container)?;
        confirmation.refuse_for(facts.confirmation_needed(length)?)?;
        let (suite, state) = self.recover_state(container, password, None, on_progress)?;
        Ok(RecoveredForRekey {
            origin: Arc::new(RekeyOrigin {
                facts,
                password: LockedBytes::copy_of(password.as_bytes()),
                work: self.work_factor(),
            }),
            suite,
            state,
        })
    }
}

/// A container recovered to be encrypted again: its facts and state `X` in locked memory, from
/// which a phrase comes out only once confirmed (the re-encryption guard). A confirmation that is
/// refused, such as the built-in check where several lengths pass, can be followed by another
/// without the rounds again (AUD-017-UI002). It also retains a locked copy of the normalized old
/// password to bind rekey consumers to the source credentials. These sensitive capabilities allow
/// credential equality checks; the state and credentials are wiped when their last owner drops.
pub struct RecoveredForRekey {
    origin: Arc<RekeyOrigin>,
    suite: Suite,
    state: LockedBytes,
}

impl RecoveredForRekey {
    pub(crate) fn origin(&self) -> &Arc<RekeyOrigin> {
        &self.origin
    }

    /// The phrase of `length`, a stated word count or [`PhraseLength::Detect`], once
    /// `confirmation` confirms it. A 12- to 21-word original of a 24-word container passes its
    /// built-in check at the length the owner states; a 24-word original, a detected length or a
    /// same-length container, which the built-in check does not confirm, need a wallet reference
    /// or the owner. A reference given is compared with every reading, whatever length is stated,
    /// as the rehearsal check compares it (AUD-024-FUN008); `before_compare` is called before it
    /// is. The reading it matches says when its length is not the stated one. Several short lengths that pass by accident are refused with
    /// [`crate::CipherError::AmbiguousLength`], as one phrase is sealed, and a stated length the built-in
    /// check contradicts with [`crate::CipherError::LengthDiffers`].
    pub fn confirm(
        &self,
        length: PhraseLength,
        confirmation: Confirmation<'_>,
        before_compare: &mut dyn FnMut() -> Result<(), MhfeError>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        confirmation.refuse_for(self.origin.facts.confirmation_needed(length)?)?;
        if let Some(reference) = confirmation.wallet_reference() {
            // An address or the fingerprint tells the readings apart, as the rehearsal check
            // compares them: the one that matches is the wallet's.
            let readings = self.every_reading(length)?;
            before_compare()?;
            for reading in readings {
                if compare(reading.phrase(), reference)?.matches() {
                    return Ok(reading);
                }
            }
            return Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceMismatch,
            ));
        }
        let reading = one_reading(self.readings(length)?)?;
        let by_owner = matches!(confirmation, Confirmation::Owner);
        // A check that finds another length than the one stated takes precedence, but seals the
        // phrase only once the wallet confirms it: the owner, who compares the phrase shown with
        // their backup, or a reference, asked for after this refusal.
        if let (Some(stated), false) = (reading.stated_words(), by_owner) {
            return Err(MhfeError::Cipher(crate::CipherError::LengthDiffers {
                stated,
                found: reading.words(),
            }));
        }
        // The built-in check confirms only a short reading that passed it; a 24-word reading has
        // none and is confirmed by a reference or the owner alone.
        if !by_owner && !reading.verified() {
            return Err(MhfeError::Format(crate::FormatError::VerifierMismatch));
        }
        // A stated length that selected this reading among several that pass: the built-in check
        // alone does not tell them apart, so a reference or the owner confirms it (the
        // specification's re-encryption rules).
        if !by_owner && !reading.other_lengths().is_empty() {
            let mut readings: Vec<usize> = reading.other_lengths().to_vec();
            readings.push(reading.words());
            readings.sort_unstable();
            readings.push(STATE_WORDS);
            return Err(MhfeError::Cipher(crate::CipherError::AmbiguousLength {
                readings,
            }));
        }
        Ok(reading)
    }

    /// The lengths the owner may state to compare one reading with their backup
    /// ([`Confirmation::Owner`]): the readings of a detection, less those the owner cannot tell
    /// from another, such as 24 words beside a short length whose check passes.
    pub fn lengths_the_owner_can_confirm(&self) -> Result<Vec<usize>, MhfeError> {
        let mut lengths = Vec::new();
        for words in self.origin.facts.phrase_lengths() {
            let length = PhraseLength::Words(WordCount::new(*words)?);
            if self.owner_can_confirm(length)? {
                lengths.push(*words);
            }
        }
        Ok(lengths)
    }

    /// Whether the owner can confirm the reading of `length` by comparing it with their backup:
    /// false where the owner could not tell it from another reading.
    pub fn owner_can_confirm(&self, length: PhraseLength) -> Result<bool, MhfeError> {
        if self.origin.facts.require_length(length).is_err() {
            return Ok(false);
        }
        // A stated short length whose check fails gives no reading to compare.
        let readings = match self.readings(length) {
            Err(MhfeError::Format(crate::FormatError::VerifierMismatch)) => return Ok(false),
            readings => readings?,
        };
        Ok(match one_reading(readings) {
            Ok(_) => true,
            Err(
                MhfeError::Cipher(crate::CipherError::LengthDiffers { .. })
                | MhfeError::Cipher(crate::CipherError::AmbiguousLength { .. }),
            ) => false,
            Err(other) => return Err(other),
        })
    }

    /// Every reading of the state worth comparing with a wallet, for a `length` the container
    /// allows: those of the length detection for a 24-word container, the one reading of a
    /// same-length one.
    fn every_reading(&self, length: PhraseLength) -> Result<Vec<RecoveredPhrase>, MhfeError> {
        self.origin.facts.require_length(length)?;
        match self.suite {
            Suite::TwentyFourWords => {
                every_reading(suite_3_state(&self.state)?, length).map_err(Into::into)
            }
            Suite::SameLength => Ok(vec![read_same_length(&self.state)?]),
        }
    }

    /// The readings of the state for `length`, under the length rules of recovery: a built-in
    /// check that passes takes precedence over a stated length.
    fn readings(&self, length: PhraseLength) -> Result<Vec<RecoveredPhrase>, MhfeError> {
        self.origin.facts.require_length(length)?;
        let recovery = match self.suite {
            Suite::TwentyFourWords => recover(suite_3_state(&self.state)?, length),
            Suite::SameLength => Ok(Recovery::Phrase(read_same_length(&self.state)?)),
        };
        Ok(match recovery? {
            Recovery::Phrase(phrase) => vec![phrase],
            Recovery::Ambiguous(readings) => readings,
        })
    }
}

/// The one reading the built-in check or the owner can confirm. Several are told apart only by a
/// receiving address or the fingerprint, or by a length stated among those that pass: lengths that
/// pass by accident (`AMBIGUOUS_LENGTH`), or one that passes beside 24 stated words
/// (`LENGTH_DIFFERS`), which encryption asked to keep.
fn one_reading(mut readings: Vec<RecoveredPhrase>) -> Result<RecoveredPhrase, MhfeError> {
    if readings.len() == 1 {
        return Ok(readings.remove(0));
    }
    let checked: Vec<&RecoveredPhrase> = readings
        .iter()
        .filter(|reading| reading.verified())
        .collect();
    if let [only] = checked[..] {
        if let Some(stated) = only.stated_words() {
            return Err(MhfeError::Cipher(crate::CipherError::LengthDiffers {
                stated,
                found: only.words(),
            }));
        }
    }
    Err(MhfeError::Cipher(crate::CipherError::AmbiguousLength {
        readings: readings.iter().map(RecoveredPhrase::words).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        reduced, test_password, wrong_password, ABANDON_12 as ABANDON, ABANDON_12_FINGERPRINT,
        ABANDON_24, AMBIGUOUS_12_21,
    };
    use crate::wallet;

    /// The re-encryption guard: a phrase comes out only once confirmed. A 12-word original in a
    /// 24-word container: its built-in check at the stated length.
    #[test]
    fn a_recovery_to_encrypt_again_is_confirmed_by_the_built_in_check_of_a_short_original() {
        let password = test_password();
        let wrong = wrong_password();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let twelve = WordCount::new(12).unwrap();
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::BuiltInCheck,
                none,
            )
            .unwrap();
        assert_eq!(phrase.phrase(), ABANDON);
        assert!(matches!(
            mhfe.recover_confirmed(&container, &wrong, twelve, Confirmation::BuiltInCheck, none),
            Err(MhfeError::Format(crate::FormatError::VerifierMismatch))
        ));
    }

    /// The re-encryption guard: a 24-word original has no check, so a reference or its owner
    /// confirms it.
    #[test]
    fn a_recovery_to_encrypt_again_of_a_24_word_original_needs_a_reference_or_its_owner() {
        let password = test_password();
        let wrong = wrong_password();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let twenty_four = WordCount::new(24).unwrap();

        // Refused without a reference, before any Argon2 call.
        const ART: &str = ABANDON_24;
        let container = mhfe
            .encrypt(ART, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let mut rounds = 0;
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::BuiltInCheck,
                &mut |_, _| {
                    rounds += 1;
                    Ok(())
                }
            ),
            Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceRequired
            ))
        ));
        assert_eq!(rounds, 0);
        let fingerprint = wallet::Fingerprint::of(ART, "").unwrap();
        let right = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&right),
                none,
            )
            .unwrap();
        assert_eq!(phrase.phrase(), ART);
        // The wrong password gives another valid phrase, which the reference refuses.
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &wrong,
                twenty_four,
                Confirmation::Wallet(&right),
                none
            ),
            Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceMismatch
            ))
        ));
        let other_passphrase = Reference::Fingerprint {
            fingerprint,
            passphrase: "TREZOR",
        };
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&other_passphrase),
                none
            ),
            Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceMismatch
            ))
        ));

        // The owner may confirm a 24-word original instead: the phrase comes out for showing.
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Owner,
                none,
            )
            .unwrap();
        assert_eq!(phrase.phrase(), ART);
    }

    /// A wallet reference confirms the reading it matches, whatever length the length rules give
    /// or the person states, as the rehearsal check compares it (AUD-024-FUN008): a 24-word
    /// original whose 12-word reading passes the built-in check too, and a 12-word original after
    /// a stated 21 words, which pass as well, was refused as ambiguous.
    #[test]
    fn a_wallet_reference_confirms_the_reading_it_matches_at_any_length() {
        use sha2::{Digest, Sha256};
        let password = test_password();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let words = |count| PhraseLength::Words(WordCount::new(count).unwrap());
        let fingerprint_of = |phrase: &str| Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(phrase, "").unwrap(),
            passphrase: "",
        };
        // The state of the 24-word phrase of entropy 0^16 || SHA-256(0^16)[..16] is that of the
        // 12-word phrase of 0^16 with its built-in check.
        let mut entropy = [0u8; 32];
        entropy[16..].copy_from_slice(&Sha256::digest([0u8; 16])[..16]);
        let both = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let container = mhfe
            .encrypt(&both, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let own = fingerprint_of(&both);
        for length in [PhraseLength::Detect, words(15), words(24)] {
            let reading = mhfe
                .recover_confirmed_reporting(
                    &container,
                    &password,
                    length,
                    Confirmation::Wallet(&own),
                    none,
                    &mut || Ok(()),
                )
                .unwrap();
            assert_eq!((reading.phrase(), reading.words()), (both.as_str(), 24));
        }

        let container = mhfe
            .encrypt(AMBIGUOUS_12_21, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let recovered = mhfe
            .recover_for_rekey(
                &container,
                &password,
                words(21),
                Confirmation::BuiltInCheck,
                none,
            )
            .unwrap();
        assert!(matches!(
            recovered.confirm(words(21), Confirmation::BuiltInCheck, &mut || Ok(())),
            Err(MhfeError::Cipher(
                crate::CipherError::AmbiguousLength { .. }
            ))
        ));
        let own = fingerprint_of(AMBIGUOUS_12_21);
        let reading = recovered
            .confirm(words(21), Confirmation::Wallet(&own), &mut || Ok(()))
            .unwrap();
        assert_eq!(
            (reading.phrase(), reading.words(), reading.stated_words()),
            (AMBIGUOUS_12_21, 12, Some(21))
        );
    }

    /// The re-encryption guard: a same-length container needs its own length, and a reference.
    #[test]
    fn a_recovery_to_encrypt_again_of_a_same_length_container_needs_a_reference() {
        let password = test_password();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let twelve = WordCount::new(12).unwrap();
        let twenty_four = WordCount::new(24).unwrap();
        let right = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(ABANDON_24, "").unwrap(),
            passphrase: "",
        };
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::SameLength, none)
            .unwrap();
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::BuiltInCheck,
                none
            ),
            Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceRequired
            ))
        ));
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&right),
                none
            ),
            Err(MhfeError::Format(
                crate::FormatError::LengthChoiceNotApplicable {
                    container_words: 12
                }
            ))
        ));
        let abandon = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes(ABANDON_12_FINGERPRINT),
            passphrase: "",
        };
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::Wallet(&abandon),
                none,
            )
            .unwrap();
        assert_eq!(phrase.phrase(), ABANDON);
    }
}
