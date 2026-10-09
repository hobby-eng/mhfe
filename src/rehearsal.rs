//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! "matches" or "does not match", and on a match with an address the path where it was found.
//! No part of the recovered phrase leaves the check, and a wrong password gives no hint of how
//! close it was. The re-encryption guard uses the same comparison: a phrase recovered to be
//! encrypted again comes out only once it is confirmed.

use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::detection::LengthDetection;
use crate::engine::Argon2Engine;
use crate::memory::LockedBytes;
use crate::mhfe::{
    read_as, read_same_length, recover, suite_3_state, PhraseLength, RecoveredPhrase, Recovery,
};
use crate::operation::{RoundCounter, Stage, StageCallback};
use crate::packing::STATE_WORDS;
use crate::suite::{Suite, ROUNDS};
use crate::wallet::{self, Address, DerivationPath, SearchLimits};
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// What a rehearsal found. A match on a receiving address names the path where the address was
/// found, which tells the person which account and address of the wallet it is; it is not part of
/// the phrase and is given only on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Matches { path: Option<DerivationPath> },
    DoesNotMatch,
}

impl CheckOutcome {
    pub fn matches(&self) -> bool {
        matches!(self, Self::Matches { .. })
    }

    /// The path of a matched address; `None` for any other outcome.
    pub fn path(&self) -> Option<&DerivationPath> {
        match self {
            Self::Matches { path } => path.as_ref(),
            Self::DoesNotMatch => None,
        }
    }

    fn of(matches: bool) -> Self {
        if matches {
            Self::Matches { path: None }
        } else {
            Self::DoesNotMatch
        }
    }
}

/// What a check found, its reference's outcome first, and what the same recovery shows beside it:
/// a front end lists every check that passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckEvidence {
    /// How the recovery compared with the reference.
    pub outcome: CheckOutcome,
    /// The length of a 12- to 21-word original seed phrase whose built-in check passes, the
    /// stated one where it passes; `None` for a 24-word one and for a same-length container,
    /// which have none.
    pub built_in_check: Option<usize>,
    /// Whether the 24-word reading passes the phrase + passphrase check of `mhfe new` (the 16-bit
    /// source check) with the reference's passphrase, or the empty one where it has none, where
    /// that reading comes out: no short length's check passes, several do, or the reference
    /// matched the 24-word reading. `None` for the built-in check, for a same-length container,
    /// and when exactly one short length passes and the reference did not match the 24-word
    /// reading. A phrase drawn without that check fails it, so that only a pass says anything.
    pub wallet_check: Option<bool>,
}

/// What the recovered phrase is compared with.
pub enum Reference<'a> {
    /// The built-in check value of a 12-, 15-, 18- or 21-word original in a 24-word container,
    /// `words` the length the person states. As in recovery, a check that passes at another short
    /// length takes precedence and matches, and [`CheckEvidence::built_in_check`] names that
    /// length. It confirms that the recovery is consistent, not that it gives the same wallet, and
    /// it says nothing about a BIP39 passphrase. A 24-word original and a same-length container
    /// have no such check and are refused.
    BuiltInCheck { words: WordCount },
    /// A receiving address of the wallet, the strong check. The address is searched on the
    /// standard paths of its type within `limits`, or only at `path` when given.
    Address {
        address: &'a Address,
        passphrase: &'a str,
        path: Option<&'a DerivationPath>,
        limits: SearchLimits,
    },
    /// The BIP32 master key fingerprint: quick, but only 32 bits, so a weaker check.
    Fingerprint {
        fingerprint: [u8; 4],
        passphrase: &'a str,
    },
    /// The wallet check of a 24-word phrase drawn to pass it, as `mhfe new` does on request (the
    /// draft profile MHFE-WALLET-CHECK-SEED-1, [`crate::wallet_check`]), with its BIP39
    /// `passphrase`, which may not be empty (`WALLET_CHECK_NEEDS_PASSPHRASE`). Only the 24-word
    /// reading of the recovery is compared, as the profile defines the check for it alone
    /// ([`crate::wallet_check::verify_entropy`]). It tells a right password and passphrase from
    /// wrong ones with 16 bits, not which wallet it is, so it never confirms a recovery to encrypt
    /// again.
    WalletCheck { passphrase: &'a str },
    /// The original seed phrase's own checks, its length detected (`detection`): the
    /// built-in check of whichever 12- to 21-word length passes it, or else, with a BIP39
    /// `passphrase`, which may not be empty, the phrase + passphrase check of the 24-word reading.
    /// Like those checks it tells a right password from a wrong one, not which wallet it is, and
    /// it finds a 24-word phrase only if that phrase was drawn with the check. A same-length
    /// container has neither and is refused.
    OwnChecks { passphrase: Option<&'a str> },
}

/// A reference as a front end reads it, owning what [`Reference`] borrows except the BIP39
/// passphrase, which the front end holds apart, in locked memory, and gives with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTarget {
    /// A receiving address, searched on the standard paths of its type, or only at `path`.
    Address {
        address: Address,
        path: Option<DerivationPath>,
    },
    /// The BIP32 master key fingerprint.
    Fingerprint([u8; 4]),
    /// The built-in check at a stated length, or with the length detected the phrase's own
    /// checks.
    Length(PhraseLength),
    /// The phrase + passphrase check.
    WalletCheck,
}

impl ReferenceTarget {
    /// The reference to compare with, with `passphrase` the BIP39 passphrase it is compared
    /// with: the wallet's for an address or a fingerprint, the original seed phrase's for its own
    /// checks, empty for none.
    pub fn with<'a>(&'a self, passphrase: &'a str) -> Reference<'a> {
        match self {
            Self::Address { address, path } => Reference::Address {
                address,
                passphrase,
                path: path.as_ref(),
                limits: SearchLimits::default(),
            },
            Self::Fingerprint(fingerprint) => Reference::Fingerprint {
                fingerprint: *fingerprint,
                passphrase,
            },
            Self::Length(PhraseLength::Words(words)) => Reference::BuiltInCheck { words: *words },
            Self::Length(PhraseLength::Detect) => Reference::own_checks(passphrase),
            Self::WalletCheck => Reference::WalletCheck { passphrase },
        }
    }
}

impl<'a> Reference<'a> {
    /// The BIP39 passphrase the recovery is compared with; none for the built-in check, which
    /// says nothing about one.
    pub fn passphrase(&self) -> Option<&str> {
        match self {
            Self::BuiltInCheck { .. } => None,
            Self::Address { passphrase, .. }
            | Self::Fingerprint { passphrase, .. }
            | Self::WalletCheck { passphrase } => Some(passphrase),
            Self::OwnChecks { passphrase } => *passphrase,
        }
    }

    /// The BIP39 passphrase the recovery is compared with when one is given, not empty: what shows
    /// that the wallet has one.
    pub fn given_passphrase(&self) -> Option<&str> {
        self.passphrase().filter(|text| !text.is_empty())
    }

    /// The phrase's own checks with the BIP39 passphrase of the original seed phrase as typed:
    /// empty for none, which leaves the built-in check alone.
    pub fn own_checks(passphrase: &'a str) -> Self {
        Self::OwnChecks {
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    }

    /// Whether it identifies the wallet, a receiving address or the master key fingerprint,
    /// rather than the phrase's own checks, which tell a right password from a wrong one but not
    /// which wallet it is. Only such a reference confirms a phrase without a built-in check to
    /// encrypt it again, and tells apart the candidates of a search, several of which may pass a
    /// check of the phrase. A wallet check has 16 bits: too few to seal a phrase on its own.
    pub fn identifies_wallet(&self) -> bool {
        matches!(self, Self::Address { .. } | Self::Fingerprint { .. })
    }
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Runs a full recovery and compares it with `reference`. Returns whether it matches, and for
    /// an address the path where it was found.
    pub fn check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        let recovered = self.recover_for_check(container, password, reference, on_progress)?;
        Ok(recovered.compare(reference)?.outcome)
    }

    /// Recovers `container` for a check against `reference` and any reference after it, such as
    /// an address once detection found no length ([`RecoveredForCheck`]). A `reference` the
    /// container cannot be checked with is refused first, before any Argon2 work.
    pub fn recover_for_check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredForCheck, MhfeError> {
        let (suite, state) = self.recover_to_check(container, password, reference, on_progress)?;
        Ok(RecoveredForCheck {
            container_words: container.split_whitespace().count(),
            suite,
            state,
        })
    }

    /// [`Mhfe::recover_for_check`], reporting its two stages: the twelve rounds of the recovery as
    /// [`Stage::Recover`], then [`Stage::Compare`] once more at round 12 of 12, before the
    /// recovery is compared, which for an address can take seconds.
    pub fn recover_for_check_in_stages(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: StageCallback<'_>,
    ) -> Result<RecoveredForCheck, MhfeError> {
        let rounds = RoundCounter::starting_after(0, ROUNDS);
        let recovered =
            self.recover_for_check(container, password, reference, &mut |round, _| {
                rounds.report(Stage::Recover, round, on_progress)
            })?;
        rounds.report(Stage::Compare, ROUNDS, on_progress)?;
        Ok(recovered)
    }

    /// The first part of a check: refuses a reference the container cannot be checked with, before
    /// any Argon2 work, then recovers the suite and the state `X` of `container`.
    fn recover_to_check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(Suite, LockedBytes), MhfeError> {
        refuse_impossible(container.split_whitespace().count(), reference)?;
        self.recover_state(container, password, None, on_progress)
    }
}

/// A container recovered for a check: its suite and state `X` in locked memory, which a front end
/// compares with one reference after another without the rounds again, such as an address once
/// detection found no length the built-in check passes. No part of the phrase comes out of it,
/// only whether a reference matches, and the state is wiped when it is dropped.
pub struct RecoveredForCheck {
    container_words: usize,
    suite: Suite,
    state: LockedBytes,
}

impl RecoveredForCheck {
    /// Compares the recovery with `reference`, refusing one the container cannot be checked with,
    /// as [`Mhfe::check`] refuses it, with what the recovery shows beside it ([`CheckEvidence`]).
    pub fn compare(&self, reference: &Reference<'_>) -> Result<CheckEvidence, MhfeError> {
        refuse_impossible(self.container_words, reference)?;
        evidence_of(self.suite, &self.state, reference)
    }
}

/// Refuses, before a container is read, a built-in check at a length that has none in any container
/// (`INVALID_WORD_COUNT`): only a 12- to 21-word original carries one.
pub fn require_built_in_check_length(words: WordCount) -> Result<(), MhfeError> {
    if !crate::BUILT_IN_CHECK_WORD_COUNTS.contains(&words.get()) {
        return Err(MhfeError::NoBuiltInCheckAtLength(words.get()));
    }
    Ok(())
}

/// Refuses a built-in check, a wallet check or the phrase's own checks that a container of
/// `container_words` words cannot have, from the word counts and the passphrase alone.
pub(crate) fn refuse_impossible(
    container_words: usize,
    reference: &Reference<'_>,
) -> Result<(), MhfeError> {
    // A count no container has is refused where the container is read, after this.
    let Ok(suite) = Suite::of_container(container_words) else {
        return Ok(());
    };
    let built_in_lengths = suite.built_in_check_lengths();
    match reference {
        Reference::BuiltInCheck { .. } | Reference::OwnChecks { .. }
            if built_in_lengths.is_empty() =>
        {
            return Err(MhfeError::NoBuiltInCheck { container_words });
        }
        Reference::BuiltInCheck { words } if !built_in_lengths.contains(&words.get()) => {
            return Err(MhfeError::NoBuiltInCheckAtLength(words.get()));
        }
        Reference::WalletCheck { .. } if !suite.holds_full_state() => {
            return Err(MhfeError::NoWalletCheck { container_words });
        }
        // The wallet check's own rule, the one every front end gets: it needs a passphrase.
        Reference::WalletCheck { passphrase } => wallet_check::require_passphrase(passphrase)?,
        Reference::OwnChecks {
            passphrase: Some(passphrase),
        } => wallet_check::require_passphrase(passphrase)?,
        _ => {}
    }
    Ok(())
}

/// The reference's outcome and the checks of the original seed phrase itself, from the state `x`
/// recovered from a container of `suite`.
fn evidence_of(
    suite: Suite,
    x: &[u8],
    reference: &Reference<'_>,
) -> Result<CheckEvidence, MhfeError> {
    let (outcome, matched_words) = compare_state(suite, x, reference)?;
    if suite == Suite::SameLength {
        return Ok(CheckEvidence {
            outcome,
            built_in_check: None,
            wallet_check: None,
        });
    }
    let detection = LengthDetection::of(suite_3_state(x)?);
    // The 16-bit source check on the 24-word reading, with the passphrase compared or the empty
    // one, wherever that reading comes out: no short length passes, several do, or a reference
    // matched the 24-word reading beside one that passes (AUD-017). A built-in check states a
    // short length, and no passphrase.
    let reads_24_words = detection.short_lengths().len() != 1 || matched_words == Some(STATE_WORDS);
    let wallet_check = match reference {
        Reference::BuiltInCheck { .. } => None,
        _ if !reads_24_words => None,
        other => Some(detection.source_check(other.passphrase().unwrap_or(""))?),
    };
    // A stated length whose check passes is named, also among others that pass by chance.
    let built_in_check = match reference {
        Reference::BuiltInCheck { words } if detection.passes_built_in_check(words.get()) => {
            Some(words.get())
        }
        _ => detection.short_lengths().first().copied(),
    };
    Ok(CheckEvidence {
        outcome,
        built_in_check,
        wallet_check,
    })
}

/// The second part of a check: compares the state `x` recovered from a container of `suite` with
/// `reference`, with the length of the reading that an address or the fingerprint matched.
fn compare_state(
    suite: Suite,
    x: &[u8],
    reference: &Reference<'_>,
) -> Result<(CheckOutcome, Option<usize>), MhfeError> {
    if suite == Suite::SameLength {
        // The container's own length is the only reading.
        return Ok((compare(read_same_length(x)?.phrase(), reference)?, None));
    }
    let x = suite_3_state(x)?;
    let detection = LengthDetection::of(x);
    match reference {
        // The length rules of recovery: a short length whose check passes takes precedence over
        // the stated one, which the evidence then names (AUD-015-FUN001).
        Reference::BuiltInCheck { .. } => Ok((
            CheckOutcome::of(!detection.short_lengths().is_empty()),
            None,
        )),
        Reference::WalletCheck { passphrase } => Ok((
            CheckOutcome::of(detection.passes_wallet_check(passphrase)?),
            None,
        )),
        Reference::OwnChecks { passphrase } => Ok((
            CheckOutcome::of(detection.passes_own_checks(*passphrase)?),
            None,
        )),
        Reference::Address { .. } | Reference::Fingerprint { .. } => {
            // Every reading the detection gives is compared, whatever length the person has.
            for words in detection.readings() {
                // Held in locked memory while it is compared: an address search can take seconds.
                let reading = read_as(x, words)?;
                let outcome = compare(reading.phrase(), reference)?;
                if outcome.matches() {
                    return Ok((outcome, Some(words)));
                }
            }
            Ok((CheckOutcome::DoesNotMatch, None))
        }
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
    pub(crate) fn refuse_for(&self, needed: ConfirmationNeeded) -> Result<(), MhfeError> {
        let refused = match needed {
            ConfirmationNeeded::BuiltInCheck => false,
            ConfirmationNeeded::WalletOrOwner => {
                matches!(self, Self::BuiltInCheck) || self.gives_own_checks()
            }
        };
        if refused {
            return Err(MhfeError::ReferenceRequired);
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
            facts,
            suite,
            state,
        })
    }
}

/// A container recovered to be encrypted again: its facts and state `X` in locked memory, from
/// which a phrase comes out only once confirmed (the re-encryption guard). A confirmation that is
/// refused, such as the built-in check where several lengths pass, can be followed by another
/// without the rounds again (AUD-017-UI002). The state is wiped when it is dropped.
pub struct RecoveredForRekey {
    facts: ContainerFacts,
    suite: Suite,
    state: LockedBytes,
}

impl RecoveredForRekey {
    /// The phrase of `length`, a stated word count or [`PhraseLength::Detect`], once
    /// `confirmation` confirms it. A 12- to 21-word original of a 24-word container passes its
    /// built-in check at the length the owner states; a 24-word original, a detected length or a
    /// same-length container, which the built-in check does not confirm, need a wallet reference
    /// or the owner. A reference given is compared with every reading; `before_compare` is called
    /// before it is. Several short lengths that pass by accident are refused with
    /// [`MhfeError::AmbiguousLength`], as one phrase is sealed, and a stated length the built-in
    /// check contradicts with [`MhfeError::LengthDiffers`].
    pub fn confirm(
        &self,
        length: PhraseLength,
        confirmation: Confirmation<'_>,
        before_compare: &mut dyn FnMut() -> Result<(), MhfeError>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        confirmation.refuse_for(self.facts.confirmation_needed(length)?)?;
        let readings = self.readings(length)?;
        if let Some(reference) = confirmation.wallet_reference() {
            // An address or the fingerprint tells the readings apart, as the rehearsal check
            // compares them: the one that matches is the wallet's.
            before_compare()?;
            for reading in readings {
                if compare(reading.phrase(), reference)?.matches() {
                    return Ok(reading);
                }
            }
            return Err(MhfeError::ReferenceMismatch);
        }
        let reading = one_reading(readings)?;
        let by_owner = matches!(confirmation, Confirmation::Owner);
        // A check that finds another length than the one stated takes precedence, but seals the
        // phrase only once the wallet confirms it: the owner, who compares the phrase shown with
        // their backup, or a reference, asked for after this refusal.
        if let (Some(stated), false) = (reading.stated_words(), by_owner) {
            return Err(MhfeError::LengthDiffers {
                stated,
                found: reading.words(),
            });
        }
        // The built-in check confirms only a short reading that passed it; a 24-word reading has
        // none and is confirmed by a reference or the owner alone.
        if !by_owner && !reading.verified() {
            return Err(MhfeError::VerifierMismatch);
        }
        // A stated length that selected this reading among several that pass: the built-in check
        // alone does not tell them apart, so a reference or the owner confirms it (the
        // specification's re-encryption rules).
        if !by_owner && !reading.other_lengths().is_empty() {
            let mut readings: Vec<usize> = reading.other_lengths().to_vec();
            readings.push(reading.words());
            readings.sort_unstable();
            readings.push(STATE_WORDS);
            return Err(MhfeError::AmbiguousLength { readings });
        }
        Ok(reading)
    }

    /// The lengths the owner may state to compare one reading with their backup
    /// ([`Confirmation::Owner`]): the readings of a detection, less those the owner cannot tell
    /// from another, such as 24 words beside a short length whose check passes.
    pub fn lengths_the_owner_can_confirm(&self) -> Result<Vec<usize>, MhfeError> {
        let mut lengths = Vec::new();
        for words in self.facts.phrase_lengths() {
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
        if self.facts.require_length(length).is_err() {
            return Ok(false);
        }
        // A stated short length whose check fails gives no reading to compare.
        let readings = match self.readings(length) {
            Err(MhfeError::VerifierMismatch) => return Ok(false),
            readings => readings?,
        };
        Ok(match one_reading(readings) {
            Ok(_) => true,
            Err(MhfeError::LengthDiffers { .. } | MhfeError::AmbiguousLength { .. }) => false,
            Err(other) => return Err(other),
        })
    }

    /// The readings of the state for `length`, under the length rules of recovery: a built-in
    /// check that passes takes precedence over a stated length.
    fn readings(&self, length: PhraseLength) -> Result<Vec<RecoveredPhrase>, MhfeError> {
        self.facts.require_length(length)?;
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
            return Err(MhfeError::LengthDiffers {
                stated,
                found: only.words(),
            });
        }
    }
    Err(MhfeError::AmbiguousLength {
        readings: readings.iter().map(RecoveredPhrase::words).collect(),
    })
}

pub(crate) fn compare(phrase: &str, reference: &Reference<'_>) -> Result<CheckOutcome, MhfeError> {
    compare_until(phrase, reference, &|| false)
}

/// [`compare`] that an address search ends with [`MhfeError::Cancelled`] once `stopped` says so,
/// between the addresses it derives.
pub(crate) fn compare_until(
    phrase: &str,
    reference: &Reference<'_>,
    stopped: &dyn Fn() -> bool,
) -> Result<CheckOutcome, MhfeError> {
    match reference {
        Reference::BuiltInCheck { .. } => Ok(CheckOutcome::DoesNotMatch),
        Reference::Address {
            address,
            passphrase,
            path,
            limits,
        } => Ok(
            match wallet::find_address_until(phrase, passphrase, address, *path, *limits, stopped)?
            {
                Some(found) => CheckOutcome::Matches { path: Some(found) },
                None => CheckOutcome::DoesNotMatch,
            },
        ),
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => Ok(CheckOutcome::of(
            wallet::master_fingerprint(phrase, passphrase)? == *fingerprint,
        )),
        Reference::WalletCheck { passphrase } => {
            Ok(CheckOutcome::of(wallet_check::verify(phrase, passphrase)?))
        }
        // The phrase's own checks are read from the recovered state, never from one reading.
        Reference::OwnChecks { .. } => Ok(CheckOutcome::DoesNotMatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phrase_from_entropy;
    use crate::test_support::{
        container_of, reduced, test_password, wrong_password, ABANDON_12 as ABANDON,
        ABANDON_12_FINGERPRINT,
    };

    /// A check of `container` against `reference` with no progress to report.
    fn check<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        mhfe.check(container, password, reference, &mut |_, _| Ok(()))
    }

    /// What a check of `container` against `reference` shows, with no progress to report.
    fn evidence_for<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        reference: &Reference<'_>,
    ) -> CheckEvidence {
        mhfe.recover_for_check(container, &test_password(), reference, &mut |_, _| Ok(()))
            .unwrap()
            .compare(reference)
            .unwrap()
    }

    /// A check tells beside its reference the original seed phrase's own checks: the built-in
    /// check of a 12-word original, and for a 24-word one the 16-bit source check with the
    /// reference's passphrase or none, which a phrase drawn without it fails.
    #[test]
    fn a_check_lists_the_checks_of_the_phrase_itself() {
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let fingerprint = wallet::master_fingerprint(ABANDON, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let evidence = evidence_for(&mut mhfe, &container, &reference);
        assert!(evidence.outcome.matches());
        assert_eq!(evidence.built_in_check, Some(12));
        assert_eq!(evidence.wallet_check, None);
        let with_passphrase = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(ABANDON, "TREZOR").unwrap(),
            passphrase: "TREZOR",
        };
        let evidence = evidence_for(&mut mhfe, &container, &with_passphrase);
        assert!(evidence.outcome.matches());
        // A 12-word phrase: the 24-word reading does not come out, so it is not checked.
        assert_eq!(evidence.wallet_check, None);
        // A 24-word phrase drawn without the check fails it, with no passphrase as with one.
        let phrase = crate::phrase_from_entropy(&[7u8; 32]).unwrap();
        let container = container_of(&mut mhfe, &phrase, Suite::TwentyFourWords);
        let reference = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(&phrase, "").unwrap(),
            passphrase: "",
        };
        let evidence = evidence_for(&mut mhfe, &container, &reference);
        assert!(evidence.outcome.matches());
        assert_eq!(evidence.built_in_check, None);
        assert_eq!(evidence.wallet_check, Some(false));
    }

    /// The re-encryption guard: a phrase comes out only once confirmed.
    #[test]
    fn a_recovery_to_encrypt_again_needs_a_confirmation() {
        let password = test_password();
        let wrong = wrong_password();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let twelve = WordCount::new(12).unwrap();
        let twenty_four = WordCount::new(24).unwrap();

        // A 12-word original in a 24-word container: its built-in check at the stated length.
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
            Err(MhfeError::VerifierMismatch)
        ));

        // A 24-word original has no check: refused without a reference, before any Argon2 call.
        const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon art";
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
            Err(MhfeError::ReferenceRequired)
        ));
        assert_eq!(rounds, 0);
        let fingerprint = wallet::master_fingerprint(ART, "").unwrap();
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
            Err(MhfeError::ReferenceMismatch)
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
            Err(MhfeError::ReferenceMismatch)
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

        // A same-length container: its own length, and a reference.
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
            Err(MhfeError::ReferenceRequired)
        ));
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&right),
                none
            ),
            Err(MhfeError::LengthChoiceNotApplicable {
                container_words: 12
            })
        ));
        let abandon = Reference::Fingerprint {
            fingerprint: ABANDON_12_FINGERPRINT,
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

    #[test]
    fn a_wallet_check_matches_a_phrase_made_with_it_and_never_confirms_a_rekey() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let phrase = phrase_from_entropy(&entropy).unwrap();
        let container = mhfe
            .encrypt(&phrase, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let reference = Reference::WalletCheck {
            passphrase: "TREZOR",
        };
        assert!(mhfe
            .check(&container, &password, &reference, none)
            .unwrap()
            .matches());
        assert!(!mhfe
            .check(&container, &wrong, &reference, none)
            .unwrap()
            .matches());
        let other = Reference::WalletCheck {
            passphrase: "trezor",
        };
        assert!(!mhfe
            .check(&container, &password, &other, none)
            .unwrap()
            .matches());
        // Without a passphrase the check is not offered: refused before any Argon2 work, as the
        // browser and wallet_check::verify refuse it (AUD-010).
        let mut rounds = 0;
        assert_eq!(
            mhfe.check(
                &container,
                &password,
                &Reference::WalletCheck { passphrase: "" },
                &mut |_, _| {
                    rounds += 1;
                    Ok(())
                }
            ),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(rounds, 0);
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                WordCount::new(24).unwrap(),
                Confirmation::Wallet(&reference),
                none
            ),
            Err(MhfeError::ReferenceRequired)
        ));
    }

    /// The phrase's own checks with its length detected: a 12-word original passes by its built-in
    /// check with or without a passphrase, a 24-word one drawn with the wallet check passes only
    /// with its passphrase, and a wrong password fails. An empty passphrase and a same-length
    /// container are refused before any Argon2 work.
    #[test]
    fn the_own_checks_detect_the_length() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        let own = |passphrase| Reference::OwnChecks { passphrase };
        let short = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        for passphrase in [None, Some("TREZOR")] {
            let evidence = mhfe
                .recover_for_check(&short, &password, &own(passphrase), none)
                .unwrap()
                .compare(&own(passphrase))
                .unwrap();
            assert!(evidence.outcome.matches());
            assert_eq!(evidence.built_in_check, Some(12));
        }
        assert!(!mhfe
            .check(&short, &wrong, &own(None), none)
            .unwrap()
            .matches());
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let drawn = phrase_from_entropy(&entropy).unwrap();
        let full = mhfe
            .encrypt(&drawn, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let evidence = mhfe
            .recover_for_check(&full, &password, &own(Some("TREZOR")), none)
            .unwrap()
            .compare(&own(Some("TREZOR")))
            .unwrap();
        assert!(evidence.outcome.matches());
        assert_eq!(
            (evidence.built_in_check, evidence.wallet_check),
            (None, Some(true))
        );
        for passphrase in [None, Some("trezor")] {
            assert!(!mhfe
                .check(&full, &password, &own(passphrase), none)
                .unwrap()
                .matches());
        }
        assert_eq!(
            mhfe.check(&full, &password, &own(Some("")), none),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        let same_length = mhfe
            .encrypt(ABANDON, &password, Suite::SameLength, none)
            .unwrap();
        assert_eq!(
            mhfe.check(&same_length, &password, &own(None), none),
            Err(MhfeError::NoBuiltInCheck {
                container_words: 12
            })
        );
    }

    /// A front end's reference gives the library's, with the passphrase it is given; the own
    /// checks take an empty passphrase as none.
    #[test]
    fn a_reference_target_gives_its_reference() {
        let fingerprint = ReferenceTarget::Fingerprint(ABANDON_12_FINGERPRINT);
        assert!(matches!(
            fingerprint.with("TREZOR"),
            Reference::Fingerprint {
                fingerprint: ABANDON_12_FINGERPRINT,
                passphrase: "TREZOR"
            }
        ));
        let twelve = ReferenceTarget::Length(PhraseLength::Words(WordCount::new(12).unwrap()));
        assert!(matches!(twelve.with(""), Reference::BuiltInCheck { words } if words.get() == 12));
        let detected = ReferenceTarget::Length(PhraseLength::Detect);
        assert!(matches!(
            detected.with(""),
            Reference::OwnChecks { passphrase: None }
        ));
        assert!(matches!(
            detected.with("TREZOR"),
            Reference::OwnChecks {
                passphrase: Some("TREZOR")
            }
        ));
        assert!(matches!(
            ReferenceTarget::WalletCheck.with("TREZOR"),
            Reference::WalletCheck {
                passphrase: "TREZOR"
            }
        ));
        assert!(fingerprint.with("").identifies_wallet());
        assert!(!detected.with("").identifies_wallet());
    }

    /// One recovery compared with one reference after another: a 24-word phrase that detection
    /// finds no length for is then compared with its fingerprint, without the rounds again, and a
    /// reference the container cannot be checked with is refused as a check refuses it.
    #[test]
    fn a_recovery_is_compared_again_without_its_rounds() {
        let mut mhfe = reduced();
        let password = test_password();
        let phrase = phrase_from_entropy(&[7u8; 32]).unwrap();
        let container = mhfe
            .encrypt(&phrase, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let own = Reference::OwnChecks { passphrase: None };
        let mut rounds = 0;
        let recovered = mhfe
            .recover_for_check(&container, &password, &own, &mut |_, _| {
                rounds += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(rounds, ROUNDS);
        assert!(!recovered.compare(&own).unwrap().outcome.matches());
        let fingerprint = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(&phrase, "").unwrap(),
            passphrase: "",
        };
        assert!(recovered.compare(&fingerprint).unwrap().outcome.matches());
        assert_eq!(
            recovered.compare(&Reference::WalletCheck { passphrase: "" }),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
    }

    /// A public passphrase with which the 12-word test phrase passes the wallet check's criterion
    /// as 12 words, under BE32(128), which the profile does not define; its 24-word reading fails
    /// (AUD-010, harness crypto-core/short_reading_wallet_check.py).
    const SHORT_READING_PASSPHRASE: &str = "aud010 public probe 11656";

    /// The wallet check compares only the 24-word reading of a recovery: a 12-word original whose
    /// own reading passes the criterion with a passphrase does not make a match (AUD-010).
    #[test]
    fn a_wallet_check_compares_the_24_word_reading_only() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        assert!(wallet_check::phrase_passes(ABANDON, SHORT_READING_PASSPHRASE).unwrap());
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        // The recovery reads as the 12-word phrase, which the built-in check confirms.
        let built_in = Reference::BuiltInCheck {
            words: WordCount::new(12).unwrap(),
        };
        assert!(mhfe
            .check(&container, &password, &built_in, none)
            .unwrap()
            .matches());
        let reference = Reference::WalletCheck {
            passphrase: SHORT_READING_PASSPHRASE,
        };
        assert_eq!(
            mhfe.check(&container, &password, &reference, none),
            Ok(CheckOutcome::DoesNotMatch)
        );
        let staged = mhfe
            .recover_for_check_in_stages(&container, &password, &reference, &mut |_, _, _| Ok(()))
            .unwrap();
        assert_eq!(
            staged.compare(&reference).unwrap().outcome,
            CheckOutcome::DoesNotMatch
        );
    }

    #[test]
    fn every_reference_matches_the_right_password_only() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);

        let address = Address::parse(
            wallet::Coin::Bitcoin,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        )
        .unwrap();
        let references = [
            Reference::BuiltInCheck {
                words: WordCount::new(12).unwrap(),
            },
            Reference::Address {
                address: &address,
                passphrase: "",
                path: None,
                limits: SearchLimits::default(),
            },
            Reference::Fingerprint {
                fingerprint: ABANDON_12_FINGERPRINT,
                passphrase: "",
            },
        ];
        for reference in &references {
            assert!(check(&mut mhfe, &container, &password, reference)
                .unwrap()
                .matches());
            assert!(!check(&mut mhfe, &container, &wrong, reference)
                .unwrap()
                .matches());
        }

        // A matched address names its path: the first native SegWit receiving address.
        let found = check(&mut mhfe, &container, &password, &references[1]).unwrap();
        assert_eq!(
            found.path().map(ToString::to_string).as_deref(),
            Some("m/84'/0'/0'/0/0")
        );

        // The right password with a wrong BIP39 passphrase is a different wallet.
        let with_passphrase = Reference::Fingerprint {
            fingerprint: ABANDON_12_FINGERPRINT,
            passphrase: "TREZOR",
        };
        assert!(!check(&mut mhfe, &container, &password, &with_passphrase)
            .unwrap()
            .matches());
    }

    /// The twelve rounds of the recovery, then the comparison, which can be stopped as well.
    #[test]
    fn a_recovery_in_stages_reports_its_rounds_and_its_comparison() {
        let password = test_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let reference = Reference::Fingerprint {
            fingerprint: ABANDON_12_FINGERPRINT,
            passphrase: "",
        };
        let mut reports = Vec::new();
        let recovered = mhfe
            .recover_for_check_in_stages(
                &container,
                &password,
                &reference,
                &mut |stage, round, rounds| {
                    reports.push((stage, round, rounds));
                    Ok(())
                },
            )
            .unwrap();
        assert!(recovered.compare(&reference).unwrap().outcome.matches());
        let mut expected: Vec<(Stage, u32, u32)> =
            (1..=12).map(|round| (Stage::Recover, round, 12)).collect();
        expected.push((Stage::Compare, 12, 12));
        assert_eq!(reports, expected);

        let stopped = mhfe.recover_for_check_in_stages(
            &container,
            &password,
            &reference,
            &mut |stage, _, _| {
                if stage == Stage::Compare {
                    Err(MhfeError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(stopped, Err(MhfeError::Cancelled)));
    }

    #[test]
    fn a_24_word_original_is_checked_against_the_wallet() {
        let password = test_password();
        let mut mhfe = reduced();
        let original = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal winner thank year wave sausage worth title";
        let container = mhfe
            .encrypt(original, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let fingerprint = wallet::master_fingerprint(original, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        assert!(check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(24).unwrap()
                }
            )
            .err(),
            Some(MhfeError::NoBuiltInCheckAtLength(24))
        );
    }

    #[test]
    fn a_same_length_container_is_checked_against_the_wallet_only() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::SameLength);
        assert_eq!(container.split(' ').count(), 12);
        let reference = Reference::Fingerprint {
            fingerprint: ABANDON_12_FINGERPRINT,
            passphrase: "",
        };
        assert!(check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert!(!check(&mut mhfe, &container, &wrong, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(12).unwrap()
                }
            )
            .err(),
            Some(MhfeError::NoBuiltInCheck {
                container_words: 12
            })
        );
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::WalletCheck {
                    passphrase: "TREZOR"
                }
            )
            .err(),
            Some(MhfeError::NoWalletCheck {
                container_words: 12
            })
        );
    }
}
