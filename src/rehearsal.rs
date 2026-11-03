//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! "matches" or "does not match", and on a match with an address the path where it was found.
//! No part of the recovered phrase leaves the check, and a wrong password gives no hint of how
//! close it was. The re-encryption guard uses the same comparison: a phrase recovered to be
//! encrypted again comes out only once it is confirmed.

use std::ops::ControlFlow;

use mhfe_core::{Argon2Engine, Mhfe, Password, Recovery, Suite};

use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::detection;
use crate::mhfe::{readings, recover_state, PhraseLength, RecoveredPhrase};
use crate::operation::{RoundCounter, Stage, StageCallback};
use crate::packing::STATE_WORDS;
use crate::suite::{built_in_check_lengths, holds_full_state, ROUNDS};
use crate::wallet::{self, Address, DerivationPath, SearchLimits};
use crate::wallet_check;
use crate::{MhfeError, ProgressCallback, WordCount};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// What a rehearsal found. A match on a receiving address names the path where the address was
/// found, which tells the person which account and address of the wallet it is; it is not part of
/// the phrase and is given only on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The recovery matches the reference.
    Matches {
        /// Where the matching receiving address was found; `None` for any other reference.
        path: Option<DerivationPath>,
    },
    /// The recovery does not match the reference.
    DoesNotMatch,
    /// The recovery gives only a 24-word reading, which only a wallet reference can confirm: a
    /// wrong password gives one too (APP-6). A pass of its 16-bit check does not change that, and
    /// stands in [`CheckEvidence::wallet_check`].
    NotVerified,
}

impl CheckOutcome {
    /// Whether the outcome is [`CheckOutcome::Matches`].
    pub fn matches(&self) -> bool {
        matches!(self, Self::Matches { .. })
    }

    /// The path of a matched address; `None` for any other outcome.
    pub fn path(&self) -> Option<&DerivationPath> {
        match self {
            Self::Matches { path } => path.as_ref(),
            Self::DoesNotMatch | Self::NotVerified => None,
        }
    }

    /// The result in the specification's words.
    pub fn words(&self) -> &'static str {
        match self {
            Self::Matches { .. } => "matches",
            Self::DoesNotMatch => "does not match",
            Self::NotVerified => "not verified",
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
    /// The other 12- to 21-word lengths whose built-in check passes too, by chance, about once in
    /// 2^32 recoveries. A front end names every length that matches, as none tells them apart.
    pub other_lengths: Vec<usize>,
    /// Whether the 24-word reading passes the phrase + passphrase check of `mhfe new` (the 16-bit
    /// wallet check) with the reference's passphrase, or the empty one where it has none, where
    /// that reading comes out: no short length's check passes, several do, or the reference
    /// matched the 24-word reading. `None` for the built-in check, for a same-length container,
    /// and when exactly one short length passes and the reference did not match the 24-word
    /// reading. A phrase drawn without that check almost always fails it, so that only a pass says
    /// anything.
    pub wallet_check: Option<bool>,
    /// Whether an address or the fingerprint matched the wallet without a BIP39 passphrase,
    /// although one was given: the wallet with it is compared first, and when it does not match,
    /// the one without it. Such a match confirms the phrase, not the passphrase.
    pub without_passphrase: bool,
}

/// What the recovered phrase is compared with.
#[derive(Clone, Copy)]
pub enum Reference<'a> {
    /// The built-in check value of a 12-, 15-, 18- or 21-word original in a 24-word container,
    /// `words` the length the person states. As in recovery, a check that passes at another short
    /// length takes precedence and matches, and [`CheckEvidence::built_in_check`] names that
    /// length. It confirms that the recovery is consistent, not that it gives the same wallet, and
    /// it says nothing about a BIP39 passphrase. A 24-word original and a same-length container
    /// have no such check and are refused.
    BuiltInCheck {
        /// The length the person states.
        words: WordCount,
    },
    /// A receiving address of the wallet, the strong check. The address is searched on the
    /// standard paths of its type within `limits`, or only at `path` when given, as the address of
    /// each coin it is read as ([`Address::parse_any`]).
    Address {
        /// The receiving address, read as one coin's or as every coin's whose form it has.
        addresses: &'a [Address],
        /// The wallet's BIP39 passphrase; empty for none.
        passphrase: &'a str,
        /// The one path to look at, in place of the standard paths.
        path: Option<&'a DerivationPath>,
        /// How many accounts and addresses of the standard paths are searched.
        limits: SearchLimits,
    },
    /// The BIP32 master key fingerprint: quick, but only 32 bits, so a weaker check.
    Fingerprint {
        /// The four bytes of the fingerprint.
        fingerprint: [u8; 4],
        /// The wallet's BIP39 passphrase; empty for none.
        passphrase: &'a str,
    },
    /// The wallet check of a 24-word phrase drawn to pass it, as `mhfe new` does on request (the
    /// draft profile MHFE-WALLET-CHECK-SEED-1, [`crate::wallet_check`]), with its BIP39
    /// `passphrase`, which may not be empty (`WALLET_CHECK_NEEDS_PASSPHRASE`). Only the 24-word
    /// reading of the recovery is compared, as the profile defines the check for it alone
    /// ([`crate::wallet_check::verify`]). It tells a right password and passphrase from
    /// wrong ones with 16 bits, not which wallet it is, so it never confirms a recovery to encrypt
    /// again.
    WalletCheck {
        /// The wallet's BIP39 passphrase, not empty.
        passphrase: &'a str,
    },
    /// The original seed phrase's own checks, its length detected (`detection`): the
    /// built-in check of whichever 12- to 21-word length passes it, or else, with a BIP39
    /// `passphrase`, which may not be empty, the phrase + passphrase check of the 24-word reading.
    /// Like those checks it tells a right password from a wrong one, not which wallet it is, and
    /// it finds a 24-word phrase only if that phrase was drawn with the check. A same-length
    /// container has neither and is refused.
    OwnChecks {
        /// The wallet's BIP39 passphrase for the phrase + passphrase check, not empty; `None`
        /// leaves that check out.
        passphrase: Option<&'a str>,
    },
}

/// A reference as a front end reads it, owning what [`Reference`] borrows except the BIP39
/// passphrase, which the front end holds apart, in locked memory, and gives with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTarget {
    /// A receiving address, searched on the standard paths of its type, or only at `path`.
    Address {
        /// The receiving address, read as one coin's or as every coin's whose form it has.
        addresses: Vec<Address>,
        /// The one path to look at, in place of the standard paths.
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
            Self::Address { addresses, path } => Reference::Address {
                addresses,
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

    /// The same address or fingerprint compared with the wallet without a BIP39 passphrase; any
    /// other reference as it is.
    fn without_passphrase(self) -> Self {
        match self {
            Self::Address {
                addresses,
                path,
                limits,
                ..
            } => Self::Address {
                addresses,
                passphrase: "",
                path,
                limits,
            },
            Self::Fingerprint { fingerprint, .. } => Self::Fingerprint {
                fingerprint,
                passphrase: "",
            },
            other => other,
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

/// Runs a full recovery and compares it with `reference`. Returns whether it matches, and for
/// an address the path where it was found.
pub fn check<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    reference: &Reference<'_>,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<CheckOutcome> {
    let recovered = proceed!(recover_for_check(
        mhfe,
        container,
        password,
        reference,
        on_progress
    ));
    Ok(ControlFlow::Continue(recovered.compare(reference)?.outcome))
}

/// Recovers `container` for a check against `reference` and any reference after it, such as
/// an address once detection found no length ([`RecoveredForCheck`]). A `reference` the
/// container cannot be checked with is refused first, before any Argon2 work.
pub fn recover_for_check<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    reference: &Reference<'_>,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<RecoveredForCheck> {
    let container_words = container.split_whitespace().count();
    refuse_impossible(container_words, reference)?;
    let recovery = proceed!(recover_state(mhfe, container, password, None, on_progress));
    Ok(ControlFlow::Continue(RecoveredForCheck {
        container_words,
        recovery,
    }))
}

/// [`recover_for_check`], reporting its two stages: the twelve rounds of the recovery as
/// [`Stage::Recover`], then [`Stage::Compare`] once more at round 12 of 12, before the
/// recovery is compared, which for an address can take seconds.
pub fn recover_for_check_in_stages<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    reference: &Reference<'_>,
    on_progress: StageCallback<'_>,
) -> crate::Outcome<RecoveredForCheck> {
    let rounds = RoundCounter::starting_after(0, ROUNDS);
    let recovered = proceed!(recover_for_check(
        mhfe,
        container,
        password,
        reference,
        &mut |round, _| rounds.report(Stage::Recover, round, on_progress)
    ));
    proceed!(rounds.report(Stage::Compare, ROUNDS, on_progress));
    Ok(ControlFlow::Continue(recovered))
}

/// A container recovered for a check: its suite and state `X` in locked memory, which a front end
/// compares with one reference after another without the rounds again, such as an address once
/// detection found no length the built-in check passes. No part of the phrase comes out of it,
/// only whether a reference matches, and the state is wiped when it is dropped.
pub struct RecoveredForCheck {
    container_words: usize,
    recovery: Recovery,
}

impl RecoveredForCheck {
    /// Compares the recovery with `reference`, refusing one the container cannot be checked with,
    /// as [`check`] refuses it, with what the recovery shows beside it ([`CheckEvidence`]).
    pub fn compare(&self, reference: &Reference<'_>) -> Result<CheckEvidence, MhfeError> {
        refuse_impossible(self.container_words, reference)?;
        evidence_of(&self.recovery, reference)
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
    let Some(suite) = Suite::of_container(container_words) else {
        return Ok(());
    };
    let built_in_lengths = built_in_check_lengths(suite);
    match reference {
        Reference::BuiltInCheck { .. } | Reference::OwnChecks { .. }
            if built_in_lengths.is_empty() =>
        {
            return Err(MhfeError::NoBuiltInCheck { container_words });
        }
        Reference::BuiltInCheck { words } if !built_in_lengths.contains(&words.get()) => {
            return Err(MhfeError::NoBuiltInCheckAtLength(words.get()));
        }
        Reference::WalletCheck { .. } if !holds_full_state(suite) => {
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

/// The reference's outcome and the checks of the original seed phrase itself, from `recovery`.
fn evidence_of(recovery: &Recovery, reference: &Reference<'_>) -> Result<CheckEvidence, MhfeError> {
    let (outcome, matched_words, without_passphrase) = compare_state(recovery, reference)?;
    if recovery.suite() == Suite::SameLength {
        return Ok(CheckEvidence {
            outcome,
            built_in_check: None,
            other_lengths: Vec::new(),
            wallet_check: None,
            without_passphrase,
        });
    }
    let short = recovery.detected_lengths();
    // The 16-bit wallet check on the 24-word reading, with the passphrase compared or the empty
    // one, wherever that reading comes out: no short length passes, several do, or a reference
    // matched the 24-word reading beside one that passes (AUD-017). A built-in check states a
    // short length, and no passphrase.
    let reads_24_words = short.len() != 1 || matched_words == Some(STATE_WORDS);
    let wallet_check = match reference {
        Reference::BuiltInCheck { .. } => None,
        _ if !reads_24_words => None,
        other => detection::twenty_four_word_reading(recovery)?
            .passes_wallet_check(other.passphrase().unwrap_or(""))?,
    };
    // A stated length whose check passes is named, also among others that pass by chance.
    let built_in_check = match reference {
        Reference::BuiltInCheck { words } if short.contains(&words.get()) => Some(words.get()),
        _ => short.first().copied(),
    };
    let other_lengths = short
        .iter()
        .copied()
        .filter(|&words| Some(words) != built_in_check)
        .collect();
    Ok(CheckEvidence {
        outcome,
        built_in_check,
        other_lengths,
        wallet_check,
        without_passphrase,
    })
}

/// The second part of a check: compares `recovery` with `reference`, with the length of the
/// reading that an address or the fingerprint matched, and whether it matched the wallet without
/// the BIP39 passphrase given ([`CheckEvidence::without_passphrase`]).
fn compare_state(
    recovery: &Recovery,
    reference: &Reference<'_>,
) -> Result<(CheckOutcome, Option<usize>, bool), MhfeError> {
    match reference {
        // The length rules of recovery: a short length whose check passes takes precedence over
        // the stated one, which the evidence then names (AUD-015-FUN001).
        Reference::BuiltInCheck { .. } => Ok((
            CheckOutcome::of(!recovery.detected_lengths().is_empty()),
            None,
            false,
        )),
        Reference::WalletCheck { .. } | Reference::OwnChecks { .. } => {
            let outcome = if recovery.detected_lengths().is_empty() {
                CheckOutcome::NotVerified
            } else {
                CheckOutcome::Matches { path: None }
            };
            Ok((outcome, None, false))
        }
        Reference::Address { .. } | Reference::Fingerprint { .. } => {
            // Held in locked memory while they are compared: an address search can take seconds.
            let readings = every_reading(recovery)?;
            // The phrase is the same with any passphrase, so the wallet without the one given
            // confirms it too, compared after the wallet with it, which alone confirms both.
            let without = reference
                .given_passphrase()
                .map(|_| (reference.without_passphrase(), true));
            for (compared, without_passphrase) in
                std::iter::once((*reference, false)).chain(without)
            {
                for reading in &readings {
                    let outcome = compare(reading.phrase(), &compared)?;
                    if outcome.matches() {
                        return Ok((outcome, Some(reading.words()), without_passphrase));
                    }
                }
            }
            Ok((CheckOutcome::DoesNotMatch, None, false))
        }
    }
}

/// Every reading of `recovery`, for a wallet reference to be compared with, whatever length the
/// person has, so that no accidental match hides the real phrase: 24 stated words give each short
/// length that passes and then the 24-word reading. A same-length container has its own length
/// alone.
fn every_reading(recovery: &Recovery) -> Result<Vec<RecoveredPhrase>, MhfeError> {
    readings(
        recovery,
        holds_full_state(recovery.suite()).then_some(STATE_WORDS),
    )
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

/// Recovers the state of `container` to confirm a phrase from it, once or again after a
/// confirmation was refused, without the rounds again ([`RecoveredForRekey`]). `length` and
/// `confirmation` are those of the first confirmation, which is refused here, before any
/// Argon2 work, if it cannot confirm a phrase of that length.
pub(crate) fn recover_for_rekey<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    length: PhraseLength,
    confirmation: Confirmation<'_>,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<RecoveredForRekey> {
    let facts = ContainerFacts::read(container)?;
    confirmation.refuse_for(facts.confirmation_needed(length)?)?;
    let recovery = proceed!(recover_state(mhfe, container, password, None, on_progress));
    Ok(ControlFlow::Continue(RecoveredForRekey { facts, recovery }))
}

/// A container recovered to be encrypted again: its facts and state `X` in locked memory, from
/// which a phrase comes out only once confirmed (the re-encryption guard). A confirmation that is
/// refused, such as the built-in check where several lengths pass, can be followed by another
/// without the rounds again (AUD-017-UI002). The state is wiped when it is dropped.
pub struct RecoveredForRekey {
    facts: ContainerFacts,
    recovery: Recovery,
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
        before_compare: &mut dyn FnMut() -> crate::Outcome,
    ) -> crate::Outcome<RecoveredPhrase> {
        confirmation.refuse_for(self.facts.confirmation_needed(length)?)?;
        let readings = self.readings(length)?;
        if let Some(reference) = confirmation.wallet_reference() {
            // An address or the fingerprint tells the readings apart, as the rehearsal check
            // compares them: the one that matches is the wallet's, whatever length was stated.
            proceed!(before_compare());
            for reading in every_reading(&self.recovery)? {
                if compare(reading.phrase(), reference)?.matches() {
                    return Ok(ControlFlow::Continue(reading));
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
        Ok(ControlFlow::Continue(reading))
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
        readings(&self.recovery, length.stated())
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
    // Never stopped, so never `Break`.
    Ok(compare_until(phrase, reference, &|| false)?
        .continue_value()
        .unwrap_or(CheckOutcome::DoesNotMatch))
}

/// [`compare`] that an address search ends with `Break` once `stopped` says so, between the
/// addresses it derives.
pub(crate) fn compare_until(
    phrase: &str,
    reference: &Reference<'_>,
    stopped: &dyn Fn() -> bool,
) -> crate::Outcome<CheckOutcome> {
    let outcome = match reference {
        Reference::Address {
            addresses,
            passphrase,
            path,
            limits,
        } => {
            let mut outcome = CheckOutcome::DoesNotMatch;
            for address in *addresses {
                if let Some(found) = proceed!(wallet::find_address_until(
                    phrase, passphrase, address, *path, *limits, stopped
                )) {
                    outcome = CheckOutcome::Matches { path: Some(found) };
                    break;
                }
            }
            outcome
        }
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => CheckOutcome::of(wallet::master_fingerprint(phrase, passphrase)? == *fingerprint),
        // Every caller holds an address or a fingerprint: the other references are read from the
        // recovered state, never from one reading.
        Reference::BuiltInCheck { .. }
        | Reference::WalletCheck { .. }
        | Reference::OwnChecks { .. } => CheckOutcome::DoesNotMatch,
    };
    Ok(ControlFlow::Continue(outcome))
}

#[cfg(test)]
mod tests {
    use mhfe_core::Phrase;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::test_support::{
        container_of, reduced, state_from_hex, test_password, wrong_password,
        ABANDON_12 as ABANDON, ABANDON_12_FINGERPRINT, AMBIGUOUS_STATES,
    };
    use crate::Unstopped as _;

    /// Recovers the phrase of `container` to encrypt it again under a new password or settings,
    /// and gives it only once it is confirmed (the re-encryption guard), as `confirmation` says:
    /// a 12- to 21-word original of a 24-word container passes its built-in check at the length
    /// `words` the owner states in every case, and a 24-word original or a same-length container,
    /// which have none, need a wallet reference or the owner. Encrypting the phrase again under the
    /// old password and comparing proves nothing, as that gives the same container for every
    /// password, so it is not a confirmation. Everything is checked before the first Argon2 call.
    fn recover_confirmed<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        password: &Password,
        words: WordCount,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> crate::Outcome<RecoveredPhrase> {
        let length = PhraseLength::Words(words);
        proceed!(recover_for_rekey(
            mhfe,
            container,
            password,
            length,
            confirmation,
            on_progress
        ))
        .confirm(length, confirmation, &mut || Ok(ControlFlow::Continue(())))
    }

    /// A check of `container` against `reference` with no progress to report.
    fn quiet_check<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        check(mhfe, container, password, reference, &mut |_, _| {
            crate::GO_ON
        })
        .unstopped()
    }

    /// What a check of `container` against `reference` shows, with no progress to report.
    fn evidence_for<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        reference: &Reference<'_>,
    ) -> CheckEvidence {
        recover_for_check(mhfe, container, &test_password(), reference, &mut |_, _| {
            crate::GO_ON
        })
        .unstopped()
        .unwrap()
        .compare(reference)
        .unwrap()
    }

    /// With a BIP39 passphrase a check compares the wallet with it and then the wallet without it:
    /// either confirms the phrase, and the evidence says when it was the wallet without it. A
    /// reference of neither does not match, and without a passphrase only the one wallet is
    /// compared.
    #[test]
    fn a_check_compares_the_wallet_with_the_passphrase_and_without_it() {
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let recovered = recover_for_check(
            &mut mhfe,
            &container,
            &test_password(),
            &Reference::Fingerprint {
                fingerprint: ABANDON_12_FINGERPRINT,
                passphrase: "",
            },
            &mut |_, _| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let with = wallet::master_fingerprint(ABANDON, "TREZOR").unwrap();
        let compared = |fingerprint, passphrase| {
            let evidence = recovered
                .compare(&Reference::Fingerprint {
                    fingerprint,
                    passphrase,
                })
                .unwrap();
            (evidence.outcome.matches(), evidence.without_passphrase)
        };
        assert_eq!(compared(with, "TREZOR"), (true, false));
        assert_eq!(compared(ABANDON_12_FINGERPRINT, "TREZOR"), (true, true));
        assert_eq!(compared(ABANDON_12_FINGERPRINT, ""), (true, false));
        assert_eq!(compared(with, "trezor"), (false, false));
        assert_eq!(compared(with, ""), (false, false));
        // An address read as two coins is searched as both: the Ethereum address of the phrase,
        // read as Ethereum and Ethereum Classic, matches without the passphrase given.
        let addresses = Address::parse_any("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap();
        let evidence = recovered
            .compare(&Reference::Address {
                addresses: &addresses,
                passphrase: "TREZOR",
                path: None,
                limits: SearchLimits::default(),
            })
            .unwrap();
        assert_eq!(
            evidence.outcome.path().map(ToString::to_string).as_deref(),
            Some("m/44'/60'/0'/0/0")
        );
        assert!(evidence.without_passphrase);
    }

    /// A check tells beside its reference the original seed phrase's own checks: the built-in
    /// check of a 12-word original, and for a 24-word one the 16-bit wallet check with the
    /// reference's passphrase or none, which a phrase drawn without it fails. The 24-word reading
    /// is not hidden by short lengths that pass beside it (AUD-017).
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
        assert!(evidence.other_lengths.is_empty());
        assert_eq!(evidence.wallet_check, None);
        let with_passphrase = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(ABANDON, "TREZOR").unwrap(),
            passphrase: "TREZOR",
        };
        let evidence = evidence_for(&mut mhfe, &container, &with_passphrase);
        assert!(evidence.outcome.matches());
        // A 12-word phrase: the 24-word reading does not come out, so it is not checked.
        assert_eq!(evidence.wallet_check, None);
        // A 24-word phrase drawn without the check fails it, with no passphrase as with one, also
        // one that passes a short check by chance, whose reading a reference still finds. So does
        // the 24-word reading of a short original that passes two checks.
        let packed = [&[0; 16], &Sha256::digest([0; 16])[..16]].concat();
        let ambiguous = state_from_hex(AMBIGUOUS_STATES[0].0);
        for (entropy, built_in_check) in [
            (&[7u8; 32][..], None),
            (&packed, Some(12)),
            (&ambiguous[..16], Some(12)),
        ] {
            let phrase = Phrase::from_entropy(entropy).unwrap();
            let phrase = phrase.as_str();
            let container = container_of(&mut mhfe, phrase, Suite::TwentyFourWords);
            let reference = Reference::Fingerprint {
                fingerprint: wallet::master_fingerprint(phrase, "").unwrap(),
                passphrase: "",
            };
            let evidence = evidence_for(&mut mhfe, &container, &reference);
            assert!(evidence.outcome.matches());
            assert_eq!(evidence.built_in_check, built_in_check);
            assert_eq!(evidence.wallet_check, Some(false));
        }
    }

    /// Every length that matches is named, whatever the check is compared with: a stated length
    /// among them comes first, and one that fails leaves them as with none stated (the
    /// specification's rehearsal check).
    #[test]
    fn a_check_names_every_length_that_matches() {
        let mut mhfe = reduced();
        for (text, [first, second]) in AMBIGUOUS_STATES {
            // A 24-word phrase fills the state alone, so that its container holds this very X.
            let phrase = Phrase::from_entropy(&state_from_hex(text)).unwrap();
            let phrase = phrase.as_str();
            let container = container_of(&mut mhfe, phrase, Suite::TwentyFourWords);
            let stated = |words| Reference::BuiltInCheck {
                words: WordCount::new(words).unwrap(),
            };
            let other = [12, 15, 18, 21]
                .into_iter()
                .find(|words| ![first, second].contains(words))
                .unwrap();
            let fingerprint = Reference::Fingerprint {
                fingerprint: wallet::master_fingerprint(phrase, "").unwrap(),
                passphrase: "",
            };
            for (reference, named, beside) in [
                (Reference::OwnChecks { passphrase: None }, first, second),
                (fingerprint, first, second),
                (stated(first), first, second),
                (stated(second), second, first),
                (stated(other), first, second),
            ] {
                let evidence = evidence_for(&mut mhfe, &container, &reference);
                assert!(evidence.outcome.matches());
                assert_eq!(evidence.built_in_check, Some(named));
                assert_eq!(evidence.other_lengths, [beside]);
            }
        }
    }

    /// The re-encryption guard: a phrase comes out only once confirmed.
    #[test]
    fn a_recovery_to_encrypt_again_needs_a_confirmation() {
        let password = test_password();
        let wrong = wrong_password();
        let none = &mut |_, _| crate::GO_ON;
        let mut mhfe = reduced();
        let twelve = WordCount::new(12).unwrap();
        let twenty_four = WordCount::new(24).unwrap();

        // A 12-word original in a 24-word container: its built-in check at the stated length.
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let phrase = recover_confirmed(
            &mut mhfe,
            &container,
            &password,
            twelve,
            Confirmation::BuiltInCheck,
            none,
        )
        .unstopped()
        .unwrap();
        assert_eq!(phrase.phrase(), ABANDON);
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
                &container,
                &wrong,
                twelve,
                Confirmation::BuiltInCheck,
                none
            ),
            Err(MhfeError::VerifierMismatch)
        ));

        // A 24-word original has no check: refused without a reference, before any Argon2 call.
        const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon art";
        let container = container_of(&mut mhfe, ART, Suite::TwentyFourWords);
        let mut rounds = 0;
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
                &container,
                &password,
                twenty_four,
                Confirmation::BuiltInCheck,
                &mut |_, _| {
                    rounds += 1;
                    crate::GO_ON
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
        let phrase = recover_confirmed(
            &mut mhfe,
            &container,
            &password,
            twenty_four,
            Confirmation::Wallet(&right),
            none,
        )
        .unstopped()
        .unwrap();
        assert_eq!(phrase.phrase(), ART);
        // The wrong password gives another valid phrase, which the reference refuses.
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
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
            recover_confirmed(
                &mut mhfe,
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&other_passphrase),
                none
            ),
            Err(MhfeError::ReferenceMismatch)
        ));

        // The owner may confirm a 24-word original instead: the phrase comes out for showing.
        let phrase = recover_confirmed(
            &mut mhfe,
            &container,
            &password,
            twenty_four,
            Confirmation::Owner,
            none,
        )
        .unstopped()
        .unwrap();
        assert_eq!(phrase.phrase(), ART);

        // A same-length container: its own length, and a reference.
        let container = container_of(&mut mhfe, ABANDON, Suite::SameLength);
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
                &container,
                &password,
                twelve,
                Confirmation::BuiltInCheck,
                none
            ),
            Err(MhfeError::ReferenceRequired)
        ));
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
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
        let phrase = recover_confirmed(
            &mut mhfe,
            &container,
            &password,
            twelve,
            Confirmation::Wallet(&abandon),
            none,
        )
        .unstopped()
        .unwrap();
        assert_eq!(phrase.phrase(), ABANDON);
    }

    #[test]
    fn a_wallet_check_matches_a_phrase_made_with_it_and_never_confirms_a_rekey() {
        let none = &mut |_, _| crate::GO_ON;
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let phrase = Phrase::from_entropy(&entropy).unwrap();
        let container = container_of(&mut mhfe, phrase.as_str(), Suite::TwentyFourWords);
        let reference = Reference::WalletCheck {
            passphrase: "TREZOR",
        };
        // A pass is evidence and no match: the reading stays not verified (REC-5).
        let evidence = recover_for_check(&mut mhfe, &container, &password, &reference, none)
            .unstopped()
            .unwrap()
            .compare(&reference)
            .unwrap();
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(evidence.wallet_check, Some(true));
        let evidence = recover_for_check(&mut mhfe, &container, &wrong, &reference, none)
            .unstopped()
            .unwrap()
            .compare(&reference)
            .unwrap();
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(evidence.wallet_check, Some(false));
        let other = Reference::WalletCheck {
            passphrase: "trezor",
        };
        assert_eq!(
            check(&mut mhfe, &container, &password, &other, none).unstopped(),
            Ok(CheckOutcome::NotVerified)
        );
        // Without a passphrase the check is not offered: refused before any Argon2 work, as the
        // browser and wallet_check::verify refuse it (AUD-010).
        let mut rounds = 0;
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::WalletCheck { passphrase: "" },
                &mut |_, _| {
                    rounds += 1;
                    crate::GO_ON
                }
            ),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(rounds, 0);
        assert!(matches!(
            recover_confirmed(
                &mut mhfe,
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
        let none = &mut |_, _| crate::GO_ON;
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        let own = |passphrase| Reference::OwnChecks { passphrase };
        let short = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        for passphrase in [None, Some("TREZOR")] {
            let evidence = recover_for_check(&mut mhfe, &short, &password, &own(passphrase), none)
                .unstopped()
                .unwrap()
                .compare(&own(passphrase))
                .unwrap();
            assert!(evidence.outcome.matches());
            assert_eq!(evidence.built_in_check, Some(12));
        }
        // A wrong password leaves a 24-word reading that nothing confirms (APP-6).
        assert_eq!(
            check(&mut mhfe, &short, &wrong, &own(None), none).unstopped(),
            Ok(CheckOutcome::NotVerified)
        );
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let drawn = Phrase::from_entropy(&entropy).unwrap();
        let full = container_of(&mut mhfe, drawn.as_str(), Suite::TwentyFourWords);
        let evidence = recover_for_check(&mut mhfe, &full, &password, &own(Some("TREZOR")), none)
            .unstopped()
            .unwrap()
            .compare(&own(Some("TREZOR")))
            .unwrap();
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(
            (evidence.built_in_check, evidence.wallet_check),
            (None, Some(true))
        );
        for passphrase in [None, Some("trezor")] {
            assert_eq!(
                check(&mut mhfe, &full, &password, &own(passphrase), none).unstopped(),
                Ok(CheckOutcome::NotVerified)
            );
        }
        assert_eq!(
            check(&mut mhfe, &full, &password, &own(Some("")), none),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        let same_length = container_of(&mut mhfe, ABANDON, Suite::SameLength);
        assert_eq!(
            check(&mut mhfe, &same_length, &password, &own(None), none),
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
        let phrase = Phrase::from_entropy(&[7u8; 32]).unwrap();
        let phrase = phrase.as_str();
        let container = container_of(&mut mhfe, phrase, Suite::TwentyFourWords);
        let own = Reference::OwnChecks { passphrase: None };
        let mut rounds = 0;
        let recovered = recover_for_check(&mut mhfe, &container, &password, &own, &mut |_, _| {
            rounds += 1;
            crate::GO_ON
        })
        .unstopped()
        .unwrap();
        assert_eq!(rounds, ROUNDS);
        assert_eq!(
            recovered.compare(&own).unwrap().outcome,
            CheckOutcome::NotVerified
        );
        let fingerprint = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(phrase, "").unwrap(),
            passphrase: "",
        };
        assert!(recovered.compare(&fingerprint).unwrap().outcome.matches());
        assert_eq!(
            recovered.compare(&Reference::WalletCheck { passphrase: "" }),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
    }

    /// A public passphrase with which the 12-word test phrase would pass under BE32(128), which
    /// the profile does not define and the core never computes; its 24-word reading fails
    /// (AUD-010, harness crypto-core/short_reading_wallet_check.py).
    const SHORT_READING_PASSPHRASE: &str = "aud010 public probe 11656";

    /// A 12-word original is verified by its built-in check: a passphrase that would pass under
    /// BE32(128) changes nothing, and the wallet check is not computed for it (AUD-010).
    #[test]
    fn a_wallet_check_compares_the_24_word_reading_only() {
        let none = &mut |_, _| crate::GO_ON;
        let mut mhfe = reduced();
        let password = test_password();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        // The recovery reads as the 12-word phrase, which the built-in check confirms.
        let built_in = Reference::BuiltInCheck {
            words: WordCount::new(12).unwrap(),
        };
        assert!(check(&mut mhfe, &container, &password, &built_in, none)
            .unstopped()
            .unwrap()
            .matches());
        let reference = Reference::WalletCheck {
            passphrase: SHORT_READING_PASSPHRASE,
        };
        assert_eq!(
            check(&mut mhfe, &container, &password, &reference, none).unstopped(),
            Ok(CheckOutcome::Matches { path: None })
        );
        let staged = recover_for_check_in_stages(
            &mut mhfe,
            &container,
            &password,
            &reference,
            &mut |_, _, _| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let evidence = staged.compare(&reference).unwrap();
        assert_eq!(evidence.outcome, CheckOutcome::Matches { path: None });
        assert_eq!(evidence.wallet_check, None);
    }

    #[test]
    fn every_reference_matches_the_right_password_only() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);

        let address = [Address::parse(
            wallet::Coin::Bitcoin,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        )
        .unwrap()];
        let references = [
            Reference::BuiltInCheck {
                words: WordCount::new(12).unwrap(),
            },
            Reference::Address {
                addresses: &address,
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
            assert!(quiet_check(&mut mhfe, &container, &password, reference)
                .unwrap()
                .matches());
            assert!(!quiet_check(&mut mhfe, &container, &wrong, reference)
                .unwrap()
                .matches());
        }

        // A matched address names its path: the first native SegWit receiving address.
        let found = quiet_check(&mut mhfe, &container, &password, &references[1]).unwrap();
        assert_eq!(
            found.path().map(ToString::to_string).as_deref(),
            Some("m/84'/0'/0'/0/0")
        );

        // The right password with a wrong BIP39 passphrase is a different wallet, and the wallet
        // with the passphrase is not the one without it.
        let with_passphrase = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(ABANDON, "TREZOR").unwrap(),
            passphrase: "trezor",
        };
        assert!(
            !quiet_check(&mut mhfe, &container, &password, &with_passphrase)
                .unwrap()
                .matches()
        );
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
        let recovered = recover_for_check_in_stages(
            &mut mhfe,
            &container,
            &password,
            &reference,
            &mut |stage, round, rounds| {
                reports.push((stage, round, rounds));
                crate::GO_ON
            },
        )
        .unstopped()
        .unwrap();
        assert!(recovered.compare(&reference).unwrap().outcome.matches());
        let mut expected: Vec<(Stage, u32, u32)> =
            (1..=12).map(|round| (Stage::Recover, round, 12)).collect();
        expected.push((Stage::Compare, 12, 12));
        assert_eq!(reports, expected);

        let stopped = recover_for_check_in_stages(
            &mut mhfe,
            &container,
            &password,
            &reference,
            &mut |stage, _, _| {
                if stage == Stage::Compare {
                    Ok(ControlFlow::Break(()))
                } else {
                    crate::GO_ON
                }
            },
        );
        assert!(matches!(stopped, Ok(ControlFlow::Break(()))));
    }

    #[test]
    fn a_24_word_original_is_checked_against_the_wallet() {
        let password = test_password();
        let mut mhfe = reduced();
        let original = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal winner thank year wave sausage worth title";
        let container = container_of(&mut mhfe, original, Suite::TwentyFourWords);
        let reference = Reference::Fingerprint {
            fingerprint: wallet::master_fingerprint(original, "").unwrap(),
            passphrase: "",
        };
        assert!(quiet_check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            quiet_check(
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
        assert!(quiet_check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert!(!quiet_check(&mut mhfe, &container, &wrong, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            quiet_check(
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
            quiet_check(
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
