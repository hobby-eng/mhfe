//! Terminal display data from the library's immutable rehearsal comparisons.

use mhfe::{CheckEvidence, CheckOutcome, PassedCheck, RecoveredForCheck, Reference};

use super::Choice;
use crate::exit::Failure;

/// Public recovery evidence translated once into the terminal's display data. The library owns
/// its immutable result; terminal tests supply explicit display fixtures without forging one.
pub(super) struct DisplayedEvidence {
    pub(super) outcome: CheckOutcome,
    pub(super) built_in_check: Option<usize>,
    pub(super) matching_lengths: Vec<usize>,
    pub(super) wallet_check: Option<bool>,
    pub(super) passed: Vec<PassedCheck>,
}

impl From<&CheckEvidence> for DisplayedEvidence {
    fn from(evidence: &CheckEvidence) -> Self {
        Self {
            outcome: evidence.outcome().clone(),
            built_in_check: evidence.built_in_check(),
            matching_lengths: evidence.matching_lengths().to_vec(),
            wallet_check: evidence.wallet_check(),
            passed: evidence.own_checks_passed(),
        }
    }
}

/// A check's comparison, as the result lists it.
pub(super) struct Compared {
    pub(super) choice: Choice,
    pub(super) evidence: DisplayedEvidence,
    pub(super) asks_length: bool,
    pub(super) identifies_wallet: bool,
    pub(super) with_passphrase: bool,
}

impl Compared {
    pub(super) fn with(
        choice: Choice,
        reference: &Reference<'_>,
        recovered: &RecoveredForCheck,
    ) -> Result<Self, Failure> {
        Ok(Self::from_evidence(
            choice,
            reference,
            recovered.compare(reference)?,
        ))
    }

    pub(super) fn after_detection(
        choice: Choice,
        reference: &Reference<'_>,
        recovered: &RecoveredForCheck,
    ) -> Result<Self, Failure> {
        Ok(Self::from_evidence(
            choice,
            reference,
            recovered.compare_after_detection(reference)?,
        ))
    }

    fn from_evidence(
        choice: Choice,
        reference: &Reference<'_>,
        evidence: mhfe::CheckEvidence,
    ) -> Self {
        Self {
            choice,
            asks_length: evidence.asks_length(),
            evidence: DisplayedEvidence::from(&evidence),
            identifies_wallet: reference.identifies_wallet(),
            with_passphrase: reference.given_passphrase().is_some(),
        }
    }
}
