//! Terminal display data from the library's immutable rehearsal comparisons.

use mhfe::{CheckEvidence, CheckOutcome, PassedCheck, RecoveredForCheck, Reference};

use super::Choice;
use crate::exit::Failure;

/// Public recovery evidence translated once into the terminal's display data. The library owns
/// its immutable result; terminal tests supply explicit display fixtures without forging one.
pub(super) struct DisplayedEvidence {
    outcome: CheckOutcome,
    built_in_check: Option<usize>,
    matching_lengths: Vec<usize>,
    wallet_check: Option<bool>,
    passed: Vec<PassedCheck>,
}

impl DisplayedEvidence {
    pub(super) fn outcome(&self) -> &CheckOutcome {
        &self.outcome
    }
    pub(super) fn built_in_check(&self) -> Option<usize> {
        self.built_in_check
    }
    pub(super) fn matching_lengths(&self) -> &[usize] {
        &self.matching_lengths
    }
    pub(super) fn wallet_check(&self) -> Option<bool> {
        self.wallet_check
    }
    pub(super) fn passed(&self) -> &[PassedCheck] {
        &self.passed
    }
    #[cfg(test)]
    pub(super) fn fixture(
        outcome: CheckOutcome,
        built_in_check: Option<usize>,
        matching_lengths: Vec<usize>,
        wallet_check: Option<bool>,
        passed: Vec<PassedCheck>,
    ) -> Self {
        Self {
            outcome,
            built_in_check,
            matching_lengths,
            wallet_check,
            passed,
        }
    }
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
    choice: Choice,
    evidence: DisplayedEvidence,
    asks_length: bool,
    identifies_wallet: bool,
    with_passphrase: bool,
}

impl Compared {
    pub(super) fn choice(&self) -> Choice {
        self.choice
    }
    pub(super) fn evidence(&self) -> &DisplayedEvidence {
        &self.evidence
    }
    pub(super) fn asks_length(&self) -> bool {
        self.asks_length
    }
    pub(super) fn identifies_wallet(&self) -> bool {
        self.identifies_wallet
    }
    pub(super) fn with_passphrase(&self) -> bool {
        self.with_passphrase
    }

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
