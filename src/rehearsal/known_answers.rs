//! Known answers of the rehearsal check: the self-check `rehearsal`.
//!
//! The published container zero-12 with its password, replayed with its recorded round keys and
//! compared with each kind of reference: the master key fingerprint 73c5da0a of the root key that
//! BIP84's test vector publishes, the receiving address of BIP84's test vector at its path, and the
//! built-in check. A fingerprint that differs in one bit must not match. The length rules give each
//! outcome on the published containers that carry it ([`LENGTH_CASES`]).

use crate::wallet::Fingerprint;

use crate::mhfe::known_answers::{published, published_table};
use crate::rehearsal::{CheckEvidence, CheckOutcome, PassedCheck, Reference};
use crate::self_check::{
    damaged, expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::wallet::{Address, Coin, DerivationPath, SearchLimits};
use crate::WordCount;

use crate::vectors::inputs::WRONG_FINGERPRINT;
/// The master key fingerprint of zero-12's phrase without a passphrase, derived from the root key
/// that BIP-0084's test vector publishes, and shown by many wallets.
use crate::vectors::inputs::ZERO_12_FINGERPRINT as FINGERPRINT;
/// BIP-0084's first receiving address of the same phrase, at its path.
const ADDRESS: (&str, &str) = (
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "m/84'/0'/0'/0/0",
);

/// A reference of the original seed phrase's own checks, as a case names it.
#[derive(Clone, Copy)]
enum OwnReference {
    BuiltInCheck(usize),
    Detected,
    WalletCheck(&'static str),
}

impl OwnReference {
    fn reference(self) -> Result<Reference<'static>, crate::self_check::FailureDetail> {
        Ok(match self {
            Self::BuiltInCheck(words) => Reference::BuiltInCheck {
                words: WordCount::new(words).map_err(stopped)?,
            },
            Self::Detected => Reference::OwnChecks { passphrase: None },
            Self::WalletCheck(passphrase) => Reference::WalletCheck { passphrase },
        })
    }

    fn diagnostic(self) -> crate::self_check::LengthReference {
        use crate::self_check::LengthReference;
        match self {
            Self::BuiltInCheck(words) => LengthReference::BuiltInCheck(words),
            Self::Detected => LengthReference::Detected,
            Self::WalletCheck(_) => LengthReference::WalletCheck,
        }
    }
}

/// A check of a published container against one of the phrase's own checks, and what the length
/// rules of recovery must give: the outcome, the length of the one verified reading and every
/// length whose built-in check passes.
#[derive(Clone)]
struct LengthCase {
    vector: &'static str,
    reference: OwnReference,
    outcome: CheckOutcome,
    built_in_check: Option<usize>,
    matching_lengths: &'static [usize],
    wallet_check: Option<bool>,
    passed: fn() -> Vec<PassedCheck>,
    asks_length: bool,
}

const MATCHES: CheckOutcome = CheckOutcome::Matches { path: None };

/// Each outcome of the length rules on the published containers that carry it (AUD-023-ARC015): a
/// short original that matches, also with its length detected; a stated short length with no
/// reading; a 24-word reading that nothing verifies; a wallet check that fails; and several lengths
/// that pass, which match only where one of them is stated.
const LENGTH_CASES: &[LengthCase] = &[
    LengthCase {
        vector: "zero-12",
        reference: OwnReference::Detected,
        outcome: MATCHES,
        built_in_check: Some(12),
        matching_lengths: &[12],
        wallet_check: None,
        passed: || vec![PassedCheck::BuiltInCheck(12)],
        asks_length: false,
    },
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::BuiltInCheck(12),
        outcome: CheckOutcome::DoesNotMatch,
        built_in_check: None,
        matching_lengths: &[],
        wallet_check: None,
        passed: || vec![],
        asks_length: false,
    },
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::Detected,
        outcome: CheckOutcome::NotVerified,
        built_in_check: None,
        matching_lengths: &[],
        wallet_check: Some(false),
        passed: || vec![],
        asks_length: true,
    },
    // 24 zero bytes fail the 16-bit check with "TREZOR": the first counter whose phrase passes
    // with it is 76,562 (src/wallet_check/known_answers.rs).
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::WalletCheck("TREZOR"),
        outcome: CheckOutcome::DoesNotMatch,
        built_in_check: None,
        matching_lengths: &[],
        wallet_check: Some(false),
        passed: || vec![],
        asks_length: false,
    },
    LengthCase {
        vector: "ambiguous-12-21",
        reference: OwnReference::Detected,
        outcome: CheckOutcome::NotVerified,
        built_in_check: None,
        matching_lengths: &[12, 21],
        wallet_check: Some(false),
        passed: || vec![PassedCheck::BuiltInChecks(vec![12, 21])],
        asks_length: true,
    },
    LengthCase {
        vector: "ambiguous-12-21",
        reference: OwnReference::BuiltInCheck(21),
        outcome: MATCHES,
        built_in_check: Some(21),
        matching_lengths: &[12, 21],
        wallet_check: None,
        passed: || vec![PassedCheck::BuiltInCheck(21)],
        asks_length: false,
    },
];

impl LengthCase {
    fn run(&self) -> Result<(), crate::self_check::FailureDetail> {
        let reference = self.reference.reference()?;
        let evidence = RehearsalCheck::evidence(self.vector, &reference)?;
        let expected = self.expected();
        if evidence == expected && evidence.own_checks_passed() == (self.passed)() {
            return Ok(());
        }
        Err(crate::self_check::FailureDetail::LengthRule {
            reference: self.reference.diagnostic(),
            actual: Box::new(diagnostic(&evidence, evidence.own_checks_passed())),
            expected: Box::new(diagnostic(&expected, (self.passed)())),
        })
    }

    fn expected(&self) -> CheckEvidence {
        CheckEvidence {
            outcome: self.outcome.clone(),
            built_in_check: self.built_in_check,
            matching_lengths: self.matching_lengths.to_vec(),
            wallet_check: self.wallet_check,
            asks_length: self.asks_length,
        }
    }
}

/// Only public comparison metadata, with every compared field retained for diagnostics.
fn diagnostic(
    evidence: &CheckEvidence,
    passed: Vec<PassedCheck>,
) -> crate::self_check::LengthEvidence {
    crate::self_check::LengthEvidence::from_check(evidence, passed)
}

/// The `rehearsal` check.
pub(crate) struct RehearsalCheck {
    fingerprint: Fingerprint,
    length_cases: &'static [LengthCase],
}

impl RehearsalCheck {
    pub(crate) fn new() -> Self {
        Self {
            fingerprint: Fingerprint::from_bytes(FINGERPRINT),
            length_cases: LENGTH_CASES,
        }
    }

    /// Runs the rehearsal of zero-12 against `reference`.
    fn check(reference: &Reference<'_>) -> Result<CheckOutcome, crate::self_check::FailureDetail> {
        Ok(Self::evidence("zero-12", reference)?.outcome)
    }

    /// Runs the rehearsal of the published container `name` against `reference`.
    fn evidence(
        name: &str,
        reference: &Reference<'_>,
    ) -> Result<CheckEvidence, crate::self_check::FailureDetail> {
        let vector = published(name)?;
        vector
            .mhfe(published_table())?
            .recover_for_check(
                vector.container,
                &vector.password()?,
                reference,
                &mut |_, _| Ok(()),
            )
            .and_then(|recovered| recovered.compare(reference))
            .map_err(stopped)
    }
}

impl ComponentCheck for RehearsalCheck {
    fn id(&self) -> &'static str {
        "rehearsal"
    }

    fn label(&self) -> &'static str {
        "Rehearsal"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        let fingerprint = self.fingerprint;
        findings.one(|| {
            let outcome = Self::check(&Reference::Fingerprint {
                fingerprint,
                passphrase: "",
            })?;
            expect(
                outcome.matches(), crate::self_check::KnownAnswerDifference::AMatchingFingerprintIsReportedAsNotMatching,
            )
        });
        findings.one(|| {
            let address = Address::parse(Coin::Bitcoin, ADDRESS.0).map_err(stopped)?;
            let path: DerivationPath = ADDRESS.1.parse().map_err(|_| damaged())?;
            let outcome = Self::check(&Reference::Address {
                address: &address,
                passphrase: "",
                path: Some(&path),
                limits: SearchLimits::default(),
            })?;
            expect(
                outcome.path() == Some(&path),
                crate::self_check::KnownAnswerDifference::AMatchingAddressIsReportedAsNotMatching,
            )
        });
        findings.one(|| {
            let words = WordCount::new(12).map_err(stopped)?;
            let outcome = Self::check(&Reference::BuiltInCheck { words })?;
            expect(
                outcome.matches(),
                crate::self_check::KnownAnswerDifference::TheBuiltInCheckIsReportedAsNotMatching,
            )
        });
        findings.one(|| {
            let outcome = Self::check(&Reference::Fingerprint {
                fingerprint: Fingerprint::from_bytes(WRONG_FINGERPRINT),
                passphrase: "",
            })?;
            expect(
                outcome == CheckOutcome::DoesNotMatch, crate::self_check::KnownAnswerDifference::AFingerprintThatDiffersIsReportedAsMatching,
            )
        });
        findings.each(
            crate::self_check::CaseKind::LengthRule,
            self.length_cases,
            LengthCase::run,
        );
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rehearsal_passes() {
        assert_eq!(
            RehearsalCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_wrong_fingerprint_fails() {
        let mut check = RehearsalCheck {
            fingerprint: Fingerprint::from_bytes([0x73, 0xc5, 0xda, 0x0c]),
            length_cases: LENGTH_CASES,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "a matching fingerprint is reported as not matching".to_owned()
        );
    }

    /// A case of the length rules whose answer differs fails the check and names what it gave
    /// (AUD-023-ARC015).
    #[test]
    fn a_length_rule_that_differs_fails() {
        const DAMAGED: &[LengthCase] = &[LengthCase {
            vector: "zero-24",
            reference: OwnReference::Detected,
            outcome: CheckOutcome::DoesNotMatch,
            built_in_check: None,
            matching_lengths: &[],
            wallet_check: Some(false),
            passed: || vec![],
            asks_length: true,
        }];
        let mut check = RehearsalCheck {
            fingerprint: Fingerprint::from_bytes(FINGERPRINT),
            length_cases: DAMAGED,
        };
        crate::self_check::assert_failed!(check.run(Tier::Startup), "length rule 1 of 1 with the length detected gives \"not verified, verified length none, \
                 lengths [], wallet check Some(false), passed [], asks length true\", not \"does not match, verified length none, lengths [], wallet check Some(false), passed [], asks length true\""
                    .to_owned());
    }
    #[test]
    fn wallet_evidence_passed_checks_and_follow_up_decisions_are_checked() {
        for original in LENGTH_CASES {
            assert!(original.run().is_ok());
            let mut wrong = original.clone();
            wrong.wallet_check = Some(!original.wallet_check.unwrap_or(false));
            assert!(wrong
                .run()
                .unwrap_err()
                .to_string()
                .contains("wallet check"));
            let mut wrong = original.clone();
            wrong.passed = || vec![PassedCheck::WalletCheck];
            assert!(wrong.run().unwrap_err().to_string().contains("passed"));
            let mut wrong = original.clone();
            wrong.asks_length = !original.asks_length;
            assert!(wrong.run().unwrap_err().to_string().contains("asks length"));
        }
    }
}
