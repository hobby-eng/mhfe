//! Known answers of the rehearsal check: the self-check `rehearsal`.
//!
//! The published container zero-12 with its password, replayed with its recorded round keys and
//! compared with each kind of reference: the master key fingerprint 73c5da0a of the root key that
//! BIP84's test vector publishes, the receiving address of BIP84's test vector at its path, and the
//! built-in check. A fingerprint that differs in one bit must not match. The length rules give each
//! outcome on the published containers that carry it ([`LENGTH_CASES`]).

use crate::mhfe::known_answers::{published, published_table};
use crate::rehearsal::{CheckEvidence, CheckOutcome, Reference};
use crate::self_check::{
    damaged, expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::wallet::{Address, Coin, DerivationPath, SearchLimits};
use crate::WordCount;

/// The master key fingerprint of zero-12's phrase without a passphrase, derived from the root key
/// that BIP-0084's test vector publishes, and shown by many wallets.
const FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const WRONG_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0b];
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
    fn reference(self) -> Result<Reference<'static>, String> {
        Ok(match self {
            Self::BuiltInCheck(words) => Reference::BuiltInCheck {
                words: WordCount::new(words).map_err(stopped)?,
            },
            Self::Detected => Reference::OwnChecks { passphrase: None },
            Self::WalletCheck(passphrase) => Reference::WalletCheck { passphrase },
        })
    }

    fn name(self) -> String {
        match self {
            Self::BuiltInCheck(words) => format!("the built-in check of {words} words"),
            Self::Detected => "the length detected".to_owned(),
            Self::WalletCheck(_) => "the wallet check".to_owned(),
        }
    }
}

/// A check of a published container against one of the phrase's own checks, and what the length
/// rules of recovery must give: the outcome, the length of the one verified reading and every
/// length whose built-in check passes.
struct LengthCase {
    vector: &'static str,
    reference: OwnReference,
    outcome: CheckOutcome,
    built_in_check: Option<usize>,
    matching_lengths: &'static [usize],
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
    },
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::BuiltInCheck(12),
        outcome: CheckOutcome::DoesNotMatch,
        built_in_check: None,
        matching_lengths: &[],
    },
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::Detected,
        outcome: CheckOutcome::NotVerified,
        built_in_check: None,
        matching_lengths: &[],
    },
    // 24 zero bytes fail the 16-bit check with "TREZOR": the first counter whose phrase passes
    // with it is 76,562 (src/wallet_check/known_answers.rs).
    LengthCase {
        vector: "zero-24",
        reference: OwnReference::WalletCheck("TREZOR"),
        outcome: CheckOutcome::DoesNotMatch,
        built_in_check: None,
        matching_lengths: &[],
    },
    LengthCase {
        vector: "ambiguous-12-21",
        reference: OwnReference::Detected,
        outcome: CheckOutcome::NotVerified,
        built_in_check: None,
        matching_lengths: &[12, 21],
    },
    LengthCase {
        vector: "ambiguous-12-21",
        reference: OwnReference::BuiltInCheck(21),
        outcome: MATCHES,
        built_in_check: Some(21),
        matching_lengths: &[12, 21],
    },
];

impl LengthCase {
    fn run(&self) -> Result<(), String> {
        let reference = self.reference.reference()?;
        let evidence = RehearsalCheck::evidence(self.vector, &reference)?;
        let given = (
            &evidence.outcome,
            evidence.built_in_check,
            evidence.matching_lengths.as_slice(),
        );
        if given == (&self.outcome, self.built_in_check, self.matching_lengths) {
            return Ok(());
        }
        Err(format!(
            "{} with {} gives \"{}\", not \"{}\"",
            self.vector,
            self.reference.name(),
            describe(&evidence),
            describe_expected(self),
        ))
    }
}

/// An outcome with the lengths beside it, as a failure names it.
fn described(outcome: &CheckOutcome, built_in_check: Option<usize>, lengths: &[usize]) -> String {
    let built_in = built_in_check.map_or("none".to_owned(), |words| words.to_string());
    format!(
        "{}, verified length {built_in}, lengths {lengths:?}",
        outcome.text()
    )
}

fn describe(evidence: &CheckEvidence) -> String {
    described(
        &evidence.outcome,
        evidence.built_in_check,
        &evidence.matching_lengths,
    )
}

fn describe_expected(case: &LengthCase) -> String {
    described(&case.outcome, case.built_in_check, case.matching_lengths)
}

/// The `rehearsal` check.
pub(crate) struct RehearsalCheck {
    fingerprint: [u8; 4],
    length_cases: &'static [LengthCase],
}

impl RehearsalCheck {
    pub(crate) fn new() -> Self {
        Self {
            fingerprint: FINGERPRINT,
            length_cases: LENGTH_CASES,
        }
    }

    /// Runs the rehearsal of zero-12 against `reference`.
    fn check(reference: &Reference<'_>) -> Result<CheckOutcome, String> {
        Ok(Self::evidence("zero-12", reference)?.outcome)
    }

    /// Runs the rehearsal of the published container `name` against `reference`.
    fn evidence(name: &str, reference: &Reference<'_>) -> Result<CheckEvidence, String> {
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
                outcome.matches(),
                "a matching fingerprint is reported as not matching",
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
                "a matching address is reported as not matching",
            )
        });
        findings.one(|| {
            let words = WordCount::new(12).map_err(stopped)?;
            let outcome = Self::check(&Reference::BuiltInCheck { words })?;
            expect(
                outcome.matches(),
                "the built-in check is reported as not matching",
            )
        });
        findings.one(|| {
            let outcome = Self::check(&Reference::Fingerprint {
                fingerprint: WRONG_FINGERPRINT,
                passphrase: "",
            })?;
            expect(
                outcome == CheckOutcome::DoesNotMatch,
                "a fingerprint that differs is reported as matching",
            )
        });
        for case in self.length_cases {
            findings.one(|| case.run());
        }
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
            fingerprint: [0x73, 0xc5, 0xda, 0x0c],
            length_cases: LENGTH_CASES,
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "a matching fingerprint is reported as not matching".to_owned()
            )
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
        }];
        let mut check = RehearsalCheck {
            fingerprint: FINGERPRINT,
            length_cases: DAMAGED,
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "zero-24 with the length detected gives \"not verified, verified length none, \
                 lengths []\", not \"does not match, verified length none, lengths []\""
                    .to_owned()
            )
        );
    }
}
