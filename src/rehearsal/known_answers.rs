//! Known answers of the rehearsal check: the self-check `rehearsal`.
//!
//! The published container zero-12 with its password, replayed with its recorded round keys and
//! compared with each kind of reference: the master key fingerprint 73c5da0a (published), the
//! receiving address of BIP84's test vector at its path, and the built-in check. A fingerprint
//! that differs in one bit must not match.

use crate::mhfe::known_answers::{published, published_table};
use crate::rehearsal::{CheckOutcome, Reference};
use crate::self_check::{expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier};
use crate::wallet::{Address, Coin, DerivationPath, SearchLimits};
use crate::WordCount;

/// The master key fingerprint of zero-12's phrase without a passphrase, published by BIP-0084's
/// test vector and many wallets.
const FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const WRONG_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0b];
/// BIP-0084's first receiving address of the same phrase, at its path.
const ADDRESS: (&str, &str) = (
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "m/84'/0'/0'/0/0",
);

/// The `rehearsal` check.
pub(crate) struct RehearsalCheck {
    fingerprint: [u8; 4],
}

impl RehearsalCheck {
    pub(crate) fn new() -> Self {
        Self {
            fingerprint: FINGERPRINT,
        }
    }

    /// Runs the rehearsal of zero-12 against `reference`.
    fn check(reference: &Reference<'_>) -> Result<CheckOutcome, String> {
        let vector = published("zero-12")?;
        vector
            .mhfe(published_table())?
            .check(
                vector.container,
                &vector.password()?,
                reference,
                &mut |_, _| Ok(()),
            )
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
            let path: DerivationPath = ADDRESS
                .1
                .parse()
                .map_err(|_| "the built-in cases are damaged".to_owned())?;
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
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "a matching fingerprint is reported as not matching".to_owned()
            )
        );
    }
}
