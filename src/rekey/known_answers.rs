//! Known answers of a rekey: the self-check `rekey`.
//!
//! zero-12's container recovered with its password, confirmed by its built-in check, and sealed
//! again must give the published container of the same phrase under the new password or settings:
//! unicode-password (another password) and zero-12-pim-1 (PIM 1). Both are replayed with the
//! recorded round keys of the three vectors, whose salts differ. The refusals: the same password
//! and settings, and a fingerprint that does not match.

use super::Rekey;
use crate::mhfe::known_answers::{published, published_table};
use crate::rehearsal::{Confirmation, Reference};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

/// A rekey from one published vector to another of the same phrase.
#[derive(Clone, Copy)]
struct RekeyCase {
    from: &'static str,
    to: &'static str,
}

const CASES: [RekeyCase; 2] = [
    RekeyCase {
        from: "zero-12",
        to: "unicode-password",
    },
    RekeyCase {
        from: "zero-12",
        to: "zero-12-pim-1",
    },
];

/// The master key fingerprint of "abandon" 11 times and "about" is 73c5da0a; this one differs in
/// its last bit, so no recovery of a zero-24 container can match it.
const WRONG_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0b];

/// The `rekey` check.
pub(crate) struct RekeyCheck {
    cases: &'static [RekeyCase],
}

impl RekeyCheck {
    pub(crate) fn new() -> Self {
        Self { cases: &CASES }
    }

    fn case(case: &RekeyCase) -> Result<(), String> {
        let from = published(case.from)?;
        let to = published(case.to)?;
        let words = Some(from.phrase.split(' ').count());
        let rekey = Rekey::new(from.container, words, from.password()?, from.work()?, true)
            .map_err(stopped)?;
        let confirmed = rekey
            .recover(
                &mut from.mhfe(published_table())?,
                Confirmation::BuiltInCheck,
                Some(false),
                &mut |_, _, _| Ok(()),
            )
            .map_err(stopped)?;
        let sealed = rekey
            .seal(
                &mut to.mhfe(published_table())?,
                &confirmed,
                &to.password()?,
                None,
                &mut |_, _, _| Ok(()),
                &mut |_| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            sealed.container() == to.container,
            "the sealed container differs from the published one",
        )
    }
}

impl ComponentCheck for RekeyCheck {
    fn id(&self) -> &'static str {
        "rekey"
    }

    fn label(&self) -> &'static str {
        "Rekey"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("rekey", self.cases, Self::case);
        findings.one(|| {
            let vector = published("zero-12")?;
            let rekey = Rekey::new(
                vector.container,
                Some(12),
                vector.password()?,
                vector.work()?,
                true,
            )
            .map_err(stopped)?;
            expect_refusal(
                rekey.check_new(&vector.password()?, vector.work()?),
                "NEW_PASSWORD_SAME_AS_OLD",
            )
            .map_err(|what| format!("the same password and settings {what}"))
        });
        // zero-24 has no built-in check: a reference confirms it, and a wrong one is refused.
        findings.one(|| {
            let vector = published("zero-24")?;
            let rekey = Rekey::new(
                vector.container,
                Some(24),
                vector.password()?,
                vector.work()?,
                true,
            )
            .map_err(stopped)?;
            let reference = Reference::Fingerprint {
                fingerprint: WRONG_FINGERPRINT,
                passphrase: "",
            };
            let result = rekey.recover(
                &mut vector.mhfe(published_table())?,
                Confirmation::Wallet(&reference),
                Some(false),
                &mut |_, _, _| Ok(()),
            );
            expect_refusal(result.map(|_| ()), "REFERENCE_MISMATCH")
                .map_err(|what| format!("a fingerprint that does not match {what}"))
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rekey_passes() {
        assert_eq!(
            RekeyCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_rekey_is_compared_with_its_target_vector() {
        let mut check = RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from: "zero-12",
                to: "spaces-password",
            }])),
        };
        // spaces-password and zero-12-memory-level-1 hold the same phrase under another password
        // or memory level: the rekey gives their containers. A vector of another phrase fails.
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut check = RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from: "zero-12",
                to: "zero-12-memory-level-1",
            }])),
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut check = RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from: "zero-12",
                to: "nonzero-12",
            }])),
        };
        assert!(check.run(Tier::Startup).is_failure());
    }
}
