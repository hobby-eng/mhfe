//! Known answers of a rekey: the self-check `rekey`.
//!
//! zero-12's container recovered with its password, confirmed by its built-in check, and sealed
//! again must give the published container of the same phrase under the new password or settings:
//! unicode-password (another password) and zero-12-pim-1 (PIM 1), the second with the length
//! detected. Both are replayed with the recorded round keys of the three vectors, whose salts
//! differ; the detected one is confirmed by its fingerprint, as the built-in check alone confirms
//! no detected length (AUD-017-FUN001). One recovery is confirmed twice (AUD-017-UI002): zero-12
//! with 15 words stated, whose built-in check finds 12 and is refused, leaves the owner the stated
//! length and is then confirmed by its fingerprint without the rounds again, and sealed as
//! unicode-password. The refusals: the same password and settings, a fingerprint that does not
//! match, zero-24 with its length detected and only the built-in check, and zero-12 with 15 words
//! stated and only the built-in check, which finds 12 (AUD-015-FUN001).

use crate::wallet::Fingerprint;

use super::{ConfirmedPhrase, Rekey, ReplacementRehearsal};
use crate::mhfe::known_answers::{published_in, published_table, PublishedVector};
use crate::rehearsal::{Confirmation, Reference};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::{PhraseLength, WordCount};

/// A rekey from one published vector to another of the same phrase, its length stated or
/// detected (`detection`).
#[derive(Clone)]
struct RekeyCase {
    from: &'static str,
    to: &'static str,
    detected: bool,
    replacement: ReplacementRehearsal,
}

const CASES: [RekeyCase; 2] = [
    RekeyCase {
        from: "zero-12",
        to: "unicode-password",
        detected: false,
        replacement: ReplacementRehearsal::BuiltInCheck,
    },
    RekeyCase {
        from: "zero-12",
        to: "zero-12-pim-1",
        detected: true,
        replacement: ReplacementRehearsal::BuiltInCheck,
    },
];

/// The master key fingerprint of "abandon" 11 times and "about" is 73c5da0a; this one differs in
/// its last bit, so no recovery of a zero-24 container can match it.
use crate::vectors::inputs::WRONG_FINGERPRINT;

/// A rekey of one published vector that must be refused with `code`.
#[derive(Clone, Copy)]
struct Refusal {
    vector: &'static str,
    /// A new vector for a same-password/settings refusal; otherwise recover and confirm.
    new_vector: Option<&'static str>,
    /// The stated length, or none for a detected one.
    words: Option<usize>,
    /// A wrong fingerprint as the confirmation, or the built-in check alone.
    wrong_fingerprint: bool,
    code: &'static str,
    what: crate::self_check::CheckContext,
}

const REFUSALS: [Refusal; 4] = [
    Refusal {
        vector: "zero-12",
        new_vector: Some("zero-12"),
        words: Some(12),
        wrong_fingerprint: false,
        code: "NEW_PASSWORD_SAME_AS_OLD",
        what: crate::self_check::CheckContext::TheSamePasswordAndSettings,
    },
    // zero-24 has no built-in check: a reference confirms it, and a wrong one is refused.
    Refusal {
        vector: "zero-24",
        new_vector: None,
        words: Some(24),
        wrong_fingerprint: true,
        code: "REFERENCE_MISMATCH",
        what: crate::self_check::CheckContext::AFingerprintThatDoesNotMatch,
    },
    // A detected length is never confirmed by the built-in check alone, before any Argon2 work.
    Refusal {
        vector: "zero-24",
        new_vector: None,
        words: None,
        wrong_fingerprint: false,
        code: "REFERENCE_REQUIRED",
        what: crate::self_check::CheckContext::ADetectedLengthWithTheBuiltInCheckAlone,
    },
    // zero-12 with 15 words stated: its built-in check finds 12, which takes precedence, but only
    // the wallet then confirms the phrase.
    Refusal {
        vector: "zero-12",
        new_vector: None,
        words: Some(15),
        wrong_fingerprint: false,
        code: "LENGTH_DIFFERS",
        what: crate::self_check::CheckContext::AStatedLengthTheBuiltInCheckContradicts,
    },
];

impl Refusal {
    fn run(
        &self,
        vectors: &'static [PublishedVector],
    ) -> Result<(), crate::self_check::FailureDetail> {
        let vector = published_in(vectors, self.vector)?;
        let length = match self.words {
            Some(words) => PhraseLength::Words(WordCount::new(words).map_err(stopped)?),
            None => PhraseLength::Detect,
        };
        let rekey = Rekey::new(vector.container, length, vector.password()?, vector.work()?)
            .map_err(stopped)?;
        if let Some(name) = self.new_vector {
            let new = published_in(vectors, name)?;
            return expect_refusal(rekey.check_new(&new.password()?, new.work()?), self.code)
                .map_err(|what| crate::self_check::FailureDetail::Context {
                    context: self.what,
                    cause: Box::new(what),
                });
        }
        let reference = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes(WRONG_FINGERPRINT),
            passphrase: "",
        };
        let confirmation = if self.wrong_fingerprint {
            Confirmation::Wallet(&reference)
        } else {
            Confirmation::BuiltInCheck
        };
        let result = rekey.recover(
            &mut vector.mhfe(vectors)?,
            confirmation,
            Some(false),
            &mut |_, _, _| Ok(()),
        );
        expect_refusal(result.map(|_| ()), self.code).map_err(|what| {
            crate::self_check::FailureDetail::Context {
                context: self.what,
                cause: Box::new(what),
            }
        })
    }
}

/// Replacement rehearsals of the unverified published 24-word phrase. Fingerprints were
/// independently computed from the public BIP39 seed and BIP32 root (empty/TREZOR passphrase).
#[derive(Clone)]
struct ReplacementCase {
    vector: &'static str,
    owner: bool,
    passphrase: &'static str,
    expected: ReplacementRehearsal,
}

const REPLACEMENTS: [ReplacementCase; 3] = [
    ReplacementCase {
        vector: "zero-24",
        owner: false,
        passphrase: "",
        expected: ReplacementRehearsal::ConfirmingReference,
    },
    ReplacementCase {
        vector: "zero-24",
        owner: true,
        passphrase: "",
        expected: ReplacementRehearsal::Fingerprint(Fingerprint::from_bytes([
            0x54, 0x36, 0xd7, 0x24,
        ])),
    },
    ReplacementCase {
        vector: "zero-24",
        owner: true,
        passphrase: "TREZOR",
        expected: ReplacementRehearsal::Fingerprint(Fingerprint::from_bytes([
            0x88, 0xbc, 0xa9, 0x2b,
        ])),
    },
];

/// The `rekey` check.
pub(crate) struct RekeyCheck {
    cases: &'static [RekeyCase],
    refusals: &'static [Refusal],
    vectors: &'static [PublishedVector],
    replacements: &'static [ReplacementCase],
    confirm_again: bool,
}

impl RekeyCheck {
    pub(crate) fn new() -> Self {
        Self {
            cases: &CASES,
            refusals: &REFUSALS,
            vectors: published_table(),
            replacements: &REPLACEMENTS,
            confirm_again: true,
        }
    }

    fn case(&self, case: &RekeyCase) -> Result<(), crate::self_check::FailureDetail> {
        let from = published_in(self.vectors, case.from)?;
        let to = published_in(self.vectors, case.to)?;
        let length = if case.detected {
            PhraseLength::Detect
        } else {
            PhraseLength::Words(WordCount::new(from.phrase.split(' ').count()).map_err(stopped)?)
        };
        let rekey =
            Rekey::new(from.container, length, from.password()?, from.work()?).map_err(stopped)?;
        // A detected length is confirmed by the wallet: here its fingerprint.
        let fingerprint = Reference::Fingerprint {
            fingerprint: crate::wallet::Fingerprint::of(from.phrase, "").map_err(stopped)?,
            passphrase: "",
        };
        let confirmation = if case.detected {
            Confirmation::Wallet(&fingerprint)
        } else {
            Confirmation::BuiltInCheck
        };
        let confirmed = rekey
            .recover(
                &mut from.mhfe(self.vectors)?,
                confirmation,
                Some(false),
                &mut |_, _, _| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            confirmed.replacement_rehearsal("").map_err(stopped)? == case.replacement,
            crate::self_check::KnownAnswerDifference::TheReplacementRehearsalDiffers,
        )?;
        // This retained capability must reject other source credentials before any work.
        let foreign =
            Rekey::new(to.container, length, to.password()?, to.work()?).map_err(stopped)?;
        expect_refusal(
            foreign
                .seal(
                    &mut to.mhfe(self.vectors)?,
                    &confirmed,
                    &to.password()?,
                    None,
                    &mut |_, _, _| Err(crate::CancelledError),
                    &mut |_| Err(crate::MhfeError::Cancelled),
                )
                .map(|_| ()),
            crate::ErrorCode::InvalidRequest.as_str(),
        )?;
        // Equivalent instances remain compatible; no extra recovery rounds are needed.
        let equivalent =
            Rekey::new(from.container, length, from.password()?, from.work()?).map_err(stopped)?;
        self.sealed_as(&equivalent, &confirmed, to)
    }

    /// One recovery, a refused confirmation, then another on the same recovery (AUD-017-UI002):
    /// zero-12 with 15 words stated, whose built-in check finds 12, leaves the owner the stated
    /// length; its fingerprint confirms it without the rounds again.
    fn confirmed_again(&self) -> Result<(), crate::self_check::FailureDetail> {
        let from = published_in(self.vectors, "zero-12")?;
        let mut rekey = Rekey::new(
            from.container,
            PhraseLength::Words(WordCount::new(15).map_err(stopped)?),
            from.password()?,
            from.work()?,
        )
        .map_err(stopped)?;
        let recovered = rekey
            .recover_state(
                &mut from.mhfe(self.vectors)?,
                Confirmation::BuiltInCheck,
                &mut |_, _, _| Ok(()),
            )
            .map_err(stopped)?;
        let confirm = |confirmation| {
            rekey.confirm(&recovered, confirmation, Some(false), &mut |_, _, _| Ok(()))
        };
        let refusal =
            match confirm(Confirmation::BuiltInCheck) {
                Ok(_) => return Err(crate::self_check::FailureDetail::from(
                    crate::self_check::KnownAnswerDifference::TheBuiltInCheckConfirmedStated15Words,
                )),
                Err(refusal) => refusal,
            };
        expect_refusal(Err::<(), _>(refusal.clone()), "LENGTH_DIFFERS").map_err(|what| {
            crate::self_check::FailureDetail::Context {
                context: crate::self_check::CheckContext::Stated15Words,
                cause: Box::new(what),
            }
        })?;
        expect(
            rekey
                .owner_lengths_after(&recovered, &refusal)
                .map_err(stopped)?
                == Some(vec![15]), crate::self_check::KnownAnswerDifference::TheOwnerIsNotLeftTheStatedLengthAfterTheRefusal,
        )?;
        let fingerprint = Reference::Fingerprint {
            fingerprint: crate::wallet::Fingerprint::of(from.phrase, "").map_err(stopped)?,
            passphrase: "",
        };
        let confirmed = rekey
            .confirm_again(
                &recovered,
                &refusal,
                Confirmation::Wallet(&fingerprint),
                None,
                Some(false),
                &mut |_, _, _| Ok(()),
            )
            .map_err(stopped)?;
        self.sealed_as(
            &rekey,
            &confirmed,
            published_in(self.vectors, "unicode-password")?,
        )
    }

    fn replacement(&self, case: &ReplacementCase) -> Result<(), crate::self_check::FailureDetail> {
        let vector = published_in(self.vectors, case.vector)?;
        let rekey = Rekey::new(
            vector.container,
            PhraseLength::Detect,
            vector.password()?,
            vector.work()?,
        )
        .map_err(stopped)?;
        let reference = Reference::Fingerprint {
            fingerprint: crate::wallet::Fingerprint::of(vector.phrase, case.passphrase)
                .map_err(stopped)?,
            passphrase: case.passphrase,
        };
        let confirmation = if case.owner {
            Confirmation::Owner
        } else {
            Confirmation::Wallet(&reference)
        };
        let confirmed = rekey
            .recover(
                &mut vector.mhfe(self.vectors)?,
                confirmation,
                Some(!case.passphrase.is_empty()),
                &mut |_, _, _| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            confirmed.awaits_owner() == case.owner,
            crate::self_check::KnownAnswerDifference::TheOwnerSConfirmationStepDiffers,
        )?;
        let confirmed = if case.owner {
            confirmed.confirmed_by_owner()
        } else {
            confirmed
        };
        expect(
            confirmed
                .replacement_rehearsal(case.passphrase)
                .map_err(stopped)?
                == case.expected,
            crate::self_check::KnownAnswerDifference::TheReplacementRehearsalDiffers,
        )
    }

    /// Seals `confirmed` with the password and settings of `to`, whose container it must give.
    fn sealed_as(
        &self,
        rekey: &Rekey,
        confirmed: &ConfirmedPhrase,
        to: &PublishedVector,
    ) -> Result<(), crate::self_check::FailureDetail> {
        let sealed = rekey
            .seal(
                &mut to.mhfe(self.vectors)?,
                confirmed,
                &to.password()?,
                None,
                &mut |_, _, _| Ok(()),
                &mut |_| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            sealed.container() == to.container,
            crate::self_check::KnownAnswerDifference::TheSealedContainerDiffersFromThePublishedOne,
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
        findings.each(crate::self_check::CaseKind::Rekey, self.cases, |case| {
            self.case(case)
        });
        if self.confirm_again {
            findings.one(|| self.confirmed_again());
        }
        findings.each(
            crate::self_check::CaseKind::Refusal,
            self.refusals,
            |case| case.run(self.vectors),
        );
        findings.each(
            crate::self_check::CaseKind::Replacement,
            self.replacements,
            |case| self.replacement(case),
        );
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

    /// The rekey check of one case, from vector `from` to vector `to`.
    fn one_case(from: &'static str, to: &'static str, detected: bool) -> RekeyCheck {
        RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from,
                to,
                detected,
                replacement: ReplacementRehearsal::BuiltInCheck,
            }])),
            ..RekeyCheck::new()
        }
    }

    #[test]
    fn a_rekey_is_compared_with_its_target_vector() {
        let mut check = one_case("zero-12", "spaces-password", false);
        // The same phrase under another password or memory level must give each recorded
        // target container; the damaged-container control below reaches that comparison.
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut check = one_case("zero-12", "zero-12-memory-level-1", true);
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        // Keep the new password/settings and their recorded keys valid. Damage only the
        // target container, so the failure must reach the final published-container comparison.
        let mut vectors = published_table().to_vec();
        vectors
            .iter_mut()
            .find(|vector| vector.name == "unicode-password")
            .unwrap()
            .container = published_in(published_table(), "zero-12")
            .unwrap()
            .container;
        let mut check = one_case("zero-12", "unicode-password", false);
        check.vectors = crate::self_check::leak(vectors);
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "rekey 1 of 1 the sealed container differs from the published one".to_owned()
        );
        let mut again = RekeyCheck {
            cases: &[],
            vectors: check.vectors,
            refusals: &[],
            replacements: &[],
            ..RekeyCheck::new()
        };
        crate::self_check::assert_failed!(
            again.run(Tier::Startup),
            "the sealed container differs from the published one".to_owned()
        );
    }
    #[test]
    fn every_refusal_has_a_control_that_is_accepted_and_names_that_branch() {
        for original in REFUSALS {
            let mut accepted = original;
            if accepted.new_vector.is_some() {
                accepted.new_vector = Some("unicode-password");
            } else {
                accepted.vector = "zero-12";
                accepted.words = Some(12);
                accepted.wrong_fingerprint = false;
            }
            let mut check = RekeyCheck {
                cases: &[],
                refusals: crate::self_check::leak([accepted]),
                replacements: &[],
                confirm_again: false,
                ..RekeyCheck::new()
            };
            crate::self_check::assert_failed!(
                check.run(Tier::Startup),
                format!(
                    "refusal 1 of 1 {} is accepted instead of refused with {}",
                    original.what, original.code
                )
            );
        }
    }

    #[test]
    fn each_replacement_rehearsal_is_compared_with_its_known_answer() {
        for original in REPLACEMENTS {
            let mut wrong = original.clone();
            wrong.expected = match original.expected {
                ReplacementRehearsal::Fingerprint(fingerprint) => {
                    let mut bytes = fingerprint.bytes();
                    bytes[0] ^= 1;
                    ReplacementRehearsal::Fingerprint(bytes.into())
                }
                _ => ReplacementRehearsal::BuiltInCheck,
            };
            let mut check = RekeyCheck {
                cases: &[],
                refusals: &[],
                confirm_again: false,
                replacements: crate::self_check::leak([wrong]),
                ..RekeyCheck::new()
            };
            crate::self_check::assert_failed!(
                check.run(Tier::Startup),
                "replacement 1 of 1 the replacement rehearsal differs".to_owned()
            );
        }
        for original in CASES {
            let mut wrong = original.clone();
            wrong.replacement = ReplacementRehearsal::ConfirmingReference;
            let mut check = RekeyCheck {
                cases: crate::self_check::leak([wrong]),
                ..RekeyCheck::new()
            };
            crate::self_check::assert_failed!(
                check.run(Tier::Startup),
                "rekey 1 of 1 the replacement rehearsal differs".to_owned()
            );
        }
    }
}
