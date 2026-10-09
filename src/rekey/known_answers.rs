//! Known answers of a rekey: the self-check `rekey`.
//!
//! zero-12's container recovered with its password, confirmed by its built-in check, and sealed
//! again must give the published container of the same phrase under the new password or settings:
//! unicode-password (another password) and zero-12-pim-1 (PIM 1), the second with the length
//! detected. Both are replayed with the recorded round keys of the three vectors, whose salts
//! differ; the detected one is confirmed by its fingerprint, as the built-in check alone confirms
//! no detected length (AUD-017-FUN001). The refusals: the same password and settings, a
//! fingerprint that does not match, zero-24 with its length detected and only the built-in check,
//! and zero-12 with 15 words stated and only the built-in check, which finds 12 (AUD-015-FUN001).

use super::Rekey;
use crate::mhfe::known_answers::{published, published_table};
use crate::rehearsal::{Confirmation, Reference};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::{PhraseLength, WordCount};

/// A rekey from one published vector to another of the same phrase, its length stated or
/// detected (`detection`).
#[derive(Clone, Copy)]
struct RekeyCase {
    from: &'static str,
    to: &'static str,
    detected: bool,
}

const CASES: [RekeyCase; 2] = [
    RekeyCase {
        from: "zero-12",
        to: "unicode-password",
        detected: false,
    },
    RekeyCase {
        from: "zero-12",
        to: "zero-12-pim-1",
        detected: true,
    },
];

/// The master key fingerprint of "abandon" 11 times and "about" is 73c5da0a; this one differs in
/// its last bit, so no recovery of a zero-24 container can match it.
const WRONG_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0b];

/// A rekey of one published vector that must be refused with `code`.
struct Refusal {
    vector: &'static str,
    /// The stated length, or none for a detected one.
    words: Option<usize>,
    /// A wrong fingerprint as the confirmation, or the built-in check alone.
    wrong_fingerprint: bool,
    code: &'static str,
    what: &'static str,
}

const REFUSALS: [Refusal; 3] = [
    // zero-24 has no built-in check: a reference confirms it, and a wrong one is refused.
    Refusal {
        vector: "zero-24",
        words: Some(24),
        wrong_fingerprint: true,
        code: "REFERENCE_MISMATCH",
        what: "a fingerprint that does not match",
    },
    // A detected length is never confirmed by the built-in check alone, before any Argon2 work.
    Refusal {
        vector: "zero-24",
        words: None,
        wrong_fingerprint: false,
        code: "REFERENCE_REQUIRED",
        what: "a detected length with the built-in check alone",
    },
    // zero-12 with 15 words stated: its built-in check finds 12, which takes precedence, but only
    // the wallet then confirms the phrase.
    Refusal {
        vector: "zero-12",
        words: Some(15),
        wrong_fingerprint: false,
        code: "LENGTH_DIFFERS",
        what: "a stated length the built-in check contradicts",
    },
];

impl Refusal {
    fn run(&self) -> Result<(), String> {
        let vector = published(self.vector)?;
        let length = match self.words {
            Some(words) => PhraseLength::Words(WordCount::new(words).map_err(stopped)?),
            None => PhraseLength::Detect,
        };
        let rekey = Rekey::new(vector.container, length, vector.password()?, vector.work()?)
            .map_err(stopped)?;
        let reference = Reference::Fingerprint {
            fingerprint: WRONG_FINGERPRINT,
            passphrase: "",
        };
        let confirmation = if self.wrong_fingerprint {
            Confirmation::Wallet(&reference)
        } else {
            Confirmation::BuiltInCheck
        };
        let result = rekey.recover(
            &mut vector.mhfe(published_table())?,
            confirmation,
            Some(false),
            &mut |_, _, _| Ok(()),
        );
        expect_refusal(result.map(|_| ()), self.code)
            .map_err(|what| format!("{} {what}", self.what))
    }
}

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
        let length = if case.detected {
            PhraseLength::Detect
        } else {
            PhraseLength::Words(WordCount::new(from.phrase.split(' ').count()).map_err(stopped)?)
        };
        let rekey =
            Rekey::new(from.container, length, from.password()?, from.work()?).map_err(stopped)?;
        // A detected length is confirmed by the wallet: here its fingerprint.
        let fingerprint = Reference::Fingerprint {
            fingerprint: crate::wallet::master_fingerprint(from.phrase, "").map_err(stopped)?,
            passphrase: "",
        };
        let confirmation = if case.detected {
            Confirmation::Wallet(&fingerprint)
        } else {
            Confirmation::BuiltInCheck
        };
        let confirmed = rekey
            .recover(
                &mut from.mhfe(published_table())?,
                confirmation,
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
                PhraseLength::Words(WordCount::new(12).map_err(stopped)?),
                vector.password()?,
                vector.work()?,
            )
            .map_err(stopped)?;
            expect_refusal(
                rekey.check_new(&vector.password()?, vector.work()?),
                "NEW_PASSWORD_SAME_AS_OLD",
            )
            .map_err(|what| format!("the same password and settings {what}"))
        });
        findings.each("refusal", &REFUSALS, Refusal::run);
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
            cases: Box::leak(Box::new([RekeyCase { from, to, detected }])),
        }
    }

    #[test]
    fn a_rekey_is_compared_with_its_target_vector() {
        let mut check = one_case("zero-12", "spaces-password", false);
        // spaces-password and zero-12-memory-level-1 hold the same phrase under another password
        // or memory level: the rekey gives their containers. A vector of another phrase fails.
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut check = one_case("zero-12", "zero-12-memory-level-1", true);
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        let mut check = one_case("zero-12", "nonzero-12", false);
        assert!(check.run(Tier::Startup).is_failure());
    }
}
