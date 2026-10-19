//! Known answers of the password check word (MHFE-PASSWORD-CHECK-1): the self-check
//! `password-check-word`.
//!
//! The EFF list's bytes, the weights modulo 7,776, the dice digits of each word, the review that
//! restores a word left out, and the refusal of six words that do not fit. The known answers are
//! the specification's four public vectors (vectors/profiles/README.md).

use sha2::Digest;

use super::{PasswordReview, Reading, DRAWN_WORDS};
use crate::eff::{EffList, EFF_LIST, LIST_SIZE};
use crate::new_password::PasswordRecipe;
use crate::self_check::{
    damaged, expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

use crate::eff::EFF_LIST_SHA256;

/// One public vector: five dice rolls, the check index and the password.
#[derive(Clone, Copy)]
pub(super) struct CheckWordVector {
    pub(super) rolls: &'static str,
    pub(super) check_index: usize,
    pub(super) password: &'static str,
}

pub(super) const VECTORS: [CheckWordVector; 4] = [
    CheckWordVector {
        rolls: "11111 11112 11113 11114 11115",
        check_index: 104,
        password: "abacus abdomen abdominal abide abiding aids",
    },
    CheckWordVector {
        rolls: "66666 66666 66666 66666 66666",
        check_index: 7739,
        password: "zoom zoom zoom zoom zoom yelling",
    },
    CheckWordVector {
        rolls: "35214 62431 15543 44126 21365",
        check_index: 4150,
        password: "jovial trailing chokehold pavilion cresting ninth",
    },
    CheckWordVector {
        rolls: "24255 61534 11111 66622 26522",
        check_index: 5527,
        password: "drop-down t-shirt abacus yo-yo felt-tip rubble",
    },
];

/// The specification: "In the third row, an erased third word is recovered as chokehold."
pub(super) const ERASED: (&str, usize, &str) =
    ("jovial trailing ? pavilion cresting ninth", 3, "chokehold");
/// The third row with its check word replaced: all six words are in the list but do not fit.
const MISMATCH: &str = "jovial trailing chokehold pavilion cresting zoom";

/// The `password-check-word` check.
pub(crate) struct CheckWordCheck {
    list_sha256: &'static str,
    vectors: &'static [CheckWordVector],
}

impl CheckWordCheck {
    pub(crate) fn new() -> Self {
        Self {
            list_sha256: EFF_LIST_SHA256,
            vectors: &VECTORS,
        }
    }

    fn vector(vector: &CheckWordVector) -> Result<(), crate::self_check::FailureDetail> {
        let made = PasswordRecipe::check_word()
            .make_from_rolls(vector.rolls)
            .map_err(stopped)?;
        expect(
            made.text() == vector.password,
            crate::self_check::KnownAnswerDifference::GivesOtherWords,
        )?;
        let list = EffList::try_get().map_err(stopped)?;
        let drawn: Vec<usize> = vector
            .password
            .split(' ')
            .take(DRAWN_WORDS)
            .map(|word| {
                list.index_of(word).ok_or_else(|| {
                    crate::self_check::FailureDetail::from(
                        crate::self_check::KnownAnswerDifference::ABuiltInWordIsNotInTheList,
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        let drawn: [usize; DRAWN_WORDS] = drawn.try_into().map_err(|_| damaged())?;
        expect(
            PasswordReview::check_index(&drawn).map_err(stopped)? == vector.check_index,
            crate::self_check::KnownAnswerDifference::GivesAnotherCheckIndex,
        )?;
        expect(
            PasswordReview::of(vector.password)
                .map_err(stopped)?
                .reading()
                == Reading::Fits,
            crate::self_check::KnownAnswerDifference::DoesNotFitItsCheckWord,
        )
    }
    fn repair_identity(typed: &str) -> Result<(), crate::self_check::FailureDetail> {
        let review = PasswordReview::of(typed).map_err(stopped)?;
        let repair = review
            .repairs()
            .first()
            .ok_or(crate::self_check::KnownAnswerDifference::AWordLeftOutIsNotRestored)?
            .clone();
        let unrelated = PasswordReview::of(typed).map_err(stopped)?;
        crate::self_check::expect_refusal(
            unrelated.typed_word(&repair),
            "PASSWORD_REPAIR_NOT_OFFERED",
        )
    }
}

impl ComponentCheck for CheckWordCheck {
    fn id(&self) -> &'static str {
        "password-check-word"
    }

    fn label(&self) -> &'static str {
        "Password check word (MHFE-PASSWORD-CHECK-1)"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.one(|| {
            expect(
                hex::encode(sha2::Sha256::digest(EFF_LIST.as_bytes())) == self.list_sha256,
                crate::self_check::KnownAnswerDifference::TheEffListDiffersFromTheVendoredFile,
            )
        });
        findings.one(|| {
            let list = EffList::try_get().map_err(stopped)?;
            expect(
                list.words().len() == LIST_SIZE
                    && list.word(0).map_err(stopped)? == "abacus"
                    && list.word(LIST_SIZE - 1).map_err(stopped)? == "zoom",
                crate::self_check::KnownAnswerDifference::TheEffListIsReadWrongly,
            )
        });
        findings.each(
            crate::self_check::CaseKind::Vector,
            self.vectors,
            Self::vector,
        );
        // One fast five-index refusal guards the public boundary without any Argon2 work.
        findings.one(|| {
            crate::self_check::expect_refusal(
                PasswordReview::check_index(&[0, 0, 0, 0, usize::MAX]),
                "INVALID_REQUEST",
            )
        });
        findings.one(|| {
            crate::self_check::expect_refusal(
                EffList::try_get().map_err(stopped)?.word(LIST_SIZE),
                "INVALID_REQUEST",
            )
        });
        // A small public over-limit input guards the byte bound, including the no-review choice.
        findings.one(|| {
            let oversized = "x".repeat(crate::input_text::InputText::MAX_BYTES + 1);
            crate::self_check::expect_refusal(
                PasswordReview::choose(&oversized, None),
                "INVALID_REQUEST",
            )
        });
        findings.one(|| {
            let (typed, position, word) = ERASED;
            let review = PasswordReview::of(typed).map_err(stopped)?;
            let repaired =
                |repair: &super::Repair| repair.position() == position && repair.word() == word;
            let restored = review.reading() == Reading::Restorable
                && matches!(review.repairs(), [repair] if repaired(repair));
            expect(
                restored,
                crate::self_check::KnownAnswerDifference::AWordLeftOutIsNotRestored,
            )
        });
        findings.one(|| Self::repair_identity(ERASED.0));
        findings.one(|| {
            let review = PasswordReview::of(MISMATCH).map_err(stopped)?;
            expect(
                review.reading() == Reading::Mismatch && review.repairs().len() == DRAWN_WORDS + 1,
                crate::self_check::KnownAnswerDifference::SixWordsThatDoNotFitAreAccepted,
            )
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};

    #[test]
    fn an_absent_offered_repair_is_a_diagnostic_failure() {
        assert_eq!(
            CheckWordCheck::repair_identity("ordinary text").unwrap_err(),
            crate::self_check::FailureDetail::from(
                crate::self_check::KnownAnswerDifference::AWordLeftOutIsNotRestored,
            )
        );
    }

    #[test]
    fn the_check_word_passes() {
        assert_eq!(
            CheckWordCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
        assert_eq!(
            CheckWordCheck::new().run(Tier::Full),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_corrupted_list_digest_or_vector_fails() {
        let mut check = CheckWordCheck {
            list_sha256: "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903f",
            ..CheckWordCheck::new()
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "the EFF list differs from the vendored file".to_owned()
        );
        let mut vectors = VECTORS;
        vectors[2].check_index = 4151;
        fails_with(
            CheckWordCheck {
                vectors: leak(vectors),
                ..CheckWordCheck::new()
            },
            "vector 3 of 4 gives another check index",
        );
        let mut vectors = VECTORS;
        vectors[3].password = "drop-down t-shirt abacus yoyo felt-tip rubble";
        fails_with(
            CheckWordCheck {
                vectors: leak(vectors),
                ..CheckWordCheck::new()
            },
            "vector 4 of 4 gives other words",
        );
    }
}
