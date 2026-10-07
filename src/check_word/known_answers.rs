//! Known answers of the password check word (MHFE-PASSWORD-CHECK-1): the self-check
//! `password-check-word`.
//!
//! The EFF list's bytes, the weights modulo 7,776, the dice digits of each word, the review that
//! restores a word left out, and the refusal of six words that do not fit. The known answers are
//! the specification's four public vectors (vectors/profiles/README.md).

use sha2::Digest;

use super::{check_index, PasswordReview, Reading, DRAWN_WORDS};
use crate::eff::{EffList, EFF_LIST, LIST_SIZE};
use crate::new_password::PasswordRecipe;
use crate::self_check::{expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier};

/// SHA-256 of the vendored eff_large_wordlist.txt, as vendor/eff-large-wordlist.md records it for
/// the file the EFF publishes. It confirms that the embedded bytes are that file; it is not an
/// independent answer of the code.
const EFF_LIST_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

/// One public vector: five dice rolls, the check index and the password.
#[derive(Clone, Copy)]
struct CheckWordVector {
    rolls: &'static str,
    check_index: usize,
    password: &'static str,
}

const VECTORS: [CheckWordVector; 4] = [
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
const ERASED: (&str, usize, &str) = ("jovial trailing ? pavilion cresting ninth", 3, "chokehold");
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

    fn vector(vector: &CheckWordVector) -> Result<(), String> {
        let made = PasswordRecipe::check_word()
            .make_from_rolls(vector.rolls)
            .map_err(stopped)?;
        expect(made.text() == vector.password, "gives other words")?;
        let list = EffList::try_get().map_err(stopped)?;
        let drawn: Vec<usize> = vector
            .password
            .split(' ')
            .take(DRAWN_WORDS)
            .map(|word| {
                list.index_of(word)
                    .ok_or_else(|| "a built-in word is not in the list".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let drawn: [usize; DRAWN_WORDS] = drawn
            .try_into()
            .map_err(|_| "the built-in cases are damaged".to_owned())?;
        expect(
            check_index(&drawn) == vector.check_index,
            "gives another check index",
        )?;
        expect(
            PasswordReview::of(vector.password).reading() == Reading::Fits,
            "does not fit its check word",
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
                "the EFF list differs from the vendored file",
            )
        });
        findings.one(|| {
            let list = EffList::try_get().map_err(stopped)?;
            expect(
                list.words().len() == LIST_SIZE
                    && list.word(0) == "abacus"
                    && list.word(LIST_SIZE - 1) == "zoom",
                "the EFF list is read wrongly",
            )
        });
        findings.each("vector", self.vectors, Self::vector);
        findings.one(|| {
            let (typed, position, word) = ERASED;
            let review = PasswordReview::of(typed);
            let repaired =
                |repair: &super::Repair| repair.position() == position && repair.word() == word;
            let restored = review.reading() == Reading::Restorable
                && matches!(review.repairs(), [repair] if repaired(repair));
            expect(restored, "a word left out is not restored")
        });
        findings.one(|| {
            let review = PasswordReview::of(MISMATCH);
            expect(
                review.reading() == Reading::Mismatch && review.repairs().len() == DRAWN_WORDS + 1,
                "six words that do not fit are accepted",
            )
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("the EFF list differs from the vendored file".to_owned())
        );
        let mut vectors = VECTORS;
        vectors[2].check_index = 4151;
        let mut check = CheckWordCheck {
            vectors: Box::leak(Box::new(vectors)),
            ..CheckWordCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("vector 3 of 4 gives another check index".to_owned())
        );
        let mut vectors = VECTORS;
        vectors[3].password = "drop-down t-shirt abacus yoyo felt-tip rubble";
        let mut check = CheckWordCheck {
            vectors: Box::leak(Box::new(vectors)),
            ..CheckWordCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("vector 4 of 4 gives other words".to_owned())
        );
    }
}
