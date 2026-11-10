//! Known answers of the password check word (MHFE-PASSWORD-CHECK-1): the self-check
//! `password-check-word`.
//!
//! The EFF list's words, the weights modulo 7,776, the dice digits of each word, the review that
//! restores a word left out, and the refusal of six words that do not fit. The known answers are
//! the specification's four public vectors (vectors/profiles/password-check-word.json).

use mhfe_core::password_check::{check_word, EFF_WORDS};
use sha2::Digest;

use super::{PasswordReview, Reading, DRAWN_WORDS};
use crate::new_password::PasswordRecipe;
use crate::self_check::{expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier};

/// SHA-256 of eff_large_wordlist.txt, as vendor/eff-large-wordlist.md records it for the file the
/// EFF publishes. It confirms that the built-in words are that file; it is not an independent
/// answer of the code.
const EFF_LIST_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

/// One public vector: five dice rolls, the check index and the password.
#[derive(Clone, Copy)]
struct CheckWordVector {
    rolls: &'static str,
    check_index: u16,
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

/// The specification's erasure: in the third row, an erased third word is recovered as chokehold.
const ERASED: (&str, usize, &str) = ("jovial trailing ? pavilion cresting ninth", 3, "chokehold");
/// The third row with its check word replaced: all six words are in the list but do not fit.
const MISMATCH: &str = "jovial trailing chokehold pavilion cresting zoom";

/// The SHA-256 of the list file rebuilt from the words: each index's five dice digits from 1 in
/// base 6, a tab, the word and a line feed. A deliberate copy of mhfe_core's test
/// the_words_rebuild_the_published_list, which a program cannot import; a change goes to both.
fn rebuilt_list_sha256() -> String {
    let mut file = sha2::Sha256::new();
    for (index, word) in EFF_WORDS.iter().enumerate() {
        let dice: String = (0..5u32)
            .rev()
            .map(|place| char::from(b'1' + (index / 6usize.pow(place) % 6) as u8))
            .collect();
        file.update(format!("{dice}\t{word}\n"));
    }
    hex::encode(file.finalize())
}

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
        let drawn: Vec<u16> = vector
            .password
            .split(' ')
            .take(DRAWN_WORDS)
            .map(|word| {
                EFF_WORDS
                    .binary_search(&word)
                    .map(|index| index as u16)
                    .map_err(|_| "a built-in word is not in the list".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let drawn: [u16; DRAWN_WORDS] = drawn
            .try_into()
            .map_err(|_| crate::self_check::DAMAGED.to_owned())?;
        expect(
            check_word(drawn) == Some(vector.check_index),
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
                rebuilt_list_sha256() == self.list_sha256,
                "the EFF list differs from the vendored file",
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
    use crate::self_check::{fails_with, leak};

    /// The vectors and the erasure are the specification's
    /// vectors/profiles/password-check-word.json, in its order.
    #[test]
    fn the_vectors_are_the_published_ones() {
        let published: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/spec/vectors/profiles/password-check-word.json"
        ))
        .unwrap();
        let cases = published["cases"].as_array().unwrap();
        assert_eq!(cases.len(), VECTORS.len());
        for (vector, case) in VECTORS.iter().zip(cases) {
            let dice: Vec<&str> = case["dice"]
                .as_array()
                .unwrap()
                .iter()
                .map(|roll| roll.as_str().unwrap())
                .collect();
            assert_eq!(dice.join(" "), vector.rolls);
            assert_eq!(case["check_index"], vector.check_index);
            assert_eq!(case["password"], vector.password);
        }
        let [erasure] = &published["erasures"].as_array().unwrap()[..] else {
            panic!("one erasure");
        };
        assert_eq!(erasure["input"], ERASED.0);
        assert_eq!(erasure["position"], ERASED.1);
        assert_eq!(erasure["recovered"], ERASED.2);
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
        // Fault: the list digest and two vectors, damaged as by a broken build or faulty memory.
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
