//! Known answers of the password generator: the self-check `password-generator`.
//!
//! Scripted bytes in place of the random source: the rejection bound and the byte order of the
//! unbiased draw, the 57 characters in their order, the words and the check word of a drawn
//! password, and the refusal of a stuck source before anything is drawn. The expected values follow
//! from the specification's rules by hand (each case says how); the check-word password is the
//! specification's first public vector of MHFE-PASSWORD-CHECK-1.

use super::PasswordRecipe;
use crate::random::{uniform_below, ScriptedSource};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::strength::Strength;

/// The 57 characters in the order a draw maps 0 to 56 to them, written out here rather than
/// read from the generator's own table: digits 2 to 9, capitals without I and O, small letters
/// without l.
const ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A draw of the generator from scripted bytes.
#[derive(Clone, Copy)]
struct DrawCase {
    /// The recipe: words or characters with their count, or the check-word password.
    recipe: Recipe,
    /// The bytes after the two probe blocks of the source check.
    bytes: &'static [u8],
    expected: &'static str,
}

#[derive(Clone, Copy)]
enum Recipe {
    Words(usize),
    CheckWord,
    Characters(usize),
}

/// Bytes 0 to 56, one per character.
const EVERY_CHARACTER: [u8; 57] = {
    let mut bytes = [0u8; 57];
    let mut index = 0;
    while index < 57 {
        bytes[index] = index as u8;
        index += 1;
    }
    bytes
};

const DRAWS: [DrawCase; 4] = [
    // Indexes 0 to 4 as two big-endian bytes each: the dice rolls 11111 to 11115, whose check word
    // is "aids" (the specification's first vector).
    DrawCase {
        recipe: Recipe::CheckWord,
        bytes: &[0, 0, 0, 1, 0, 2, 0, 3, 0, 4],
        expected: "abacus abdomen abdominal abide abiding aids",
    },
    // 0x1E5F = 7,775, the last word, and 0.
    DrawCase {
        recipe: Recipe::Words(2),
        bytes: &[0x1e, 0x5f, 0, 0],
        expected: "zoom abacus",
    },
    // 0, 56, 57 = 0 modulo 57, then 228, the first value above the last full multiple of 57,
    // which is drawn again, and 1.
    DrawCase {
        recipe: Recipe::Characters(4),
        bytes: &[0x00, 0x38, 0x39, 0xe4, 0x01],
        expected: "2z23",
    },
    DrawCase {
        recipe: Recipe::Characters(57),
        bytes: &EVERY_CHARACTER,
        expected: ALPHABET,
    },
];

/// The `password-generator` check.
pub(crate) struct GeneratorCheck {
    draws: &'static [DrawCase],
}

impl GeneratorCheck {
    pub(crate) fn new() -> Self {
        Self { draws: &DRAWS }
    }

    fn draw(case: &DrawCase) -> Result<(), String> {
        let recipe = match case.recipe {
            Recipe::Words(count) => PasswordRecipe::words(count),
            Recipe::CheckWord => Ok(PasswordRecipe::check_word()),
            Recipe::Characters(count) => PasswordRecipe::characters(count),
        }
        .map_err(stopped)?;
        let mut source = ScriptedSource::after_probes(case.bytes);
        let password = recipe.make(&mut source).map_err(stopped)?;
        expect(password.text() == case.expected, "gives another password")
    }
}

impl ComponentCheck for GeneratorCheck {
    fn id(&self) -> &'static str {
        "password-generator"
    }

    fn label(&self) -> &'static str {
        "Password generator"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        // 228 = 4 x 57 is the first byte refused for 57 values; 62,208 = 8 x 7,776 the first pair
        // refused for 7,776, and the pair is read as a big-endian number.
        findings.one(|| {
            let mut source = ScriptedSource::new(vec![228, 5]);
            expect(uniform_below(&mut source, 57) == Ok(5), "a draw is biased")
        });
        findings.one(|| {
            let mut source = ScriptedSource::new(vec![0xf3, 0x00, 0x00, 0x07]);
            expect(
                uniform_below(&mut source, 7776) == Ok(7),
                "a draw is biased",
            )
        });
        findings.each("draw", self.draws, Self::draw);
        // A stuck source is refused before anything is drawn from it.
        findings.one(|| {
            let mut stuck = ScriptedSource::new(vec![0; 256]);
            expect_refusal(
                PasswordRecipe::characters(16).and_then(|recipe| recipe.make(&mut stuck)),
                "RANDOM_FAILED",
            )
            .map_err(|what| format!("a stuck source {what}"))
        });
        if tier == Tier::Full {
            // The most common leaked password is weak, a generated one of five words and their
            // check word is not.
            findings.one(|| {
                expect(
                    Strength::of("password").is_weak()
                        && !Strength::of(DRAWS[0].expected).is_weak(),
                    "the strength estimate misjudges a password",
                )
            });
        }
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_passes() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(GeneratorCheck::new().run(tier), ComponentOutcome::Passed);
        }
        assert_eq!(ALPHABET.as_bytes(), super::super::CHARACTERS);
    }

    #[test]
    fn a_corrupted_draw_fails() {
        let mut draws = DRAWS;
        draws[2].expected = "2z32";
        let mut check = GeneratorCheck {
            draws: Box::leak(Box::new(draws)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("draw 3 of 4 gives another password".to_owned())
        );
    }
}
