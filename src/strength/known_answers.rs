//! Known answers of the password strength estimate: the self-check `password-strength`.
//!
//! Each value is the estimate in millibits, which the rules of `src/strength.rs` give by hand:
//!
//! - "P@ssw0rd": "password" spelled with two substitutions, from the list of common passwords (53
//!   words of four letters or more, log2 53 = 5.728) plus 1 bit of variation: 6,728.
//! - "Password2024!": the same word with a capital (6.728), the year 2024 (7.64) and "!" as another
//!   character (5.04): 19,408.
//! - "Tr0ub4dor&3": no word of either list, so eleven characters: seven letters (4.70 each), three
//!   digits (3.32 each) and "&" (5.04), less 3.70 for the "r" that follows "T" on the keyboard row
//!   qwerty, which counts 1 bit: 44,200.
//! - "щуклебтжрвзф": twelve letters of another alphabet, each counted as another character
//!   (5.04): 60,480.
//! - "abacus zoom yearbook zipfile": four different EFF dice words at 12,925 each: 51,700.
//!
//! The first four are read part by part (`read_parts`): the common list, substitutions, capitals,
//! years and character kinds. The last takes the dice-word path.

use super::Strength;
use crate::self_check::{expect, ComponentCheck, ComponentOutcome, Findings, Tier};

/// A password and its estimate in millibits.
#[derive(Clone, Copy)]
struct StrengthCase {
    password: &'static str,
    millibits: u32,
}

const CASES: [StrengthCase; 5] = [
    StrengthCase {
        password: "P@ssw0rd",
        millibits: 6_728,
    },
    StrengthCase {
        password: "Password2024!",
        millibits: 19_408,
    },
    StrengthCase {
        password: "Tr0ub4dor&3",
        millibits: 44_200,
    },
    StrengthCase {
        password: "щуклебтжрвзф",
        millibits: 60_480,
    },
    StrengthCase {
        password: "abacus zoom yearbook zipfile",
        millibits: 51_700,
    },
];

/// The `password-strength` check.
pub(crate) struct StrengthCheck {
    cases: &'static [StrengthCase],
}

impl StrengthCheck {
    pub(crate) fn new() -> Self {
        Self { cases: &CASES }
    }
}

impl ComponentCheck for StrengthCheck {
    fn id(&self) -> &'static str {
        "password-strength"
    }

    fn label(&self) -> &'static str {
        "Password strength estimate"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("password", self.cases, |case| {
            expect(
                Strength::of(case.password).millibits() == case.millibits,
                "gives another estimate",
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
    fn the_estimate_passes() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(StrengthCheck::new().run(tier), ComponentOutcome::Passed);
        }
    }

    #[test]
    fn a_damaged_value_fails() {
        let mut cases = CASES;
        cases[1].millibits = 19_409;
        fails_with(
            StrengthCheck { cases: leak(cases) },
            "password 2 of 5 gives another estimate",
        );
    }
}
