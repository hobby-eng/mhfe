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
//! - "abacus abdomen abdominal abide abiding aids": the first published vector of
//!   MHFE-PASSWORD-CHECK-1, five drawn words at 12,925 each and its check word, which adds none
//!   (AUD-024-FUN011): 64,625. The third vector, which the check word's own known answers hold, is
//!   held once in the program, so that a damaged copy of it names that part alone.
//! - "1234 1234 1234 1234 1234": "1234" counts 3.32 for its first digit and 1 bit for each digit
//!   that continues the run (6.32), the first space 5.04, and each of the three copies that follow
//!   1 bit (AUD-024-FUN003): 14,360.
//! - "abcd" eight times: "abcd" counts 4.70 for its first letter and 1 bit for each letter that
//!   continues the run (7.70), and each longer copy of what came before, three of them, 1 bit:
//!   10,700.
//!
//! The Latin, Cyrillic and repeated cases are read part by part (`read_parts`): the common list,
//! substitutions, capitals, years, repeats and character kinds. The dice-word cases take the
//! dice-word path.

use super::Strength;
use crate::self_check::{expect, ComponentCheck, ComponentOutcome, Findings, Tier};

/// A password and its estimate in millibits.
#[derive(Clone, Copy)]
pub(super) struct StrengthCase {
    pub(super) password: &'static str,
    pub(super) millibits: u32,
}

pub(super) const CASES: [StrengthCase; 8] = [
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
    StrengthCase {
        password: "abacus abdomen abdominal abide abiding aids",
        millibits: 64_625,
    },
    StrengthCase {
        password: "1234 1234 1234 1234 1234",
        millibits: 14_360,
    },
    StrengthCase {
        password: "abcdabcdabcdabcdabcdabcdabcdabcd",
        millibits: 10_700,
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
            "password 2 of 8 gives another estimate",
        );
    }
}
