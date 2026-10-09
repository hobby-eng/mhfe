//! Known answers of the word hints: the self-check `word-hints`.
//!
//! The words were listed with JavaScript's startsWith over two other copies of the lists: the
//! English list of @scure/bip39 2.4.0 and the published EFF large wordlist file
//! (vendor/eff-large-wordlist, whose SHA-256 src/eff.rs checks). A word no list has must give no
//! word.

use super::{Hint, WordList};
use crate::self_check::{expect, ComponentCheck, ComponentOutcome, Findings, Tier};

/// What a line typed from a list must give.
struct HintCase {
    list: WordList,
    line: &'static str,
    hint: Hint,
}

const CASES: [HintCase; 8] = [
    HintCase {
        list: WordList::Bip39,
        line: "z",
        hint: Hint::Count(4),
    },
    HintCase {
        list: WordList::Bip39,
        line: "abandon AB",
        hint: Hint::Words(&[
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse",
        ]),
    },
    HintCase {
        list: WordList::Bip39,
        line: "xq",
        hint: Hint::NoWord,
    },
    // A whole word that begins longer ones: the search must start at the word itself.
    HintCase {
        list: WordList::Bip39,
        line: "art",
        hint: Hint::Words(&["art", "artefact", "artist", "artwork"]),
    },
    HintCase {
        list: WordList::Eff,
        line: "y",
        hint: Hint::Count(27),
    },
    HintCase {
        list: WordList::Eff,
        line: "zo",
        hint: Hint::Words(&[
            "zodiac",
            "zombie",
            "zone",
            "zoning",
            "zookeeper",
            "zoologist",
            "zoology",
            "zoom",
        ]),
    },
    HintCase {
        list: WordList::Eff,
        line: "jovial qz",
        hint: Hint::NoWord,
    },
    // One letter more than the list's longest word, which begins it (AUD-015-UI004).
    HintCase {
        list: WordList::Eff,
        line: "zookeepers",
        hint: Hint::NoWord,
    },
];

/// The `word-hints` check.
pub(crate) struct WordHintsCheck {
    cases: &'static [HintCase],
}

impl WordHintsCheck {
    pub(crate) fn new() -> Self {
        Self { cases: &CASES }
    }
}

impl ComponentCheck for WordHintsCheck {
    fn id(&self) -> &'static str {
        "word-hints"
    }

    fn label(&self) -> &'static str {
        "Word hints"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("case", self.cases, |case| {
            expect(case.list.hint(case.line) == case.hint, "gives another hint")
        });
        findings.one(|| {
            let completion = WordList::Bip39.completion("abou");
            expect(
                completion.letters == "t" && completion.word_ends,
                "Tab completes another word",
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
    fn the_cases_pass() {
        assert_eq!(
            WordHintsCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_damaged_case_fails() {
        let damaged = [HintCase {
            hint: Hint::Count(5),
            ..CASES[0]
        }];
        fails_with(
            WordHintsCheck {
                cases: leak(damaged),
            },
            "case 1 of 1 gives another hint",
        );
    }
}
