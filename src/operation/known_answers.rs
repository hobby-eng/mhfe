//! Known answers of what a new container tells its owner to keep: the self-check `keep-advice`.
//!
//! The expected lists follow the rule of [`super::Keep`] (AUD-003-DOC002 and the owner's rule):
//! with the defaults, the container's words and the password are all; the BIP39 passphrase, the
//! repair words and a PIM or memory level other than 0 are added when they apply, and the word
//! count when automatic detection would also accept another length. Each case seals a published
//! vector, replayed with its recorded round keys.

use super::{Encryption, KeepItem};
use crate::mhfe::known_answers::{published, published_table};
use crate::self_check::{expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier};

/// A vector sealed with or without repair words, kept with or without a passphrase.
#[derive(Clone, Copy)]
struct KeepCase {
    vector: &'static str,
    repair_words: Option<usize>,
    passphrase: bool,
    expected: &'static [KeepItem],
    /// Whether the container carries a built-in check, and the other lengths detection accepts.
    built_in_check: bool,
    other_lengths: &'static [usize],
}

const CASES: [KeepCase; 5] = [
    // The defaults with four repair words and no passphrase: no PIM, no memory level.
    KeepCase {
        vector: "zero-12",
        repair_words: Some(4),
        passphrase: false,
        expected: &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::RepairWords,
        ],
        built_in_check: true,
        other_lengths: &[],
    },
    KeepCase {
        vector: "zero-12",
        repair_words: None,
        passphrase: true,
        expected: &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::Passphrase,
        ],
        built_in_check: true,
        other_lengths: &[],
    },
    KeepCase {
        vector: "zero-12-pim-1-memory-level-1",
        repair_words: None,
        passphrase: false,
        expected: &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::Pim(1),
            KeepItem::MemoryLevel(1),
        ],
        built_in_check: true,
        other_lengths: &[],
    },
    // Its published recovery verifies 12 and 21 words: the owner keeps the word count.
    KeepCase {
        vector: "ambiguous-12-21",
        repair_words: None,
        passphrase: false,
        expected: &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::WordCount(12),
        ],
        built_in_check: true,
        other_lengths: &[21],
    },
    // A same-length container: its own words, no built-in check.
    KeepCase {
        vector: "same-length-zero-12",
        repair_words: None,
        passphrase: false,
        expected: &[KeepItem::ContainerWords(12), KeepItem::Password],
        built_in_check: false,
        other_lengths: &[],
    },
];

/// The `keep-advice` check.
pub(crate) struct KeepCheck {
    cases: &'static [KeepCase],
}

impl KeepCheck {
    pub(crate) fn new() -> Self {
        Self { cases: &CASES }
    }

    fn case(case: &KeepCase) -> Result<(), String> {
        let vector = published(case.vector)?;
        let mut mhfe = vector.mhfe(published_table())?;
        let sealed = Encryption::new(vector.phrase, vector.suite(), case.repair_words)
            .map_err(stopped)?
            .run(
                &mut mhfe,
                vector.phrase,
                &vector.password()?,
                &mut |_, _, _| Ok(()),
                &mut |_| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            sealed.container() == vector.container,
            "seals another container",
        )?;
        expect(
            sealed.built_in_check() == case.built_in_check
                && sealed.other_lengths() == case.other_lengths,
            "tells other checks",
        )?;
        let keep = sealed.keep(vector.work()?, case.passphrase);
        expect(keep.items() == case.expected, "differs")
    }
}

impl ComponentCheck for KeepCheck {
    fn id(&self) -> &'static str {
        "keep-advice"
    }

    fn label(&self) -> &'static str {
        "Keep advice"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("case", self.cases, Self::case);
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keep_advice_passes() {
        assert_eq!(
            KeepCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_list_with_a_default_setting_fails() {
        let mut cases = CASES;
        cases[0].expected = &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::RepairWords,
            KeepItem::Pim(0),
        ];
        let mut check = KeepCheck {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("case 1 of 5 differs".to_owned())
        );
        let mut cases = CASES;
        cases[3].other_lengths = &[];
        let mut check = KeepCheck {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("case 4 of 5 tells other checks".to_owned())
        );
    }
}
