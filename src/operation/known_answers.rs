//! Known answers of what a new container tells its owner to keep: the self-check `keep-advice`.
//!
//! The expected lists follow the rule of [`super::Keep`] (AUD-003-DOC002 and the owner's rule):
//! with the defaults, the container's words and the password are all; the BIP39 passphrase of a
//! wallet that has one, or any passphrase where that is not known, the repair words and a PIM or
//! memory level other than 0 are added when they apply, and the word count when automatic
//! detection would also accept another length. Each case seals a published vector, replayed with
//! its recorded round keys.

use super::{Encryption, Keep, KeepItem, WalletPassphrase};
use crate::mhfe::known_answers::{published, published_table};
use crate::self_check::{expect, stopped, ComponentCheck, ComponentOutcome, Findings, Tier};

/// A vector sealed with or without repair words, kept for a wallet with, without or perhaps with
/// a passphrase.
#[derive(Clone, Copy)]
struct KeepCase {
    vector: &'static str,
    repair_words: Option<usize>,
    passphrase: WalletPassphrase,
    expected: &'static [KeepItem],
    /// Whether the container carries a built-in check, and the other lengths detection accepts.
    built_in_check: bool,
    other_lengths: &'static [usize],
}

const CASES: [KeepCase; 6] = [
    // The defaults with four repair words and no passphrase: no PIM, no memory level.
    KeepCase {
        vector: "zero-12",
        repair_words: Some(4),
        passphrase: WalletPassphrase::Absent,
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
        passphrase: WalletPassphrase::Present,
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
        passphrase: WalletPassphrase::Absent,
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
        passphrase: WalletPassphrase::Absent,
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
        passphrase: WalletPassphrase::Absent,
        expected: &[KeepItem::ContainerWords(12), KeepItem::Password],
        built_in_check: false,
        other_lengths: &[],
    },
    // Not known whether the wallet has a passphrase: any passphrase is named in its place, before
    // the repair words and the settings.
    KeepCase {
        vector: "zero-12-pim-1-memory-level-1",
        repair_words: Some(2),
        passphrase: WalletPassphrase::Unknown,
        expected: &[
            KeepItem::ContainerWords(24),
            KeepItem::Password,
            KeepItem::PassphraseIfAny,
            KeepItem::RepairWords,
            KeepItem::Pim(1),
            KeepItem::MemoryLevel(1),
        ],
        built_in_check: true,
        other_lengths: &[],
    },
];

#[derive(Clone, Copy)]
struct OldKeepCase {
    vector: &'static str,
    expected: &'static [KeepItem],
}

const OLD_CASES: [OldKeepCase; 2] = [
    OldKeepCase {
        vector: "zero-12",
        expected: &[KeepItem::OldContainer, KeepItem::OldPasswords],
    },
    OldKeepCase {
        vector: "zero-12-pim-1-memory-level-1",
        expected: &[
            KeepItem::OldContainer,
            KeepItem::OldPasswords,
            KeepItem::Pim(1),
            KeepItem::MemoryLevel(1),
        ],
    },
];

/// The `keep-advice` check.
pub(crate) struct KeepCheck {
    cases: &'static [KeepCase],
    old_cases: &'static [OldKeepCase],
}

impl KeepCheck {
    pub(crate) fn new() -> Self {
        Self {
            cases: &CASES,
            old_cases: &OLD_CASES,
        }
    }

    fn case(case: &KeepCase) -> Result<(), crate::self_check::FailureDetail> {
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
            crate::self_check::KnownAnswerDifference::SealsAnotherContainer,
        )?;
        expect(
            sealed.built_in_check() == case.built_in_check
                && sealed.other_lengths() == case.other_lengths,
            crate::self_check::KnownAnswerDifference::TellsOtherChecks,
        )?;
        let keep = sealed.keep(vector.work()?, case.passphrase);
        expect(
            keep.items() == case.expected,
            crate::self_check::KnownAnswerDifference::Differs,
        )
    }
}

impl ComponentCheck for KeepCheck {
    fn id(&self) -> &'static str {
        "keep-advice"
    }

    fn label(&self) -> &'static str {
        "Keep advice"
    }

    // Deliberate copy: independent component checks implement the same runner trait.
    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each(crate::self_check::CaseKind::Case, self.cases, Self::case);
        findings.each(
            crate::self_check::CaseKind::OldContainer,
            self.old_cases,
            |case| {
                let work = published(case.vector)?.work()?;
                expect(
                    Keep::old_container(work).items() == case.expected,
                    crate::self_check::KnownAnswerDifference::Differs,
                )
            },
        );
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

    fn list_fails(cases: [KeepCase; 6], detail: &str) {
        let mut check = KeepCheck {
            cases: Box::leak(Box::new(cases)),
            ..KeepCheck::new()
        };
        crate::self_check::assert_failed!(check.run(Tier::Startup), detail.to_owned());
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
        list_fails(cases, "case 1 of 6 differs");
        let mut cases = CASES;
        cases[3].other_lengths = &[];
        list_fails(cases, "case 4 of 6 tells other checks");
    }
    #[test]
    fn old_container_lists_are_compared_with_their_known_answers() {
        for original in OLD_CASES {
            let wrong = OldKeepCase {
                expected: &[KeepItem::OldContainer],
                ..original
            };
            let mut check = KeepCheck {
                old_cases: crate::self_check::leak([wrong]),
                ..KeepCheck::new()
            };
            crate::self_check::assert_failed!(
                check.run(Tier::Startup),
                "old container 1 of 1 differs".to_owned()
            );
        }
    }
}
