//! Known answers of what a container and an original phrase tell before any Argon2 work: the
//! self-check `container-facts`.
//!
//! These facts decide which confirmation a rekey demands, whether hidden wallets open and which
//! containers an original may have, so a wrong one would weaken a guard without a wrong number
//! anywhere. The expected values are the specification's rules, cited per case, applied to the
//! published vectors' containers and phrases.

use super::{ConfirmationNeeded, ContainerFacts, OriginalFacts};
use crate::mhfe::known_answers::published;
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::{Suite, WordCount};

/// What a container's words tell.
#[derive(Clone, Copy)]
struct ContainerCase {
    /// The published vector whose container is read.
    vector: &'static str,
    suite: Suite,
    phrase_lengths: &'static [usize],
    built_in_check_lengths: &'static [usize],
    /// The confirmation each length needs, or the refusal it gets.
    confirmations: &'static [(usize, Result<ConfirmationNeeded, &'static str>)],
    opens_hidden_wallets: bool,
    offers_wallet_check: bool,
}

const CONTAINERS: [ContainerCase; 2] = [
    // A 24-word container is suite 3 ("Choosing the suite"): its original has any of the five
    // lengths, 12 to 21 words carry a built-in check ("Packing"), a 24-word original has none and
    // needs the wallet or its owner (the re-encryption rules), and hidden wallets and the wallet
    // check exist for 24-word containers only (supplement; MHFE-WALLET-CHECK-SEED-1).
    ContainerCase {
        vector: "zero-12",
        suite: Suite::TwentyFourWords,
        phrase_lengths: &[12, 15, 18, 21, 24],
        built_in_check_lengths: &[12, 15, 18, 21],
        confirmations: &[
            (12, Ok(ConfirmationNeeded::BuiltInCheck)),
            (21, Ok(ConfirmationNeeded::BuiltInCheck)),
            (24, Ok(ConfirmationNeeded::WalletOrOwner)),
        ],
        opens_hidden_wallets: true,
        offers_wallet_check: true,
    },
    // A same-length container is suite 4 and keeps its original's length ("Suite 4"): no
    // built-in check, so the wallet or the owner confirms, and another length is refused.
    ContainerCase {
        vector: "same-length-zero-15",
        suite: Suite::SameLength,
        phrase_lengths: &[15],
        built_in_check_lengths: &[],
        confirmations: &[
            (15, Ok(ConfirmationNeeded::WalletOrOwner)),
            (12, Err("LENGTH_CHOICE_NOT_APPLICABLE")),
        ],
        opens_hidden_wallets: false,
        offers_wallet_check: false,
    },
];

/// What an original phrase tells.
#[derive(Clone, Copy)]
struct OriginalCase {
    vector: &'static str,
    word_count: usize,
    /// The other lengths automatic detection would take it for.
    other_lengths: &'static [usize],
    /// The containers it can have: suite, words, and how rarely a wrong word passes the BIP39
    /// checksum (2 to the power of the checksum bits, words / 3).
    choices: &'static [(Suite, usize, u32)],
}

const ORIGINALS: [OriginalCase; 3] = [
    OriginalCase {
        vector: "zero-12",
        word_count: 12,
        other_lengths: &[],
        choices: &[
            (Suite::TwentyFourWords, 24, 256),
            (Suite::SameLength, 12, 16),
        ],
    },
    // A 24-word original fills the whole state: its only container has 24 words.
    OriginalCase {
        vector: "zero-24",
        word_count: 24,
        other_lengths: &[],
        choices: &[(Suite::TwentyFourWords, 24, 256)],
    },
    // The published recovery of ambiguous-12-21 verifies 12 and 21 words.
    OriginalCase {
        vector: "ambiguous-12-21",
        word_count: 12,
        other_lengths: &[21],
        choices: &[
            (Suite::TwentyFourWords, 24, 256),
            (Suite::SameLength, 12, 16),
        ],
    },
];

/// Texts that are no container: a word count no suite has, and a wrong checksum.
const REFUSED: [(&str, &str); 2] = [
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon",
        "INVALID_CONTAINER",
    ),
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon",
        "INVALID_CONTAINER",
    ),
];

/// The `container-facts` check.
pub(crate) struct ContainerFactsCheck {
    containers: &'static [ContainerCase],
    originals: &'static [OriginalCase],
}

impl ContainerFactsCheck {
    pub(crate) fn new() -> Self {
        Self {
            containers: &CONTAINERS,
            originals: &ORIGINALS,
        }
    }

    fn container(case: &ContainerCase) -> Result<(), String> {
        let vector = published(case.vector)?;
        // Read as typed on a plate: capitals and the first four letters of each word.
        let typed: Vec<String> = vector
            .container
            .split(' ')
            .map(|word| word[..word.len().min(4)].to_ascii_uppercase())
            .collect();
        let facts = ContainerFacts::read(&typed.join("  ")).map_err(stopped)?;
        expect(facts.words() == vector.container, "is read as other words")?;
        expect(
            facts.word_count() == vector.container.split(' ').count()
                && facts.suite() == case.suite,
            "gives another suite",
        )?;
        expect(
            facts.phrase_lengths() == case.phrase_lengths
                && facts.built_in_check_lengths() == case.built_in_check_lengths,
            "gives other lengths",
        )?;
        for &(words, expected) in case.confirmations {
            let words = WordCount::new(words).map_err(stopped)?;
            let result = facts.confirmation_needed(words);
            match expected {
                Ok(needed) => expect(result == Ok(needed), "needs another confirmation")?,
                Err(code) => expect_refusal(result, code)?,
            }
        }
        expect(
            facts.opens_hidden_wallets() == case.opens_hidden_wallets
                && facts.offers_wallet_check() == case.offers_wallet_check,
            "offers other wallets",
        )
    }

    fn original(case: &OriginalCase) -> Result<(), String> {
        let vector = published(case.vector)?;
        let facts = OriginalFacts::read(vector.phrase).map_err(stopped)?;
        expect(
            facts.word_count() == case.word_count && facts.other_lengths() == case.other_lengths,
            "gives other lengths",
        )?;
        let choices: Vec<(Suite, usize, u32)> = facts
            .container_choices()
            .iter()
            .map(|choice| {
                (
                    choice.suite(),
                    choice.word_count(),
                    choice.wrong_word_passes_one_in(),
                )
            })
            .collect();
        expect(choices == case.choices, "offers other containers")
    }
}

impl ComponentCheck for ContainerFactsCheck {
    fn id(&self) -> &'static str {
        "container-facts"
    }

    fn label(&self) -> &'static str {
        "Container facts"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("container", self.containers, Self::container);
        findings.each("original", self.originals, Self::original);
        findings.each("refused text", &REFUSED, |&(text, code)| {
            expect_refusal(ContainerFacts::read(text), code)
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_facts_pass() {
        assert_eq!(
            ContainerFactsCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_wrong_fact_fails() {
        let mut containers = CONTAINERS;
        containers[1].opens_hidden_wallets = true;
        let mut check = ContainerFactsCheck {
            containers: Box::leak(Box::new(containers)),
            ..ContainerFactsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("container 2 of 2 offers other wallets".to_owned())
        );
        let mut containers = CONTAINERS;
        containers[0].confirmations = &[(24, Ok(ConfirmationNeeded::BuiltInCheck))];
        let mut check = ContainerFactsCheck {
            containers: Box::leak(Box::new(containers)),
            ..ContainerFactsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("container 1 of 2 needs another confirmation".to_owned())
        );
        let mut originals = ORIGINALS;
        originals[2].other_lengths = &[];
        let mut check = ContainerFactsCheck {
            originals: Box::leak(Box::new(originals)),
            ..ContainerFactsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("original 3 of 3 gives other lengths".to_owned())
        );
    }
}
