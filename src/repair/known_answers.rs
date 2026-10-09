//! Known answers of the repair words (MHFE-REPAIR-1): the self-check `repair-words`.
//!
//! The field GF(2^11), the generator, the parity, the syndromes, the repair of unreadable and of
//! wrong words at the code's bound, and the refusals: too much damage, and a card of another
//! container phrase. Every expected value is a public vector of the specification
//! (vectors/profiles/README.md) or was computed by an independent Python implementation of the
//! profile, written from its description, which first reproduced every published card.

use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

// The container phrase of the suite 3 vector zero-12.
use crate::self_check::ZERO_12_CONTAINER as ZERO_12;
/// The container phrases of same-length-nonzero-12 and same-length-nonzero-21 (vectors/suite4).
const NONZERO_12: &str = "hotel supply dune casual fork treat century web wide vote steel media";
const NONZERO_21: &str = "seat govern run smooth flag fragile horse night simple luggage vacuum \
                          warfare tissue permit gym upset average blade pen blue view";
/// "abandon" 23 times, then "art": the phrase of 32 zero bytes.
const ABANDON_ART: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon art";

/// A container phrase and its cards of 2, 4, 6 and 8 repair words.
#[derive(Clone, Copy)]
struct CardRow {
    container: &'static str,
    cards: [&'static str; 4],
}

/// The table of MHFE-REPAIR-1's public vectors.
const CARDS: [CardRow; 4] = [
    CardRow {
        container: ZERO_12,
        cards: [
            "labor extra",
            "shaft pupil patient jewel",
            "credit buzz orbit tired sail coffee",
            "appear include vicious move uphold tiger song satoshi",
        ],
    },
    CardRow {
        container: NONZERO_12,
        cards: [
            "motor renew",
            "pitch lonely onion erode",
            "toe rather ribbon run enforce notice",
            "tilt object execute change cube domain vehicle hour",
        ],
    },
    CardRow {
        container: NONZERO_21,
        cards: [
            "glove blossom",
            "share mask pave crystal",
            "slow issue fame census cabbage clarify",
            "potato enemy similar myself check gesture fortune shiver",
        ],
    },
    CardRow {
        container: ABANDON_ART,
        cards: [
            "clever gravity",
            "letter wealth borrow cable",
            "clap try lift setup innocent gather",
            "mirror coffee census note proof zebra begin barrel",
        ],
    },
];

/// What a repair must give.
#[derive(Clone, Copy)]
enum Expected {
    /// The container phrase as published, with the container phrase's and the card's repaired
    /// positions, from 1.
    Repaired {
        container_words: &'static [usize],
        card_words: &'static [usize],
    },
    /// A refusal with this error code.
    Refused(&'static str),
}

/// A container phrase read with damage: the words at the positions given, from 1, are read as
/// written.
#[derive(Clone, Copy)]
struct RepairCase {
    container: &'static str,
    damage: &'static [(usize, &'static str)],
    card: &'static str,
    expected: Expected,
    startup: bool,
}

const REPAIRS: [RepairCase; 7] = [
    // The specification: words 3 and 17 unreadable, restored as "tower" and "cycle".
    RepairCase {
        container: ZERO_12,
        damage: &[(3, "?"), (17, "?")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            container_words: &[3, 17],
            card_words: &[],
        },
        startup: true,
    },
    // Three unreadable words are more than two repair words repair.
    RepairCase {
        container: ZERO_12,
        damage: &[(1, "?"), (2, "?"), (3, "?")],
        card: "labor extra",
        expected: Expected::Refused("REPAIR_NOT_POSSIBLE"),
        startup: true,
    },
    // The intact container phrase with the card of another container phrase,
    // same-length-nonzero-12's four words: the independent implementation finds no repair within
    // the bound.
    RepairCase {
        container: ZERO_12,
        damage: &[],
        card: "pitch lonely onion erode",
        expected: Expected::Refused("REPAIR_NOT_POSSIBLE"),
        startup: true,
    },
    // The specification: word 10 replaced by "zoo" and word 5 unreadable.
    RepairCase {
        container: ZERO_12,
        damage: &[(10, "zoo"), (5, "?")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            container_words: &[5, 10],
            card_words: &[],
        },
        startup: false,
    },
    // The specification, exactly at the bound 2e + s = k: words 3 and 17 wrong.
    RepairCase {
        container: ZERO_12,
        damage: &[(3, "zoo"), (17, "abandon")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            container_words: &[3, 17],
            card_words: &[],
        },
        startup: false,
    },
    // Two unreadable and one wrong word on a 21-word container phrase, and an unreadable card word.
    RepairCase {
        container: NONZERO_21,
        damage: &[(4, "?"), (13, "?"), (21, "zoo")],
        card: "slow issue fame census ? clarify",
        expected: Expected::Repaired {
            container_words: &[4, 13, 21],
            card_words: &[5],
        },
        startup: false,
    },
    // Three wrong container words and a wrong card word: eight repair words at their bound.
    RepairCase {
        container: ZERO_12,
        damage: &[(2, "abandon"), (11, "zoo"), (23, "legal")],
        card: "appear include vicious move uphold abandon song satoshi",
        expected: Expected::Repaired {
            container_words: &[2, 11, 23],
            card_words: &[6],
        },
        startup: false,
    },
];

/// What a container phrase as typed must be read as, before anything is computed with it.
#[derive(Clone, Copy)]
enum ExpectedReading {
    Container,
    Marked(&'static [usize]),
    NotAContainer,
    WrongLength(usize),
}

/// The container phrase of zero-12 typed with the changes given, from 1, and how it must be read.
#[derive(Clone, Copy)]
struct ReadingCase {
    changes: &'static [(usize, &'static str)],
    expected: ExpectedReading,
}

/// Every kind of reading, each a case that the others must not give.
const READINGS: [ReadingCase; 5] = [
    ReadingCase {
        changes: &[],
        expected: ExpectedReading::Container,
    },
    ReadingCase {
        changes: &[(3, "?"), (17, "?")],
        expected: ExpectedReading::Marked(&[3, 17]),
    },
    // A word outside the list is unreadable once another is marked.
    ReadingCase {
        changes: &[(3, "?"), (9, "towr")],
        expected: ExpectedReading::Marked(&[3, 9]),
    },
    // "abandon" as the last word fails the BIP39 checksum of zero-12's container phrase.
    ReadingCase {
        changes: &[(24, "abandon")],
        expected: ExpectedReading::NotAContainer,
    },
    // The last word left out.
    ReadingCase {
        changes: &[(24, "")],
        expected: ExpectedReading::WrongLength(23),
    },
];

/// The `repair-words` check.
pub(crate) struct RepairWordsCheck {
    cards: &'static [CardRow],
    repairs: &'static [RepairCase],
    readings: &'static [ReadingCase],
}

impl RepairWordsCheck {
    pub(crate) fn new() -> Self {
        Self {
            cards: &CARDS,
            repairs: &REPAIRS,
            readings: &READINGS,
        }
    }

    fn cards(row: &CardRow) -> Result<(), String> {
        for (count, card) in super::REPAIR_WORD_COUNTS.into_iter().zip(row.cards) {
            let words = super::repair_words(row.container, count).map_err(stopped)?;
            expect(words == card, "gives other words")?;
        }
        Ok(())
    }

    fn repair(case: &RepairCase) -> Result<(), String> {
        let mut words: Vec<&str> = case.container.split_whitespace().collect();
        for &(position, word) in case.damage {
            let slot = words
                .get_mut(position.wrapping_sub(1))
                .ok_or_else(|| "the built-in cases are damaged".to_owned())?;
            *slot = word;
        }
        let result = super::repair(&words.join(" "), case.card);
        match case.expected {
            Expected::Refused(code) => expect_refusal(result, code),
            Expected::Repaired {
                container_words,
                card_words,
            } => {
                let repaired = result.map_err(stopped)?;
                let expected: Vec<&str> = case.container.split_whitespace().collect();
                expect(
                    repaired.container == expected.join(" "),
                    "gives another container phrase",
                )?;
                expect(
                    repaired.container_words == container_words
                        && repaired.card_words == card_words,
                    "repairs other words",
                )
            }
        }
    }

    fn reading(case: &ReadingCase) -> Result<(), String> {
        let mut words: Vec<&str> = ZERO_12.split_whitespace().collect();
        for &(position, word) in case.changes {
            let slot = words
                .get_mut(position.wrapping_sub(1))
                .ok_or_else(|| "the built-in cases are damaged".to_owned())?;
            *slot = word;
        }
        let read = super::ContainerReading::read(&words.join(" "));
        let expected = match case.expected {
            ExpectedReading::Container => super::ContainerReading::Container,
            ExpectedReading::Marked(unreadable) => super::ContainerReading::Marked {
                unreadable: unreadable.to_vec(),
            },
            ExpectedReading::NotAContainer => super::ContainerReading::NotAContainer,
            ExpectedReading::WrongLength(words) => super::ContainerReading::WrongLength(words),
        };
        expect(read == expected, "is read as another kind")
    }
}

impl ComponentCheck for RepairWordsCheck {
    fn id(&self) -> &'static str {
        "repair-words"
    }

    fn label(&self) -> &'static str {
        "Repair words (MHFE-REPAIR-1)"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let full = tier == Tier::Full;
        let cards = if full { self.cards } else { &self.cards[..1] };
        let repairs: Vec<RepairCase> = self
            .repairs
            .iter()
            .filter(|case| full || case.startup)
            .copied()
            .collect();
        let mut findings = Findings::new();
        findings.each("card", cards, Self::cards);
        findings.each("repair", &repairs, Self::repair);
        findings.each("reading", self.readings, Self::reading);
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};

    #[test]
    fn the_repair_words_pass_at_both_tiers() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(RepairWordsCheck::new().run(tier), ComponentOutcome::Passed);
        }
    }

    #[test]
    fn a_corrupted_card_or_repair_fails() {
        let mut cards = CARDS;
        cards[0].cards[1] = "shaft pupil patient jewels";
        fails_with(
            RepairWordsCheck {
                cards: leak(cards),
                ..RepairWordsCheck::new()
            },
            "card 1 of 1 gives other words",
        );
        let mut repairs = REPAIRS;
        repairs[0].expected = Expected::Repaired {
            container_words: &[3],
            card_words: &[],
        };
        fails_with(
            RepairWordsCheck {
                repairs: leak(repairs),
                ..RepairWordsCheck::new()
            },
            "repair 1 of 3 repairs other words",
        );
    }

    /// A refusal the code must give, turned into a repair it must not make, fails.
    #[test]
    fn an_accepted_wrong_card_fails() {
        let mut repairs = REPAIRS;
        repairs[2].card = "shaft pupil patient jewel";
        fails_with(
            RepairWordsCheck {
                repairs: leak(repairs),
                ..RepairWordsCheck::new()
            },
            "repair 3 of 3 is accepted instead of refused with REPAIR_NOT_POSSIBLE",
        );
    }

    #[test]
    fn the_full_tier_adds_every_row_and_repair() {
        let mut cards = CARDS;
        cards[3].cards[3] = "mirror coffee census note proof zebra begin barrels";
        let mut check = RepairWordsCheck {
            cards: Box::leak(Box::new(cards)),
            ..RepairWordsCheck::new()
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        assert_eq!(
            check.run(Tier::Full),
            ComponentOutcome::Failed("card 4 of 4 gives other words".to_owned())
        );
    }
}
