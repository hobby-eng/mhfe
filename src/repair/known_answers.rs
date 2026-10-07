//! Known answers of the repair words (MHFE-REPAIR-1): the self-check `repair-words`.
//!
//! The field GF(2^11), the generator, the parity, the syndromes, the repair of unreadable and of
//! wrong words at the code's bound, and the refusals: too much damage, and a card of another
//! plate. Every expected value is a public vector of the specification (vectors/profiles/README.md)
//! or was computed by an independent Python implementation of the profile, written from its
//! description, which first reproduced every published card.

use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

/// The plate of the suite 3 vector zero-12 (vectors/suite3/zero-12.json).
const ZERO_12: &str = "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag \
                       pledge also nerve cycle famous provide heart ahead chunk caution peace";
/// The plates of same-length-nonzero-12 and same-length-nonzero-21 (vectors/suite4).
const NONZERO_12: &str = "hotel supply dune casual fork treat century web wide vote steel media";
const NONZERO_21: &str = "seat govern run smooth flag fragile horse night simple luggage vacuum \
                          warfare tissue permit gym upset average blade pen blue view";
/// "abandon" 23 times, then "art": the phrase of 32 zero bytes.
const ABANDON_ART: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon art";

/// A plate and its cards of 2, 4, 6 and 8 repair words.
#[derive(Clone, Copy)]
struct CardRow {
    plate: &'static str,
    cards: [&'static str; 4],
}

/// The table of MHFE-REPAIR-1's public vectors.
const CARDS: [CardRow; 4] = [
    CardRow {
        plate: ZERO_12,
        cards: [
            "labor extra",
            "shaft pupil patient jewel",
            "credit buzz orbit tired sail coffee",
            "appear include vicious move uphold tiger song satoshi",
        ],
    },
    CardRow {
        plate: NONZERO_12,
        cards: [
            "motor renew",
            "pitch lonely onion erode",
            "toe rather ribbon run enforce notice",
            "tilt object execute change cube domain vehicle hour",
        ],
    },
    CardRow {
        plate: NONZERO_21,
        cards: [
            "glove blossom",
            "share mask pave crystal",
            "slow issue fame census cabbage clarify",
            "potato enemy similar myself check gesture fortune shiver",
        ],
    },
    CardRow {
        plate: ABANDON_ART,
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
    /// The plate as published, with the plate's and the card's repaired positions, from 1.
    Repaired {
        plate_words: &'static [usize],
        card_words: &'static [usize],
    },
    /// A refusal with this error code.
    Refused(&'static str),
}

/// A plate read with damage: the words at the positions given, from 1, are read as written.
#[derive(Clone, Copy)]
struct RepairCase {
    plate: &'static str,
    damage: &'static [(usize, &'static str)],
    card: &'static str,
    expected: Expected,
    startup: bool,
}

const REPAIRS: [RepairCase; 7] = [
    // The specification: words 3 and 17 unreadable, restored as "tower" and "cycle".
    RepairCase {
        plate: ZERO_12,
        damage: &[(3, "?"), (17, "?")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            plate_words: &[3, 17],
            card_words: &[],
        },
        startup: true,
    },
    // Three unreadable words are more than two repair words repair.
    RepairCase {
        plate: ZERO_12,
        damage: &[(1, "?"), (2, "?"), (3, "?")],
        card: "labor extra",
        expected: Expected::Refused("REPAIR_NOT_POSSIBLE"),
        startup: true,
    },
    // The intact plate with the card of another plate, same-length-nonzero-12's four words: the
    // independent implementation finds no repair within the bound.
    RepairCase {
        plate: ZERO_12,
        damage: &[],
        card: "pitch lonely onion erode",
        expected: Expected::Refused("REPAIR_NOT_POSSIBLE"),
        startup: true,
    },
    // The specification: word 10 replaced by "zoo" and word 5 unreadable.
    RepairCase {
        plate: ZERO_12,
        damage: &[(10, "zoo"), (5, "?")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            plate_words: &[5, 10],
            card_words: &[],
        },
        startup: false,
    },
    // The specification, exactly at the bound 2e + s = k: words 3 and 17 wrong.
    RepairCase {
        plate: ZERO_12,
        damage: &[(3, "zoo"), (17, "abandon")],
        card: "shaft pupil patient jewel",
        expected: Expected::Repaired {
            plate_words: &[3, 17],
            card_words: &[],
        },
        startup: false,
    },
    // Two unreadable and one wrong word on a 21-word plate, and an unreadable card word.
    RepairCase {
        plate: NONZERO_21,
        damage: &[(4, "?"), (13, "?"), (21, "zoo")],
        card: "slow issue fame census ? clarify",
        expected: Expected::Repaired {
            plate_words: &[4, 13, 21],
            card_words: &[5],
        },
        startup: false,
    },
    // Three wrong plate words and a wrong card word: eight repair words at their bound.
    RepairCase {
        plate: ZERO_12,
        damage: &[(2, "abandon"), (11, "zoo"), (23, "legal")],
        card: "appear include vicious move uphold abandon song satoshi",
        expected: Expected::Repaired {
            plate_words: &[2, 11, 23],
            card_words: &[6],
        },
        startup: false,
    },
];

/// The `repair-words` check.
pub(crate) struct RepairWordsCheck {
    cards: &'static [CardRow],
    repairs: &'static [RepairCase],
}

impl RepairWordsCheck {
    pub(crate) fn new() -> Self {
        Self {
            cards: &CARDS,
            repairs: &REPAIRS,
        }
    }

    fn cards(row: &CardRow) -> Result<(), String> {
        for (count, card) in super::REPAIR_WORD_COUNTS.into_iter().zip(row.cards) {
            let words = super::repair_words(row.plate, count).map_err(stopped)?;
            expect(words == card, "gives other words")?;
        }
        Ok(())
    }

    fn repair(case: &RepairCase) -> Result<(), String> {
        let mut words: Vec<&str> = case.plate.split_whitespace().collect();
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
                plate_words,
                card_words,
            } => {
                let repaired = result.map_err(stopped)?;
                let plate: Vec<&str> = case.plate.split_whitespace().collect();
                expect(repaired.container == plate.join(" "), "gives another plate")?;
                expect(
                    repaired.plate_words == plate_words && repaired.card_words == card_words,
                    "repairs other words",
                )
            }
        }
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
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut check = RepairWordsCheck {
            cards: Box::leak(Box::new(cards)),
            ..RepairWordsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("card 1 of 1 gives other words".to_owned())
        );
        let mut repairs = REPAIRS;
        repairs[0].expected = Expected::Repaired {
            plate_words: &[3],
            card_words: &[],
        };
        let mut check = RepairWordsCheck {
            repairs: Box::leak(Box::new(repairs)),
            ..RepairWordsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("repair 1 of 3 repairs other words".to_owned())
        );
    }

    /// A refusal the code must give, turned into a repair it must not make, fails.
    #[test]
    fn an_accepted_wrong_card_fails() {
        let mut repairs = REPAIRS;
        repairs[2].card = "shaft pupil patient jewel";
        let mut check = RepairWordsCheck {
            repairs: Box::leak(Box::new(repairs)),
            ..RepairWordsCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "repair 3 of 3 is accepted instead of refused with REPAIR_NOT_POSSIBLE".to_owned()
            )
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
