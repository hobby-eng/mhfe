//! Repair words for a container phrase: the optional profile MHFE-REPAIR-1 of the specification
//! (README, "Optional repair words"), outside suites 3 and 4.
//!
//! A written container phrase can fade, rust, be scratched or be copied with a wrong word. A few
//! extra English BIP39 words, kept on a card apart from the container phrase, let any program
//! repair it without the password and without Argon2. [`mhfe_core::repair`] holds the code, byte
//! for byte; this module holds mhfe's refusals and what a container phrase as typed is.
//!
//! The card holds nothing secret beyond what the container phrase holds: with the container phrase,
//! it adds nothing; on its own it gives k of the container phrase's word values in mixed form. But
//! a container is what a guesser of passwords needs, and the card repairs a damaged or partial copy
//! of the container phrase for whoever has both, as it does for the owner. It belongs apart from
//! the container phrase, so that one accident or one thief does not take both, and is guarded like
//! the container phrase.

use mhfe_core::repair::{Card, Change, Error, Repaired};
use mhfe_core::Phrase;

use crate::phrase::{self, WORD_COUNTS};
use crate::MhfeError;

/// Why the repair module refuses: each variant is the [`MhfeError`] of the same name, whose text
/// and code it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairError {
    /// A container phrase that cannot be read, such as one of the wrong word count.
    InvalidContainer(String),
    /// Repair words that are not 2, 4, 6 or 8 English BIP39 words.
    InvalidRepairWords(String),
    /// No repair within the bound of the repair words passes the BIP39 checksum.
    RepairNotPossible {
        /// The number of repair words given.
        repair_words: usize,
    },
    /// A refusal of the core's code that a front end cannot cause.
    Internal(String),
}

impl From<RepairError> for MhfeError {
    fn from(error: RepairError) -> Self {
        match error {
            RepairError::InvalidContainer(reason) => Self::InvalidContainer(reason),
            RepairError::InvalidRepairWords(reason) => Self::InvalidRepairWords(reason),
            RepairError::RepairNotPossible { repair_words } => {
                Self::RepairNotPossible { repair_words }
            }
            RepairError::Internal(reason) => Self::Internal(reason),
        }
    }
}

shown_as_mhfe_error!(RepairError);

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-repair"
))]
pub(crate) mod known_answers;

/// Four repair words repair four unreadable words or two wrong ones: enough for the usual damage
/// of a container phrase at a card of four words.
pub const RECOMMENDED_REPAIR_WORDS: usize = 4;

/// What a card of `count` repair words repairs: as many unreadable words, or half as many wrong
/// ones.
pub fn capacity(count: usize) -> (usize, usize) {
    (count, count / 2)
}

/// How a refusal tells a person typing words to mark one that cannot be read.
const MARK_UNREADABLE: &str = "type ? for a word that cannot be read";

/// Why a card cannot have `count` words, as a refusal says it.
fn wrong_count(count: usize) -> String {
    format!(
        "a card has {} repair words, not {count}",
        phrase::counts_text(&Card::SIZES)
    )
}

/// Refuses a number of repair words that no card has (`INVALID_REPAIR_WORDS`): 2, 4, 6 or 8
/// ([`Card::SIZES`]).
pub fn require_count(count: usize) -> Result<(), RepairError> {
    if !Card::SIZES.contains(&count) {
        return Err(RepairError::InvalidRepairWords(wrong_count(count)));
    }
    Ok(())
}

/// The `count` repair words of `container`, refusing a count as [`require_count`] does.
pub fn repair_words(container: &Phrase, count: usize) -> Result<Card, RepairError> {
    Card::new(container, count).map_err(|_| RepairError::InvalidRepairWords(wrong_count(count)))
}

/// What a container phrase as typed is, before anything is computed with it: a container as it
/// stands, or words that its repair words may repair. A front end that reads a container asks for
/// the card at once when the owner marked words with `?`, and offers it when the words have a
/// container's length but are not a container, which may be a typing mistake as well.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerReading {
    /// A valid container: nothing to repair.
    Container,
    /// Words typed as `?`: the owner marked them as unreadable. `unreadable` lists every word that
    /// cannot be read, from 1, words outside the BIP39 list included.
    Marked {
        /// The places of the unreadable words, counted from 1.
        unreadable: Vec<usize>,
    },
    /// A container's length, but not a container: a word outside the BIP39 list or a BIP39
    /// checksum that fails, from a typing mistake or from a damaged or miscopied container phrase.
    NotAContainer,
    /// Not 12, 15, 18, 21 or 24 words, `?` included: nothing that repair words could repair.
    WrongLength(usize),
}

impl ContainerReading {
    /// Reads `written` as [`repair`] reads a container phrase: `?` for a word that cannot be read,
    /// any spacing and letter case, and the first four letters of a word.
    pub fn read(written: &str) -> Self {
        let typed: Vec<&str> = written.split_whitespace().collect();
        if !WORD_COUNTS.contains(&typed.len()) {
            return Self::WrongLength(typed.len());
        }
        if typed.contains(&UNREADABLE) {
            let (_, unreadable) = phrase::word_numbers(written);
            return Self::Marked {
                unreadable: unreadable.iter().map(|position| position + 1).collect(),
            };
        }
        if Phrase::read(written).is_ok() {
            Self::Container
        } else {
            Self::NotAContainer
        }
    }

    /// Whether repair words may make a container of these words.
    pub fn can_be_repaired(&self) -> bool {
        matches!(self, Self::Marked { .. } | Self::NotAContainer)
    }
}

/// What stands for a word that cannot be read, on the container phrase and on the card.
pub const UNREADABLE: &str = "?";

/// The name of the profile, which the card carries; a reader of a card skips it.
pub const PROFILE: &str = "MHFE-REPAIR-1";

/// Repairs a container from its words as read from the container phrase and its repair words as
/// read from the card. A word that cannot be read is typed as `?`; a word that is not in the
/// English BIP39 list counts as unreadable too, and the first four letters of a word are enough, as
/// for a container. Fails when no repair within the code's bound gives a container that passes its
/// BIP39 checksum. Damage beyond the bound, or a card of another container phrase, usually fails
/// so, but can also give another container that passes the checksum: a repair does not show that
/// the card belongs to the container phrase or that the container is the original, which only a
/// rehearsal against the wallet does (AUD-008-DOC001).
pub fn repair(written: &str, card: &str) -> Result<Repaired, RepairError> {
    let card = card_text(card);
    Repaired::of(written, &card).map_err(|refused| match refused {
        Error::ContainerWordCount { words } => RepairError::InvalidContainer(format!(
            "it has {words} words, but a container has {}; {MARK_UNREADABLE}",
            phrase::word_counts_text()
        )),
        // A card being typed: say how to mark a word that cannot be read.
        Error::CardWordCount { words } => {
            RepairError::InvalidRepairWords(format!("{}; {MARK_UNREADABLE}", wrong_count(words)))
        }
        Error::NotPossible => RepairError::RepairNotPossible {
            repair_words: card.split_whitespace().count(),
        },
        other => RepairError::Internal(other.to_string()),
    })
}

/// The positions of the repaired words, from 1, in order: those of the card with `on_card`, those
/// of the container phrase without.
pub fn positions(repaired: &Repaired, on_card: bool) -> Vec<usize> {
    repaired
        .changes()
        .filter(|change| change.on_card() == on_card)
        .map(Change::position)
        .collect()
}

/// The words of a card as written: the profile's name and the numbers such as "1/4" before each
/// word are left out, so that a card can be typed as it is.
pub fn card_text(card: &str) -> String {
    card.split_whitespace()
        .filter(|token| {
            let numbered = token.split_once('/').is_some_and(|(left, right)| {
                !left.is_empty()
                    && !right.is_empty()
                    && left
                        .chars()
                        .chain(right.chars())
                        .all(|c| c.is_ascii_digit())
            });
            !numbered && !token.eq_ignore_ascii_case(PROFILE)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::zero_12_container;

    /// The repair words of a container as text.
    fn card_of(container: &str, count: usize) -> Card {
        repair_words(&Phrase::read(container).unwrap(), count).unwrap()
    }

    #[test]
    fn a_container_phrase_and_its_card_have_nothing_to_repair() {
        let container = zero_12_container();
        for count in Card::SIZES {
            let card = card_of(&container, count);
            let repaired = repair(&container, card.as_str()).unwrap();
            assert_eq!(repaired.container().as_str(), container);
            assert_eq!(repaired.changes().count(), 0);
        }
    }

    fn fixture_container(json: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["container"].as_str().unwrap().to_owned()
    }

    /// Repair words computed by an independent Python implementation, written from the profile's
    /// description without this code, for public containers of 24, 12 and 21 words.
    #[test]
    fn repair_words_match_the_independent_vectors() {
        let cases = [
            (
                fixture_container(include_str!("../tests/spec/vectors/suite3/zero-12.json")),
                [
                    "labor extra",
                    "shaft pupil patient jewel",
                    "credit buzz orbit tired sail coffee",
                    "appear include vicious move uphold tiger song satoshi",
                ],
            ),
            (
                fixture_container(include_str!(
                    "../tests/spec/vectors/suite4/same-length-nonzero-12.json"
                )),
                [
                    "motor renew",
                    "pitch lonely onion erode",
                    "toe rather ribbon run enforce notice",
                    "tilt object execute change cube domain vehicle hour",
                ],
            ),
            (
                fixture_container(include_str!(
                    "../tests/spec/vectors/suite4/same-length-nonzero-21.json"
                )),
                [
                    "glove blossom",
                    "share mask pave crystal",
                    "slow issue fame census cabbage clarify",
                    "potato enemy similar myself check gesture fortune shiver",
                ],
            ),
            (
                format!("{} art", ["abandon"; 23].join(" ")),
                [
                    "clever gravity",
                    "letter wealth borrow cable",
                    "clap try lift setup innocent gather",
                    "mirror coffee census note proof zebra begin barrel",
                ],
            ),
        ];
        for (container, cards) in cases {
            for (count, card) in Card::SIZES.into_iter().zip(cards) {
                assert_eq!(card_of(&container, count).as_str(), card, "{count} words");
            }
        }
    }

    /// The independent implementation's repair cases on zero-12 and same-length-nonzero-21.
    #[test]
    fn repairs_match_the_independent_vectors() {
        let zero_12 = zero_12_container();
        let cases: [(&str, &str, Vec<usize>, Vec<usize>); 6] = [
            (
                "donate stove ? picnic iron rescue trick shrimp roof rib home cigar bag pledge \
                 also nerve ? famous provide heart ahead chunk caution peace",
                "shaft pupil patient jewel",
                vec![3, 17],
                vec![],
            ),
            (
                "donate stove tower picnic zoo rescue trick shrimp roof rib home cigar bag pledge \
                 also nerve cycle famous provide abandon ahead chunk caution peace",
                "shaft pupil patient jewel",
                vec![5, 20],
                vec![],
            ),
            (
                "? stove tower picnic iron rescue trick shrimp legal rib home cigar bag pledge \
                 also nerve cycle famous provide heart ahead chunk caution ?",
                "shaft pupil patient jewel",
                vec![1, 9, 24],
                vec![],
            ),
            (
                "? stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also \
                 nerve cycle famous provide heart ahead chunk caution peace",
                "shaft ? patient jewel",
                vec![1],
                vec![2],
            ),
            (&zero_12, "zoo extra", vec![], vec![1]),
            (
                "donate abandon tower picnic iron rescue trick shrimp roof rib zoo cigar bag \
                 pledge also nerve cycle famous provide heart ahead chunk legal peace",
                "appear include vicious move uphold abandon song satoshi",
                vec![2, 11, 23],
                vec![6],
            ),
        ];
        for (written, card, container_words, card_words) in cases {
            let repaired = repair(written, card).unwrap();
            assert_eq!(repaired.container().as_str(), zero_12);
            assert_eq!(positions(&repaired, false), container_words, "{written}");
            assert_eq!(positions(&repaired, true), card_words, "{card}");
        }
        let nonzero_21 = fixture_container(include_str!(
            "../tests/spec/vectors/suite4/same-length-nonzero-21.json"
        ));
        let repaired = repair(
            "seat govern run ? flag fragile horse night simple luggage vacuum warfare ? permit gym \
             upset average blade pen blue zoo",
            "slow issue fame census ? clarify",
        )
        .unwrap();
        assert_eq!(repaired.container().as_str(), nonzero_21);
        assert_eq!(positions(&repaired, false), vec![4, 13, 21]);
        assert_eq!(positions(&repaired, true), vec![5]);
    }

    /// Each repaired word is reported with what was read there (the specification asks that no
    /// repair be silent), and a card typed with its name and numbers is read as its words.
    #[test]
    fn every_repair_is_reported_and_a_written_card_is_read() {
        let container = zero_12_container();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[8] = "legal";
        let repaired = repair(
            &words.join(" "),
            "MHFE-REPAIR-1 1/4 shaft 2/4 ? 3/4 patient 4/4 jewel",
        )
        .unwrap();
        assert_eq!(repaired.container().as_str(), container);
        let shown: Vec<(bool, usize, Option<&str>, &str)> = repaired
            .changes()
            .map(|c| (c.on_card(), c.position(), c.read(), c.word()))
            .collect();
        assert_eq!(
            shown,
            vec![
                (false, 1, None, "donate"),
                (false, 9, Some("legal"), "roof"),
                (true, 2, None, "pupil"),
            ]
        );
    }

    #[test]
    fn unreadable_and_unknown_words_are_marked_and_repaired() {
        let container = zero_12_container();
        let card = card_of(&container, 4);
        let mut words: Vec<&str> = container.split(' ').collect();
        words[2] = "?";
        words[16] = "notaword";
        let repaired = repair(&words.join(" "), card.as_str()).unwrap();
        assert_eq!(repaired.container().as_str(), container);
        assert_eq!(positions(&repaired, false), vec![3, 17]);
    }

    #[test]
    fn too_much_damage_or_a_wrong_card_is_refused() {
        let container = zero_12_container();
        let card = card_of(&container, 2);
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[1] = "?";
        words[2] = "?";
        assert_eq!(
            repair(&words.join(" "), card.as_str()).unwrap_err(),
            RepairError::RepairNotPossible { repair_words: 2 }
        );
        assert_eq!(
            repair(&container, "abandon abandon abandon").unwrap_err(),
            RepairError::InvalidRepairWords(
                "a card has 2, 4, 6 or 8 repair words, not 3; type ? for a word that cannot be read"
                    .to_owned()
            )
        );
        assert_eq!(
            repair_words(&Phrase::read(&container).unwrap(), 3).unwrap_err(),
            RepairError::InvalidRepairWords(
                "a card has 2, 4, 6 or 8 repair words, not 3".to_owned()
            )
        );
        // The count of a card that is refused leaves out its name and numbers.
        assert_eq!(
            repair(&words.join(" "), &format!("{PROFILE} 1/2 labor 2/2 extra")).unwrap_err(),
            RepairError::RepairNotPossible { repair_words: 2 }
        );
        assert_eq!(
            repair(&words[1..].join(" "), card.as_str()).unwrap_err(),
            RepairError::InvalidContainer(
                "it has 23 words, but a container has 12, 15, 18, 21 or 24; type ? for a word \
                 that cannot be read"
                    .to_owned()
            )
        );
    }

    /// AUD-008-DOC001: a card of another container phrase is not always refused. The container
    /// phrases of the zero entropy and of entropy 00…01 differ in their last word only; with the
    /// other container phrase's two repair words, that word is "repaired" into a container that
    /// passes its checksum but is not the container phrase's. A repair never proves the container;
    /// a rehearsal against the wallet does.
    #[test]
    fn a_card_of_another_container_phrase_can_give_another_valid_container() {
        let container = [vec!["abandon"; 23], vec!["art"]].concat().join(" ");
        let other = [vec!["abandon"; 23], vec!["diesel"]].concat().join(" ");
        let card = card_of(&other, 2);
        let repaired = repair(&container, card.as_str()).unwrap();
        assert_eq!(repaired.container().as_str(), other);
        assert_eq!(positions(&repaired, false), [24]);
    }

    /// A container phrase as typed is read as a container, as words marked with `?`, as words
    /// that are not a container, or as a length no container has; the last two kinds that a card
    /// may repair, it repairs.
    #[test]
    fn a_container_phrase_is_read_before_it_is_used() {
        let container = zero_12_container();
        let with = |changes: &[(usize, &'static str)]| {
            let mut words: Vec<&str> = container.split(' ').collect();
            for &(position, word) in changes {
                words[position - 1] = word;
            }
            words.join(" ")
        };
        assert_eq!(
            ContainerReading::read(&container),
            ContainerReading::Container
        );
        // Capitals, extra spaces and four letters a word, as for any container.
        let typed: Vec<String> = container
            .split(' ')
            .map(|word| word[..word.len().min(4)].to_uppercase())
            .collect();
        assert_eq!(
            ContainerReading::read(&typed.join("   ")),
            ContainerReading::Container
        );
        assert_eq!(
            ContainerReading::read(&with(&[(3, "?"), (17, "?")])),
            ContainerReading::Marked {
                unreadable: vec![3, 17]
            }
        );
        // A word outside the list is unreadable too once the owner has marked another.
        assert_eq!(
            ContainerReading::read(&with(&[(3, "?"), (9, "towr")])),
            ContainerReading::Marked {
                unreadable: vec![3, 9]
            }
        );
        for unmarked in [with(&[(9, "towr")]), with(&[(24, "abandon")])] {
            assert_eq!(
                ContainerReading::read(&unmarked),
                ContainerReading::NotAContainer
            );
            assert!(ContainerReading::read(&unmarked).can_be_repaired());
            let repaired = repair(&unmarked, "shaft pupil patient jewel").unwrap();
            assert_eq!(repaired.container().as_str(), container);
        }
        let shorter: Vec<&str> = container.split(' ').take(23).collect();
        assert_eq!(
            ContainerReading::read(&shorter.join(" ")),
            ContainerReading::WrongLength(23)
        );
        assert_eq!(
            ContainerReading::read(&format!("{container} ?")),
            ContainerReading::WrongLength(25)
        );
        assert!(!ContainerReading::Container.can_be_repaired());
        assert!(!ContainerReading::WrongLength(23).can_be_repaired());
    }
}
