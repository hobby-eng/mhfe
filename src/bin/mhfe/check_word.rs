//! The password check word, the optional profile MHFE-PASSWORD-CHECK-1 of the specification
//! (README, "Optional password check word"). Five words drawn from the EFF large wordlist get a
//! sixth computed from them; the six words are the password. The check word lets the program notice
//! and repair a typing error before any Argon2 work: one forgotten or unreadable word at a known
//! place, the check word included, is restored uniquely; one wrong word is noticed, but not where
//! it is.
//!
//! The five drawn words carry about 64.6 bits; the check word adds none and is as secret as the
//! rest. A check word that fits shows only that the six words belong together, never that the
//! password opens a given container.

use std::collections::HashMap;

use mhfe::memory::LockedPages;
use zeroize::Zeroizing;

use crate::choice::{self, Answer, Question};
use crate::diceware;
use crate::exit::Failure;
use crate::locked_text::LockedText;
use crate::readme;
use crate::terminal::{Input, PrivateScreen};

/// Said where a password is typed, so that a person who forgot a word knows how to get it back:
/// a word left out would make it five words, an ordinary password.
pub const FORGOTTEN_WORD_HINT: &str = "A password with a check word: type ? for a word you forgot.";
/// The words drawn at random, before the check word.
pub const DRAWN_WORDS: usize = 5;
/// Words in the EFF large wordlist: 6^5, one for every roll of five dice.
const LIST_SIZE: usize = 7776;
/// The weights of the five drawn words, each coprime to 7,776, which is what makes one erased word
/// recoverable and one wrong word noticeable.
const WEIGHTS: [usize; DRAWN_WORDS] = [1, 5, 7, 11, 13];
/// What a person types for a word they cannot read; any other word outside the list counts the
/// same, but this one says it on purpose.
const UNREADABLE: &str = "?";

/// The index of the check word for the indexes of the five drawn words:
/// (d1 + 5 d2 + 7 d3 + 11 d4 + 13 d5) mod 7776.
pub fn check_index(drawn: &[usize; DRAWN_WORDS]) -> usize {
    drawn
        .iter()
        .zip(WEIGHTS)
        .map(|(&index, weight)| index * weight % LIST_SIZE)
        .sum::<usize>()
        % LIST_SIZE
}

/// What a typed password is under the profile. It borrows the words typed and those of the list,
/// so that no copy of the password is made until a repair is chosen.
#[derive(Debug, PartialEq, Eq)]
enum Reading<'t> {
    /// Not six words of the list with at most one gap: the profile does not apply to it.
    NotThisShape,
    /// The six words fit together.
    Fits,
    /// One word was left out or is not in the list; the check word restores it.
    Restored(Repair<'t>),
    /// All six words are in the list but do not fit: one is wrong, at a place that cannot be told.
    /// Each place allows exactly one repair, so there are six.
    Mismatch(Vec<Repair<'t>>),
}

/// One word of a typed password replaced so that the six fit.
#[derive(Debug, PartialEq, Eq)]
struct Repair<'t> {
    /// The place of the word, from 1; 6 is the check word.
    position: usize,
    /// The word as typed.
    typed: &'t str,
    /// The word it becomes.
    word: &'static str,
}

/// The EFF list with each word's index, for reading typed words exactly as written.
struct List {
    words: Vec<&'static str>,
    index: HashMap<&'static str, usize>,
}

impl List {
    fn new() -> Self {
        let words = diceware::eff_words();
        let index = words
            .iter()
            .enumerate()
            .map(|(position, &word)| (word, position))
            .collect();
        Self { words, index }
    }

    /// Reads a typed password. It is split at single spaces and each word is compared with the
    /// list exactly as written, hyphens included: the prefix rules of seed phrases do not apply,
    /// since the list has both "yo-yo" and "yoyo". A word not in the list, such as "?", is a gap.
    fn read<'t>(&self, typed: &'t str) -> Reading<'t> {
        let tokens: Vec<&str> = typed.split(' ').collect();
        if tokens.len() != DRAWN_WORDS + 1 {
            return Reading::NotThisShape;
        }
        // The positions in the list reveal the password: wiped when done.
        let found: Zeroizing<Vec<Option<usize>>> = Zeroizing::new(
            tokens
                .iter()
                .map(|token| self.index.get(token).copied())
                .collect(),
        );
        let gaps: Vec<usize> = (0..tokens.len()).filter(|&i| found[i].is_none()).collect();
        let known: Zeroizing<Vec<usize>> =
            Zeroizing::new(found.iter().map(|index| index.unwrap_or(0)).collect());
        let repair_at = |position: usize| Repair {
            position: position + 1,
            typed: tokens[position],
            word: self.words[restored_index(&known, position)],
        };
        match gaps.as_slice() {
            [] if restored_index(&known, DRAWN_WORDS) == known[DRAWN_WORDS] => Reading::Fits,
            [] => Reading::Mismatch((0..tokens.len()).map(repair_at).collect()),
            [gap] => Reading::Restored(repair_at(*gap)),
            _ => Reading::NotThisShape,
        }
    }
}

/// The index at `position` that makes the six fit, the other five as given.
fn restored_index(indexes: &[usize], position: usize) -> usize {
    let mut drawn: Zeroizing<[usize; DRAWN_WORDS]> = Zeroizing::new(
        indexes[..DRAWN_WORDS]
            .try_into()
            .expect("a password of the profile has five drawn words"),
    );
    if position == DRAWN_WORDS {
        return check_index(&drawn);
    }
    // weight * d = check - (the weighted sum of the others): d is that times the weight's inverse.
    drawn[position] = 0;
    let wanted = (indexes[DRAWN_WORDS] + LIST_SIZE - check_index(&drawn)) % LIST_SIZE;
    wanted * inverse(WEIGHTS[position]) % LIST_SIZE
}

/// The inverse of `weight` modulo 7,776, which exists because the weight is coprime to it.
fn inverse(weight: usize) -> usize {
    (1..LIST_SIZE)
        .find(|&candidate| weight * candidate % LIST_SIZE == 1)
        .expect("every weight is coprime to 7,776")
}

/// The typed password with one word replaced, built at its final size and locked, so that no
/// unwiped copy is left behind.
fn repaired(typed: &str, repair: &Repair) -> LockedText {
    let mut text = Zeroizing::new(String::with_capacity(
        typed.len() - repair.typed.len() + repair.word.len(),
    ));
    let locked = LockedPages::of_string(&text);
    for (index, token) in typed.split(' ').enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(if index + 1 == repair.position {
            repair.word
        } else {
            token
        });
    }
    LockedText::from_locked(text, locked)
}

/// The profile's written form of a typed password, its words in small letters one space apart
/// with no space before or after, and what that changed; `None` when nothing changes. It is built
/// at its final size and locked, as the password itself is. Only a password that then fits the
/// profile is offered in this form: any other keeps its spaces and capitals, which count.
fn written_form(typed: &str) -> Option<(LockedText, &'static str)> {
    let extra_spaces = typed.split(' ').any(str::is_empty);
    let capitals = typed.bytes().any(|byte| byte.is_ascii_uppercase());
    let change = match (extra_spaces, capitals) {
        (false, false) => return None,
        (true, false) => "extra spaces removed",
        (false, true) => "capitals made small",
        (true, true) => "spaces and capitals corrected",
    };
    // Never longer than typed: spaces are only removed, and ASCII letters keep their length.
    let mut text = Zeroizing::new(String::with_capacity(typed.len()));
    let locked = LockedPages::of_string(&text);
    for (index, word) in typed.split(' ').filter(|word| !word.is_empty()).enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.extend(word.chars().map(|letter| letter.to_ascii_lowercase()));
    }
    Some((LockedText::from_locked(text, locked), change))
}

/// What to do with a typed password once its check word has been looked at.
pub enum Reviewed {
    /// Use this password, as typed, corrected or with one word repaired; the outcome goes into the
    /// summary once the password is read.
    Use(LockedText, Outcome),
    /// Ask for the password again.
    TypeAgain,
}

/// How the check word came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The password cannot have a check word, or it was not looked at.
    NotChecked,
    /// The six words fit, as typed or with their spaces or capitals corrected as this says.
    Fits(Option<&'static str>),
    /// The word at this place, from 1, was repaired, and the spaces or capitals corrected as the
    /// second value says, if they were.
    Repaired(usize, Option<&'static str>),
    /// The words do not fit and the password is used as typed.
    DoesNotFit,
}

impl Outcome {
    /// The answer of the summary line that records the password, `typed` ("typed" or "typed
    /// twice") followed by how the check word came out.
    pub fn record(self, typed: &str) -> String {
        match self {
            Self::NotChecked => typed.to_owned(),
            Self::Fits(None) => format!("{typed}, its check word fits"),
            Self::Fits(Some(change)) => format!("{typed}, {change}; its check word fits"),
            Self::Repaired(position, change) => {
                let change = change.map_or(String::new(), |change| format!("; {change}"));
                format!("{typed}, word {position} repaired by its check word{change}")
            }
            Self::DoesNotFit => format!("{typed}; no check word fits"),
        }
    }
}

/// Looks at the check word of a password just typed on `screen`, before any Argon2 work. A
/// password typed with extra spaces or capitals is read in the profile's written form when that
/// fits the profile. Every correction and repair is shown and used only when the person chooses
/// it, and the password as typed is always one of the answers: the container does not record
/// whether its password has a check word. Only a person at a terminal is asked, on the private
/// screen, since the answers show words of the password; a script, and a password that cannot have
/// a check word, pass unchanged.
pub fn review(
    input: &mut Input,
    typed: LockedText,
    screen: &PrivateScreen,
) -> Result<Reviewed, Failure> {
    if input.is_script() || !screen.is_active() || !choice::can_run() {
        return Ok(Reviewed::Use(typed, Outcome::NotChecked));
    }
    let list = List::new();
    let form = match list.read(&typed) {
        Reading::Fits => return Ok(Reviewed::Use(typed, Outcome::Fits(None))),
        Reading::NotThisShape => match written_form(&typed) {
            Some((form, change)) if !matches!(list.read(&form), Reading::NotThisShape) => {
                Some((form, change))
            }
            _ => return Ok(Reviewed::Use(typed, Outcome::NotChecked)),
        },
        Reading::Restored(_) | Reading::Mismatch(_) => None,
    };
    let change = form.as_ref().map(|(_, change)| *change);
    let text = form.as_ref().map_or(&*typed, |(form, _)| &**form);
    Ok(match decide(input, &list, text, change)? {
        Decision::Repaired(repaired, position) => {
            Reviewed::Use(repaired, Outcome::Repaired(position, change))
        }
        Decision::Corrected => {
            let (form, change) = form.expect("only a written form is offered as corrected");
            Reviewed::Use(form, Outcome::Fits(Some(change)))
        }
        Decision::AsTyped => Reviewed::Use(typed, Outcome::DoesNotFit),
        Decision::TypeAgain => Reviewed::TypeAgain,
    })
}

/// What the person chose for a password that does not simply fit.
enum Decision {
    Repaired(LockedText, usize),
    /// The written form, which fits.
    Corrected,
    AsTyped,
    TypeAgain,
}

/// Asks what to do with `text`, the password as typed, or its written form when `change` says how
/// that differs from it.
fn decide(
    input: &mut Input,
    list: &List,
    text: &str,
    change: Option<&'static str>,
) -> Result<Decision, Failure> {
    let (mut explanation, repairs, restore): (Vec<String>, Vec<Repair>, bool) = match list
        .read(text)
    {
        Reading::Fits => (
            vec!["Once corrected, its six words fit their check word.".to_owned()],
            Vec::new(),
            false,
        ),
        Reading::Restored(repair) => (
            vec![
                "One word is missing or not in the word list. If the password was made".to_owned(),
                "with a check word, the check word restores it.".to_owned(),
            ],
            vec![repair],
            true,
        ),
        Reading::Mismatch(repairs) => (
            vec![
                "Its six words do not fit their check word. If it was made with one, one"
                    .to_owned(),
                "word is wrong, and which one cannot be told: compare each answer with".to_owned(),
                "what you wrote down.".to_owned(),
            ],
            repairs,
            false,
        ),
        Reading::NotThisShape => unreachable!("only a password of the profile's shape is asked"),
    };
    if let (Some(change), false) = (change, repairs.is_empty()) {
        explanation.push(format!("Each repair below also has its {change}."));
    }
    let explanation: Vec<&str> = explanation.iter().map(String::as_str).collect();
    let question = Question {
        text: "Repair the password with its check word?",
        explanation: &explanation,
        more: Some(readme::CHECK_WORD),
        record: None,
    };
    let mut actions = vec![Action::AsTyped, Action::TypeAgain];
    // A word typed as "?" asks for the repair, and a corrected password that fits is strong
    // evidence of the profile: either comes first. Any other word may belong to a password made
    // without a check word, which is used as typed unless a repair is chosen.
    let first = repairs.iter().any(|repair| repair.typed == UNREADABLE) || repairs.is_empty();
    let position = if first { 0 } else { actions.len() };
    let mut offered: Vec<Action> = repairs
        .iter()
        .map(|repair| {
            if restore {
                Action::Restore(repair)
            } else {
                Action::Replace(repair)
            }
        })
        .collect();
    if let (Some(change), true) = (change, repairs.is_empty()) {
        offered.push(Action::Correct(change));
    }
    actions.splice(position..position, offered);
    let answers: Vec<Answer> = actions.iter().map(Action::answer).collect();
    let chosen = input.choose_here(&question, &answers)?;
    Ok(match actions[chosen] {
        Action::Restore(repair) | Action::Replace(repair) => {
            Decision::Repaired(repaired(text, repair), repair.position)
        }
        Action::Correct(_) => Decision::Corrected,
        Action::AsTyped => Decision::AsTyped,
        Action::TypeAgain => Decision::TypeAgain,
    })
}

/// An answer of the question in [`decide`].
enum Action<'r, 't> {
    /// Restore a word that is missing or not in the list.
    Restore(&'r Repair<'t>),
    /// Replace a word of the list by another.
    Replace(&'r Repair<'t>),
    /// Use the written form, which fits; the value says what it corrects.
    Correct(&'static str),
    AsTyped,
    TypeAgain,
}

impl Action<'_, '_> {
    fn answer(&self) -> Answer {
        match self {
            // A word outside the list is not repeated: it may be too long for the line.
            Self::Restore(repair) => Answer::new(
                format!("Word {}: {}", repair.position, repair.word),
                "restored by the check word",
            ),
            Self::Replace(repair) => Answer::new(
                format!(
                    "Word {}: {} instead of {}",
                    repair.position, repair.word, repair.typed
                ),
                "",
            ),
            Self::Correct(change) => Answer::new("Use the corrected password", *change),
            Self::AsTyped => Answer::new("Use the password as typed", "it has no check word"),
            Self::TypeAgain => Answer::new("Type the password again", ""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The index of five dice rolls, as the list orders its words.
    fn index(rolls: &str) -> usize {
        rolls
            .bytes()
            .fold(0, |index, roll| index * 6 + usize::from(roll - b'1'))
    }

    fn drawn(rolls: &str) -> [usize; DRAWN_WORDS] {
        let indexes: Vec<usize> = rolls.split(' ').map(index).collect();
        indexes.try_into().unwrap()
    }

    /// The password of five drawn word indexes and their check word.
    fn password(list: &List, drawn: &[usize; DRAWN_WORDS]) -> String {
        drawn
            .iter()
            .chain(std::iter::once(&check_index(drawn)))
            .map(|&index| list.words[index])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The public vectors of the specification.
    const VECTORS: [(&str, usize, &str); 4] = [
        (
            "11111 11112 11113 11114 11115",
            104,
            "abacus abdomen abdominal abide abiding aids",
        ),
        (
            "66666 66666 66666 66666 66666",
            7739,
            "zoom zoom zoom zoom zoom yelling",
        ),
        (
            "35214 62431 15543 44126 21365",
            4150,
            "jovial trailing chokehold pavilion cresting ninth",
        ),
        (
            "24255 61534 11111 66622 26522",
            5527,
            "drop-down t-shirt abacus yo-yo felt-tip rubble",
        ),
    ];

    #[test]
    fn the_public_vectors_are_reproduced() {
        let list = List::new();
        for (rolls, check, expected) in VECTORS {
            assert_eq!(check_index(&drawn(rolls)), check, "{rolls}");
            assert_eq!(password(&list, &drawn(rolls)), expected);
            assert_eq!(list.read(expected), Reading::Fits);
        }
    }

    /// "In the third row, an erased third word is recovered as chokehold."
    #[test]
    fn the_erased_third_word_of_the_third_vector_is_chokehold() {
        let list = List::new();
        assert_eq!(
            list.read("jovial trailing ? pavilion cresting ninth"),
            Reading::Restored(Repair {
                position: 3,
                typed: "?",
                word: "chokehold"
            })
        );
    }

    #[test]
    fn one_missing_word_is_restored_at_any_place() {
        let list = List::new();
        for (_, _, expected) in VECTORS {
            for position in 0..=DRAWN_WORDS {
                let mut words: Vec<&str> = expected.split(' ').collect();
                words[position] = "unreadable";
                let typed = words.join(" ");
                let Reading::Restored(repair) = list.read(&typed) else {
                    panic!("{expected}, word {position}: not restored");
                };
                assert_eq!(&*repaired(&typed, &repair), expected);
            }
        }
    }

    #[test]
    fn one_wrong_word_leaves_six_repairs_with_the_right_one_among_them() {
        let list = List::new();
        let (_, _, expected) = VECTORS[0];
        let typed = expected.replace("abide", "zoom");
        let Reading::Mismatch(repairs) = list.read(&typed) else {
            panic!("a wrong word was not noticed");
        };
        assert_eq!(repairs.len(), DRAWN_WORDS + 1);
        let right: Vec<&Repair> = repairs
            .iter()
            .filter(|repair| &*repaired(&typed, repair) == expected)
            .collect();
        assert_eq!(
            right,
            [&Repair {
                position: 4,
                typed: "zoom",
                word: "abide"
            }]
        );
        // Every one of the six makes the words fit.
        for repair in &repairs {
            assert_eq!(list.read(&repaired(&typed, repair)), Reading::Fits);
        }
    }

    #[test]
    fn extra_spaces_and_capitals_give_the_written_form() {
        let list = List::new();
        let (form, change) = written_form(" jovial trailing ? pavilion  cresting ninth ").unwrap();
        assert_eq!(&*form, "jovial trailing ? pavilion cresting ninth");
        assert_eq!(change, "extra spaces removed");
        assert!(matches!(
            list.read(&form),
            Reading::Restored(Repair {
                position: 3,
                word: "chokehold",
                ..
            })
        ));
        let (form, change) =
            written_form("JOVIAL Trailing chokehold pavilion cresting ninth").unwrap();
        assert_eq!(&*form, "jovial trailing chokehold pavilion cresting ninth");
        assert_eq!(change, "capitals made small");
        assert_eq!(list.read(&form), Reading::Fits);
        let (_, change) =
            written_form("  Jovial trailing chokehold pavilion cresting ninth").unwrap();
        assert_eq!(change, "spaces and capitals corrected");
        // The written form already: nothing to correct.
        assert!(written_form("jovial trailing chokehold pavilion cresting ninth").is_none());
    }

    #[test]
    fn the_summary_says_what_was_corrected() {
        assert_eq!(
            Outcome::Fits(Some("extra spaces removed")).record("typed"),
            "typed, extra spaces removed; its check word fits"
        );
        assert_eq!(
            Outcome::Repaired(3, Some("extra spaces removed")).record("typed"),
            "typed, word 3 repaired by its check word; extra spaces removed"
        );
        assert_eq!(
            Outcome::Repaired(3, None).record("typed"),
            "typed, word 3 repaired by its check word"
        );
    }

    #[test]
    fn other_passwords_are_left_alone() {
        let list = List::new();
        for typed in [
            "correct horse battery staple",
            "abacus abdomen abdominal abide abiding",
            "abacus  abdomen abdominal abide abiding aids",
            "abacus ? ? abide abiding aids",
            "Abacus abdomen abdominal abide abiding aids extra",
        ] {
            assert_eq!(list.read(typed), Reading::NotThisShape, "{typed}");
        }
        // Words count only as written: "yoyo" and "yo-yo" are different words of the list.
        assert!(matches!(
            list.read("drop-down t-shirt abacus yoyo felt-tip rubble"),
            Reading::Mismatch(_)
        ));
    }
}
