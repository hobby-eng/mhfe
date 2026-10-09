//! The terminal side of the password check word, the optional profile MHFE-PASSWORD-CHECK-1: what
//! to ask when a typed password may have a check word. Reading the password and its repairs is the
//! library's [`mhfe::check_word::PasswordReview`].

use mhfe::check_word::{Correction, PasswordReview, Reading, Repair, ReviewChoice};
use mhfe::memory::LockedText;

use crate::choice::{self, Answer, Question};
use crate::exit::Failure;
use crate::readme;
use crate::terminal::{Input, PrivateScreen};

/// Said where a password is typed, so that a person who forgot a word knows how to get it back:
/// a word left out would make it five words, an ordinary password.
pub const FORGOTTEN_WORD_HINT: &str =
    "If you forgot a word of a password with a check word, type ? in its place.";

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
    let review = PasswordReview::of(&typed);
    let change = review.correction().map(Correction::text);
    match (review.reading(), change) {
        (Reading::NotThisShape, _) => return Ok(Reviewed::Use(typed, Outcome::NotChecked)),
        (Reading::Fits, None) => return Ok(Reviewed::Use(typed, Outcome::Fits(None))),
        _ => {}
    }
    Ok(match decide(input, &review, change)? {
        Decision::Repaired(position) => Reviewed::Use(
            review.apply(ReviewChoice::Repair(position))?,
            Outcome::Repaired(position, change),
        ),
        Decision::Corrected => Reviewed::Use(
            review.apply(ReviewChoice::Corrected)?,
            Outcome::Fits(change),
        ),
        Decision::AsTyped => Reviewed::Use(typed, Outcome::DoesNotFit),
        Decision::TypeAgain => Reviewed::TypeAgain,
    })
}

/// What the person chose for a password that does not simply fit.
enum Decision {
    /// The repair at this place, from 1.
    Repaired(usize),
    /// The written form, which fits.
    Corrected,
    AsTyped,
    TypeAgain,
}

/// Asks what to do with the reviewed password; `change` says how its written form differs from
/// the text typed, if it does.
fn decide(
    input: &mut Input,
    review: &PasswordReview,
    change: Option<&'static str>,
) -> Result<Decision, Failure> {
    let (mut explanation, restore): (Vec<String>, bool) = match review.reading() {
        Reading::Fits => (
            vec!["Once corrected, its six words fit their check word.".to_owned()],
            false,
        ),
        Reading::Restorable => (
            vec![
                "One word is missing or not in the word list. If the password was made".to_owned(),
                "with a check word, the check word restores it.".to_owned(),
            ],
            true,
        ),
        Reading::Mismatch => (
            vec![
                "Its six words do not fit their check word. If it was made with one, one"
                    .to_owned(),
                "word is wrong, and which one cannot be told: compare each answer with".to_owned(),
                "what you wrote down.".to_owned(),
            ],
            false,
        ),
        Reading::NotThisShape => unreachable!("only a password of the profile's shape is asked"),
    };
    let repairs = review.repairs();
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
    let position = if review.repairs_first() {
        0
    } else {
        actions.len()
    };
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
    let answers: Vec<Answer> = actions.iter().map(|action| action.answer(review)).collect();
    let chosen = input.choose_here(&question, &answers)?;
    Ok(match actions[chosen] {
        Action::Restore(repair) | Action::Replace(repair) => Decision::Repaired(repair.position()),
        Action::Correct(_) => Decision::Corrected,
        Action::AsTyped => Decision::AsTyped,
        Action::TypeAgain => Decision::TypeAgain,
    })
}

/// An answer of the question in [`decide`].
enum Action<'r> {
    /// Restore a word that is missing or not in the list.
    Restore(&'r Repair),
    /// Replace a word of the list by another.
    Replace(&'r Repair),
    /// Use the written form, which fits; the value says what it corrects.
    Correct(&'static str),
    AsTyped,
    TypeAgain,
}

impl Action<'_> {
    fn answer(&self, review: &PasswordReview) -> Answer {
        match self {
            // A word outside the list is not repeated: it may be too long for the line.
            Self::Restore(repair) => Answer::new(
                format!("Word {}: {}", repair.position(), repair.word()),
                "restored by the check word",
            ),
            Self::Replace(repair) => Answer::new(
                format!(
                    "Word {}: {} instead of {}",
                    repair.position(),
                    repair.word(),
                    review.typed_word(repair)
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

    /// The hint stays on one line where a password is typed.
    #[test]
    fn the_forgotten_word_hint_fits_one_line() {
        assert!(FORGOTTEN_WORD_HINT.len() <= crate::style::TEXT_WIDTH);
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
}
