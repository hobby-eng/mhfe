//! The length of the original seed phrase as the commands that recover it take it: a word count,
//! or detected after the recovery (`PhraseLength::Detect`, the library's detection). `--words`
//! takes the same values, and the question about the length offers detection as its last answer.

use mhfe::{PhraseLength, WordCount, WORD_COUNTS};

use crate::choice::{Answer, Question};
use crate::exit::Failure;
use crate::terminal::Input;

/// The value of `--words` that detects the length.
pub const AUTO: &str = "auto";

/// Reads `--words`: a word count, or "auto" to detect the length; 0 detects it too, as in the
/// browser package (the library's [`PhraseLength::from_count`]).
pub fn parse(text: &str) -> Result<PhraseLength, String> {
    if text.eq_ignore_ascii_case(AUTO) {
        return Ok(PhraseLength::Detect);
    }
    let words: usize = text
        .parse()
        .map_err(|_| format!("expected a word count or {AUTO}"))?;
    PhraseLength::from_count(words).map_err(|error| error.to_string())
}

/// The word counts of an original seed phrase as help lists them: "12, 15, 18, 21, 24".
pub fn length_list() -> String {
    let counts: Vec<String> = WORD_COUNTS.iter().map(ToString::to_string).collect();
    counts.join(", ")
}

/// The question about the length, in every command that asks it.
const LENGTH_ASKED: &str = "How many words does your original seed phrase have?";

/// An answer for each of `lengths`.
fn length_answers(lengths: &[usize]) -> Vec<Answer> {
    lengths
        .iter()
        .map(|words| Answer::new(format!("{words} words"), ""))
        .collect()
}

/// The answers to the question about the length: each of `lengths`, then detection, with `misses`
/// saying in a few words what it may not find.
fn answers(lengths: &[usize], misses: &str) -> Vec<Answer> {
    let mut answers = length_answers(lengths);
    answers.push(Answer::new("Detect automatically", misses));
    answers
}

/// Asks how many words the original seed phrase has, among `lengths` or detected; `misses` as for
/// [`answers`], and `record` the summary's label of the answer.
pub fn ask(
    input: &mut Input,
    lengths: &[usize],
    misses: &str,
    record: &'static str,
) -> Result<PhraseLength, Failure> {
    let answers = answers(lengths, misses);
    let question = Question::new(LENGTH_ASKED, record);
    let chosen = input.choose(&question, &answers)?;
    match lengths.get(chosen) {
        Some(&words) => Ok(PhraseLength::Words(WordCount::new(words)?)),
        None => Ok(PhraseLength::Detect),
    }
}

/// Asks the length among `lengths` alone, once detection could not settle it: `explanation` says
/// why, over the question.
/// The warning that the built-in check found another length than the one stated, which takes
/// precedence (the length rules of recovery): one wording for every command (AUD-017-ARC001).
pub fn check_finds(found: usize, stated: usize) -> String {
    format!("The built-in check finds {found} words, not the {stated} you gave.")
}

/// Why the check takes precedence, said after [`check_finds`].
pub const MORE_RELIABLE: &str = "A check that passes is far more reliable than memory";

pub fn ask_stated(
    input: &mut Input,
    lengths: &[usize],
    explanation: &[&str],
    record: &'static str,
) -> Result<WordCount, Failure> {
    let question = Question {
        text: LENGTH_ASKED,
        explanation,
        more: None,
        record: Some(record),
    };
    let chosen = input.choose(&question, &length_answers(lengths))?;
    Ok(WordCount::new(lengths[chosen])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::choice;

    #[test]
    fn auto_or_a_word_count_is_read() {
        assert_eq!(parse("auto"), Ok(PhraseLength::Detect));
        assert_eq!(parse("AUTO"), Ok(PhraseLength::Detect));
        // 0 as in the browser package.
        assert_eq!(parse("0"), Ok(PhraseLength::Detect));
        assert_eq!(
            parse("15"),
            Ok(PhraseLength::Words(WordCount::new(15).unwrap()))
        );
        assert!(parse("13").is_err());
        assert!(parse("twelve").is_err());
    }

    /// Every list of the commands shows whole, its note on detection included.
    #[test]
    fn the_lists_show_whole() {
        for (lengths, misses) in [
            (&[12, 15, 18, 21, 24][..], crate::rekey::DETECTION_MISSES),
            (&[12, 15, 18, 21][..], crate::check::DETECTION_MISSES),
        ] {
            assert!(choice::answers_fit(&answers(lengths, misses)));
        }
    }
}
