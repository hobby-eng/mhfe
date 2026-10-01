//! Reading recovery phrases the way people write them down.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::MhfeError;

/// Word counts of a BIP39 phrase.
pub const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];
/// The longest English BIP39 word has eight letters.
const LONGEST_WORD: usize = 8;
/// Shortest typed prefix that is expanded: the English list is unique in its first four letters.
const PREFIX_LETTERS: usize = 4;

/// Parses an English BIP39 phrase. Any spacing and letter case is accepted, and so are the
/// first four or more letters of a word, because many metal backups keep only four letters.
/// The checksum must be valid. Error messages give word positions, never the words.
pub fn parse(input: &str) -> Result<Mnemonic, String> {
    let word_count = input.split_whitespace().count();
    if !WORD_COUNTS.contains(&word_count) {
        return Err(format!(
            "it has {word_count} words, but a phrase has 12, 15, 18, 21 or 24"
        ));
    }

    // Reserved at full size up front, so the phrase is never copied by a reallocation.
    let mut normalized = Zeroizing::new(String::with_capacity(word_count * (LONGEST_WORD + 1)));
    for (position, typed) in input.split_whitespace().enumerate() {
        let lowercase = Zeroizing::new(typed.to_ascii_lowercase());
        let word = complete_word(&lowercase).ok_or_else(|| {
            format!(
                "word {} is not in the English BIP39 word list",
                position + 1
            )
        })?;
        if position > 0 {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }

    Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|error| match error {
        bip39::Error::InvalidChecksum => {
            "its checksum does not match, so a word is wrong or words are out of order".to_owned()
        }
        other => other.to_string(),
    })
}

/// Parses a container: a valid phrase of exactly 24 words.
pub fn parse_container(input: &str) -> Result<Mnemonic, String> {
    let container = parse(input)?;
    match container.word_count() {
        24 => Ok(container),
        other => Err(format!(
            "it has {other} words, but a container always has 24"
        )),
    }
}

/// Checks an original phrase before anything is computed and returns its word count, so that
/// a tool can ask again at once instead of after a long operation.
pub fn check_phrase(input: &str) -> Result<usize, MhfeError> {
    parse(input)
        .map(|phrase| phrase.word_count())
        .map_err(MhfeError::InvalidPhrase)
}

/// Checks an original phrase and returns it as read: every word written out in full and in lower
/// case, one space apart, so that an application can show the user what it understood.
pub fn read_phrase(input: &str) -> Result<Zeroizing<String>, MhfeError> {
    parse(input)
        .map(|phrase| phrase_text(&phrase))
        .map_err(MhfeError::InvalidPhrase)
}

/// The words of a phrase, one space apart, in a buffer that is wiped when dropped. It is reserved
/// at its final size and never grows: `Mnemonic::to_string` writes into a growing string instead,
/// and every growth would leave an unwiped copy of the first words in freed memory.
pub(crate) fn phrase_text(phrase: &Mnemonic) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(
        phrase.word_count() * (LONGEST_WORD + 1),
    ));
    for (position, word) in phrase.words().enumerate() {
        if position > 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
    text
}

/// Checks a container before anything is computed and returns it as read: every word written
/// out in full and in lower case, one space apart, so a person can compare it with the backup.
pub fn check_container(input: &str) -> Result<String, MhfeError> {
    parse_container(input)
        .map(|container| container.to_string())
        .map_err(MhfeError::InvalidContainer)
}

/// A word of the English list, or the only word that starts with the typed letters when at
/// least four were typed.
fn complete_word(typed: &str) -> Option<&'static str> {
    let english = Language::English;
    if let Some(index) = english.find_word(typed) {
        return Some(english.word_list()[usize::from(index)]);
    }
    if typed.len() < PREFIX_LETTERS {
        return None;
    }
    let mut candidates = english.words_by_prefix_iter(typed);
    match (candidates.next(), candidates.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn accepts_spacing_case_and_four_letter_prefixes() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon abandon abou ";
        assert_eq!(parse(typed).unwrap().to_string(), ZERO_12);
        assert_eq!(*read_phrase(typed).unwrap(), ZERO_12);
    }

    /// AUD-005-SEC001: the text of a phrase is written into its reserved buffer without a
    /// reallocation, which would leave an unwiped copy of the first words in freed memory.
    #[test]
    fn phrase_text_never_outgrows_its_buffer() {
        for words in WORD_COUNTS {
            let bytes = words / 3 * 4;
            // Varied public entropy, so that the phrases include words of every length.
            for seed in 0u8..64 {
                let entropy: Vec<u8> = (0..bytes)
                    .map(|index| {
                        (index as u8)
                            .wrapping_mul(97)
                            .wrapping_add(seed.wrapping_mul(53))
                    })
                    .collect();
                let phrase = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
                let text = phrase_text(&phrase);
                assert_eq!(*text, phrase.to_string());
                assert_eq!(text.capacity(), words * (LONGEST_WORD + 1), "{words} words");
            }
        }
        let read = read_phrase(ZERO_12).unwrap();
        assert_eq!(read.capacity(), 12 * (LONGEST_WORD + 1));
    }

    #[test]
    fn an_exact_word_comes_before_a_prefix() {
        // "act" is a word and also begins action, actor, actress and actual.
        assert_eq!(complete_word("act"), Some("act"));
        assert_eq!(complete_word("acti"), Some("action"));
        assert_eq!(complete_word("acto"), Some("actor"));
        assert_eq!(complete_word("actr"), Some("actress"));
        assert_eq!(complete_word("actu"), Some("actual"));
        assert_eq!(complete_word("ac"), None);
    }

    #[test]
    fn four_letters_identify_every_word_and_only_three_letter_words_begin_others() {
        let words = Language::English.word_list();
        let mut first_four: Vec<&str> = words
            .iter()
            .map(|word| &word[..4.min(word.len())])
            .collect();
        first_four.sort_unstable();
        first_four.dedup();
        assert_eq!(first_four.len(), words.len());

        let prefixes: Vec<&str> = words
            .iter()
            .copied()
            .filter(|word| {
                words
                    .iter()
                    .any(|other| other != word && other.starts_with(word))
            })
            .collect();
        assert_eq!(prefixes.len(), 49);
        assert!(prefixes.iter().all(|word| word.len() == 3));
        for word in prefixes {
            assert_eq!(complete_word(word), Some(word));
        }
    }

    #[test]
    fn rejects_short_or_ambiguous_prefixes_and_unknown_words() {
        let with_short_prefix = ZERO_12.replacen("abandon", "aba", 1);
        assert_eq!(
            parse(&with_short_prefix).unwrap_err(),
            "word 1 is not in the English BIP39 word list"
        );
        let with_unknown_word = ZERO_12.replacen("about", "aboutx", 1);
        assert_eq!(
            parse(&with_unknown_word).unwrap_err(),
            "word 12 is not in the English BIP39 word list"
        );
    }

    #[test]
    fn reports_word_count_and_checksum_problems_without_words() {
        assert_eq!(
            parse("abandon abandon").unwrap_err(),
            "it has 2 words, but a phrase has 12, 15, 18, 21 or 24"
        );
        let bad_checksum = ZERO_12.replace("about", "abandon");
        assert_eq!(
            parse(&bad_checksum).unwrap_err(),
            "its checksum does not match, so a word is wrong or words are out of order"
        );
        assert_eq!(
            parse_container(ZERO_12).unwrap_err(),
            "it has 12 words, but a container always has 24"
        );
    }
}
