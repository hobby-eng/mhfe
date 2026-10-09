//! Reading seed phrases the way people write them down.

use std::convert::Infallible;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::memory::LockedText;
use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};
use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-repair",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;

/// Word counts of a BIP39 phrase.
pub const WORD_COUNTS: [usize; 5] = [
    SHORT_WORD_COUNTS[0],
    SHORT_WORD_COUNTS[1],
    SHORT_WORD_COUNTS[2],
    SHORT_WORD_COUNTS[3],
    STATE_WORDS,
];
/// The bits of a word's number in the list (BIP39).
pub(crate) const WORD_BITS: usize = 11;
/// The words of the English list: 2^11.
pub(crate) const LIST_SIZE: u16 = 1 << WORD_BITS;
/// The longest English BIP39 word has eight letters.
pub(crate) const LONGEST_WORD: usize = 8;
/// Shortest typed prefix that is expanded: the English list is unique in its first four letters.
const PREFIX_LETTERS: usize = 4;

/// Parses an English BIP39 phrase. Any spacing and letter case is accepted, and so are the
/// first four or more letters of a word, because many metal backups keep only four letters.
/// The checksum must be valid. Error messages give word positions, never the words.
pub fn parse(input: &str) -> Result<Mnemonic, String> {
    let word_count = input.split_whitespace().count();
    if !WORD_COUNTS.contains(&word_count) {
        return Err(format!(
            "it has {word_count} words, but a phrase has {}",
            word_counts_text()
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

/// Parses a container: a valid phrase of 24 words (suite 3) or of 12, 15, 18 or 21 words
/// (suite 4, the same-length containers), which [`crate::Suite::of_container`] tells apart.
pub fn parse_container(input: &str) -> Result<Mnemonic, String> {
    parse(input)
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
    let mut text = Zeroizing::new(String::with_capacity(text_capacity(phrase)));
    write_words(phrase, &mut text);
    text
}

/// [`phrase_text`] in a buffer that is locked before the words are written into it, for a phrase
/// that a long operation holds, such as a recovered one or a new one.
pub(crate) fn locked_phrase_text(phrase: &Mnemonic) -> LockedText {
    let Ok(text) = LockedText::build::<Infallible>(text_capacity(phrase), |text| {
        write_words(phrase, text);
        Ok(())
    });
    text
}

/// The final size of the text of `phrase`: each word with at most eight letters and a space.
fn text_capacity(phrase: &Mnemonic) -> usize {
    phrase.word_count() * (LONGEST_WORD + 1)
}

fn write_words(phrase: &Mnemonic, text: &mut String) {
    for (position, word) in phrase.words().enumerate() {
        if position > 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
}

/// The English BIP39 phrase of `entropy`, 16 to 32 bytes in steps of four, written into a buffer
/// that is reserved at its final size and wiped when dropped, so that no growing copy of the words
/// is left in freed memory (AUD-005-SEC001, AUD-008-SEC002). For a program that draws its own
/// entropy, as `mhfe new` does. Another length is a programming error: `MhfeError::Internal`.
pub fn phrase_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, MhfeError> {
    Ok(phrase_text(&mnemonic_of(entropy)?))
}

/// [`phrase_from_entropy`] in a buffer that is locked before the words are written into it.
pub(crate) fn locked_phrase_from_entropy(entropy: &[u8]) -> Result<LockedText, MhfeError> {
    Ok(locked_phrase_text(&mnemonic_of(entropy)?))
}

fn mnemonic_of(entropy: &[u8]) -> Result<Mnemonic, MhfeError> {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|error| MhfeError::Internal(error.to_string()))
}

/// Checks a container before anything is computed and returns it as read: every word written
/// out in full and in lower case, one space apart, so a person can compare it with the backup.
pub fn check_container(input: &str) -> Result<String, MhfeError> {
    crate::ContainerFacts::read(input).map(|facts| facts.words().to_owned())
}

/// A word of the English list, or the only word that starts with the typed letters when at
/// least four were typed.
pub(crate) fn complete_word(typed: &str) -> Option<&'static str> {
    let english = Language::English;
    if let Some(number) = english.find_word(typed) {
        return Some(word(number));
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

/// The word counts of a BIP39 phrase as a message lists them: "12, 15, 18, 21 or 24".
pub(crate) fn word_counts_text() -> String {
    counts_text(&WORD_COUNTS)
}

/// Word counts as a message lists them, the last after "or": "12, 15, 18 or 21".
pub(crate) fn counts_text(counts: &[usize]) -> String {
    let counts: Vec<String> = counts.iter().map(ToString::to_string).collect();
    match counts.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

/// The word numbers of `text` as typed, each word completed from four letters in any case, and the
/// positions, from 0, that are unreadable: `?` or not a word of the list. An unreadable word stands
/// as 0 until it is repaired or found.
pub(crate) fn word_numbers(text: &str) -> (Vec<u16>, Vec<usize>) {
    let mut numbers = Vec::new();
    let mut unreadable = Vec::new();
    for (position, typed) in text.split_whitespace().enumerate() {
        match complete_word(&typed.to_ascii_lowercase()).and_then(word_number) {
            Some(number) => numbers.push(number),
            None => {
                numbers.push(0);
                unreadable.push(position);
            }
        }
    }
    (numbers, unreadable)
}

/// The number of a word of the English list.
pub(crate) fn word_number(word: &str) -> Option<u16> {
    Language::English.find_word(word)
}

/// The word of the English list with `number`.
pub(crate) fn word(number: u16) -> &'static str {
    Language::English.word_list()[usize::from(number)]
}

/// The number of word `index` of the phrase whose entropy and checksum are `bits`, read as BIP39
/// writes it: 11 bits each, the first bit the highest.
pub(crate) fn number_at(bits: &[u8], index: usize) -> u16 {
    (0..WORD_BITS).fold(0, |number, bit| {
        let at = index * WORD_BITS + bit;
        (number << 1) | u16::from(bits[at / 8] >> (7 - at % 8) & 1)
    })
}

/// Writes the `count` lowest bits of `value` into `bits` from bit `start` on, the highest first,
/// as BIP39 writes a word's number; the bits around them stay as they are.
pub(crate) fn write_bits(bits: &mut [u8], start: usize, count: usize, value: u16) {
    for offset in 0..count {
        let at = start + offset;
        let mask = 0x80 >> (at % 8);
        if value >> (count - 1 - offset) & 1 == 1 {
            bits[at / 8] |= mask;
        } else {
            bits[at / 8] &= !mask;
        }
    }
}

/// The words of `numbers`, one space apart.
pub(crate) fn words_of(numbers: &[u16]) -> String {
    numbers
        .iter()
        .map(|&number| word(number))
        .collect::<Vec<_>>()
        .join(" ")
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
            let bytes = crate::packing::entropy_of_words(words);
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
        // AUD-008-SEC002: the public formatter, with the BIP39 vector 7f…7f.
        let new = phrase_from_entropy(&[0x7f; 32]).unwrap();
        assert!(new.starts_with("legal winner thank year"));
        assert_eq!(new.capacity(), 24 * (LONGEST_WORD + 1));
        // The locked form that a new or recovered phrase is written into: the same words, in a
        // buffer of the same size that was locked first.
        let locked = locked_phrase_from_entropy(&[0x7f; 32]).unwrap();
        assert_eq!(&*locked, &*new);
        assert_eq!(locked.capacity(), 24 * (LONGEST_WORD + 1));
        assert_eq!(locked.is_locked(), cfg!(unix));
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
        // A 12-word phrase is a same-length container; which suite applies is decided later.
        assert_eq!(parse_container(ZERO_12).unwrap().word_count(), 12);
    }
}
