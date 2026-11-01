//! Reading seed phrases the way people write them down.

use bip39::Language;
use mhfe_core::{Error, Phrase};

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

/// Reads an English BIP39 phrase. Any spacing and letter case is accepted, and so are the
/// first four or more letters of a word, because many metal backups keep only four letters.
/// The checksum must be valid. `role` is the refusal of what was read, an original phrase or a
/// container, around a reason that gives word positions, never the words.
pub(crate) fn read(input: &str, role: fn(String) -> MhfeError) -> Result<Phrase, MhfeError> {
    Phrase::read(input).map_err(|refused| role(reason(refused)))
}

/// Why [`Phrase::read`] refused a text, as mhfe's refusals say it.
fn reason(refused: Error) -> String {
    match refused {
        Error::InvalidWordCount { words } => format!(
            "it has {words} words, but a phrase has {}",
            word_counts_text()
        ),
        Error::UnknownWord { position } => {
            format!("word {position} is not in the English BIP39 word list")
        }
        Error::InvalidChecksum => {
            "its checksum does not match, so a word is wrong or words are out of order".to_owned()
        }
        // Phrase::read gives only those three, but the core's errors are open to new ones.
        other => other.to_string(),
    }
}

/// Checks an original phrase before anything is computed and returns its word count, so that
/// a tool can ask again at once instead of after a long operation.
pub fn check_phrase(input: &str) -> Result<usize, MhfeError> {
    read_phrase(input).map(|phrase| phrase.words())
}

/// Checks an original phrase and returns it as read: every word written out in full and in lower
/// case, one space apart, so that an application can show the user what it understood.
pub fn read_phrase(input: &str) -> Result<Phrase, MhfeError> {
    read(input, MhfeError::InvalidPhrase)
}

/// Checks a container before anything is computed and returns it as read: every word written
/// out in full and in lower case, one space apart, so a person can compare it with the backup.
pub fn check_container(input: &str) -> Result<String, MhfeError> {
    crate::ContainerFacts::read(input).map(|facts| facts.words().to_owned())
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
        match Phrase::read_word(typed).and_then(word_number) {
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

    /// Why `input` is refused, in mhfe's words.
    fn refused(input: &str) -> String {
        reason(Phrase::read(input).unwrap_err())
    }

    #[test]
    fn accepts_spacing_case_and_four_letter_prefixes() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon abandon abou ";
        assert_eq!(read_phrase(typed).unwrap().as_str(), ZERO_12);
    }

    #[test]
    fn rejects_short_or_ambiguous_prefixes_and_unknown_words() {
        let with_short_prefix = ZERO_12.replacen("abandon", "aba", 1);
        assert_eq!(
            refused(&with_short_prefix),
            "word 1 is not in the English BIP39 word list"
        );
        let with_unknown_word = ZERO_12.replacen("about", "aboutx", 1);
        assert_eq!(
            refused(&with_unknown_word),
            "word 12 is not in the English BIP39 word list"
        );
    }

    #[test]
    fn reports_word_count_and_checksum_problems_without_words() {
        assert_eq!(
            refused("abandon abandon"),
            "it has 2 words, but a phrase has 12, 15, 18, 21 or 24"
        );
        let bad_checksum = ZERO_12.replace("about", "abandon");
        assert_eq!(
            refused(&bad_checksum),
            "its checksum does not match, so a word is wrong or words are out of order"
        );
    }
}
