//! Reading seed phrases the way people write them down.

use std::convert::Infallible;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::memory::LockedText;
use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};
pub(crate) use crate::text::counts_text;
mod error;
pub use error::{PhraseError, PhraseIssue};

/// A validated English BIP39 phrase whose full words are locked before being written and wiped
/// when dropped. Its input spelling is never included in a refusal or diagnostic.
pub struct Phrase {
    words: LockedText,
    word_count: usize,
}

impl Phrase {
    /// Reads full words or unique prefixes of at least four letters, ignoring case and spacing
    /// within [`crate::input_text::InputText::MAX_BYTES`] raw UTF-8 bytes.
    ///
    /// Oversized text returns [`PhraseError::Text`] before scanning or copying. Invalid length,
    /// words or checksum return [`PhraseError::Original`].
    pub fn read(input: &str) -> Result<Self, PhraseError> {
        parse(input).map(Self::of)
    }

    /// Encodes 16 to 32 entropy bytes in steps of four. Other lengths are refused before the
    /// dependency is called; the caller retains ownership of the entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, PhraseError> {
        mnemonic_of(entropy).map(Self::of)
    }

    fn of(mnemonic: Mnemonic) -> Self {
        Self {
            words: locked_phrase_text(&mnemonic),
            word_count: mnemonic.word_count(),
        }
    }

    /// Full lower-case words with one space between them, borrowed without a copy.
    pub fn words(&self) -> &str {
        &self.words
    }

    /// The phrase's BIP39 length in words.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Transfers the locked, wiping text owner without copying its secret buffer.
    pub fn into_words(self) -> LockedText {
        self.words
    }
}

impl std::fmt::Debug for Phrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Phrase { .. }")
    }
}

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

/// Parses an English BIP39 phrase within the raw input byte limit. Any spacing and letter case
/// within that limit is accepted, and so are the
/// first four or more letters of a word, because many metal backups keep only four letters.
/// The checksum must be valid. Error messages give word positions, never the words.
pub(crate) fn parse(input: &str) -> Result<Mnemonic, PhraseError> {
    crate::input_text::InputText::read(input)?;
    let word_count = input.split_whitespace().count();
    if !WORD_COUNTS.contains(&word_count) {
        return Err(PhraseError::Original(PhraseIssue::WordCount(word_count)));
    }

    // Reserved at full size up front, so the phrase is never copied by a reallocation.
    let mut normalized = Zeroizing::new(String::with_capacity(word_count * (LONGEST_WORD + 1)));
    for (position, typed) in input.split_whitespace().enumerate() {
        let word = typed_word(typed).ok_or(PhraseError::Original(PhraseIssue::UnknownWord(
            position + 1,
        )))?;
        if position > 0 {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }

    Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|error| {
        PhraseError::Original(match error {
            bip39::Error::InvalidChecksum => PhraseIssue::Checksum,
            _ => PhraseIssue::UnexpectedEncoding,
        })
    })
}

/// Parses a container: a valid phrase of 24 words (suite 3) or of 12, 15, 18 or 21 words
/// (suite 4, the same-length containers), which [`crate::Suite::of_container`] tells apart.
pub(crate) fn parse_container(input: &str) -> Result<Mnemonic, PhraseError> {
    parse(input).map_err(PhraseError::as_container)
}

/// Checks an original phrase before anything is computed and returns its word count, so that
/// a tool can ask again at once instead of after a long operation.
pub(crate) fn check_phrase(input: &str) -> Result<usize, PhraseError> {
    parse(input).map(|phrase| phrase.word_count())
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

/// Count the canonical text before allocating it: the owner can transfer this exact buffer
/// instead of making a second, shorter secret copy in `OriginalFacts`.
fn text_capacity(phrase: &Mnemonic) -> usize {
    phrase.words().map(str::len).sum::<usize>() + phrase.word_count() - 1
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
/// entropy, as `mhfe new` does. Another length is refused with `INTERNAL_ERROR` before entering the BIP39 dependency.
pub(crate) fn phrase_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, PhraseError> {
    Ok(phrase_text(&mnemonic_of(entropy)?))
}

/// [`phrase_from_entropy`] in a buffer that is locked before the words are written into it.
pub(crate) fn locked_phrase_from_entropy(entropy: &[u8]) -> Result<LockedText, PhraseError> {
    Ok(locked_phrase_text(&mnemonic_of(entropy)?))
}

/// Guards a byte count before any multiplication or dependency call. The public raw-entropy
/// entry and the wallet criterion share it, including on 32-bit WebAssembly.
pub(crate) fn require_entropy_length(bytes: usize) -> Result<(), PhraseError> {
    if WORD_COUNTS
        .into_iter()
        .any(|words| crate::packing::entropy_of_words(words) == bytes)
    {
        Ok(())
    } else {
        Err(PhraseError::EntropyLength(bytes))
    }
}

pub(crate) fn mnemonic_of(entropy: &[u8]) -> Result<Mnemonic, PhraseError> {
    require_entropy_length(entropy.len())?;
    Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| PhraseError::EntropyEncoding)
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

/// The list word that one word as typed stands for: in any case of ASCII letters, four letters of
/// it enough. The lower-case copy, part of a secret phrase, is wiped. Unicode case is not folded:
/// a sign such as U+212A KELVIN SIGN is no letter of the list, in a phrase or in a wish
/// (AUD-024-FUN012).
pub(crate) fn typed_word(typed: &str) -> Option<&'static str> {
    // Every accepted full word or prefix fits the longest ASCII list word. Refuse before
    // allocating a lower-case secret copy, including for an enormous token from a caller.
    if typed.len() > LONGEST_WORD {
        return None;
    }
    complete_word(&Zeroizing::new(typed.to_ascii_lowercase()))
}

/// The word numbers of `text` as typed, each word completed from four letters in any case, and the
/// positions, from 0, that are unreadable: `?` or not a word of the list. An unreadable word stands
/// as 0 until it is repaired or found. More than [`STATE_WORDS`] tokens fail before allocation;
/// both returned exact-capacity owners wipe their numbers and positions on drop.
pub(crate) fn word_numbers(text: &str) -> Result<IndexedWords, PhraseError> {
    let count = text.split_whitespace().count();
    if count > STATE_WORDS {
        return Err(PhraseError::Container(PhraseIssue::WordCount(count)));
    }
    let mut numbers = Zeroizing::new(Vec::with_capacity(count));
    let mut unreadable = Zeroizing::new(Vec::with_capacity(count));
    for (position, typed) in text.split_whitespace().enumerate() {
        match typed_word(typed).and_then(word_number) {
            Some(number) => numbers.push(number),
            None => {
                numbers.push(0);
                unreadable.push(position);
            }
        }
    }
    Ok((numbers, unreadable))
}

/// Wiping word numbers and their unreadable positions, both allocated at the validated token count.
type IndexedWords = (Zeroizing<Vec<u16>>, Zeroizing<Vec<usize>>);

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
    let mut text = String::with_capacity(numbers.len() * (LONGEST_WORD + 1));
    for &number in numbers {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(word(number));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_12: &str = crate::test_support::ABANDON_12;

    #[test]
    fn accepts_spacing_case_and_four_letter_prefixes() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon abandon abou ";
        assert_eq!(parse(typed).unwrap().to_string(), ZERO_12);
        let phrase = Phrase::read(typed).unwrap();
        assert_eq!(phrase.words(), ZERO_12);
        assert_eq!(phrase.word_count(), 12);
    }

    #[test]
    fn phrase_readers_bound_raw_utf8_before_ignoring_whitespace() {
        let maximum = crate::input_text::InputText::MAX_BYTES;
        for size in [maximum - 1, maximum, maximum + 1] {
            for whitespace in [" ", "\u{2003}"] {
                let extra = size - ZERO_12.len();
                let padding = format!(
                    "{}{}",
                    whitespace.repeat(extra / whitespace.len()),
                    " ".repeat(extra % whitespace.len())
                );
                for text in [
                    format!("{padding}{ZERO_12}"),
                    ZERO_12.replacen(' ', &format!(" {padding}"), 1),
                ] {
                    assert_eq!(text.len(), size);
                    let results = [
                        Phrase::read(&text)
                            .map(|facts| facts.words() == ZERO_12)
                            .map_err(|error| error.error_code()),
                        crate::OriginalFacts::read(&text)
                            .map(|facts| facts.words() == ZERO_12)
                            .map_err(|error| error.error_code()),
                        crate::ContainerFacts::read(&text)
                            .map(|facts| facts.words() == ZERO_12)
                            .map_err(|error| error.error_code()),
                    ];
                    for result in results {
                        assert_eq!(
                            result,
                            if size <= maximum {
                                Ok(true)
                            } else {
                                Err(crate::ErrorCode::InvalidRequest)
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn raw_size_refusals_preserve_the_typed_cause_without_repeating_input() {
        let marker = "synthetic-private-marker";
        let text = format!(
            "{marker}{}",
            " ".repeat(crate::input_text::InputText::MAX_BYTES)
        );
        let size = crate::input_text::TextSizeError::TooLong { bytes: text.len() };
        let error = Phrase::read(&text).unwrap_err();
        assert_eq!(error, PhraseError::Text(size));
        assert_eq!(error.as_container(), error);
        assert_eq!(error.to_string(), size.to_string());
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            size.to_string()
        );
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
    }

    #[test]
    fn a_phrase_transfers_its_locked_buffer_without_exposing_it_in_debug() {
        // Trezor's BIP39 all-zero 128-bit vector is an independent literal answer.
        let phrase = Phrase::from_entropy(&[0; 16]).unwrap();
        assert_eq!(phrase.words(), ZERO_12);
        assert_eq!(phrase.word_count(), 12);
        assert_eq!(format!("{phrase:?}"), "Phrase { .. }");
        let address = phrase.words().as_ptr();
        let words = phrase.into_words();
        assert_eq!(
            words.as_ptr(),
            address,
            "transferring ownership makes no secret copy"
        );
        assert_eq!(&*words, ZERO_12);
    }

    #[test]
    fn the_phrase_owner_refuses_invalid_input_without_repeating_it() {
        for (input, issue) in [
            (
                "synthetic-private-marker".to_owned(),
                PhraseIssue::WordCount(1),
            ),
            (
                ZERO_12.replacen("about", "synthetic-private-marker", 1),
                PhraseIssue::UnknownWord(12),
            ),
            (ZERO_12.replace("about", "abandon"), PhraseIssue::Checksum),
        ] {
            let error = Phrase::read(&input).unwrap_err();
            assert_eq!(error, PhraseError::Original(issue));
            assert_eq!(error.code(), "INVALID_PHRASE");
            assert!(!error.to_string().contains("synthetic-private-marker"));
        }
        for bytes in [0, 15, 17, 31, 33] {
            assert_eq!(
                Phrase::from_entropy(&vec![0; bytes]).unwrap_err(),
                PhraseError::EntropyLength(bytes)
            );
        }
    }

    #[test]
    fn an_overlong_word_is_refused_without_echoing_it() {
        let maximum = crate::input_text::InputText::MAX_BYTES;
        for length in [
            LONGEST_WORD + 1,
            maximum - ZERO_12.len() + "about".len(),
            100_000,
        ] {
            let token = "X".repeat(length);
            let input = ZERO_12.replacen("about", &token, 1);
            let error = Phrase::read(&input).unwrap_err();
            if input.len() > maximum {
                assert_eq!(
                    error,
                    PhraseError::Text(crate::input_text::TextSizeError::TooLong {
                        bytes: input.len()
                    })
                );
                assert_eq!(error.code(), "INVALID_REQUEST");
            } else {
                assert_eq!(error, PhraseError::Original(PhraseIssue::UnknownWord(12)));
                assert_eq!(error.code(), "INVALID_PHRASE");
            }
            assert!(!error.to_string().contains(&token));
        }
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
                assert_eq!(text.capacity(), text.len(), "{words} words");
            }
        }
        let read = Phrase::read(ZERO_12).unwrap().into_words();
        assert_eq!(read.capacity(), ZERO_12.len());
        // AUD-008-SEC002: the public formatter, with the BIP39 vector 7f…7f.
        let new = phrase_from_entropy(&[0x7f; 32]).unwrap();
        assert!(new.starts_with("legal winner thank year"));
        assert_eq!(new.capacity(), new.len());
        // The locked form that a new or recovered phrase is written into: the same words, in a
        // buffer of the same size that was locked first.
        let locked = locked_phrase_from_entropy(&[0x7f; 32]).unwrap();
        assert_eq!(&*locked, &*new);
        assert_eq!(locked.capacity(), new.len());
        assert_eq!(locked.is_locked(), cfg!(any(unix, windows)));
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
    fn entropy_lengths_are_checked_without_multiplication_or_allocating_the_input() {
        for bytes in [0, 1, 15, 17, 31, 33, usize::MAX / 8 + 1, usize::MAX] {
            assert_eq!(
                require_entropy_length(bytes),
                Err(PhraseError::EntropyLength(bytes))
            );
        }
        for words in WORD_COUNTS {
            let bytes = crate::packing::entropy_of_words(words);
            assert_eq!(require_entropy_length(bytes), Ok(()));
            assert_eq!(mnemonic_of(&vec![0; bytes]).unwrap().word_count(), words);
        }
    }

    #[test]
    fn rejects_short_or_ambiguous_prefixes_and_unknown_words() {
        let with_short_prefix = ZERO_12.replacen("abandon", "aba", 1);
        assert_eq!(
            parse(&with_short_prefix).unwrap_err(),
            PhraseError::Original(PhraseIssue::UnknownWord(1))
        );
        let with_unknown_word = ZERO_12.replacen("about", "aboutx", 1);
        assert_eq!(
            parse(&with_unknown_word).unwrap_err(),
            PhraseError::Original(PhraseIssue::UnknownWord(12))
        );
    }

    #[test]
    fn reports_word_count_and_checksum_problems_without_words() {
        assert_eq!(
            parse("abandon abandon").unwrap_err(),
            PhraseError::Original(PhraseIssue::WordCount(2))
        );
        let bad_checksum = ZERO_12.replace("about", "abandon");
        assert_eq!(
            parse(&bad_checksum).unwrap_err(),
            PhraseError::Original(PhraseIssue::Checksum)
        );
        // A 12-word phrase is a same-length container; which suite applies is decided later.
        assert_eq!(parse_container(ZERO_12).unwrap().word_count(), 12);
    }
}
