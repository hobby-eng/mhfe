//! A rough strength estimate of a password the owner typed, made without any dependency. The
//! password is read as the parts people build passwords from: dictionary words, common passwords,
//! years, repeats, runs and keyboard rows, each counting what an attacker who tries such parts must
//! guess, and the remaining characters by their kind. It catches the common weak passwords. It
//! overrates one made of words it does not know, such as names or words of other languages, which
//! the README says. The password is read in place: no copy of it is made.

use std::sync::OnceLock;

use crate::eff::{EffList, MILLIBITS_PER_WORD};

/// About 50 bits, a little under four different dice words (51.7 bits), the least the README
/// recommends: a weaker password gets a warning before it protects a phrase.
pub const WEAK_BELOW_BITS: f64 = 50.0;
/// Only the first 100 characters are read: they tell a weak password from a strong one, and the
/// reading stays quick for a password thousands of characters long.
const READ_CHARACTERS: usize = 100;
/// Shorter dictionary words are not looked for: three letters turn up by chance in random
/// characters too often to tell anything.
const SHORTEST_WORD: usize = 4;
/// log2(200): a year from 1900 to 2099.
const YEAR_BITS: f64 = 7.64;
/// A character that repeats, continues or reverses a run (aaa, 123, cba, qwe), or one that
/// separates two words.
const PATTERN_BITS: f64 = 1.0;
/// Capital letters or substitutions such as 0 for o inside a word.
const VARIATION_BITS: f64 = 1.0;
/// log2 of the kinds of characters: 10 digits, 26 letters, 33 other printable ASCII characters
/// (with the space); a letter of another alphabet counts like the latter.
const DIGIT_BITS: f64 = 3.32;
const LETTER_BITS: f64 = 4.70;
const OTHER_BITS: f64 = 5.04;

/// A few of the passwords and password words most frequent in published leaks that neither word
/// list holds, or holds as rarer words. Each counts as one of these few dozen.
const COMMON: &[&str] = &[
    "password", "passwd", "qwerty", "letmein", "iloveyou", "admin", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "baseball", "soccer", "hockey", "superman",
    "batman", "starwars", "whatever", "freedom", "hello", "login", "secret", "trustno", "michael",
    "jennifer", "jordan", "hunter", "ranger", "buster", "killer", "george", "charlie", "andrew",
    "thomas", "robert", "daniel", "matthew", "jessica", "ashley", "nicole", "pepper", "cookie",
    "flower", "summer", "winter", "love", "angel", "lovely", "family", "money", "computer",
];

/// Substitutions people make for letters, as (character, letter).
const SUBSTITUTIONS: &[(u8, u8)] = &[
    (b'4', b'a'),
    (b'@', b'a'),
    (b'8', b'b'),
    (b'3', b'e'),
    (b'9', b'g'),
    (b'1', b'i'),
    (b'!', b'i'),
    (b'1', b'l'),
    (b'0', b'o'),
    (b'5', b's'),
    (b'$', b's'),
    (b'7', b't'),
    (b'+', b't'),
    (b'2', b'z'),
];

/// The keyboard rows a run can follow, in either direction.
const KEYBOARD_ROWS: &[&[u8]] = &[b"1234567890", b"qwertyuiop", b"asdfghjkl", b"zxcvbnm"];

/// A list of words with the bits a word of it counts.
struct WordList {
    words: Vec<&'static str>,
    bits: f64,
}

impl WordList {
    fn new(mut words: Vec<&'static str>) -> Self {
        words.retain(|word| word.len() >= SHORTEST_WORD);
        words.sort_unstable();
        words.dedup();
        let bits = (words.len() as f64).log2();
        Self { words, bits }
    }
}

/// The estimated strength of a password, in bits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Strength {
    bits: f64,
}

impl Strength {
    /// Estimates `password`. A password of different EFF dice words counts 12.9 bits a word, as if
    /// drawn at random; any other is read part by part.
    pub fn of(password: &str) -> Self {
        Self {
            bits: estimated_bits(password),
        }
    }

    pub fn bits(self) -> f64 {
        self.bits
    }

    /// Whether the password deserves a warning before it protects a phrase.
    pub fn is_weak(self) -> bool {
        self.bits < WEAK_BELOW_BITS
    }
}

fn estimated_bits(password: &str) -> f64 {
    let dice_words = EffList::get().different_dice_words(password);
    if dice_words > 0 {
        return (dice_words * MILLIBITS_PER_WORD) as f64 / 1000.0;
    }
    let end = password
        .char_indices()
        .nth(READ_CHARACTERS)
        .map_or(password.len(), |(index, _)| index);
    read_parts(&password[..end], word_lists())
}

/// The common passwords and the dictionary, sorted once and shared.
fn word_lists() -> &'static [WordList; 2] {
    static LISTS: OnceLock<[WordList; 2]> = OnceLock::new();
    LISTS.get_or_init(|| {
        let mut dictionary = EffList::get().words().to_vec();
        dictionary.extend(bip39::Language::English.word_list());
        [WordList::new(COMMON.to_vec()), WordList::new(dictionary)]
    })
}

/// Adds up the parts of `text` from left to right, taking at each place the longest word of the
/// lists, else a year, else one character.
fn read_parts(text: &str, lists: &[WordList]) -> f64 {
    let bytes = text.as_bytes();
    let mut bits = 0.0;
    let mut at = 0;
    // The previous ASCII character in lower case, for runs; the previous word, for repeats and
    // separators.
    let mut previous: Option<u8> = None;
    let mut previous_word: Option<&str> = None;
    while at < bytes.len() {
        if let Some(word) = longest_word(lists, &bytes[at..]) {
            bits += if previous_word == Some(word.text) {
                PATTERN_BITS
            } else {
                word.bits
            };
            previous_word = Some(word.text);
            previous = None;
            at += word.text.len();
            continue;
        }
        if is_year(&bytes[at..]) {
            bits += YEAR_BITS;
            previous = Some(bytes[at + 3]);
            previous_word = None;
            at += 4;
            continue;
        }
        let character = text[at..]
            .chars()
            .next()
            .expect("the place is a character boundary");
        let ascii = character
            .is_ascii()
            .then(|| (character as u8).to_ascii_lowercase());
        let separator = previous_word.is_some() && matches!(character, ' ' | '-' | '_' | '.');
        bits += match (previous, ascii) {
            _ if separator => PATTERN_BITS,
            (Some(before), Some(now)) if continues(before, now) => PATTERN_BITS,
            _ => character_bits(character),
        };
        if !separator {
            previous_word = None;
        }
        previous = ascii;
        at += character.len_utf8();
    }
    bits
}

/// A word found at the start of the rest of the password, with the bits it counts.
struct Found {
    text: &'static str,
    bits: f64,
}

/// The longest word of the lists that the rest of the password starts with, letter case and
/// substitutions allowed; between words of the same length, the more common one.
fn longest_word(lists: &[WordList], rest: &[u8]) -> Option<Found> {
    let mut best: Option<Found> = None;
    for list in lists {
        for &word in &list.words {
            let Some(varied) = spelled(word.as_bytes(), rest) else {
                continue;
            };
            let bits = list.bits + if varied { VARIATION_BITS } else { 0.0 };
            let better = match &best {
                None => true,
                Some(found) => {
                    word.len() > found.text.len()
                        || (word.len() == found.text.len() && bits < found.bits)
                }
            };
            if better {
                best = Some(Found { text: word, bits });
            }
        }
    }
    best
}

/// Whether `rest` starts with `word`: `Some(true)` when capitals or substitutions spell it.
fn spelled(word: &[u8], rest: &[u8]) -> Option<bool> {
    if rest.len() < word.len() {
        return None;
    }
    let mut varied = false;
    for (&letter, &byte) in word.iter().zip(rest) {
        if byte == letter {
            continue;
        }
        let substituted = SUBSTITUTIONS.contains(&(byte, letter));
        if byte.to_ascii_lowercase() == letter || substituted {
            varied = true;
        } else {
            return None;
        }
    }
    Some(varied)
}

/// A year from 1900 to 2099 at the start of `rest`.
fn is_year(rest: &[u8]) -> bool {
    match rest.get(..4) {
        Some(&[a, b, c, d]) if [a, b, c, d].iter().all(u8::is_ascii_digit) => {
            matches!((a, b), (b'1', b'9') | (b'2', b'0'))
        }
        _ => false,
    }
}

/// Whether `now` repeats `before`, continues or reverses a run of letters or digits, or follows
/// it on a keyboard row.
fn continues(before: u8, now: u8) -> bool {
    let alphanumeric = before.is_ascii_alphanumeric() && now.is_ascii_alphanumeric();
    let same_kind = before.is_ascii_digit() == now.is_ascii_digit();
    if alphanumeric && same_kind && before.abs_diff(now) <= 1 {
        return true;
    }
    KEYBOARD_ROWS.iter().any(|row| {
        row.windows(2)
            .any(|pair| pair == [before, now] || pair == [now, before])
    })
}

fn character_bits(character: char) -> f64 {
    if character.is_ascii_digit() {
        DIGIT_BITS
    } else if character.is_ascii_alphabetic() {
        LETTER_BITS
    } else {
        OTHER_BITS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_weak(bits: f64) -> bool {
        bits < WEAK_BELOW_BITS
    }

    #[test]
    fn common_weak_passwords_are_recognised() {
        for weak in [
            "password",
            "password123",
            "Password2024!",
            "Summer2024!",
            "P@ssw0rd",
            "qwertyuiop",
            "1qaz2wsx3edc",
            "19840101",
            "aaaaaaaaaaaaaaaa",
            "abcdefghijklmnop",
            "dragonmonkey",
            "iloveyou2",
            "Tr0ub4dor&3",
            "abacus zoom yearbook",
            "correct horse battery",
        ] {
            let bits = estimated_bits(weak);
            assert!(is_weak(bits), "{weak}: {bits:.1} bits");
        }
    }

    #[test]
    fn random_characters_and_four_or_more_words_pass() {
        for strong in [
            "Xk7mQ2vR9pLw4tZn",
            "Hq3vNk8wPz2RcY6m",
            "abacus zoom yearbook zipfile",
            "correct horse battery staple",
            "correcthorsebatterystaple",
        ] {
            let bits = estimated_bits(strong);
            assert!(!is_weak(bits), "{strong}: {bits:.1} bits");
        }
        assert!((estimated_bits("abacus zoom yearbook zipfile") - 51.7).abs() < 0.01);
    }

    #[test]
    fn repeated_words_and_runs_add_little() {
        let once = estimated_bits("staple");
        assert!(estimated_bits("staplestaplestaple") < once + 3.0);
        assert!(estimated_bits("123456789") < 12.0);
        assert!(estimated_bits("zyxwvutsrq") < 15.0);
    }

    #[test]
    fn only_the_first_hundred_characters_are_read() {
        let long = "Xk7mQ2vR9pLw4tZn".repeat(256);
        assert!(!is_weak(estimated_bits(&long)));
        let start = std::time::Instant::now();
        estimated_bits(&"a".repeat(4096));
        assert!(start.elapsed().as_secs() < 5);
    }

    #[test]
    fn other_alphabets_count_per_letter() {
        // Twelve Cyrillic letters without a pattern: about 60 bits.
        assert!(!is_weak(estimated_bits("щуклебтжрвзф")));
        assert!(is_weak(estimated_bits("пароль")));
    }
}
