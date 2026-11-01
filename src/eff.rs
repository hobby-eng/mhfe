//! The EFF large wordlist of 7,776 words, one for every roll of five dice, which the password
//! tools draw from: generated passwords, the password check word (MHFE-PASSWORD-CHECK-1) and the
//! strength estimate. The core holds the words, [`EFF_WORDS`]; the rest of what these tools read
//! of the list is here.

use mhfe_core::password_check::EFF_WORDS;
use zeroize::Zeroizing;

/// Words in the list: 6^5, one for every roll of five dice.
pub const LIST_SIZE: usize = EFF_WORDS.len();
/// log2(7776) = 12.925 bits per word, in thousandths, to state strengths without floats.
pub const MILLIBITS_PER_WORD: usize = 12_925;
/// The longest word of the list has nine letters.
pub const LONGEST_WORD: usize = 9;
/// Dice rolled for one word.
const DICE_PER_WORD: usize = 5;

/// The position of `word`, compared exactly as written, hyphens included. A deliberate copy of
/// `index_of` in the core's src/password_check.rs, which keeps it private: a change goes to both.
pub fn index_of(word: &str) -> Option<u16> {
    // The list is in byte order, and every position is below 7,776.
    EFF_WORDS
        .binary_search(&word)
        .ok()
        .map(|index| index as u16)
}

/// How many different words of the list a text has if it consists only of such words, in any
/// ASCII letter case, else 0. A repeated word counts once: "abacus abacus abacus abacus" is one
/// dice word, about 12.9 bits, not four (AUD-005-FUN001). The text is compared in place, so no copy
/// of it is made; the positions found, which reveal it, are wiped.
pub(crate) fn different_dice_words(text: &str) -> usize {
    // Reserved for every token up front, so the list never grows and leaves no unwiped copy.
    let mut found = Zeroizing::new(Vec::with_capacity(text.split_whitespace().count()));
    for token in text.split_whitespace() {
        match EFF_WORDS
            .iter()
            .position(|word| word.eq_ignore_ascii_case(token))
        {
            Some(index) => found.push(index),
            None => return 0,
        }
    }
    found.sort_unstable();
    found.dedup();
    found.len()
}

/// The word index that five dice digits select, read as a number in base 6 in the order of the
/// list; `None` unless the text is exactly five digits from 1 to 6, spaces around allowed.
pub fn index_of_rolls(rolls: &str) -> Option<usize> {
    let digits = rolls.trim().as_bytes();
    if digits.len() != DICE_PER_WORD || !digits.iter().all(|digit| (b'1'..=b'6').contains(digit)) {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0, |index, digit| index * 6 + usize::from(digit - b'1')),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_word_is_found_at_its_place_and_only_as_written() {
        for (index, word) in (0..).zip(EFF_WORDS) {
            assert_eq!(index_of(word), Some(index));
        }
        assert_eq!(EFF_WORDS[0], "abacus");
        assert_eq!(EFF_WORDS[LIST_SIZE - 1], "zoom");
        assert_eq!(index_of("Zoom"), None);
    }

    #[test]
    fn dice_digits_select_the_listed_word() {
        // Words of the specification's public vectors of the check word, and the list's ends.
        for (rolls, word) in [
            ("11111", "abacus"),
            ("35214", "jovial"),
            ("15543", "chokehold"),
            ("24255", "drop-down"),
            ("61534", "t-shirt"),
            ("66622", "yo-yo"),
            ("66666", "zoom"),
        ] {
            assert_eq!(EFF_WORDS[index_of_rolls(rolls).unwrap()], word);
        }
        assert_eq!(index_of_rolls("11111"), Some(0));
        assert_eq!(index_of_rolls(" 66666 "), Some(LIST_SIZE - 1));
        for invalid in ["1111", "111111", "11117", "01111", "abcde"] {
            assert_eq!(index_of_rolls(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn recognises_texts_made_of_dice_words() {
        assert_eq!(different_dice_words("abacus zoom yearbook zipfile"), 4);
        assert_eq!(different_dice_words("Abacus  ZOOM"), 2);
        assert_eq!(different_dice_words("abacus zoom Tr0ub4dor"), 0);
        assert_eq!(different_dice_words(""), 0);
    }

    /// AUD-005-FUN001: a repeated word adds nothing, in any letter case.
    #[test]
    fn a_repeated_dice_word_counts_once() {
        assert_eq!(different_dice_words("abacus abacus abacus abacus"), 1);
        assert_eq!(different_dice_words("abacus ABACUS Abacus zoom"), 2);
        assert_eq!(different_dice_words("abacus zoom abacus zoom yearbook"), 3);
        // Only ASCII letters change case; any other letter makes it a word outside the list.
        assert_eq!(different_dice_words("abacus zo\u{d3}m"), 0);
    }
}
