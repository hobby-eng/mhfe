//! The EFF large wordlist of 7,776 words, one for every roll of five dice, which the password
//! tools draw from: generated passwords, the password check word (MHFE-PASSWORD-CHECK-1) and the
//! strength estimate.

use std::collections::HashMap;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::MhfeError;

/// The EFF large wordlist, unchanged: "11111<TAB>abacus" to "66666<TAB>zoom", one per line.
/// Provenance and licence: vendor/eff-large-wordlist.md.
pub(crate) const EFF_LIST: &str =
    include_str!("../vendor/eff-large-wordlist/eff_large_wordlist.txt");
/// Words in the list: 6^5, one for every roll of five dice.
pub const LIST_SIZE: usize = 7776;
/// log2(7776) = 12.925 bits per word, in thousandths, to state strengths without floats.
pub const MILLIBITS_PER_WORD: usize = 12_925;
/// The longest word of the list has nine letters.
pub const LONGEST_WORD: usize = 9;
/// Dice rolled for one word.
const DICE_PER_WORD: usize = 5;

/// The list in dice order, with each word's position for exact lookups. It is read from the
/// vendored file once and shared.
pub struct EffList {
    words: Vec<&'static str>,
    index: HashMap<&'static str, usize>,
}

impl EffList {
    /// The list, read on first use. The self-check of the password check word reads it with
    /// [`EffList::try_get`] at every start, so that a damaged list stops the program there with a
    /// clear error instead of here.
    pub fn get() -> &'static EffList {
        Self::try_get().expect("the vendored EFF list is complete")
    }

    /// The list, read on first use, or [`MhfeError::Internal`] when the vendored file is damaged.
    pub fn try_get() -> Result<&'static EffList, MhfeError> {
        static LIST: OnceLock<Result<EffList, &'static str>> = OnceLock::new();
        LIST.get_or_init(|| EffList::read(EFF_LIST))
            .as_ref()
            .map_err(|reason| MhfeError::Internal((*reason).to_owned()))
    }

    /// Reads a list in the vendored file's form: dice digits, a tab and a word on every line.
    fn read(text: &'static str) -> Result<Self, &'static str> {
        let mut words = Vec::with_capacity(LIST_SIZE);
        for line in text.lines() {
            let word = line
                .split('\t')
                .nth(1)
                .ok_or("a line of the vendored EFF list holds no word")?;
            words.push(word);
        }
        if words.len() != LIST_SIZE {
            return Err("the vendored EFF list is incomplete");
        }
        let index: HashMap<&'static str, usize> = words
            .iter()
            .enumerate()
            .map(|(position, &word)| (word, position))
            .collect();
        if index.len() != LIST_SIZE {
            return Err("the vendored EFF list holds a word twice");
        }
        Ok(Self { words, index })
    }

    /// The 7,776 words in dice order.
    pub fn words(&self) -> &[&'static str] {
        &self.words
    }

    /// The word at `index`, below [`LIST_SIZE`].
    pub fn word(&self, index: usize) -> &'static str {
        self.words[index]
    }

    /// The position of `word`, compared exactly as written, hyphens included.
    pub fn index_of(&self, word: &str) -> Option<usize> {
        self.index.get(word).copied()
    }

    /// How many different words of the list a text has if it consists only of such words, in
    /// any ASCII letter case, else 0. A repeated word counts once: "abacus abacus abacus abacus"
    /// is one dice word, about 12.9 bits, not four (AUD-005-FUN001). The text is compared in
    /// place, so no copy of it is made; the positions found, which reveal it, are wiped.
    pub fn different_dice_words(&self, text: &str) -> usize {
        // Reserved for every token up front, so the list never grows and leaves no unwiped copy.
        let mut found = Zeroizing::new(Vec::with_capacity(text.split_whitespace().count()));
        for token in text.split_whitespace() {
            match self
                .words
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
    use sha2::{Digest, Sha256};

    #[test]
    fn the_vendored_list_is_the_published_file() {
        let digest = Sha256::digest(EFF_LIST.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let list = EffList::get();
        assert_eq!(list.word(0), "abacus");
        assert_eq!(list.word(LIST_SIZE - 1), "zoom");
        assert_eq!(list.index_of("zoom"), Some(LIST_SIZE - 1));
        assert_eq!(list.index_of("Zoom"), None);
    }

    #[test]
    fn a_damaged_list_is_an_error_not_a_panic() {
        assert_eq!(
            EffList::read("11111\tabacus\n").err(),
            Some("the vendored EFF list is incomplete")
        );
        assert_eq!(
            EffList::read("11111 abacus\n").err(),
            Some("a line of the vendored EFF list holds no word")
        );
        let doubled: &'static str = EFF_LIST.replacen("\tzoom", "\tabacus", 1).leak();
        assert_eq!(
            EffList::read(doubled).err(),
            Some("the vendored EFF list holds a word twice")
        );
        assert!(EffList::try_get().is_ok());
    }

    #[test]
    fn dice_digits_select_the_listed_word() {
        let list = EffList::get();
        for line in EFF_LIST.lines().step_by(97) {
            let (rolls, word) = line.split_once('\t').unwrap();
            assert_eq!(list.word(index_of_rolls(rolls).unwrap()), word);
        }
        assert_eq!(index_of_rolls("11111"), Some(0));
        assert_eq!(index_of_rolls(" 66666 "), Some(LIST_SIZE - 1));
        for invalid in ["1111", "111111", "11117", "01111", "abcde"] {
            assert_eq!(index_of_rolls(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn recognises_texts_made_of_dice_words() {
        let list = EffList::get();
        assert_eq!(list.different_dice_words("abacus zoom yearbook zipfile"), 4);
        assert_eq!(list.different_dice_words("Abacus  ZOOM"), 2);
        assert_eq!(list.different_dice_words("abacus zoom Tr0ub4dor"), 0);
        assert_eq!(list.different_dice_words(""), 0);
    }

    /// AUD-005-FUN001: a repeated word adds nothing, in any letter case.
    #[test]
    fn a_repeated_dice_word_counts_once() {
        let list = EffList::get();
        assert_eq!(list.different_dice_words("abacus abacus abacus abacus"), 1);
        assert_eq!(list.different_dice_words("abacus ABACUS Abacus zoom"), 2);
        assert_eq!(
            list.different_dice_words("abacus zoom abacus zoom yearbook"),
            3
        );
        // Only ASCII letters change case; any other letter makes it a word outside the list.
        assert_eq!(list.different_dice_words("abacus zo\u{d3}m"), 0);
    }
}
