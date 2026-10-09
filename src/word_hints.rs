//! Hints for a word being typed from one of the two word lists people type in MHFE: the English
//! BIP39 list of seed phrases, container phrases, repair words and chosen words, and the EFF large
//! wordlist of passwords made of words.
//!
//! The owner's rule (2026-10-08): from [`LIST_FROM_LETTERS`] letters on, the words that begin with
//! them; after one letter, how many words do. Both lists are public, so a hint tells nothing that a
//! person who sees the screen could not look up; a front end shows one only where the typed text
//! itself is shown. Tab completes a word as far as the words that begin with it agree.

use bip39::Language;
use zeroize::Zeroizing;

use crate::eff::{self, EffList};
use crate::phrase;
use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;

/// Letters typed before the words that begin with them are listed; fewer give how many there are.
pub const LIST_FROM_LETTERS: usize = 2;

/// The longest word of either list: the EFF list's nine letters, BIP39's eight.
const LONGEST_WORD: usize = if eff::LONGEST_WORD > phrase::LONGEST_WORD {
    eff::LONGEST_WORD
} else {
    phrase::LONGEST_WORD
};

/// A word list that a field is typed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordList {
    /// The English BIP39 list: seed phrases, container phrases, repair words, chosen words.
    Bip39,
    /// The EFF large wordlist: passwords of words.
    Eff,
}

/// What a front end shows below a word being typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    /// Nothing: no word is being typed, or the list has it whole and no longer word begins with it.
    Nothing,
    /// One letter typed: how many words of the list begin with it.
    Count(usize),
    /// [`LIST_FROM_LETTERS`] letters or more: the words that begin with them, in list order.
    Words(&'static [&'static str]),
    /// No word of the list begins with what is typed.
    NoWord,
}

/// What Tab adds to the word being typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The letters every word that begins with the typed ones has next; empty when they differ.
    pub letters: &'static str,
    /// Whether one word is left, so that the word ends and a space follows.
    pub word_ends: bool,
}

impl Completion {
    const NONE: Self = Self {
        letters: "",
        word_ends: false,
    };
}

impl WordList {
    /// The name a person reads: "BIP39" or "EFF".
    pub fn name(self) -> &'static str {
        match self {
            Self::Bip39 => "BIP39",
            Self::Eff => "EFF",
        }
    }

    /// The list a page names: "bip39" or "eff"; any other name is `INVALID_REQUEST`.
    pub fn from_name(name: &str) -> Result<Self, MhfeError> {
        match name {
            "bip39" => Ok(Self::Bip39),
            "eff" => Ok(Self::Eff),
            _ => Err(MhfeError::InvalidRequest(
                "the word list is \"bip39\" or \"eff\"".to_owned(),
            )),
        }
    }

    /// The words of the list. Both are in alphabetical order, which the search relies on; a test
    /// checks it.
    fn words(self) -> &'static [&'static str] {
        match self {
            Self::Bip39 => Language::English.word_list(),
            Self::Eff => EffList::get().words(),
        }
    }

    /// The hint for `line` as typed so far: about its last word, after its last space.
    pub fn hint(self, line: &str) -> Hint {
        let typed = match TypedWord::last_of(line) {
            LastWord::Typed(typed) => typed,
            LastWord::Longer => return Hint::NoWord,
            LastWord::None => return Hint::Nothing,
        };
        let matches = self.starting_with(typed.letters());
        match matches {
            [] => Hint::NoWord,
            [only] if *only == typed.letters() => Hint::Nothing,
            _ if typed.letters().len() < LIST_FROM_LETTERS => Hint::Count(matches.len()),
            _ => Hint::Words(matches),
        }
    }

    /// What Tab adds to the last word of `line`: see [`Completion`].
    pub fn completion(self, line: &str) -> Completion {
        let LastWord::Typed(typed) = TypedWord::last_of(line) else {
            return Completion::NONE;
        };
        let matches = self.starting_with(typed.letters());
        let (Some(first), Some(last)) = (matches.first(), matches.last()) else {
            return Completion::NONE;
        };
        // The list is sorted, so the first and the last word share what all of them share.
        let shared = first
            .bytes()
            .zip(last.bytes())
            .take_while(|(one, other)| one == other)
            .count();
        Completion {
            letters: &first[typed.letters().len()..shared],
            word_ends: matches.len() == 1,
        }
    }

    /// The words that begin with `letters`, in list order.
    fn starting_with(self, letters: &str) -> &'static [&'static str] {
        let words = self.words();
        let start = words.partition_point(|word| *word < letters);
        let count = words[start..].partition_point(|word| word.starts_with(letters));
        &words[start..start + count]
    }
}

/// What the last word of a line is to the hints.
enum LastWord {
    /// A word of the length a list word may have.
    Typed(TypedWord),
    /// Letters and hyphens, more than the longest list word has: no word begins like this
    /// (AUD-015-UI004).
    Longer,
    /// No word is being typed: an empty line, a space at its end, or other characters.
    None,
}

/// The last word of a line in lower case, in a buffer that is wiped when dropped: it may be part
/// of a password or a seed phrase. Only a word of letters and hyphens, which every word of both
/// lists is, up to the length of the longest.
struct TypedWord {
    letters: Zeroizing<[u8; LONGEST_WORD]>,
    length: usize,
}

impl TypedWord {
    fn last_of(line: &str) -> LastWord {
        let word = line.rsplit(char::is_whitespace).next().unwrap_or_default();
        if word.is_empty()
            || !word
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b'-')
        {
            return LastWord::None;
        }
        if word.len() > LONGEST_WORD {
            return LastWord::Longer;
        }
        let mut typed = Self {
            letters: Zeroizing::new([0; LONGEST_WORD]),
            length: word.len(),
        };
        for (slot, byte) in typed.letters.iter_mut().zip(word.bytes()) {
            *slot = byte.to_ascii_lowercase();
        }
        LastWord::Typed(typed)
    }

    fn letters(&self) -> &str {
        // Only ASCII letters and hyphens were written.
        std::str::from_utf8(&self.letters[..self.length]).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_lists_are_in_alphabetical_order() {
        for list in [WordList::Bip39, WordList::Eff] {
            assert!(
                list.words().windows(2).all(|pair| pair[0] < pair[1]),
                "{list:?}"
            );
        }
    }

    #[test]
    fn one_letter_gives_a_count_and_two_the_words() {
        assert_eq!(WordList::Bip39.hint("z"), Hint::Count(4));
        assert_eq!(
            WordList::Bip39.hint("Z"),
            Hint::Count(4),
            "in any letter case"
        );
        assert_eq!(
            WordList::Bip39.hint("abandon zo"),
            Hint::Words(&["zone", "zoo"])
        );
        assert_eq!(WordList::Eff.hint("y"), Hint::Count(27));
        assert_eq!(WordList::Eff.hint("yo-"), Hint::Words(&["yo-yo"]));
        let Hint::Words(un) = WordList::Eff.hint("un") else {
            panic!("no words");
        };
        assert_eq!(un.len(), 410);
    }

    #[test]
    fn a_whole_word_alone_needs_no_hint_but_a_shared_start_does() {
        assert_eq!(WordList::Bip39.hint("zoo"), Hint::Nothing);
        assert_eq!(
            WordList::Bip39.hint("art"),
            Hint::Words(&["art", "artefact", "artist", "artwork"])
        );
    }

    #[test]
    fn no_word_and_no_hint_are_told_apart() {
        assert_eq!(WordList::Bip39.hint("x"), Hint::NoWord);
        assert_eq!(WordList::Bip39.hint("abandon xq"), Hint::NoWord);
        // Longer than any word of either list: still no word begins like this (AUD-015-UI004).
        assert_eq!(WordList::Bip39.hint("toolongforanyword"), Hint::NoWord);
        assert_eq!(WordList::Eff.hint("zookeepers"), Hint::NoWord);
        assert_eq!(WordList::Eff.hint("zookeeper"), Hint::Nothing);
        assert_eq!(WordList::Eff.completion("zookeepers").letters, "");
        // A space after a word, a "?" for an unreadable word, a digit or a control character: no
        // word is being typed.
        for line in ["", "abandon ", "abandon ?", "ab1", "a\tb\u{1}"] {
            assert_eq!(WordList::Bip39.hint(line), Hint::Nothing, "{line:?}");
        }
    }

    #[test]
    fn tab_completes_as_far_as_the_words_agree() {
        let completion = |list: WordList, line| {
            let found = list.completion(line);
            (found.letters, found.word_ends)
        };
        assert_eq!(completion(WordList::Bip39, "abou"), ("t", true));
        assert_eq!(completion(WordList::Bip39, "ABOU"), ("t", true));
        assert_eq!(completion(WordList::Bip39, "zoo"), ("", true));
        assert_eq!(completion(WordList::Bip39, "abs"), ("", false));
        assert_eq!(completion(WordList::Bip39, "artw"), ("ork", true));
        assert_eq!(completion(WordList::Eff, "zoo"), ("", false));
        assert_eq!(completion(WordList::Eff, "zook"), ("eeper", true));
        assert_eq!(completion(WordList::Bip39, "xq"), ("", false));
        assert_eq!(completion(WordList::Bip39, "abandon "), ("", false));
    }

    #[test]
    fn a_page_names_the_list() {
        assert_eq!(WordList::from_name("bip39").unwrap(), WordList::Bip39);
        assert_eq!(WordList::from_name("eff").unwrap(), WordList::Eff);
        assert_eq!(
            WordList::from_name("BIP39").unwrap_err().code(),
            "INVALID_REQUEST"
        );
    }
}
