//! New passwords: random words from the EFF large wordlist, five words and their check word
//! (MHFE-PASSWORD-CHECK-1), or random characters. Words come from a [`RandomSource`] or from real
//! dice; characters only from a random source.

use zeroize::Zeroizing;

use crate::check_word::{PasswordReview, Reading, DRAWN_WORDS};
use crate::eff::{EffList, LIST_SIZE, LONGEST_WORD};
use crate::memory::LockedText;
use crate::random::{RandomSampler, RandomSource};
mod error;
pub use error::{NewPasswordError, PasswordKind};

mod bits;
pub use bits::Millibits;

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-passwords"))]
pub(crate) mod known_answers;

/// Words of a password by default: about 64.6 bits.
pub const DEFAULT_WORDS: usize = 5;
/// Fewer words are weak: four give about 51.7 bits.
pub const RECOMMENDED_WORDS: usize = 4;
/// The most words a generated password may have.
pub const MOST_WORDS: usize = 32;
/// The characters of a character password: digits, capital and small letters without those
/// easily confused when read back from paper (0 and O, 1, l and I).
pub const CHARACTERS: &[u8; 57] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// log2(57) = 5.833 bits per character, in thousandths.
pub const MILLIBITS_PER_CHARACTER: usize = 5_833;
/// The strengths here are counted in thousandths of a bit, so that they add up exactly.
pub const MILLIBITS_PER_BIT: u32 = 1_000;
/// Sixteen characters by default: about 93.3 bits.
pub const DEFAULT_CHARACTERS: usize = 16;
/// Fewer characters are weak: twelve give about 70.0 bits. The strength estimate counts a random
/// letter as 4.7 bits rather than 5.8, so twelve also pass there.
pub const RECOMMENDED_CHARACTERS: usize = 12;
/// The most characters a generated character password may have.
pub const MOST_CHARACTERS: usize = 64;

/// What kind of password to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Words(usize),
    CheckWord,
    Characters(usize),
}

/// A kind and size of password, checked when it is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordRecipe {
    kind: Kind,
}

impl PasswordRecipe {
    /// `count` random words, 1 to 32.
    pub fn words(count: usize) -> Result<Self, NewPasswordError> {
        if !(1..=MOST_WORDS).contains(&count) {
            return Err(NewPasswordError::Size {
                kind: PasswordKind::Words,
                count,
            });
        }
        Ok(Self {
            kind: Kind::Words(count),
        })
    }

    /// Five random words and their check word.
    pub fn check_word() -> Self {
        Self {
            kind: Kind::CheckWord,
        }
    }

    /// `count` random characters, 1 to 64.
    pub fn characters(count: usize) -> Result<Self, NewPasswordError> {
        if !(1..=MOST_CHARACTERS).contains(&count) {
            return Err(NewPasswordError::Size {
                kind: PasswordKind::Characters,
                count,
            });
        }
        Ok(Self {
            kind: Kind::Characters(count),
        })
    }

    /// The words drawn at random or rolled, the check word not counted; 0 for characters.
    pub fn drawn_words(&self) -> usize {
        match self.kind {
            Kind::Words(count) => count,
            Kind::CheckWord => DRAWN_WORDS,
            Kind::Characters(_) => 0,
        }
    }

    /// Whether the password ends with a check word (MHFE-PASSWORD-CHECK-1).
    pub fn has_check_word(&self) -> bool {
        self.kind == Kind::CheckWord
    }

    /// Whether the password is made of random characters rather than words.
    pub fn is_characters(&self) -> bool {
        matches!(self.kind, Kind::Characters(_))
    }

    /// The strength in bits of the recipe's independent random draws.
    pub fn bits(&self) -> f64 {
        self.strength().bits()
    }

    /// The strength in thousandths of a bit; the check word adds none.
    pub fn millibits(&self) -> u128 {
        self.strength().get()
    }

    /// The recipe owns the draw count and alphabet; presentation uses the resulting value.
    fn strength(&self) -> Millibits {
        match self.kind {
            Kind::Characters(count) => Millibits::characters(count),
            _ => Millibits::words(self.drawn_words()),
        }
    }

    /// What the recipe makes, as a person reads it: "5 words from the EFF list, about 64.6 bits",
    /// "5 words from the EFF list and a check word, about 64.6 bits" or "16 random characters,
    /// about 93.3 bits".
    pub fn summary(&self) -> String {
        let made = match self.kind {
            Kind::Words(count) => format!("{count} words from the EFF list"),
            Kind::CheckWord => format!("{DRAWN_WORDS} words from the EFF list and a check word"),
            Kind::Characters(count) => format!("{count} random characters"),
        };
        format!("{made}, about {} bits", self.strength())
    }

    /// Whether the password is shorter than recommended.
    pub fn is_weak(&self) -> bool {
        match self.kind {
            Kind::Words(count) => count < RECOMMENDED_WORDS,
            Kind::CheckWord => false,
            Kind::Characters(count) => count < RECOMMENDED_CHARACTERS,
        }
    }

    /// Makes the password from a random source, which is probed first ([`RandomSampler::check_source`]): a
    /// source that fills nothing or repeats itself is refused before anything is drawn.
    pub fn make(&self, source: &mut dyn RandomSource) -> Result<NewPassword, NewPasswordError> {
        let mut source = RandomSampler::new(source);
        source.check_source()?;
        match self.kind {
            Kind::Characters(count) => self.characters_from(&mut source, count),
            _ => {
                self.make_from_indexes(&mut |_| source.uniform_below(LIST_SIZE).map_err(Into::into))
            }
        }
    }

    /// Makes a word password from dice: `rolls` holds five digits from 1 to 6 per drawn word,
    /// groups separated by spaces. Characters cannot come from dice.
    pub fn make_from_rolls(&self, rolls: &str) -> Result<NewPassword, NewPasswordError> {
        if self.is_characters() {
            return Err(NewPasswordError::CharactersFromDice);
        }
        crate::input_text::InputText::read(rolls)?;
        let count = rolls.split_whitespace().count();
        // A count of groups that is not the recipe's is said as such, apart from the digits of a
        // word (AUD-024-API015).
        if count != self.drawn_words() {
            return Err(NewPasswordError::DiceGroups {
                actual: count,
                expected: self.drawn_words(),
                check_word: self.has_check_word(),
            });
        }
        let mut groups = rolls.split_whitespace();
        self.make_from_indexes(&mut |number| {
            let group = groups
                .next()
                .ok_or(NewPasswordError::WordIndexOutsideList)?;
            EffList::word_index_of_rolls(number, group).map_err(Into::into)
        })
    }

    /// Makes a word password, asking `next_index` for the list index of each drawn word, from 1;
    /// the command-line tool asks the person for dice digits there. A character recipe has no
    /// words and is refused.
    pub fn make_from_indexes(
        &self,
        next_index: &mut dyn FnMut(usize) -> Result<usize, NewPasswordError>,
    ) -> Result<NewPassword, NewPasswordError> {
        if self.is_characters() {
            return Err(NewPasswordError::CharactersFromIndexes);
        }
        let list = EffList::get();
        let drawn_words = self.drawn_words();
        let all_words = drawn_words + usize::from(self.has_check_word());
        // The indexes the check word is computed from, wiped when done.
        let mut drawn = Zeroizing::new([0; DRAWN_WORDS]);
        // Built in place at its final size and locked, so no reallocation leaves a copy.
        let text = LockedText::build(all_words * (LONGEST_WORD + 1), |text| {
            for number in 1..=drawn_words {
                let index = next_index(number)?;
                if index >= LIST_SIZE {
                    return Err(NewPasswordError::WordIndexOutsideList);
                }
                if number > 1 {
                    text.push(' ');
                }
                text.push_str(list.word(index)?);
                if let Some(slot) = drawn.get_mut(number - 1) {
                    *slot = index;
                }
            }
            if self.has_check_word() {
                text.push(' ');
                let index = PasswordReview::check_index(&drawn)
                    .map_err(|_| NewPasswordError::WordIndexOutsideList)?;
                text.push_str(list.word(index)?);
            }
            Ok(())
        })?;
        // The six words are read back as a person's program will read them: a fault between the
        // drawing and the writing would otherwise give a password whose check word does not fit.
        if self.has_check_word() && PasswordReview::of(&text)?.reading() != Reading::Fits {
            return Err(NewPasswordError::CheckWordMismatch);
        }
        Ok(NewPassword {
            text,
            recipe: *self,
        })
    }

    fn characters_from(
        &self,
        source: &mut RandomSampler<'_>,
        count: usize,
    ) -> Result<NewPassword, NewPasswordError> {
        let text = LockedText::build::<NewPasswordError>(count, |text| {
            for _ in 0..count {
                let index = source.uniform_below(CHARACTERS.len())?;
                text.push(char::from(CHARACTERS[index]));
            }
            Ok(())
        })?;
        Ok(NewPassword {
            text,
            recipe: *self,
        })
    }
}

/// A password just made, held locked and wiped when dropped.
pub struct NewPassword {
    text: LockedText,
    recipe: PasswordRecipe,
}

impl NewPassword {
    /// The password, as it is written down.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The recipe the password was made from.
    pub fn recipe(&self) -> PasswordRecipe {
        self.recipe
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_character_recipe_is_not_made_of_words() {
        let recipe = PasswordRecipe::characters(16).unwrap();
        assert!(matches!(
            recipe.make_from_indexes(&mut |_| Ok(0)),
            Err(NewPasswordError::CharactersFromIndexes)
        ));
    }

    use super::*;
    use crate::eff::MILLIBITS_PER_WORD;
    use crate::random::tests::counter_source;

    #[test]
    fn sizes_outside_the_limits_are_refused() {
        assert!(PasswordRecipe::words(0).is_err());
        assert!(PasswordRecipe::words(MOST_WORDS + 1).is_err());
        assert!(PasswordRecipe::characters(0).is_err());
        assert!(PasswordRecipe::characters(MOST_CHARACTERS + 1).is_err());
        assert_eq!(
            PasswordRecipe::words(33).unwrap_err().code(),
            "INVALID_PASSWORD_SIZE"
        );
    }

    #[test]
    fn words_and_characters_have_their_size_and_alphabet() {
        let mut source = counter_source(9);
        let words = PasswordRecipe::words(6).unwrap().make(&mut source).unwrap();
        assert_eq!(words.text().split(' ').count(), 6);
        let list = EffList::get();
        assert!(words
            .text()
            .split(' ')
            .all(|word| list.index_of(word).is_some()));
        let characters = PasswordRecipe::characters(16)
            .unwrap()
            .make(&mut source)
            .unwrap();
        assert_eq!(characters.text().len(), 16);
        assert!(characters
            .text()
            .bytes()
            .all(|byte| CHARACTERS.contains(&byte)));
    }

    #[test]
    fn the_check_word_is_the_sixth_word() {
        let password = PasswordRecipe::check_word()
            .make_from_rolls("11111 11112 11113 11114 11115")
            .unwrap();
        let list = EffList::get();
        let words: Vec<&str> = password.text().split(' ').collect();
        assert_eq!(words.len(), 6);
        assert_eq!(
            words[5],
            list.word(PasswordReview::check_index(&[0, 1, 2, 3, 4]).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn dice_rolls_must_fit_the_word_count() {
        let recipe = PasswordRecipe::words(2).unwrap();
        assert_eq!(
            recipe.make_from_rolls("11111 66666").unwrap().text(),
            "abacus zoom"
        );
        assert!(matches!(
            recipe.make_from_rolls("11111 66667"),
            Err(NewPasswordError::Eff(
                crate::eff::EffError::InvalidDiceRolls(2)
            ))
        ));
        // Too few or too many groups are said as such (AUD-024-API015).
        for (rolls, message) in [
            ("11111", "invalid request: the dice give 1 group of digits, but this password draws 2 words"),
            ("11111 22222 33333", "invalid request: the dice give 3 groups of digits, but this password draws 2 words"),
        ] {
            let refused = recipe.make_from_rolls(rolls).err().unwrap();
            assert_eq!(refused.code(), "INVALID_REQUEST");
            assert_eq!(refused.to_string(), message);
        }
        let refused = PasswordRecipe::check_word()
            .make_from_rolls("11111 11112 11113 11114 11115 11116")
            .err()
            .unwrap();
        assert!(
            refused
                .to_string()
                .ends_with("the check word is computed, not rolled"),
            "{refused}"
        );
        assert!(PasswordRecipe::characters(8)
            .unwrap()
            .make_from_rolls("11111")
            .is_err());
    }

    #[test]
    fn dice_text_is_bounded_before_group_collection_without_changing_recipe_precedence() {
        let limit = crate::input_text::InputText::MAX_BYTES;
        let oversized = "1".repeat(limit + 1);
        assert!(
            matches!(PasswordRecipe::words(1).unwrap().make_from_rolls(&oversized),
            Err(NewPasswordError::Text(crate::input_text::TextSizeError::TooLong { bytes })) if bytes == limit + 1)
        );
        assert!(matches!(
            PasswordRecipe::characters(8)
                .unwrap()
                .make_from_rolls(&oversized),
            Err(NewPasswordError::CharactersFromDice)
        ));
        let rolls = " ".repeat(limit - "11111".len()) + "11111";
        assert_eq!(
            PasswordRecipe::words(1)
                .unwrap()
                .make_from_rolls(&rolls)
                .unwrap()
                .text(),
            "abacus"
        );
        let groups = "1 ".repeat(1000);
        assert!(matches!(
            PasswordRecipe::words(2).unwrap().make_from_rolls(&groups),
            Err(NewPasswordError::DiceGroups {
                actual: 1000,
                expected: 2,
                ..
            })
        ));
        assert!(matches!(
            PasswordRecipe::words(1)
                .unwrap()
                .make_from_rolls(&"1".repeat(limit)),
            Err(NewPasswordError::Eff(
                crate::eff::EffError::InvalidDiceRolls(1)
            ))
        ));
    }

    #[test]
    fn strength_is_about_12_9_bits_per_word_and_5_8_per_character() {
        assert_eq!(Millibits::new(4 * MILLIBITS_PER_WORD).to_string(), "51.7");
        assert_eq!(Millibits::words(5).to_string(), "64.6");
        assert_eq!(Millibits::characters(16).to_string(), "93.3");
        assert_eq!(
            PasswordRecipe::check_word().summary(),
            "5 words from the EFF list and a check word, about 64.6 bits"
        );
        assert_eq!(
            PasswordRecipe::characters(16).unwrap().summary(),
            "16 random characters, about 93.3 bits"
        );
        assert_eq!(Millibits::new(5 * MILLIBITS_PER_WORD).to_string(), "64.6");
        assert_eq!(
            Millibits::new(12 * MILLIBITS_PER_CHARACTER).to_string(),
            "70.0"
        );
        assert_eq!(
            Millibits::new(16 * MILLIBITS_PER_CHARACTER).to_string(),
            "93.3"
        );
        assert!(PasswordRecipe::words(3).unwrap().is_weak());
        assert!(!PasswordRecipe::words(4).unwrap().is_weak());
        assert!(PasswordRecipe::characters(11).unwrap().is_weak());
    }

    #[test]
    fn displayed_strength_rounds_half_up_at_decimal_boundaries() {
        for (millibits, text) in [
            (0, "0.0"),
            (49, "0.0"),
            (50, "0.1"),
            (149, "0.1"),
            (150, "0.2"),
        ] {
            assert_eq!(Millibits::new(millibits).to_string(), text);
        }
    }

    #[test]
    fn characters_leave_out_those_easily_confused() {
        let mut sorted = CHARACTERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CHARACTERS.len(), "no character twice");
        for confused in b"0O1lI" {
            assert!(!CHARACTERS.contains(confused), "{}", char::from(*confused));
        }
        assert!(CHARACTERS.iter().all(u8::is_ascii_alphanumeric));
    }
}
