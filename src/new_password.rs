//! New passwords: random words from the EFF large wordlist, five words and their check word
//! (MHFE-PASSWORD-CHECK-1), or random characters. Words come from a [`RandomSource`] or from real
//! dice; characters only from a random source.

use mhfe_core::password_check::{check_word, EFF_WORDS};
use zeroize::Zeroizing;

use crate::check_word::DRAWN_WORDS;
use crate::eff::{index_of_rolls, LIST_SIZE, LONGEST_WORD, MILLIBITS_PER_WORD};
use crate::memory::LockedText;
use crate::random::{check_source, uniform_below, RandomSource};
use crate::MhfeError;

/// Why a new password is refused: each variant is the [`MhfeError`] of the same name, whose text
/// and code it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewPasswordError {
    /// A generated password of this size is not offered.
    InvalidPasswordSize(String),
    /// Dice digits for a word are not five digits from 1 to 6; the value names the word.
    InvalidDiceRolls(usize),
    /// A request that the generator does not take; the text says which.
    InvalidRequest(String),
    /// The random source failed or gave bytes that cannot be random.
    RandomFailed(String),
    /// A fault of the program itself.
    Internal(String),
}

impl From<NewPasswordError> for MhfeError {
    fn from(error: NewPasswordError) -> Self {
        match error {
            NewPasswordError::InvalidPasswordSize(value) => Self::InvalidPasswordSize(value),
            NewPasswordError::InvalidDiceRolls(value) => Self::InvalidDiceRolls(value),
            NewPasswordError::InvalidRequest(value) => Self::InvalidRequest(value),
            NewPasswordError::RandomFailed(value) => Self::RandomFailed(value),
            NewPasswordError::Internal(value) => Self::Internal(value),
        }
    }
}

shown_as_mhfe_error!(NewPasswordError);

/// The refusal of the random source, whose errors are the crate's.
fn random_failed(error: MhfeError) -> NewPasswordError {
    match error {
        MhfeError::RandomFailed(reason) => NewPasswordError::RandomFailed(reason),
        other => NewPasswordError::Internal(other.to_string()),
    }
}

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
            return Err(NewPasswordError::InvalidPasswordSize(format!(
                "choose between 1 and {MOST_WORDS} words"
            )));
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
            return Err(NewPasswordError::InvalidPasswordSize(format!(
                "choose between 1 and {MOST_CHARACTERS} characters"
            )));
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

    /// The strength in thousandths of a bit; the check word adds none.
    pub fn millibits(&self) -> usize {
        match self.kind {
            Kind::Characters(count) => count * MILLIBITS_PER_CHARACTER,
            _ => self.drawn_words() * MILLIBITS_PER_WORD,
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
        format!("{made}, about {} bits", bits_text(self.millibits()))
    }

    /// Whether the password is shorter than recommended.
    pub fn is_weak(&self) -> bool {
        match self.kind {
            Kind::Words(count) => count < RECOMMENDED_WORDS,
            Kind::CheckWord => false,
            Kind::Characters(count) => count < RECOMMENDED_CHARACTERS,
        }
    }

    /// Makes the password from a random source, which is probed first ([`check_source`]): a
    /// source that fills nothing or repeats itself is refused before anything is drawn.
    pub fn make(&self, source: &mut dyn RandomSource) -> Result<NewPassword, NewPasswordError> {
        check_source(source).map_err(random_failed)?;
        match self.kind {
            Kind::Characters(count) => self.characters_from(source, count),
            _ => self.make_from_indexes(&mut |_| {
                uniform_below(source, LIST_SIZE).map_err(random_failed)
            }),
        }
    }

    /// Makes a word password from dice: `rolls` holds five digits from 1 to 6 per drawn word,
    /// groups separated by spaces. Characters cannot come from dice.
    pub fn make_from_rolls(&self, rolls: &str) -> Result<NewPassword, NewPasswordError> {
        if self.is_characters() {
            return Err(NewPasswordError::InvalidRequest(
                "a character password cannot come from dice".to_owned(),
            ));
        }
        let groups: Vec<&str> = rolls.split_whitespace().collect();
        if groups.len() > self.drawn_words() {
            return Err(NewPasswordError::InvalidRequest(format!(
                "{} groups of dice digits for {} words",
                groups.len(),
                self.drawn_words()
            )));
        }
        // The first word without its digits.
        if groups.len() < self.drawn_words() {
            return Err(NewPasswordError::InvalidDiceRolls(groups.len() + 1));
        }
        self.make_from_indexes(&mut |number| word_index_of_rolls(number, groups[number - 1]))
    }

    /// Makes a word password, asking `next_index` for the list index of each drawn word, from 1;
    /// the command-line tool asks the person for dice digits there. A character recipe has no
    /// words and is refused.
    pub fn make_from_indexes(
        &self,
        next_index: &mut dyn FnMut(usize) -> Result<usize, NewPasswordError>,
    ) -> Result<NewPassword, NewPasswordError> {
        if self.is_characters() {
            return Err(NewPasswordError::InvalidRequest(
                "a character password is not made of words".to_owned(),
            ));
        }
        let drawn_words = self.drawn_words();
        let all_words = drawn_words + usize::from(self.has_check_word());
        // The indexes the check word is computed from, wiped when done.
        let mut drawn = Zeroizing::new([0; DRAWN_WORDS]);
        // Built in place at its final size and locked, so no reallocation leaves a copy.
        let text = LockedText::build(all_words * (LONGEST_WORD + 1), |text| {
            for number in 1..=drawn_words {
                let index = next_index(number)?;
                if index >= LIST_SIZE {
                    return Err(NewPasswordError::Internal(
                        "a word index outside the list".to_owned(),
                    ));
                }
                if number > 1 {
                    text.push(' ');
                }
                text.push_str(EFF_WORDS[index]);
                if let Some(slot) = drawn.get_mut(number - 1) {
                    // Below 7,776, as just checked.
                    *slot = index as u16;
                }
            }
            if self.has_check_word() {
                text.push(' ');
                #[expect(
                    clippy::expect_used,
                    reason = "every drawn index was checked against the list above"
                )]
                let check = check_word(*drawn).expect("the drawn indexes are on the list");
                text.push_str(EFF_WORDS[usize::from(check)]);
            }
            Ok(())
        })?;
        Ok(NewPassword {
            text,
            recipe: *self,
        })
    }

    fn characters_from(
        &self,
        source: &mut dyn RandomSource,
        count: usize,
    ) -> Result<NewPassword, NewPasswordError> {
        let text = LockedText::build::<NewPasswordError>(count, |text| {
            for _ in 0..count {
                let index = uniform_below(source, CHARACTERS.len()).map_err(random_failed)?;
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

/// The strength of `count` dice words as [`bits_text`] writes it: "64.6" for five.
pub fn word_bits(count: usize) -> String {
    bits_text(count * MILLIBITS_PER_WORD)
}

/// The strength of `count` random characters as [`bits_text`] writes it: "93.3" for sixteen.
pub fn character_bits(count: usize) -> String {
    bits_text(count * MILLIBITS_PER_CHARACTER)
}

/// "64.6" for 64,625 millibits: a strength in bits, rounded to one decimal.
pub fn bits_text(millibits: usize) -> String {
    let tenths = (millibits + 50) / 100;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// The list index of drawn word `number`, from 1, from its five dice digits as typed
/// (`INVALID_DICE_ROLLS` for that word unless they are five digits from 1 to 6).
pub fn word_index_of_rolls(number: usize, rolls: &str) -> Result<usize, NewPasswordError> {
    index_of_rolls(rolls).ok_or(NewPasswordError::InvalidDiceRolls(number))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_character_recipe_is_not_made_of_words() {
        let recipe = PasswordRecipe::characters(16).unwrap();
        assert!(matches!(
            recipe.make_from_indexes(&mut |_| Ok(0)),
            Err(NewPasswordError::InvalidRequest(_))
        ));
    }

    use super::*;
    use crate::random::tests::counter_source;

    #[test]
    fn sizes_outside_the_limits_are_refused() {
        assert!(PasswordRecipe::words(0).is_err());
        assert!(PasswordRecipe::words(MOST_WORDS + 1).is_err());
        assert!(PasswordRecipe::characters(0).is_err());
        assert!(PasswordRecipe::characters(MOST_CHARACTERS + 1).is_err());
        assert_eq!(
            MhfeError::from(PasswordRecipe::words(33).unwrap_err()).code(),
            "INVALID_PASSWORD_SIZE"
        );
    }

    #[test]
    fn words_and_characters_have_their_size_and_alphabet() {
        let mut source = counter_source(9);
        let words = PasswordRecipe::words(6).unwrap().make(&mut source).unwrap();
        assert_eq!(words.text().split(' ').count(), 6);
        assert!(words
            .text()
            .split(' ')
            .all(|word| EFF_WORDS.binary_search(&word).is_ok()));
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
        let words: Vec<&str> = password.text().split(' ').collect();
        assert_eq!(words.len(), 6);
        assert_eq!(words[5], "aids");
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
            Err(NewPasswordError::InvalidDiceRolls(2))
        ));
        assert!(matches!(
            recipe.make_from_rolls("11111 11111 11111"),
            Err(NewPasswordError::InvalidRequest(_))
        ));
        assert!(matches!(
            recipe.make_from_rolls("11111"),
            Err(NewPasswordError::InvalidDiceRolls(2))
        ));
        assert!(PasswordRecipe::characters(8)
            .unwrap()
            .make_from_rolls("11111")
            .is_err());
    }

    #[test]
    fn strength_is_about_12_9_bits_per_word_and_5_8_per_character() {
        assert_eq!(bits_text(4 * MILLIBITS_PER_WORD), "51.7");
        assert_eq!(word_bits(5), "64.6");
        assert_eq!(character_bits(16), "93.3");
        assert_eq!(
            PasswordRecipe::check_word().summary(),
            "5 words from the EFF list and a check word, about 64.6 bits"
        );
        assert_eq!(
            PasswordRecipe::characters(16).unwrap().summary(),
            "16 random characters, about 93.3 bits"
        );
        assert_eq!(bits_text(5 * MILLIBITS_PER_WORD), "64.6");
        assert_eq!(bits_text(12 * MILLIBITS_PER_CHARACTER), "70.0");
        assert_eq!(bits_text(16 * MILLIBITS_PER_CHARACTER), "93.3");
        assert!(PasswordRecipe::words(3).unwrap().is_weak());
        assert!(!PasswordRecipe::words(4).unwrap().is_weak());
        assert!(PasswordRecipe::characters(11).unwrap().is_weak());
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
