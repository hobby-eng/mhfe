//! Refusals and invariant failures of password generation, without generated material.
use std::fmt;

use crate::{eff::EffError, random::RandomError, ErrorCode};

/// The requested output kind, independent of any generated password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordKind {
    /// Words from the EFF large list.
    Words,
    /// Characters from the password alphabet.
    Characters,
}

/// Why password generation stopped; the module owns both the reason and its display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewPasswordError {
    /// The requested size is outside the kind's bounds.
    Size {
        /// The requested output kind.
        kind: PasswordKind,
        /// The requested number of words or characters.
        count: usize,
    },
    /// An own password must be entered, rather than generated.
    TypedInputRequired,
    /// The requested recipe name is not offered; no caller text is retained.
    UnknownKind,
    /// A checked-word recipe was given an explicit size.
    CheckWordCount,
    /// A character password cannot be generated from dice.
    CharactersFromDice,
    /// A character password cannot be generated from word indexes.
    CharactersFromIndexes,
    /// The number of dice groups differs from the recipe's independent word draws.
    DiceGroups {
        /// The number of whitespace-separated groups supplied.
        actual: usize,
        /// The recipe's independent word draws.
        expected: usize,
        /// Whether a final check word is computed instead of rolled.
        check_word: bool,
    },
    /// The callback returned an index outside the public list; its value is not retained.
    WordIndexOutsideList,
    /// A newly generated checked password failed its immediate profile readback.
    CheckWordMismatch,
    /// The byte source or sampling guard refused a draw.
    Random(RandomError),
    /// The numbered dice reader refused a group.
    Eff(EffError),
    /// The caller cancelled before a word was returned.
    Cancelled,
}

impl NewPasswordError {
    /// The stable typed code of this refusal.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Size { .. } => ErrorCode::InvalidPasswordSize,
            Self::TypedInputRequired
            | Self::UnknownKind
            | Self::CheckWordCount
            | Self::CharactersFromDice
            | Self::CharactersFromIndexes
            | Self::DiceGroups { .. } => ErrorCode::InvalidRequest,
            Self::WordIndexOutsideList | Self::CheckWordMismatch => ErrorCode::InternalError,
            Self::Random(error) => error.error_code(),
            Self::Eff(error) => error.error_code(),
            Self::Cancelled => ErrorCode::Cancelled,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<RandomError> for NewPasswordError {
    fn from(error: RandomError) -> Self {
        Self::Random(error)
    }
}
impl From<EffError> for NewPasswordError {
    fn from(error: EffError) -> Self {
        Self::Eff(error)
    }
}
impl From<crate::CancelledError> for NewPasswordError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}
impl fmt::Display for NewPasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size { kind, .. } => {
                let (maximum, unit) = match kind {
                    PasswordKind::Words => (super::MOST_WORDS, "words"),
                    PasswordKind::Characters => (super::MOST_CHARACTERS, "characters"),
                };
                write!(f, "choose between 1 and {maximum} {unit}")
            }
            Self::TypedInputRequired => f.write_str("invalid request: own passwords are typed"),
            Self::UnknownKind => f.write_str("invalid request: unknown password kind; choose words, checkWord or characters"),
            Self::CheckWordCount => write!(f, "invalid request: count belongs only to the kinds \"words\" and \"characters\": \"checkWord\" always gives {} words and their check word", crate::check_word::DRAWN_WORDS),
            Self::CharactersFromDice => {
                f.write_str("invalid request: a character password cannot come from dice")
            }
            Self::CharactersFromIndexes => {
                f.write_str("invalid request: a character password is not made of words")
            }
            Self::DiceGroups {
                actual,
                expected,
                check_word,
            } => {
                let group_unit = if *actual == 1 { "group" } else { "groups" };
                let word_unit = if *expected == 1 { "word" } else { "words" };
                write!(f, "invalid request: the dice give {actual} {group_unit} of digits, but this password draws {expected} {word_unit}")?;
                if *check_word {
                    f.write_str("; the check word is computed, not rolled")?;
                }
                Ok(())
            }
            Self::WordIndexOutsideList => {
                f.write_str("internal error: a word index outside the list")
            }
            Self::CheckWordMismatch => {
                f.write_str("internal error: a new password does not fit its check word")
            }
            Self::Random(error) => error.fmt(f),
            Self::Eff(error) => error.fmt(f),
            Self::Cancelled => crate::CancelledError.fmt(f),
        }
    }
}
impl std::error::Error for NewPasswordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Random(error) => Some(error),
            Self::Eff(error) => Some(error),
            Self::Cancelled => Some(&crate::CancelledError),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for NewPasswordError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
