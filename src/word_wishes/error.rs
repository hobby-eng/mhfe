//! Typed constraints on chosen and excluded phrase words; no word value is retained.
use crate::ErrorCode;
use std::fmt;

/// A word's role, rather than its secret value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WishWord {
    /// This one-based chosen-word ordinal.
    Chosen(usize),
    /// A word excluded from the generated phrase.
    NeverUse,
}
impl fmt::Display for WishWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chosen(_) if super::MAX_CHOSEN_WORDS == 1 => f.write_str("the chosen word"),
            Self::Chosen(index) => write!(f, "chosen word {index}"),
            Self::NeverUse => f.write_str("the word never to use"),
        }
    }
}

/// Why a set of phrase-word wishes cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WishError {
    /// Raw entry text exceeds the shared byte bound before trimming or word validation.
    Text(crate::input_text::TextSizeError),
    /// Too many chosen words were supplied.
    TooManyChosen,
    /// Too many excluded words were supplied.
    TooManyExcluded,
    /// This word role is not a full English BIP39 word or an allowed prefix.
    UnknownWord(WishWord),
    /// The chosen word at this ordinal was also excluded.
    ExcludedChosen(usize),
    /// The chosen word at this ordinal has an out-of-range position.
    Position(usize),
    /// The binding supplied a different number of word and position entries.
    MismatchedPlaces,
    /// A nonempty binding field did not begin each word entry with a line break.
    EntryFraming,
    /// The supplied chosen-word bytes are not UTF-8.
    Utf8,
}
impl WishError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::MismatchedPlaces | Self::Text(_) => ErrorCode::InvalidRequest,
            Self::TooManyChosen
            | Self::TooManyExcluded
            | Self::UnknownWord(_)
            | Self::ExcludedChosen(_)
            | Self::Position(_)
            | Self::EntryFraming
            | Self::Utf8 => ErrorCode::InvalidWordWish,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for WishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Text(error) = self {
            return error.fmt(f);
        }
        if *self != Self::MismatchedPlaces {
            f.write_str("the wishes for the new phrase cannot be used: ")?;
        }
        match self {
            Self::Text(error) => error.fmt(f),
            Self::MismatchedPlaces => {
                f.write_str("invalid request: give one place for every chosen word")
            }
            Self::TooManyChosen => {
                write!(f, "choose at most {}", WordCount(super::MAX_CHOSEN_WORDS))
            }
            Self::TooManyExcluded => write!(
                f,
                "name at most {} never to use",
                WordCount(super::MAX_NEVER_USE_WORDS)
            ),
            Self::UnknownWord(role) => write!(f, "{role} is not an English BIP39 word"),
            Self::ExcludedChosen(index) => write!(
                f,
                "{} is also a word never to use",
                WishWord::Chosen(*index)
            ),
            Self::Position(index) => write!(
                f,
                "{} needs a position from 1 to {}",
                WishWord::Chosen(*index),
                crate::packing::STATE_WORDS
            ),
            Self::Utf8 => f.write_str("the chosen words are not UTF-8 text"),
            Self::EntryFraming => f.write_str("begin every word entry with a line break"),
        }
    }
}
// Deliberate copy of the standard Error::source adapter: each domain error exposes its own
// typed inner error; sharing this trait method would couple unrelated error enums.
impl std::error::Error for WishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Text(error) => Some(error),
            _ => None,
        }
    }
}

/// The count's singular/plural rendering is owned with the messages that need it.
struct WordCount(usize);
impl fmt::Display for WordCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.0,
            if self.0 == 1 { "word" } else { "words" }
        )
    }
}

impl crate::ErrorIdentity for WishError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
