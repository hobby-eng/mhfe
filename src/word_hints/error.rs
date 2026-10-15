//! Refusals of the hint-list selector and UTF-8 input, without any typed word.
use crate::ErrorCode;
use std::fmt;

/// Why a word-hint request cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordHintError {
    /// The requested list identifier is unknown.
    UnknownList,
    /// The typed input bytes are not UTF-8.
    Utf8,
}
impl WordHintError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::InvalidRequest
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for WordHintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid request: ")?;
        match self {
            Self::UnknownList => write!(
                f,
                "the word list is \"{}\" or \"{}\"",
                super::WordList::Bip39.id(),
                super::WordList::Eff.id()
            ),
            Self::Utf8 => f.write_str("the typed text is not UTF-8"),
        }
    }
}
impl std::error::Error for WordHintError {}

impl crate::ErrorIdentity for WordHintError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
