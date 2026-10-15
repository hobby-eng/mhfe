//! Typed failures of the wallet-check profile and checked phrase generation.
use crate::{random::RandomError, ErrorCode, PassphraseError, PhraseError};
use std::fmt;

/// Which immediate readback guarantee of a newly drawn phrase failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrawReadback {
    /// The text could not be read as a phrase.
    Unreadable,
    /// Its entropy differs from the entropy drawn.
    Entropy,
    /// Its entropy does not have the profile's 24-word size.
    Length,
    /// Its words no longer satisfy the requested wishes.
    Wishes,
    /// Its wallet-check criterion no longer passes.
    WalletCheck,
}
impl fmt::Display for DrawReadback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "a new phrase does not read back",
            Self::Entropy => "a new phrase reads back as another entropy",
            Self::Length => "a new phrase is not 24 words",
            Self::Wishes => "a new phrase does not meet its wishes when read back",
            Self::WalletCheck => "a new phrase does not pass its wallet check when read back",
        })
    }
}
impl std::error::Error for DrawReadback {}

/// A refusal of the profile or a failure while drawing a phrase. No secret value is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletCheckError {
    /// The profile requires a nonempty BIP39 passphrase.
    NeedsPassphrase,
    /// The repeated passphrase differs from the original typed text.
    PassphrasesDiffer,
    /// This word count has no profile verification.
    WordCount(usize),
    /// The common BIP39 reader refused the phrase or entropy.
    Phrase(PhraseError),
    /// The shared BIP39 passphrase guard failed.
    Passphrase(PassphraseError),
    /// The byte source or its health guard failed.
    Random(RandomError),
    /// The caller stopped the draw.
    Cancelled,
    /// The generated phrase failed an immediate readback guarantee.
    Readback(DrawReadback),
    /// All native draw workers ended without a result.
    NoThreadResult,
}
impl WalletCheckError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::NeedsPassphrase => ErrorCode::WalletCheckNeedsPassphrase,
            Self::PassphrasesDiffer => ErrorCode::PassphrasesDiffer,
            Self::WordCount(_) => ErrorCode::InvalidWordCount,
            Self::Phrase(error) => error.error_code(),
            Self::Passphrase(error) => error.error_code(),
            Self::Random(error) => error.error_code(),
            Self::Cancelled => ErrorCode::Cancelled,
            Self::Readback(_) | Self::NoThreadResult => ErrorCode::InternalError,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<PhraseError> for WalletCheckError {
    fn from(error: PhraseError) -> Self {
        Self::Phrase(error)
    }
}
impl From<PassphraseError> for WalletCheckError {
    fn from(error: PassphraseError) -> Self {
        Self::Passphrase(error)
    }
}
impl From<RandomError> for WalletCheckError {
    fn from(error: RandomError) -> Self {
        Self::Random(error)
    }
}
impl From<crate::CancelledError> for WalletCheckError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}
impl fmt::Display for WalletCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsPassphrase => f.write_str("the wallet check needs a BIP39 passphrase; without one it would let anyone who sees the phrase test it"),
            Self::PassphrasesDiffer => f.write_str("the passphrase and its repetition differ"),
            Self::WordCount(words) => write!(f, "a {words}-word phrase has no wallet check: only a {}-word phrase is drawn with one", crate::packing::STATE_WORDS),
            Self::Phrase(error) => error.fmt(f),
            Self::Passphrase(error) => error.fmt(f),
            Self::Random(error) => error.fmt(f),
            Self::Cancelled => crate::CancelledError.fmt(f),
            Self::Readback(issue) => write!(f, "internal error: {issue}"),
            Self::NoThreadResult => f.write_str("internal error: no phrase was drawn"),
        }
    }
}
impl std::error::Error for WalletCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Phrase(error) => Some(error),
            Self::Passphrase(error) => Some(error),
            Self::Random(error) => Some(error),
            Self::Readback(issue) => Some(issue),
            Self::Cancelled => Some(&crate::CancelledError),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for WalletCheckError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
