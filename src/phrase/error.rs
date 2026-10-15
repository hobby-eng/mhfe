//! Typed BIP39 input and entropy failures. No phrase word is retained in an error.
use crate::ErrorCode;
use std::fmt;

/// Why text cannot be read as a BIP39 phrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseIssue {
    /// The count of whitespace-separated words is not a BIP39 length.
    WordCount(usize),
    /// This one-based word position is not a full word or unambiguous allowed prefix.
    UnknownWord(usize),
    /// The checksum does not match the completed words.
    Checksum,
    /// Input bytes are not UTF-8 text.
    Utf8,
    /// The dependency rejected an otherwise normalized input in an unexpected way.
    UnexpectedEncoding,
}
impl fmt::Display for PhraseIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount(count) => write!(
                f,
                "it has {count} {}, but a phrase has {}",
                if *count == 1 { "word" } else { "words" },
                super::word_counts_text()
            ),
            Self::UnknownWord(position) => {
                write!(f, "word {position} is not in the English BIP39 word list")
            }
            Self::Checksum => f.write_str(
                "its checksum does not match, so a word is wrong or words are out of order",
            ),
            Self::Utf8 => f.write_str("it is not UTF-8 text"),
            Self::UnexpectedEncoding => {
                f.write_str("its normalized words could not be read as BIP39")
            }
        }
    }
}
impl std::error::Error for PhraseIssue {}

/// An input or entropy failure owned by the phrase module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// Text supplied as an original phrase was refused.
    Original(PhraseIssue),
    /// Text supplied as a container was refused.
    Container(PhraseIssue),
    /// An entropy buffer has a length outside BIP39's five valid sizes.
    EntropyLength(usize),
    /// The dependency refused a size-checked entropy buffer.
    EntropyEncoding,
}
impl PhraseError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Original(_) => ErrorCode::InvalidPhrase,
            Self::Container(_) => ErrorCode::InvalidContainer,
            Self::EntropyLength(_) | Self::EntropyEncoding => ErrorCode::InternalError,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
    pub(super) const fn as_container(self) -> Self {
        match self {
            Self::Original(issue) => Self::Container(issue),
            other => other,
        }
    }
}
impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Original(issue) => write!(
                f,
                "the seed phrase is not a valid English BIP39 phrase: {issue}"
            ),
            Self::Container(issue) => write!(
                f,
                "the container is not a valid English BIP39 phrase: {issue}"
            ),
            Self::EntropyLength(bytes) => write!(
                f,
                "internal error: a BIP39 entropy has {} bytes, not {bytes}",
                crate::text::counts_text(&super::WORD_COUNTS.map(crate::packing::entropy_of_words))
            ),
            Self::EntropyEncoding => {
                f.write_str("internal error: a size-checked BIP39 entropy could not be encoded")
            }
        }
    }
}
impl std::error::Error for PhraseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Original(issue) | Self::Container(issue) => Some(issue),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for PhraseError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
