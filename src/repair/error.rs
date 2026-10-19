//! Refusals of the repair-card profile, with typed counts and hint state.
use crate::{ErrorCode, PhraseError};
use std::fmt;

/// Why a repair card could not be created or applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairError {
    /// Raw repair input exceeds the shared UTF-8 utility bound.
    Text(crate::input_text::TextSizeError),
    /// The card size is unsupported.
    WordCount {
        /// The number supplied, without any card word.
        count: usize,
        /// Whether input is being read from a card and needs the unreadable-word hint.
        unreadable_hint: bool,
    },
    /// A written container, including unreadable markers, has no supported length.
    ContainerLength(usize),
    /// A well-formed container is required to generate its parity.
    Phrase(PhraseError),
    /// No correction within this card's bound passes the BIP39 checksum.
    NotPossible {
        /// The card's supported number of parity words.
        repair_words: usize,
    },
    /// A generated card failed its own codeword and erasure readback.
    ParityReadback,
}
impl RepairError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Text(error) => error.error_code(),
            Self::WordCount { .. } => ErrorCode::InvalidRepairWords,
            Self::ContainerLength(_) => ErrorCode::InvalidContainer,
            Self::Phrase(error) => error.error_code(),
            Self::NotPossible { .. } => ErrorCode::RepairNotPossible,
            Self::ParityReadback => ErrorCode::InternalError,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
    pub(super) const fn with_unreadable_hint(self) -> Self {
        match self {
            Self::WordCount { count, .. } => Self::WordCount {
                count,
                unreadable_hint: true,
            },
            other => other,
        }
    }
}
impl From<PhraseError> for RepairError {
    fn from(error: PhraseError) -> Self {
        Self::Phrase(error)
    }
}
impl From<crate::input_text::TextSizeError> for RepairError {
    fn from(error: crate::input_text::TextSizeError) -> Self {
        Self::Text(error)
    }
}
impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(error) => error.fmt(f),
            Self::WordCount { count, unreadable_hint } => {
                write!(f, "the repair words cannot be used: a card has {} repair words, not {count}", crate::text::counts_text(&super::REPAIR_WORD_COUNTS))?;
                if *unreadable_hint { write!(f, "; {}", UnreadableHint)?; }
                Ok(())
            }
            Self::ContainerLength(count) => write!(f, "the container is not a valid English BIP39 phrase: it has {count} {}, but a container has {}; {}", if *count == 1 { "word" } else { "words" }, crate::phrase::word_counts_text(), UnreadableHint),
            Self::Phrase(error) => error.fmt(f),
            Self::NotPossible { repair_words } => write!(f, "the container phrase cannot be repaired with {repair_words} repair words: more words are damaged than they can repair (each repairs one unreadable word, two repair one wrong word), or the card belongs to another container phrase"),
            Self::ParityReadback => f.write_str("internal error: the new repair words do not repair their container phrase"),
        }
    }
}
impl std::error::Error for RepairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Text(error) => Some(error),
            Self::Phrase(error) => Some(error),
            _ => None,
        }
    }
}

/// One shared sentence fragment for the two typed input refusals that offer this hint.
struct UnreadableHint;
impl fmt::Display for UnreadableHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "type {} for a word that cannot be read",
            super::UNREADABLE
        )
    }
}

impl crate::ErrorIdentity for RepairError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
