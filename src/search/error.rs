//! Typed candidate-search refusals; no container words or reference values are retained.
use crate::{repair::RepairError, ErrorCode};
use std::fmt;

/// Why a missing-word search cannot select a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    /// The input has an invalid checksum but no unreadable word.
    WrongWord,
    /// The input is a complete container with no marked missing word.
    NoMissingWord,
    /// This search requires a reference that identifies a wallet.
    WalletReferenceRequired,
    /// Too many words are missing for the requested search.
    TooManyMissing {
        /// The number of missing words.
        missing: usize,
        /// The search's supported maximum.
        limit: usize,
    },
    /// More than one candidate matched and no unique container may be selected.
    SeveralMatches {
        /// The number that matched.
        matches: usize,
    },
    /// The written container's repair-style parsing failed.
    Repair(RepairError),
}
impl SearchError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::WrongWord | Self::NoMissingWord | Self::WalletReferenceRequired => {
                ErrorCode::InvalidRequest
            }
            Self::TooManyMissing { .. } => ErrorCode::TooManyMissingWords,
            Self::SeveralMatches { .. } => ErrorCode::SeveralCandidatesMatch,
            Self::Repair(error) => error.error_code(),
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<RepairError> for SearchError {
    fn from(error: RepairError) -> Self {
        Self::Repair(error)
    }
}
impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongWord => write!(f, "invalid request: every word is in the BIP39 list, but the container phrase's checksum fails: a word is wrong, not missing; type {} in the place of a word that cannot be read", crate::repair::UNREADABLE),
            Self::NoMissingWord => write!(f, "invalid request: no word of the container phrase is marked missing: type {} in its place", crate::repair::UNREADABLE),
            Self::WalletReferenceRequired => f.write_str("invalid request: a search compares with a receiving address or a master key fingerprint"),
            Self::TooManyMissing { missing, limit } => write!(f, "{missing} words of the container phrase are missing, but this search finds at most {limit}: each further word multiplies the candidates by about {}; only the repair words repair more", crate::text::grouped(crate::phrase::LIST_SIZE)),
            Self::SeveralMatches { matches } => write!(f, "{matches} candidate container phrases match the reference, which cannot tell them apart, so none is taken: search again with a receiving address of the same wallet, which tells them apart"),
            Self::Repair(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repair(error) => Some(error),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for SearchError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
