//! Typed refusals of bounded password review and explicit choices.

/// Why a bounded password review or an explicit choice was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// The raw utility input exceeds its explicit byte limit.
    Text(crate::input_text::TextSizeError),
    /// The shared EFF list refused a lookup or could not be read.
    Eff(crate::eff::EffError),
    /// The explicit choice was absent from this review.
    NotOffered,
    /// The caller supplied a review-choice name the profile does not offer.
    UnknownChoice,
    /// A drawn word's index is outside the EFF list.
    InvalidIndex,
}
impl ReviewError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::Text(error) => error.error_code(),
            Self::Eff(error) => error.error_code(),
            Self::NotOffered => crate::ErrorCode::PasswordRepairNotOffered,
            Self::UnknownChoice | Self::InvalidIndex => crate::ErrorCode::InvalidRequest,
        }
    }
    /// The machine-readable refusal code.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl std::fmt::Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(error) => error.fmt(f),
            Self::Eff(error) => error.fmt(f),
            Self::NotOffered => {
                f.write_str("the review of this password did not offer that choice")
            }
            Self::UnknownChoice => f.write_str("invalid request: unknown password choice"),
            Self::InvalidIndex => {
                f.write_str("invalid request: password word index is outside the EFF list")
            }
        }
    }
}
impl std::error::Error for ReviewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Text(error) => Some(error),
            Self::Eff(error) => Some(error),
            _ => None,
        }
    }
}
impl From<crate::input_text::TextSizeError> for ReviewError {
    fn from(error: crate::input_text::TextSizeError) -> Self {
        Self::Text(error)
    }
}
impl From<crate::eff::EffError> for ReviewError {
    fn from(error: crate::eff::EffError) -> Self {
        Self::Eff(error)
    }
}

impl crate::ErrorIdentity for ReviewError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
