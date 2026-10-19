//! Typed failures of bounded strength estimation; supplied text never enters an error.

/// Why a strength estimate could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrengthError {
    /// The password's bounded check-word review failed.
    Review(crate::check_word::ReviewError),
    /// The shared EFF word counter failed.
    Eff(crate::eff::EffError),
}

impl StrengthError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::Review(error) => error.error_code(),
            Self::Eff(error) => error.error_code(),
        }
    }

    /// The machine-readable refusal code.
    // Deliberate copy: each module exposes its own const accessor and typed conversions;
    // ErrorCode::as_str owns the spelling, not this wrapper (RUST-04, CORE-10).
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl From<crate::check_word::ReviewError> for StrengthError {
    fn from(error: crate::check_word::ReviewError) -> Self {
        Self::Review(error)
    }
}

impl From<crate::eff::EffError> for StrengthError {
    fn from(error: crate::eff::EffError) -> Self {
        Self::Eff(error)
    }
}

impl std::fmt::Display for StrengthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Review(error) => error.fmt(formatter),
            Self::Eff(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for StrengthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Review(error) => Some(error),
            Self::Eff(error) => Some(error),
        }
    }
}

impl crate::ErrorIdentity for StrengthError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
