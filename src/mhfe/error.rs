//! Failures of the MHFE cipher, its state geometry and recovery-length rules.
use std::fmt;

/// Why the core could not encrypt or recover exactly the requested state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherError {
    /// A word-count, container policy or state-geometry refusal.
    Format(crate::FormatError),
    /// Detection found several short lengths whose built-in check passes, by accident about once
    /// in four billion containers, where one phrase is needed: the length must be stated, one of
    /// `readings`, the lengths it can be read as in ascending order, 24 words last.
    AmbiguousLength {
        /// The lengths in words the container can be read as, ascending, 24 last.
        readings: Vec<usize>,
    },
    /// A phrase to be encrypted again whose built-in check finds another length, `found`, than the
    /// one stated, `stated`: the check takes precedence, but a receiving address or the master key
    /// fingerprint of the wallet must confirm the phrase before a rekey seals it, since a stated
    /// length is usually right (the specification's re-encryption rules). Where 24 words were
    /// stated, only they tell the readings apart.
    LengthDiffers {
        /// The length in words that was stated.
        stated: usize,
        /// The length in words whose built-in check passes.
        found: usize,
    },
    /// The container would equal the original phrase (see the specification, step 4 of
    /// "Creating a container"). This practically means a broken Argon2 engine.
    FixedPoint,
    /// The new container did not turn back into the original when it was checked (step 6 of
    /// "Creating a container"): a memory error or another fault. Nothing was produced.
    VerificationFailed,
    /// The common BIP39 reader refused the phrase or entropy.
    Phrase(crate::PhraseError),
    /// The reference engine or memory preflight failed.
    Engine(crate::engine::EngineError),
    /// The requested work-factor settings were refused.
    Settings(crate::SettingsError),
    /// The caller stopped before the next round.
    Cancelled,
}
impl CipherError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::Format(error) => error.error_code(),
            Self::AmbiguousLength { .. } => crate::ErrorCode::AmbiguousLength,
            Self::LengthDiffers { .. } => crate::ErrorCode::LengthDiffers,
            Self::FixedPoint => crate::ErrorCode::FixedPoint,
            Self::VerificationFailed => crate::ErrorCode::VerificationFailed,
            Self::Phrase(error) => error.error_code(),
            Self::Engine(error) => error.error_code(),
            Self::Settings(error) => error.error_code(),
            Self::Cancelled => crate::ErrorCode::Cancelled,
        }
    }
    /// Whether `error` is one of the refusals the length rules give a suite 4 phrase or container
    /// before any Argon2 work: a 24-word original, a length choice that does not apply to the
    /// suite, or a container whose length the suite does not have. The last has the code of any
    /// unreadable container, so the caller reads the container first. Suite 4's validation fixture
    /// names these cases "rejected" without an error code.
    #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
    pub(crate) fn is_length_refusal(error: &Self) -> bool {
        matches!(
            error,
            Self::Format(
                crate::FormatError::SameLengthNeedsShortPhrase
                    | crate::FormatError::LengthChoiceNotApplicable { .. }
                    | crate::FormatError::ContainerSuite { .. }
            ) | Self::Phrase(crate::PhraseError::Container(_))
        )
    }

    /// The stable machine-readable spelling.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<crate::PhraseError> for CipherError {
    fn from(error: crate::PhraseError) -> Self {
        Self::Phrase(error)
    }
}
impl From<crate::engine::EngineError> for CipherError {
    fn from(error: crate::engine::EngineError) -> Self {
        Self::Engine(error)
    }
}
impl From<crate::SettingsError> for CipherError {
    fn from(error: crate::SettingsError) -> Self {
        Self::Settings(error)
    }
}
impl From<crate::CancelledError> for CipherError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}
impl From<crate::FormatError> for CipherError {
    fn from(error: crate::FormatError) -> Self {
        Self::Format(error)
    }
}
impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(f),
            Self::AmbiguousLength { readings } => {
                // The 24-word reading, last, has no check to pass.
                let passing = &readings[..readings.len().saturating_sub(1)];
                write!(
                    f,
                    "the built-in check passes for {} words by accident: a receiving address or \
                     the master key fingerprint of the wallet tells the readings apart",
                    passing
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" and ")
                )
            }
            Self::LengthDiffers { stated, found } => write!(
                f,
                "the built-in check finds a {found}-word original seed phrase, not the {stated} \
                 words stated: confirm it with a receiving address or the master key fingerprint \
                 of the wallet"
            ),
            Self::FixedPoint => write!(
                f,
                "the container would be identical to the original seed phrase, which should \
                 never happen; nothing was produced. Choose a different password, PIM or \
                 memory level, and report this if it happens again"
            ),
            Self::VerificationFailed => write!(
                f,
                "the new container did not turn back into the original seed phrase when it was \
                 checked, which points to a memory error or another fault; it was discarded. \
                 Run the encryption again, and have the computer's memory tested if it happens \
                 again"
            ),
            Self::Phrase(error) => error.fmt(f),
            Self::Engine(error) => error.fmt(f),
            Self::Settings(error) => error.fmt(f),
            Self::Cancelled => crate::CancelledError.fmt(f),
        }
    }
}
impl std::error::Error for CipherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Phrase(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::Settings(error) => Some(error),
            Self::Cancelled => Some(&crate::CancelledError),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for CipherError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
