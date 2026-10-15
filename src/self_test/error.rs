//! Typed setup and execution failures of the published-vector self-test.
use crate::{CipherError, ErrorCode, PasswordError, SettingsError, WorkFactor};
use std::fmt;

/// One required field of a built-in vector, identified without arbitrary JSON pointer text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorField {
    /// The public vector name.
    Name,
    /// The public input phrase.
    Phrase,
    /// The public input password.
    Password,
    /// The expected container.
    Container,
    /// The recorded PIM.
    Pim,
    /// The recorded memory level.
    MemoryLevel,
}
impl VectorField {
    pub(super) const fn pointer(self) -> &'static str {
        match self {
            Self::Name => "/name",
            Self::Phrase => "/inputs/phrase",
            Self::Password => "/inputs/password",
            Self::Container => "/container",
            Self::Pim => "/inputs/pim",
            Self::MemoryLevel => "/inputs/memory_level",
        }
    }
}
impl fmt::Display for VectorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.pointer())
    }
}

/// Why the self-test could not run. A completed mismatch remains the typed SelfTestResult.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfTestError {
    /// The compiled-in vector is not readable JSON.
    DamagedVector,
    /// A required field is absent or has the wrong representation.
    MissingField(VectorField),
    /// The two compiled-in vectors disagree about the work settings.
    DifferentSettings,
    /// A retained published-round table lacks a required vector.
    MissingPublishedVector,
    /// The supplied engine has different settings from the vectors.
    WrongSettings(WorkFactor),
    /// Cipher execution failed.
    Cipher(CipherError),
    /// A compiled-in public password could not be encoded.
    Password(PasswordError),
    /// Vector settings could not be read as a supported work factor.
    Settings(SettingsError),
    /// The caller cancelled before the next round.
    Cancelled,
}
impl SelfTestError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::DamagedVector
            | Self::MissingField(_)
            | Self::DifferentSettings
            | Self::MissingPublishedVector => ErrorCode::InternalError,
            Self::WrongSettings(_) => ErrorCode::InvalidRequest,
            Self::Cipher(error) => error.error_code(),
            Self::Password(error) => error.error_code(),
            Self::Settings(error) => error.error_code(),
            Self::Cancelled => ErrorCode::Cancelled,
        }
    }
    // Deliberate copy: each module exposes its own constant identity without root coupling.
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<CipherError> for SelfTestError {
    fn from(error: CipherError) -> Self {
        Self::Cipher(error)
    }
}
impl From<PasswordError> for SelfTestError {
    fn from(error: PasswordError) -> Self {
        Self::Password(error)
    }
}
impl From<SettingsError> for SelfTestError {
    fn from(error: SettingsError) -> Self {
        Self::Settings(error)
    }
}
impl From<crate::CancelledError> for SelfTestError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}
impl fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DamagedVector => f.write_str("internal error: a built-in vector is damaged"),
            Self::MissingField(field) => write!(f, "internal error: a built-in vector lacks {field}"),
            Self::DifferentSettings => f.write_str("internal error: the built-in vectors have different settings"),
            Self::MissingPublishedVector => f.write_str("internal error: a built-in vector is missing"),
            Self::WrongSettings(work) => write!(f, "invalid request: the self-test runs at the settings of its vectors, PIM {} and memory level {}", work.pim(), work.memory_level()),
            // Deliberate copy: independent errors delegate their own typed causes (RUST-04).
            Self::Cipher(error) => error.fmt(f), Self::Password(error) => error.fmt(f),
            Self::Settings(error) => error.fmt(f), Self::Cancelled => crate::CancelledError.fmt(f),
        }
    }
}
impl std::error::Error for SelfTestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            Self::Password(error) => Some(error),
            // Deliberate copy: source delegation belongs to this independent error.
            Self::Settings(error) => Some(error),
            Self::Cancelled => Some(&crate::CancelledError),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for SelfTestError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
