//! Exit codes, so that scripts can tell the kinds of outcome apart.

use std::fmt;

use mhfe::MhfeError;

pub const SUCCESS: i32 = 0;
/// An error inside the tool or its environment, such as an Argon2 failure or unreadable input.
pub const INTERNAL_ERROR: i32 = 1;
/// A mistake in what was typed: an invalid phrase, container, password, setting or option.
pub const INVALID_INPUT: i32 = 2;
/// The recovered phrase failed its check or does not match the reference: usually a wrong
/// password, PIM, memory level or container.
pub const NO_MATCH: i32 = 3;
/// The computer cannot run the request: not enough memory for the memory level, or a processor
/// without the features this build needs.
pub const NOT_ENOUGH_RESOURCES: i32 = 4;
/// Stopped with Ctrl+C (128 + SIGINT, as shells report it).
pub const CANCELLED: i32 = 130;

/// A reason to stop, with the text to show and the exit code to return.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub exit_code: i32,
}

impl Failure {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: INVALID_INPUT,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<MhfeError> for Failure {
    fn from(error: MhfeError) -> Self {
        let exit_code = match error {
            MhfeError::InvalidPhrase(_)
            | MhfeError::InvalidContainer(_)
            | MhfeError::InvalidWordCount(_)
            | MhfeError::SameLengthNeedsShortPhrase
            | MhfeError::LengthChoiceNotApplicable { .. }
            | MhfeError::NoBuiltInCheck { .. }
            | MhfeError::ReferenceRequired
            | MhfeError::InvalidPim(_)
            | MhfeError::InvalidMemoryLevel(_)
            | MhfeError::EmptyPassword
            | MhfeError::PasswordTooLong(_)
            | MhfeError::InvalidPasswordUtf8
            | MhfeError::ControlCharacterInPassword
            | MhfeError::UnassignedCharacter
            | MhfeError::InvalidAddress(_)
            | MhfeError::InvalidDerivationPath(_)
            | MhfeError::InvalidFingerprint(_) => INVALID_INPUT,
            MhfeError::VerifierMismatch | MhfeError::ReferenceMismatch => NO_MATCH,
            MhfeError::NotEnoughMemory { .. }
            | MhfeError::MemoryAllocation { .. }
            | MhfeError::MemoryLevelNotSupportedHere { .. } => NOT_ENOUGH_RESOURCES,
            MhfeError::Cancelled => CANCELLED,
            MhfeError::FixedPoint
            | MhfeError::VerificationFailed
            | MhfeError::Argon2(_)
            | MhfeError::Internal(_) => INTERNAL_ERROR,
        };
        Self {
            message: capitalize(&error.to_string()),
            exit_code,
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("Input or output failed: {error}"))
    }
}

/// Library messages start in lower case so that they read well inside other sentences.
pub fn capitalize(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}
