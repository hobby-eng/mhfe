//! Exit codes, so that scripts can tell the kinds of outcome apart.

use std::fmt;

use mhfe::MhfeError;

/// What an operation of the library came to: its value or its refusal, or, when a callback stopped
/// it, the end of the command as a cancel ends it, with exit code 130.
pub(crate) trait Finished<T> {
    fn finished(self) -> Result<T, MhfeError>;
}

impl<T> Finished<T> for mhfe::Outcome<T> {
    fn finished(self) -> Result<T, MhfeError> {
        match self? {
            std::ops::ControlFlow::Continue(value) => Ok(value),
            std::ops::ControlFlow::Break(()) => crate::terminal::exit_cancelled(),
        }
    }
}

pub(crate) const SUCCESS: i32 = 0;
/// An error inside the tool or its environment, such as an Argon2 failure or unreadable input.
pub(crate) const INTERNAL_ERROR: i32 = 1;
/// A mistake in what was typed: an invalid phrase, container, password, setting or option.
pub(crate) const INVALID_INPUT: i32 = 2;
/// The recovered phrase failed its check or does not match the reference: usually a wrong
/// password, PIM, memory level or container.
pub(crate) const NO_MATCH: i32 = 3;
/// The computer cannot run the request: not enough memory for the memory level, memory that could
/// not be reserved, or a level beyond what this environment can use.
pub(crate) const NOT_ENOUGH_RESOURCES: i32 = 4;
/// Stopped by the person: Ctrl+C (128 + SIGINT, as shells report it), and as it Ctrl+\, Ctrl+Z,
/// SIGTERM or a closed terminal, Escape or q at a question, or Ctrl+D at an empty prompt.
pub(crate) const CANCELLED: i32 = 130;

/// Whether `code` is one of the above, with which this tool ends by itself. A process of it that
/// crashed or was killed gives none of them, or on Unix no code at all.
pub(crate) fn is_own(code: i32) -> bool {
    matches!(
        code,
        SUCCESS | INTERNAL_ERROR | INVALID_INPUT | NO_MATCH | NOT_ENOUGH_RESOURCES | CANCELLED
    )
}

/// A reason to stop, with the text to show and the exit code to return.
#[derive(Debug)]
pub(crate) struct Failure {
    pub message: String,
    pub exit_code: i32,
}

impl Failure {
    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: INVALID_INPUT,
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: INTERNAL_ERROR,
        }
    }

    /// A stop whose reason the command has shown already: `main` adds nothing.
    pub(crate) fn shown(exit_code: i32) -> Self {
        Self {
            message: String::new(),
            exit_code,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

// The message holds the text of any error under it already, so `source` adds none.
impl std::error::Error for Failure {}

impl From<mhfe::repair::RepairError> for Failure {
    fn from(error: mhfe::repair::RepairError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::new_password::NewPasswordError> for Failure {
    fn from(error: mhfe::new_password::NewPasswordError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::wallet::WalletError> for Failure {
    fn from(error: mhfe::wallet::WalletError) -> Self {
        MhfeError::from(error).into()
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
            | MhfeError::NoWalletCheck { .. }
            | MhfeError::NoHiddenWallets { .. }
            | MhfeError::ReferenceRequired
            | MhfeError::HiddenWalletPassesCheck
            | MhfeError::InvalidRepairWords(_)
            | MhfeError::RepairNotPossible { .. }
            | MhfeError::TooManyMissingWords { .. }
            | MhfeError::InvalidPim(_)
            | MhfeError::InvalidMemoryLevel(_)
            | MhfeError::EmptyPassword
            | MhfeError::PasswordTooLong(_)
            | MhfeError::InvalidPasswordUtf8
            | MhfeError::ControlCharacterInPassword
            | MhfeError::UnassignedCharacter
            | MhfeError::InvalidAddress(_)
            | MhfeError::InvalidDerivationPath(_)
            | MhfeError::InvalidFingerprint(_)
            | MhfeError::InvalidPassphrase
            | MhfeError::InvalidRequest(_)
            | MhfeError::InvalidPasswordSize(_)
            | MhfeError::InvalidDiceRolls(_)
            | MhfeError::PasswordRepairNotOffered
            | MhfeError::WalletCheckNeedsPassphrase
            | MhfeError::PasswordsDiffer
            | MhfeError::PassphrasesDiffer
            | MhfeError::NoBuiltInCheckAtLength(_)
            | MhfeError::NoWalletCheckAtLength(_)
            | MhfeError::InvalidWordWish(_)
            | MhfeError::PasswordAlreadyUsed
            | MhfeError::NewPasswordSameAsOld
            | MhfeError::InvalidCoin(_) => INVALID_INPUT,
            MhfeError::VerifierMismatch
            | MhfeError::AmbiguousLength { .. }
            | MhfeError::LengthDiffers { .. }
            | MhfeError::ReferenceMismatch
            | MhfeError::NotConfirmedByOwner => NO_MATCH,
            MhfeError::NotEnoughMemory { .. }
            | MhfeError::MemoryAllocation { .. }
            | MhfeError::MemoryLevelNotSupportedHere { .. } => NOT_ENOUGH_RESOURCES,
            MhfeError::FixedPoint
            | MhfeError::VerificationFailed
            | MhfeError::Argon2(_)
            | MhfeError::RandomFailed(_)
            | MhfeError::SelfCheckFailed { .. }
            | MhfeError::Internal(_) => INTERNAL_ERROR,
        };
        Self {
            message: capitalize(&error.to_string()),
            exit_code,
        }
    }
}

impl From<mhfe_core::Error> for Failure {
    fn from(error: mhfe_core::Error) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("Input or output failed: {error}"))
    }
}

/// A refused answer as the person reads it: the error as a sentence, then `then`, such as "Please
/// type it again.", or nothing more when `then` is empty.
pub(crate) fn refused(error: &impl fmt::Display, then: &str) -> String {
    let sentence = format!("{}.", capitalize(&error.to_string()));
    if then.is_empty() {
        return sentence;
    }
    format!("{sentence} {then}")
}

/// Library messages start in lower case so that they read well inside other sentences.
pub(crate) fn capitalize(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RUST-04: a failure goes wherever a standard error is expected, and reads as its message.
    #[test]
    fn a_failure_is_a_standard_error() {
        let failure = Failure::from(MhfeError::EmptyPassword);
        let error: &dyn std::error::Error = &failure;
        assert_eq!(error.to_string(), failure.message);
    }

    /// A panic in a debug build, then a crash and an abort on Windows.
    #[test]
    fn the_exit_codes_of_a_crash_are_not_the_tools_own() {
        assert!([0, 1, 2, 3, 4, 130].into_iter().all(is_own));
        let crashes = [101, 0xC000_0005_u32 as i32, 0xC000_0409_u32 as i32];
        assert!(!crashes.into_iter().any(is_own));
    }
}
