//! Exit codes, so that scripts can tell the kinds of outcome apart.

use std::fmt;

use mhfe::{ErrorCode, MhfeError};

// Deliberate copy in the standalone Python launcher, compared by its parity tests.
pub(crate) const SUCCESS: i32 = 0;
/// An error inside the tool or its environment, such as an Argon2 failure or unreadable input.
// Deliberate copy in the standalone Python launcher, compared by its parity tests.
pub(crate) const INTERNAL_ERROR: i32 = 1;
/// A mistake in what was typed: an invalid phrase, container, password, setting or option.
// Deliberate copy in the standalone Python launcher, compared by its parity tests.
pub(crate) const INVALID_INPUT: i32 = 2;
/// The recovered phrase failed its check or does not match the reference: usually a wrong
/// password, PIM, memory level or container.
pub(crate) const NO_MATCH: i32 = 3;
/// The computer cannot run the request: not enough memory for the memory level, memory that could
/// not be reserved, or a level beyond what this environment can use.
pub(crate) const NOT_ENOUGH_RESOURCES: i32 = 4;
/// `check` recovered only readings that nothing verifies: a 24-word reading without a wallet
/// reference, which a wrong password gives too, or several lengths whose built-in checks pass with
/// none of them stated.
pub(crate) const NOT_VERIFIED: i32 = 5;
/// Stopped by the person: Ctrl+C (128 + SIGINT, as shells report it), and as it Ctrl+\, Ctrl+Z,
/// SIGTERM or a closed terminal, Escape or q at a question, or Ctrl+D at an empty prompt.
pub(crate) const CANCELLED: i32 = 130;

/// A reason to stop, with the text to show and the exit code to return.
#[derive(Debug)]
pub(crate) struct Failure {
    message: String,
    exit_code: i32,
}

impl Failure {
    /// The already rendered refusal, without granting mutable access to it.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// Takes the rendered text when a caller needs ownership, without copying it.
    #[cfg(test)]
    pub(crate) fn into_message(self) -> String {
        self.message
    }

    /// Adds frontend advice to this refusal while keeping its exit classification.
    pub(crate) fn with_advice(mut self, advice: &str) -> Self {
        self.message.push_str(advice);
        self
    }

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

impl From<MhfeError> for Failure {
    fn from(error: MhfeError) -> Self {
        let exit_code = match error.error_code() {
            ErrorCode::InvalidPhrase
            | ErrorCode::InvalidContainer
            | ErrorCode::InvalidWordCount
            | ErrorCode::SameLengthNeedsShortPhrase
            | ErrorCode::LengthChoiceNotApplicable
            | ErrorCode::NoBuiltInCheck
            | ErrorCode::NoWalletCheck
            | ErrorCode::NoHiddenWallets
            | ErrorCode::ReferenceRequired
            | ErrorCode::HiddenWalletPassesCheck
            | ErrorCode::InvalidRepairWords
            | ErrorCode::InvalidWordWish
            | ErrorCode::RepairNotPossible
            | ErrorCode::TooManyMissingWords
            | ErrorCode::InvalidPim
            | ErrorCode::InvalidMemoryLevel
            | ErrorCode::EmptyPassword
            | ErrorCode::PasswordTooLong
            | ErrorCode::InvalidPasswordUtf8
            | ErrorCode::ControlCharacterInPassword
            | ErrorCode::UnassignedCharacter
            | ErrorCode::InvalidAddress
            | ErrorCode::InvalidDerivationPath
            | ErrorCode::InvalidFingerprint
            | ErrorCode::InvalidPassphrase
            | ErrorCode::PassphraseTooLong
            | ErrorCode::InvalidRequest
            | ErrorCode::InvalidPasswordSize
            | ErrorCode::InvalidDiceRolls
            | ErrorCode::PasswordRepairNotOffered
            | ErrorCode::WalletCheckNeedsPassphrase
            | ErrorCode::PasswordsDiffer
            | ErrorCode::PassphrasesDiffer
            | ErrorCode::PasswordAlreadyUsed
            | ErrorCode::NewPasswordSameAsOld
            | ErrorCode::InvalidCoin => INVALID_INPUT,
            ErrorCode::VerifierMismatch
            | ErrorCode::AmbiguousLength
            | ErrorCode::SeveralCandidatesMatch
            | ErrorCode::LengthDiffers
            | ErrorCode::ReferenceMismatch
            | ErrorCode::NotConfirmedByOwner => NO_MATCH,
            ErrorCode::NotEnoughMemory
            | ErrorCode::MemoryAllocationFailed
            | ErrorCode::MemoryLevelNotSupportedHere => NOT_ENOUGH_RESOURCES,
            ErrorCode::Cancelled => CANCELLED,
            ErrorCode::FixedPoint
            | ErrorCode::VerificationFailed
            | ErrorCode::Argon2Failed
            | ErrorCode::RandomFailed
            | ErrorCode::SelfCheckFailed
            | ErrorCode::InternalError => INTERNAL_ERROR,
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

// Each leaf keeps its own errors; only this command-line boundary converts them to exit status.
impl From<mhfe::PasswordError> for Failure {
    fn from(error: mhfe::PasswordError) -> Self {
        MhfeError::from(error).into()
    }
}
impl From<mhfe::check_word::ReviewError> for Failure {
    fn from(error: mhfe::check_word::ReviewError) -> Self {
        MhfeError::from(error).into()
    }
}
impl From<mhfe::new_password::NewPasswordError> for Failure {
    fn from(error: mhfe::new_password::NewPasswordError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::PhraseError> for Failure {
    fn from(error: mhfe::PhraseError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::repair::RepairError> for Failure {
    fn from(error: mhfe::repair::RepairError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::wallet::WalletError> for Failure {
    fn from(error: mhfe::wallet::WalletError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::word_wishes::WishError> for Failure {
    fn from(error: mhfe::word_wishes::WishError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::wallet_check::WalletCheckError> for Failure {
    fn from(error: mhfe::wallet_check::WalletCheckError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::SettingsError> for Failure {
    fn from(error: mhfe::SettingsError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::engine::EngineError> for Failure {
    fn from(error: mhfe::engine::EngineError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::CipherError> for Failure {
    fn from(error: mhfe::CipherError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::HiddenError> for Failure {
    fn from(error: mhfe::HiddenError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::RehearsalError> for Failure {
    fn from(error: mhfe::RehearsalError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::search::SearchError> for Failure {
    fn from(error: mhfe::search::SearchError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::self_test::SelfTestError> for Failure {
    fn from(error: mhfe::self_test::SelfTestError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::self_check::SelfCheckError> for Failure {
    fn from(error: mhfe::self_check::SelfCheckError) -> Self {
        MhfeError::from(error).into()
    }
}

impl From<mhfe::FormatError> for Failure {
    fn from(error: mhfe::FormatError) -> Self {
        MhfeError::from(error).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhfe::random::RandomError;

    #[test]
    fn module_owned_random_errors_keep_input_and_environment_exit_categories() {
        assert_eq!(
            Failure::from(MhfeError::from(RandomError::Cancelled)).exit_code,
            CANCELLED
        );
        assert_eq!(
            Failure::from(MhfeError::from(RandomError::InvalidBound(1))).exit_code,
            INVALID_INPUT
        );
        assert_eq!(
            Failure::from(MhfeError::from(RandomError::Page)).exit_code,
            INTERNAL_ERROR
        );
    }
}
