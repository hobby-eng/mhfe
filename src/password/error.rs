//! Encoding failures with no password text or code points in their fields.
use crate::ErrorCode;
use std::fmt;

/// A refusal of password encoding, repetition or an explicit review choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    /// The normalized password is empty.
    EmptyPassword,
    /// The normalized byte length exceeds the supported maximum.
    PasswordTooLong(u128),
    /// The input bytes are not UTF-8.
    InvalidPasswordUtf8,
    /// The input contains a forbidden control or separator.
    ControlCharacterInPassword,
    /// The input contains a character not assigned by the pinned Unicode version.
    UnassignedCharacter,
    /// The exact typed repetition differs.
    PasswordsDiffer,
    /// The chosen correction or repair was not offered.
    Review(crate::check_word::ReviewError),
}
impl PasswordError {
    /// The stable typed code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::EmptyPassword => ErrorCode::EmptyPassword,
            Self::PasswordTooLong(_) => ErrorCode::PasswordTooLong,
            Self::InvalidPasswordUtf8 => ErrorCode::InvalidPasswordUtf8,
            Self::ControlCharacterInPassword => ErrorCode::ControlCharacterInPassword,
            Self::UnassignedCharacter => ErrorCode::UnassignedCharacter,
            Self::PasswordsDiffer => ErrorCode::PasswordsDiffer,
            Self::Review(error) => error.error_code(),
        }
    }
    /// The machine-readable code.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<crate::check_word::ReviewError> for PasswordError {
    fn from(error: crate::check_word::ReviewError) -> Self {
        Self::Review(error)
    }
}
impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassword => write!(f, "the password is empty"),
            Self::PasswordTooLong(bytes) => write!(
                f,
                "the password is too long: {bytes} bytes after Unicode normalization, \
                 but at most {} are allowed",
                crate::MAX_PASSWORD_BYTES
            ),
            Self::InvalidPasswordUtf8 => write!(f, "the password is not valid UTF-8 text"),
            Self::ControlCharacterInPassword => write!(
                f,
                "the password contains a control character, such as a tab, NUL or line break, \
                 or a line or paragraph separator (U+2028, U+2029); a password may not contain \
                 them, so that every program takes it as typed"
            ),
            Self::UnassignedCharacter => write!(
                f,
                "the password contains a character that Unicode 17.0.0 does not define; \
                 use only defined characters so that every future version reads the \
                 password the same way"
            ),
            Self::PasswordsDiffer => write!(f, "the password and its repetition differ"),
            Self::Review(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for PasswordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Review(error) => Some(error),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for PasswordError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
