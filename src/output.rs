//! Safe diagnostic reasons for an output representation that could not be produced.
use crate::ErrorCode;
use std::fmt;

/// An internal output conversion failed; serializer text or secret values never enter the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputError {
    /// The program's result could not be serialized to JSON.
    Json,
    /// The program's serialized result is not UTF-8.
    Utf8,
}
impl OutputError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::InternalError
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("internal error: ")?;
        f.write_str(match self {
            Self::Json => "the result could not be serialized as JSON",
            Self::Utf8 => "the result is not UTF-8",
        })
    }
}
impl std::error::Error for OutputError {}

impl crate::ErrorIdentity for OutputError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
