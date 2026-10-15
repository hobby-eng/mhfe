//! Defensive failures while exporting fixed public test vectors.
use crate::ErrorCode;
use std::fmt;

/// The vector recorder refused to emit an unverified or non-public record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorError {
    /// The recorded inverse did not recover the input state.
    RoundTrip,
    /// The record is not one of the fixed public inputs at its recorded settings.
    PublicInputRequired,
}
impl VectorError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::InternalError
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for VectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("internal error: ")?;
        f.write_str(match self {
            Self::RoundTrip => "the vector round trip did not return the original state",
            Self::PublicInputRequired => {
                "test vectors are made only from the fixed public inputs, at their own settings"
            }
        })
    }
}
impl std::error::Error for VectorError {}

impl crate::ErrorIdentity for VectorError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
