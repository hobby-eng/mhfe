//! A shared cancellation signal for independent modules and host callbacks.

use std::fmt;

use crate::ErrorCode;

/// The caller stopped an operation. It carries no host text or secret data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelledError;

impl CancelledError {
    /// The stable typed cancellation identifier.
    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::Cancelled
    }

    /// The machine-readable cancellation code.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl fmt::Display for CancelledError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the operation was cancelled")
    }
}

impl std::error::Error for CancelledError {}

impl crate::ErrorIdentity for CancelledError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
