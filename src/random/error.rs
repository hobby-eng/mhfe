//! Typed failures of a host byte source and the library's randomness guards.

use std::borrow::Cow;
use std::fmt;

use crate::ErrorCode;

/// A random-source failure. It holds no random bytes or arbitrary text from a host callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    /// The operating system refused a draw; the numeric system code is retained when available.
    OperatingSystem(Option<i32>),
    /// The page's byte source threw or rejected a draw.
    Page,
    /// A deterministic self-check source exhausted its public script.
    ScriptExhausted,
    /// A probe was constant, partially unfilled, or repeated the preceding probe.
    UnusableProbes,
    /// A phrase draw was constant or repeated the preceding entropy.
    UnusableEntropy,
    /// The live-source spread test found too few values or too many repeats.
    UnusableSpread,
    /// Too many consecutive samples lay outside the unbiased acceptance interval.
    RejectionLimit,
    /// A sampling bound lies outside the supported range.
    InvalidBound(usize),
    /// The host cancelled a draw, without converting it into a random-source failure.
    Cancelled,
}

impl RandomError {
    /// A stable typed code, available without constructing a refusal for bindings.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidBound(_) => ErrorCode::InvalidRequest,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::OperatingSystem(_)
            | Self::Page
            | Self::ScriptExhausted
            | Self::UnusableProbes
            | Self::UnusableEntropy
            | Self::UnusableSpread
            | Self::RejectionLimit => ErrorCode::RandomFailed,
        }
    }

    /// The machine-readable identifier, unchanged by the module-owned error type.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl From<crate::CancelledError> for RandomError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason: Cow<'_, str> = match self {
            Self::InvalidBound(bound) => {
                return write!(formatter,
                "invalid request: a number below {bound} is not drawn: only ranges of {} to {} are",
                super::SMALLEST_BOUND, crate::text::grouped(super::LARGEST_BOUND as u64))
            }
            Self::Cancelled => return crate::CancelledError.fmt(formatter),
            Self::OperatingSystem(Some(code)) => {
                format!("the operating system's random source failed with system code {code}")
                    .into()
            }
            Self::OperatingSystem(None) => "the operating system's random source failed".into(),
            Self::Page => "the page's random source failed".into(),
            Self::ScriptExhausted => "the script ran out".into(),
            Self::UnusableProbes => "it gave bytes that cannot be random".into(),
            Self::UnusableEntropy => "it gave an entropy that cannot be random".into(),
            Self::UnusableSpread => "its bytes are not spread as random bytes are".into(),
            Self::RejectionLimit => format!(
                "it gave {} values above the range in a row",
                super::MOST_DRAWN_AGAIN
            )
            .into(),
        };
        write!(formatter, "the random generator failed: {reason}")
    }
}

impl std::error::Error for RandomError {}

impl crate::ErrorIdentity for RandomError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_failures_keep_their_codes_and_messages_when_wrapped() {
        let cases = [
            (
                RandomError::UnusableProbes,
                "it gave bytes that cannot be random",
            ),
            (
                RandomError::UnusableEntropy,
                "it gave an entropy that cannot be random",
            ),
            (
                RandomError::UnusableSpread,
                "its bytes are not spread as random bytes are",
            ),
            (RandomError::ScriptExhausted, "the script ran out"),
            (
                RandomError::RejectionLimit,
                "it gave 128 values above the range in a row",
            ),
            (RandomError::Page, "the page's random source failed"),
            (
                RandomError::OperatingSystem(None),
                "the operating system's random source failed",
            ),
            (
                RandomError::OperatingSystem(Some(5)),
                "the operating system's random source failed with system code 5",
            ),
        ];
        for (error, detail) in cases {
            assert_eq!(error.code(), "RANDOM_FAILED");
            assert_eq!(
                error.to_string(),
                format!("the random generator failed: {detail}")
            );
            let wrapped = crate::MhfeError::from(error);
            assert_eq!(wrapped.code(), error.code());
            assert_eq!(wrapped.to_string(), error.to_string());
            assert!(std::error::Error::source(&wrapped).is_some());
        }
        let cancelled = RandomError::from(crate::CancelledError);
        assert_eq!(cancelled.code(), "CANCELLED");
        assert_eq!(
            crate::MhfeError::from(cancelled),
            crate::MhfeError::Cancelled
        );
        assert_eq!(crate::MhfeError::from(cancelled).code(), "CANCELLED");
        assert_eq!(cancelled.to_string(), "the operation was cancelled");
        let error = RandomError::InvalidBound(1);
        assert_eq!(error.code(), "INVALID_REQUEST");
        assert_eq!(crate::MhfeError::from(error).code(), "INVALID_REQUEST");
        assert_eq!(
            error.to_string(),
            "invalid request: a number below 1 is not drawn: only ranges of 2 to 65,536 are"
        );
    }
}
