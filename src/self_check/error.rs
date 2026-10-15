//! Owned self-check refusals and failure framing, without caller-generated detail text.
use super::{FailureDetail, Tier};
use crate::ErrorCode;
use std::fmt;

/// Why a self-check could not be selected or why its first failing component stops the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfCheckError {
    /// The requested tier identifier is unknown; its input spelling is discarded.
    UnknownTier,
    /// A component failed its known answers or a required process protection.
    Failed {
        /// A program-defined static label supplied by ComponentCheck, never a user field.
        component: &'static str,
        /// Typed failure metadata, without the compared values.
        detail: FailureDetail,
    },
}
impl SelfCheckError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnknownTier => ErrorCode::InvalidRequest,
            Self::Failed { .. } => ErrorCode::SelfCheckFailed,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTier => write!(
                f,
                "invalid request: a self-check tier is \"{}\" or \"{}\"",
                Tier::Startup.name(),
                Tier::Full.name()
            ),
            Self::Failed { component, detail } => f.write_str(&Self::failure_message(
                "the self-test failed",
                component,
                detail,
            )),
        }
    }
}
impl std::error::Error for SelfCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed { detail, .. } => Some(detail),
            Self::UnknownTier => None,
        }
    }
}
impl crate::ErrorIdentity for SelfCheckError {
    fn error_code(&self) -> ErrorCode {
        self.error_code()
    }
}

impl SelfCheckError {
    /// The common failure frame used by startup and an explicitly requested self-test. It accepts
    /// rendered details for front ends too; the error itself always holds a typed FailureDetail.
    pub fn failure_message(what: &str, label: &str, detail: impl fmt::Display) -> String {
        let detail = detail.to_string();
        let detail = detail.trim_end_matches('.');
        format!("{what}: {label}: {detail}. Do not use this program on this computer")
    }
}
