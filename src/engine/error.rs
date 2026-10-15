//! Failures of Argon2 and its memory, without arbitrary dependency or page prose.
use crate::{ErrorCode, SettingsError};
use std::fmt;

const REFERENCE_MESSAGES: &[&str] = include!(concat!(env!("OUT_DIR"), "/argon2-messages.rs"));

/// One fixed message of the vendored reference C implementation. Caller text is accepted only
/// when it exactly matches that generated vocabulary, and is then replaced by its static entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceMessage(usize);
impl ReferenceMessage {
    /// Reads an exact reference message without retaining a caller's buffer.
    pub fn read(text: &str) -> Option<Self> {
        REFERENCE_MESSAGES
            .iter()
            .position(|candidate| *candidate == text)
            .map(Self)
    }
    #[cfg(any(not(target_arch = "wasm32"), test))]
    pub(super) const fn unknown() -> Self {
        Self(REFERENCE_MESSAGES.len() - 1)
    }
}
impl fmt::Display for ReferenceMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REFERENCE_MESSAGES[self.0])
    }
}

/// A reference or bridge failure; its message carries no arbitrary page exception text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Failure {
    /// A fixed message of the vendored reference C implementation.
    Reference(ReferenceMessage),
    /// The engine returned without a usable key.
    UnwrittenKey,
    /// The page threw an unrecognized engine exception.
    Page(super::Argon2Cost),
}
impl fmt::Display for Argon2Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(message) => message.fmt(f),
            Self::UnwrittenKey => f.write_str("the Argon2 engine returned without writing the key"),
            Self::Page(cost) => {
                let unit = if cost.passes() == 1 { "pass" } else { "passes" };
                write!(
                    f,
                    "the browser Argon2 engine failed at {} KiB and {} {unit}",
                    cost.memory_kib(),
                    cost.passes()
                )
            }
        }
    }
}
impl std::error::Error for Argon2Failure {}

/// Why the reference engine could not compute a tag or reserve its work area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The computer reports less free memory than the memory level needs.
    NotEnoughMemory {
        /// The memory the level needs, in bytes.
        needed_bytes: u64,
        /// The free memory the computer reports, in bytes.
        available_bytes: u64,
    },
    /// The operating system refused to reserve the Argon2 memory.
    MemoryAllocation {
        /// The memory asked for, in bytes.
        bytes: u64,
    },
    /// The reference implementation or its browser bridge failed.
    Argon2(Argon2Failure),
    /// The input length cannot be passed to the C interface.
    InputTooLong,
    /// A retained round-key self-check fixture lacks this public password/salt pair.
    NoPublishedRound,
    /// Work-factor settings are outside the selected engine's capacity.
    Settings(SettingsError),
}
impl EngineError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotEnoughMemory { .. } => ErrorCode::NotEnoughMemory,
            Self::MemoryAllocation { .. } => ErrorCode::MemoryAllocationFailed,
            Self::Argon2(_) => ErrorCode::Argon2Failed,
            Self::InputTooLong | Self::NoPublishedRound => ErrorCode::InternalError,
            Self::Settings(error) => error.error_code(),
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<SettingsError> for EngineError {
    fn from(error: SettingsError) -> Self {
        Self::Settings(error)
    }
}
impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughMemory {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "this memory level needs {} of memory, but only {} is available; close \
                 other programs or choose a lower memory level",
                crate::text::memory_text(*needed_bytes),
                crate::text::memory_text(*available_bytes)
            ),
            Self::MemoryAllocation { bytes } => write!(
                f,
                "the computer could not reserve {} of memory for Argon2",
                crate::text::memory_text(*bytes)
            ),
            Self::Argon2(error) => write!(f, "Argon2 failed: {error}"),
            Self::InputTooLong => f.write_str("internal error: an Argon2 input exceeds 4 GiB"),
            Self::NoPublishedRound => {
                f.write_str("internal error: no published round has this password and salt")
            }
            Self::Settings(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Settings(error) => Some(error),
            Self::Argon2(error) => Some(error),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for EngineError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_failure_keeps_only_its_public_cost_and_uses_singular_counts() {
        for (passes, expected) in [
            (1, "the browser Argon2 engine failed at 1024 KiB and 1 pass"),
            (
                12,
                "the browser Argon2 engine failed at 1024 KiB and 12 passes",
            ),
        ] {
            let reason = Argon2Failure::Page(crate::engine::Argon2Cost::new(1024, passes));
            assert_eq!(reason.to_string(), expected);
            assert_eq!(EngineError::Argon2(reason).code(), "ARGON2_FAILED");
        }
    }
    #[test]
    fn reference_messages_are_closed_and_page_text_is_not_retained() {
        for text in REFERENCE_MESSAGES {
            assert_eq!(ReferenceMessage::read(text).unwrap().to_string(), *text);
        }
        for text in [
            "synthetic-private-marker",
            "Threading failure synthetic-private-marker",
            "ARGON2_FAILED: Threading failure",
        ] {
            assert_eq!(ReferenceMessage::read(text), None);
        }
        assert_eq!(
            ReferenceMessage::unknown().to_string(),
            "Unknown error code"
        );
    }
}
