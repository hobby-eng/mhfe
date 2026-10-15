//! Work-factor refusals, independent of encryption and its front ends.
use super::Settings;
use crate::ErrorCode;
use std::fmt;

/// Why PIM or memory settings cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    /// A PIM above [`crate::MAX_PIM`], of the settings that the message names.
    InvalidPim {
        /// The PIM given.
        pim: u32,
        /// Whose PIM it is: the container's, or the new one of a rekey.
        settings: Settings,
    },
    /// A memory level above [`crate::MAX_MEMORY_LEVEL`], of the settings that the message names.
    InvalidMemoryLevel {
        /// The memory level given.
        level: u32,
        /// Whose memory level it is: the container's, or the new one of a rekey.
        settings: Settings,
    },
    /// The memory level needs more memory than this environment can address, for example a
    /// browser, where WebAssembly is limited to 4 GiB.
    MemoryLevelNotSupportedHere {
        /// The memory level asked for.
        level: u32,
        /// The highest memory level this environment can use.
        highest_supported: u32,
    },
}
impl SettingsError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidPim { .. } => ErrorCode::InvalidPim,
            Self::InvalidMemoryLevel { .. } => ErrorCode::InvalidMemoryLevel,
            Self::MemoryLevelNotSupportedHere { .. } => ErrorCode::MemoryLevelNotSupportedHere,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPim { pim, settings } => write!(
                f,
                "{settings} PIM must be a whole number from 0 to {}, not {pim}",
                crate::MAX_PIM
            ),
            Self::InvalidMemoryLevel { level, settings } => write!(
                f,
                "{settings} memory level must be a whole number from 0 to {}, not {level}",
                crate::MAX_MEMORY_LEVEL
            ),
            Self::MemoryLevelNotSupportedHere {
                level,
                highest_supported,
            } => write!(
                f,
                "memory level {level} needs more memory than this environment can use; the \
                 highest supported level here is {highest_supported}. Use the command-line \
                 tool on a 64-bit system for higher levels"
            ),
        }
    }
}
impl std::error::Error for SettingsError {}

impl crate::ErrorIdentity for SettingsError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
