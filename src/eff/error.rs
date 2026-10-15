//! Failures of the vendored EFF list and its dice reader.

use std::fmt;

use crate::ErrorCode;

/// A structural defect of the compiled-in public list, without caller-generated reason text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListIssue {
    /// A line has no word after its tab.
    MissingWord,
    /// The file has a different number of entries from the EFF large list.
    Incomplete,
    /// Two entries name the same word.
    Duplicate,
}

/// A failure of the EFF list or a numbered dice word. Dice digits never enter the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffError {
    /// The public list does not have its required structure.
    DamagedList(ListIssue),
    /// The digits for this drawn word were not five digits from 1 to 6.
    InvalidDiceRolls(usize),
}

impl EffError {
    /// The stable typed code of this refusal.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::DamagedList(_) => ErrorCode::InternalError,
            Self::InvalidDiceRolls(_) => ErrorCode::InvalidDiceRolls,
        }
    }

    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl fmt::Display for EffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDiceRolls(word) => write!(
                formatter,
                "the dice digits for word {word} must be exactly five digits, each from 1 to 6"
            ),
            Self::DamagedList(issue) => write!(
                formatter,
                "internal error: {}",
                match issue {
                    ListIssue::MissingWord => "a line of the vendored EFF list holds no word",
                    ListIssue::Incomplete => "the vendored EFF list is incomplete",
                    ListIssue::Duplicate => "the vendored EFF list holds a word twice",
                }
            ),
        }
    }
}

impl std::error::Error for EffError {}

impl crate::ErrorIdentity for EffError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
