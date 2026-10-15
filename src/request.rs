//! Typed field refusals shared by bindings and other front ends.

use std::fmt;

use crate::{ErrorCode, Settings};

/// A numeric field before a front end narrows its input to an integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberField {
    /// The original phrase's word count, with zero meaning detection.
    WordCount,
    /// The count on a repair card, with zero meaning no card in encryption.
    RepairWordCount,
    /// The size of a generated password.
    PasswordSize,
    /// A password review's repair position.
    RepairPosition,
    /// The place assigned to a wished-for word.
    ChosenWordPosition,
    /// The address scan's gap.
    ScanGap,
    /// The PIM of current or replacement settings.
    Pim(Settings),
    /// The memory level of current or replacement settings.
    MemoryLevel(Settings),
}

impl NumberField {
    /// The code of a malformed number in this field.
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::WordCount => ErrorCode::InvalidWordCount,
            Self::RepairWordCount => ErrorCode::InvalidRepairWords,
            Self::PasswordSize => ErrorCode::InvalidPasswordSize,
            Self::ChosenWordPosition => ErrorCode::InvalidWordWish,
            Self::Pim(_) => ErrorCode::InvalidPim,
            Self::MemoryLevel(_) => ErrorCode::InvalidMemoryLevel,
            Self::RepairPosition | Self::ScanGap => ErrorCode::InvalidRequest,
        }
    }

    /// Reads a nonnegative whole number without a modulo conversion. Larger finite whole values
    /// saturate at `u32::MAX`, so the owning parameter's tighter rule refuses them in its words.
    /// NaN, infinities, negative and fractional values are refused (AUD-024-API021).
    pub fn read(self, value: f64) -> Result<u32, RequestError> {
        if value.fract() == 0.0 && value >= 0.0 {
            Ok(if value > f64::from(u32::MAX) {
                u32::MAX
            } else {
                value as u32
            })
        } else {
            Err(RequestError::NotAWholeNumber {
                field: self,
                value: NumberValue::new(value),
            })
        }
    }
}

impl fmt::Display for NumberField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount => formatter.write_str("the word count"),
            Self::RepairWordCount => formatter.write_str("the repair word count"),
            Self::PasswordSize => formatter.write_str("the size"),
            Self::RepairPosition => formatter.write_str("the repair position"),
            Self::ChosenWordPosition => formatter.write_str("a chosen word's position"),
            Self::ScanGap => formatter.write_str("the scan gap"),
            Self::Pim(settings) => write!(formatter, "{settings} PIM"),
            Self::MemoryLevel(settings) => write!(formatter, "{settings} memory level"),
        }
    }
}

/// A diagnostic number, compared by bits so that NaN remains usable in an equality-checked error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumberValue(u64);

impl NumberValue {
    /// Retains a number without converting it to caller-generated text.
    pub const fn new(value: f64) -> Self {
        Self(value.to_bits())
    }

    /// The number as received by the numeric reader.
    pub const fn get(self) -> f64 {
        f64::from_bits(self.0)
    }
}

impl fmt::Display for NumberValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.get())
    }
}

/// A field that takes exactly true or false, without truth-value coercion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BooleanField {
    /// Whether a new phrase is drawn with the wallet check.
    WalletCheck,
    /// Whether the caller supplied a second password entry.
    Repeated,
    /// Whether encryption uses the same-length suite.
    SameLength,
    /// The owner's statement about the wallet's BIP39 passphrase.
    WalletHasPassphrase,
}

impl fmt::Display for BooleanField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WalletCheck => "walletCheck",
            Self::Repeated => "repeated",
            Self::SameLength => "sameLength",
            Self::WalletHasPassphrase => "walletHasPassphrase",
        })
    }
}

/// A malformed request field. Only typed field identities and numeric data enter its messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// The field was not a nonnegative whole number.
    NotAWholeNumber {
        /// The field whose rule rejected the number.
        field: NumberField,
        /// The numeric value, never arbitrary input text.
        value: NumberValue,
    },
    /// A field was supplied with a value other than true or false.
    NotBoolean(BooleanField),
    /// The reference selector is unknown; its raw spelling is not retained.
    UnknownReferenceKind,
    /// A reference's textual word count could not be read as a whole number.
    ReferenceWordCount,
}

impl RequestError {
    /// The typed stable code of this field refusal.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotAWholeNumber { field, .. } => field.error_code(),
            Self::NotBoolean(_) | Self::UnknownReferenceKind | Self::ReferenceWordCount => {
                ErrorCode::InvalidRequest
            }
        }
    }

    /// The machine-readable code for scripts and browser callers.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownReferenceKind => {
                formatter.write_str("invalid request: unknown reference kind")
            }
            Self::ReferenceWordCount => {
                formatter.write_str("invalid request: the word count must be a whole number")
            }
            Self::NotAWholeNumber { field, value } => {
                write!(formatter, "{field} must be a whole number, not {value}")
            }
            Self::NotBoolean(field) => {
                write!(formatter, "invalid request: {field} must be true or false")?;
                if *field == BooleanField::WalletHasPassphrase {
                    formatter.write_str(": whether the wallet has a BIP39 passphrase")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RequestError {}

impl crate::ErrorIdentity for RequestError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_never_wrap_and_keep_the_fields_refusal_category() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.5] {
            assert_eq!(
                NumberField::WordCount.read(value).unwrap_err().code(),
                "INVALID_WORD_COUNT"
            );
            assert_eq!(
                NumberField::Pim(Settings::New)
                    .read(value)
                    .unwrap_err()
                    .code(),
                "INVALID_PIM"
            );
        }
        assert_eq!(NumberField::ScanGap.read(4_294_967_296.0), Ok(u32::MAX));
        assert_eq!(NumberField::WordCount.read(-0.0), Ok(0));
        assert_eq!(NumberField::WordCount.read(12.0), Ok(12));
        assert_eq!(
            NumberField::ScanGap.read(0.5).unwrap_err().to_string(),
            "the scan gap must be a whole number, not 0.5"
        );
    }
}
