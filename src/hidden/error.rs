//! Refusals of a hidden-wallet session and the errors of the operations it composes.
use crate::{wallet::WalletError, wallet_check::WalletCheckError, CipherError, ErrorCode};
use std::fmt;

/// Why a hidden wallet could not be opened; no password or passphrase is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HiddenError {
    /// The normalized password has already been used in this session.
    PasswordAlreadyUsed,
    /// Its wallet passes a main-wallet check and cannot serve as a hidden wallet.
    PassesCheck,
    /// The container or cipher operation failed.
    Cipher(CipherError),
    /// The wallet's passphrase-size guard failed.
    Wallet(WalletError),
    /// The main-wallet criterion could not be evaluated.
    WalletCheck(WalletCheckError),
}
impl HiddenError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::PasswordAlreadyUsed => ErrorCode::PasswordAlreadyUsed,
            Self::PassesCheck => ErrorCode::HiddenWalletPassesCheck,
            Self::Cipher(error) => error.error_code(),
            Self::Wallet(error) => error.error_code(),
            Self::WalletCheck(error) => error.error_code(),
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl From<CipherError> for HiddenError {
    fn from(error: CipherError) -> Self {
        Self::Cipher(error)
    }
}
impl From<WalletError> for HiddenError {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}
impl From<WalletCheckError> for HiddenError {
    fn from(error: WalletCheckError) -> Self {
        Self::WalletCheck(error)
    }
}
impl fmt::Display for HiddenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordAlreadyUsed => f.write_str("this password was already used here; a hidden wallet needs a password of its own"),
            Self::PassesCheck => write!(f, "with this password the container gives a phrase that passes a check: the built-in check of a shorter phrase, as the container's own password of a 12- to 21-word phrase does, or the wallet check of a new phrase, by chance once in {}; recovery would take it for a verified or main wallet, so choose another password", crate::text::grouped(crate::wallet_check::WALLET_CHECK_ODDS)),
            Self::Cipher(error) => error.fmt(f),
            Self::Wallet(error) => error.fmt(f),
            Self::WalletCheck(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for HiddenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            Self::Wallet(error) => Some(error),
            Self::WalletCheck(error) => Some(error),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for HiddenError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
