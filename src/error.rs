//! Everything that can stop an MHFE operation, with messages written for the person using it.
//!
//! No message ever contains a seed phrase, a password or any part of them.

use std::fmt;

/// Why an MHFE operation stopped. Each variant has a stable code ([`MhfeError::code`]) and one
/// message, written by its `Display`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MhfeError {
    /// A lower-level phrase/container format refusal.
    Format(crate::FormatError),
    /// A typed phrase, container or raw entropy refusal.
    Phrase(crate::PhraseError),
    /// A core cipher, recovery-length or container-policy failure.
    Cipher(crate::CipherError),
    /// Settings refused before any cryptographic work.
    Settings(crate::SettingsError),
    /// A reference comparison or follow-up was refused.
    Rehearsal(crate::RehearsalError),
    /// A hidden-wallet session refused a password or failed.
    Hidden(crate::HiddenError),
    /// A repair-card refusal or readback failure.
    Repair(crate::repair::RepairError),
    /// Words wished for in a new phrase that cannot be used; the reason never names a word.
    Wish(crate::word_wishes::WishError),
    /// A missing-word search was refused or ambiguous.
    Search(crate::search::SearchError),
    /// The user stopped the operation.
    Cancelled,
    /// A wallet input, derivation or address failure.
    Wallet(crate::wallet::WalletError),
    /// Argon2 or its memory reservation failed.
    Engine(crate::engine::EngineError),
    /// A typed malformed field supplied to an operation.
    Request(crate::request::RequestError),
    /// A word-hint request was refused.
    WordHint(crate::word_hints::WordHintError),
    /// A result representation could not be produced safely.
    Output(crate::output::OutputError),
    /// Password encoding or an explicitly selected review failed.
    Password(crate::PasswordError),
    /// Password generation failed before returning any generated text.
    NewPassword(crate::new_password::NewPasswordError),
    /// A choice was not offered by the password check-word review.
    Review(crate::check_word::ReviewError),
    /// A failure of the EFF list or its numbered dice reader.
    Eff(crate::eff::EffError),
    /// The wallet check of a new phrase needs a BIP39 passphrase: without one, anyone who sees the
    /// phrase can test it.
    WalletCheck(crate::wallet_check::WalletCheckError),
    /// The random source failed or gave bytes that cannot be random; nothing was drawn.
    Random(crate::random::RandomError),
    /// A rekey sequencing, confirmation or setting refusal.
    Rekey(crate::rekey::RekeyError),
    /// A self-check tier or required component failed.
    SelfCheck(crate::self_check::SelfCheckError),
    #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
    /// A published-vector self-test could not run.
    SelfTest(crate::self_test::SelfTestError),
    /// A fixed public vector could not be recorded safely.
    Vector(crate::vectors::VectorError),
}

impl fmt::Display for MhfeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(f),
            Self::Phrase(error) => error.fmt(f),
            Self::Cipher(error) => error.fmt(f),
            Self::Settings(error) => error.fmt(f),
            Self::Rehearsal(error) => error.fmt(f),
            Self::Hidden(error) => error.fmt(f),
            Self::Wish(error) => error.fmt(f),
            Self::Repair(error) => error.fmt(f),
            Self::Search(error) => error.fmt(f),
            Self::Cancelled => crate::CancelledError.fmt(f),
            Self::Wallet(error) => error.fmt(f),
            Self::Engine(error) => error.fmt(f),
            Self::Eff(error) => error.fmt(f),
            Self::Password(error) => error.fmt(f),
            Self::NewPassword(error) => error.fmt(f),
            Self::Review(error) => error.fmt(f),
            Self::WalletCheck(error) => error.fmt(f),
            Self::Random(error) => error.fmt(f),
            Self::Request(error) => error.fmt(f),
            #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
            Self::SelfTest(error) => error.fmt(f),
            Self::Vector(error) => error.fmt(f),
            Self::WordHint(error) => error.fmt(f),
            Self::Output(error) => error.fmt(f),
            Self::Rekey(error) => error.fmt(f),
            Self::SelfCheck(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MhfeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Cancelled => Some(&crate::CancelledError),
            Self::Random(error) => Some(error),
            Self::Request(error) => Some(error),
            #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
            Self::SelfTest(error) => Some(error),
            Self::Vector(error) => Some(error),
            Self::WordHint(error) => Some(error),
            Self::Output(error) => Some(error),
            Self::Eff(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::WalletCheck(error) => Some(error),
            Self::Wish(error) => Some(error),
            Self::Wallet(error) => Some(error),
            Self::Repair(error) => Some(error),
            Self::Phrase(error) => Some(error),
            Self::Cipher(error) => Some(error),
            Self::Settings(error) => Some(error),
            Self::Password(error) => Some(error),
            Self::NewPassword(error) => Some(error),
            Self::Review(error) => Some(error),
            Self::SelfCheck(error) => Some(error),
            Self::Search(error) => Some(error),
            Self::Rehearsal(error) => Some(error),
            Self::Rekey(error) => Some(error),
            Self::Hidden(error) => Some(error),
        }
    }
}

impl From<crate::CancelledError> for MhfeError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}

impl From<crate::random::RandomError> for MhfeError {
    fn from(error: crate::random::RandomError) -> Self {
        match error {
            crate::random::RandomError::Cancelled => Self::Cancelled,
            other => Self::Random(other),
        }
    }
}

impl From<crate::request::RequestError> for MhfeError {
    fn from(error: crate::request::RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<crate::eff::EffError> for MhfeError {
    fn from(error: crate::eff::EffError) -> Self {
        Self::Eff(error)
    }
}

impl MhfeError {
    /// Stable machine-readable code for browser callers and scripts.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }

    /// Stable machine-readable code for the browser API and for scripts.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::Format(error) => error.error_code(),
            Self::Phrase(error) => error.error_code(),
            Self::Cipher(error) => error.error_code(),
            Self::Rehearsal(error) => error.error_code(),
            Self::Hidden(error) => error.error_code(),
            Self::Repair(error) => error.error_code(),
            Self::Wish(error) => error.error_code(),
            Self::Search(error) => error.error_code(),
            Self::Cancelled => crate::ErrorCode::Cancelled,
            Self::Settings(error) => error.error_code(),
            Self::Engine(error) => error.error_code(),
            Self::Eff(error) => error.error_code(),
            Self::Wallet(error) => error.error_code(),
            Self::Password(error) => error.error_code(),
            Self::NewPassword(error) => error.error_code(),
            Self::Review(error) => error.error_code(),
            Self::WalletCheck(error) => error.error_code(),
            Self::Random(error) => error.error_code(),
            Self::Request(error) => error.error_code(),
            #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
            Self::SelfTest(error) => error.error_code(),
            Self::Vector(error) => error.error_code(),
            Self::WordHint(error) => error.error_code(),
            Self::Output(error) => error.error_code(),
            Self::Rekey(error) => error.error_code(),
            Self::SelfCheck(error) => error.error_code(),
        }
    }
}

impl From<crate::PasswordError> for MhfeError {
    fn from(error: crate::PasswordError) -> Self {
        Self::Password(error)
    }
}
impl From<crate::check_word::ReviewError> for MhfeError {
    fn from(error: crate::check_word::ReviewError) -> Self {
        Self::Review(error)
    }
}
impl From<crate::new_password::NewPasswordError> for MhfeError {
    fn from(error: crate::new_password::NewPasswordError) -> Self {
        if error.error_code() == crate::ErrorCode::Cancelled {
            Self::Cancelled
        } else {
            Self::NewPassword(error)
        }
    }
}

impl From<crate::PhraseError> for MhfeError {
    fn from(error: crate::PhraseError) -> Self {
        Self::Phrase(error)
    }
}

impl From<crate::repair::RepairError> for MhfeError {
    fn from(error: crate::repair::RepairError) -> Self {
        Self::Repair(error)
    }
}

impl From<crate::wallet::WalletError> for MhfeError {
    fn from(error: crate::wallet::WalletError) -> Self {
        if error.error_code() == crate::ErrorCode::Cancelled {
            Self::Cancelled
        } else {
            Self::Wallet(error)
        }
    }
}

impl From<crate::word_wishes::WishError> for MhfeError {
    fn from(error: crate::word_wishes::WishError) -> Self {
        Self::Wish(error)
    }
}

impl From<crate::wallet_check::WalletCheckError> for MhfeError {
    fn from(error: crate::wallet_check::WalletCheckError) -> Self {
        if error.error_code() == crate::ErrorCode::Cancelled {
            Self::Cancelled
        } else {
            Self::WalletCheck(error)
        }
    }
}

impl From<crate::SettingsError> for MhfeError {
    fn from(error: crate::SettingsError) -> Self {
        Self::Settings(error)
    }
}

impl From<crate::engine::EngineError> for MhfeError {
    fn from(error: crate::engine::EngineError) -> Self {
        Self::Engine(error)
    }
}

impl From<crate::CipherError> for MhfeError {
    fn from(error: crate::CipherError) -> Self {
        match error {
            crate::CipherError::Format(error) => Self::Format(error),
            other if other.error_code() == crate::ErrorCode::Cancelled => Self::Cancelled,
            other => Self::Cipher(other),
        }
    }
}
impl From<crate::FormatError> for MhfeError {
    fn from(error: crate::FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<crate::word_hints::WordHintError> for MhfeError {
    fn from(error: crate::word_hints::WordHintError) -> Self {
        Self::WordHint(error)
    }
}
impl From<crate::output::OutputError> for MhfeError {
    fn from(error: crate::output::OutputError) -> Self {
        Self::Output(error)
    }
}

impl From<crate::HiddenError> for MhfeError {
    fn from(error: crate::HiddenError) -> Self {
        if error.error_code() == crate::ErrorCode::Cancelled {
            Self::Cancelled
        } else {
            Self::Hidden(error)
        }
    }
}

impl From<crate::rekey::RekeyError> for MhfeError {
    fn from(error: crate::rekey::RekeyError) -> Self {
        Self::Rekey(error)
    }
}

impl From<crate::RehearsalError> for MhfeError {
    fn from(error: crate::RehearsalError) -> Self {
        Self::Rehearsal(error)
    }
}

impl From<crate::search::SearchError> for MhfeError {
    fn from(error: crate::search::SearchError) -> Self {
        Self::Search(error)
    }
}

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
impl From<crate::self_test::SelfTestError> for MhfeError {
    fn from(error: crate::self_test::SelfTestError) -> Self {
        if error.error_code() == crate::ErrorCode::Cancelled {
            Self::Cancelled
        } else {
            Self::SelfTest(error)
        }
    }
}
impl From<crate::vectors::VectorError> for MhfeError {
    fn from(error: crate::vectors::VectorError) -> Self {
        Self::Vector(error)
    }
}

impl crate::ErrorIdentity for MhfeError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

impl From<crate::self_check::SelfCheckError> for MhfeError {
    fn from(error: crate::self_check::SelfCheckError) -> Self {
        Self::SelfCheck(error)
    }
}

impl From<crate::PassphraseError> for MhfeError {
    fn from(error: crate::PassphraseError) -> Self {
        crate::wallet::WalletError::from(error).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    /// An unknown self-check selector is never echoed, including terminal controls.
    #[test]
    fn unknown_tier_does_not_repeat_input_or_control_characters() {
        let typed = "ab\u{1b}]0;TITLE\u{7}\u{1b}[2J\u{7f}\u{9b}cd é";
        let refusal = crate::self_check::Tier::from_name(typed).unwrap_err();
        let shown = refusal.to_string();
        assert_eq!(refusal.code(), "INVALID_REQUEST");
        assert!(!shown.chars().any(char::is_control), "{shown}");
        assert!(!shown.contains("TITLE"), "{shown}");
        assert!(
            shown.contains("startup") && shown.contains("full"),
            "{shown}"
        );
    }

    /// A refusal of a public field never repeats what was typed: a seed phrase pasted there by
    /// mistake stays out of the message (AUD-016-SEC001), and so does a control sequence.
    #[test]
    fn a_refused_public_field_does_not_repeat_the_text() {
        const PASTED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon about";
        for typed in [PASTED, "ab\u{1b}]0;TITLE\u{7}cd"] {
            for refusal in [
                crate::wallet::Fingerprint::parse(typed).unwrap_err(),
                typed.parse::<crate::wallet::Coin>().unwrap_err(),
                typed.parse::<crate::wallet::DerivationPath>().unwrap_err(),
            ] {
                let message = refusal.to_string();
                assert!(!message.contains("abandon"), "{message}");
                assert!(!message.chars().any(char::is_control), "{message}");
            }
        }
    }

    #[test]
    fn memory_messages_use_readable_gib_values() {
        let error = crate::engine::EngineError::NotEnoughMemory {
            needed_bytes: 2 * GIB,
            available_bytes: GIB + GIB / 2,
        };
        assert_eq!(
            error.to_string(),
            "this memory level needs 2 GiB of memory, but only 1.5 GiB is available; \
             close other programs or choose a lower memory level"
        );
    }

    #[test]
    fn an_unknown_coin_is_one_sentence_without_the_typed_value() {
        assert_eq!(
            crate::wallet::WalletError::InvalidCoin.code(),
            "INVALID_COIN"
        );
        assert_eq!(
            crate::wallet::WalletError::InvalidCoin.to_string(),
            "unknown coin; the coins are bitcoin, bitcoin-cash, cosmos, dash, dogecoin, ethereum, \
             ethereum-classic, injective, litecoin, tron, xrp, zcash"
        );
    }

    /// The two codes that only the browser bindings used to write out themselves.
    #[test]
    fn requests_and_passphrases_have_codes_of_their_own() {
        let request = MhfeError::from(crate::request::RequestError::UnknownReferenceKind);
        assert_eq!(request.code(), "INVALID_REQUEST");
        assert_eq!(
            request.to_string(),
            "invalid request: unknown reference kind"
        );
        assert_eq!(
            crate::wallet::WalletError::InvalidPassphrase.code(),
            "INVALID_PASSPHRASE"
        );
        assert_eq!(
            crate::wallet::WalletError::InvalidPassphrase.to_string(),
            "the BIP39 passphrase is not valid UTF-8 text"
        );
    }
}
