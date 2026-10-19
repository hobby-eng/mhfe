//! BIP39 seed derivation and its passphrase guard, independent of addresses and the cipher.
use crate::memory::LockedText;
use crate::ErrorCode;
use bip39::Mnemonic;
use std::convert::Infallible;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The maximum BIP39 passphrase length, in bytes as typed.
pub const MAX_PASSPHRASE_BYTES: usize = crate::MAX_PASSWORD_BYTES;

/// A BIP39 passphrase refusal, without retaining any of its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseError {
    /// The byte input is not UTF-8.
    InvalidUtf8,
    /// The typed byte count exceeds the shared limit.
    TooLong(usize),
}
impl PassphraseError {
    /// The stable typed code.
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::InvalidUtf8 => ErrorCode::InvalidPassphrase,
            Self::TooLong(_) => ErrorCode::PassphraseTooLong,
        }
    }
    /// The stable machine-readable spelling.
    pub const fn code(self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("the BIP39 passphrase is not valid UTF-8 text"),
            Self::TooLong(bytes) => write!(f, "the BIP39 passphrase is too long: {bytes} bytes, but at most {MAX_PASSPHRASE_BYTES} are allowed"),
        }
    }
}
impl std::error::Error for PassphraseError {}
impl crate::ErrorIdentity for PassphraseError {
    fn error_code(&self) -> ErrorCode {
        (*self).error_code()
    }
}

/// A borrowed BIP39 passphrase within the raw byte limit, before normalization or seed work.
pub struct Bip39Passphrase<'a>(&'a str);

impl<'a> Bip39Passphrase<'a> {
    /// Checks [`crate::wallet::MAX_PASSPHRASE_BYTES`] raw UTF-8 bytes without copying the text.
    ///
    /// Returns [`PassphraseError::TooLong`] above the limit. An empty passphrase is accepted;
    /// requiring a nonempty one remains a separate wallet-check policy.
    pub fn read(passphrase: &'a str) -> Result<Self, PassphraseError> {
        if passphrase.len() > MAX_PASSPHRASE_BYTES {
            return Err(PassphraseError::TooLong(passphrase.len()));
        }
        Ok(Self(passphrase))
    }

    /// The original bounded text, without normalization or another allocation.
    pub const fn text(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for Bip39Passphrase<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Bip39Passphrase(hidden)")
    }
}

/// The same guard used by every seed and passphrase consumer.
pub(crate) fn require_size(passphrase: &str) -> Result<(), PassphraseError> {
    Bip39Passphrase::read(passphrase).map(|_| ())
}

/// The largest growth of UTF-8 text under NFKD: U+FDFA, 3 bytes, decomposes into 33 bytes.
const NFKD_MAX_GROWTH: usize = 11;

/// The BIP39 seed of a phrase and a passphrase: PBKDF2-HMAC-SHA512, 2,048 iterations, with the
/// salt "mnemonic" and the passphrase in NFKD. A passphrase longer than
/// [`MAX_PASSPHRASE_BYTES`] is refused first, so that no seed is derived from one
/// (AUD-024-API019).
pub(crate) fn derive(
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, PassphraseError> {
    require_size(passphrase)?;
    let normalized = normalized_passphrase(passphrase);
    Ok(Zeroizing::new(mnemonic.to_seed_normalized(&normalized)))
}

/// The passphrase in NFKD, as BIP39 requires, in a buffer that is wiped when dropped. It is
/// reserved at the largest size NFKD can produce, so it never grows and leaves no unwiped copy;
/// `Mnemonic::to_seed` would normalize into an ordinary string instead. Locked before the
/// passphrase is written into it, as the passphrase it is made from is.
fn normalized_passphrase(passphrase: &str) -> LockedText {
    let Ok(normalized) =
        LockedText::build::<Infallible>(passphrase.len() * NFKD_MAX_GROWTH, |normalized| {
            normalized.extend(passphrase.nfkd());
            Ok(())
        });
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_passphrase_bytes_are_bounded_before_normalization() {
        for unit in ["a", "é", "\u{1d400}"] {
            let at_limit = unit.repeat(MAX_PASSPHRASE_BYTES / unit.len());
            assert_eq!(
                crate::Bip39Passphrase::read(&at_limit).unwrap().text(),
                at_limit
            );
            let excessive = format!("{at_limit}a");
            assert_eq!(
                crate::Bip39Passphrase::read(&excessive).unwrap_err(),
                PassphraseError::TooLong(MAX_PASSPHRASE_BYTES + 1)
            );
        }
        assert_eq!(crate::Bip39Passphrase::read("").unwrap().text(), "");
        assert_eq!(
            format!(
                "{:?}",
                crate::Bip39Passphrase::read("public fixture").unwrap()
            ),
            "Bip39Passphrase(hidden)"
        );
    }
    /// The wiping normalization gives the seed that bip39 itself computes, also for a passphrase
    /// that NFKD changes, including one that grows the most.
    #[test]
    fn the_passphrase_is_normalized_as_bip39_does() {
        let mnemonic = crate::phrase::parse(crate::test_support::ABANDON_12).unwrap();
        for passphrase in ["", "TREZOR", "Caf\u{E9} \u{FB01}", "\u{FDFA}\u{FDFA}"] {
            let normalized = normalized_passphrase(passphrase);
            assert_eq!(
                mnemonic.to_seed_normalized(&normalized),
                mnemonic.to_seed(passphrase),
                "{passphrase:?}"
            );
        }
    }
}
