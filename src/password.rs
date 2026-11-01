//! What mhfe-core leaves to its host of a password that arrives as bytes: reading them as text.
//! The encoding of the specification, `P_enc`, is [`Password`].

use mhfe_core::Password;

use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
pub(crate) mod known_answers;

/// Same as [`Password::new`] for a password that arrives as UTF-8 bytes, as from a browser. The
/// bytes are validated where they lie, so that no second buffer holds the password. Errors:
/// [`MhfeError::InvalidPasswordUtf8`], then those of [`Password::new`].
pub fn from_utf8(bytes: &[u8]) -> Result<Password, MhfeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| MhfeError::InvalidPasswordUtf8)?;
    Ok(Password::new(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_invalid_utf8_passwords() {
        assert!(matches!(from_utf8(b""), Err(MhfeError::EmptyPassword)));
        for invalid in [
            &[0xff][..],
            &[0xc0, 0xaf],
            &[0xed, 0xa0, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
        ] {
            assert!(matches!(
                from_utf8(invalid),
                Err(MhfeError::InvalidPasswordUtf8)
            ));
        }
    }
}
