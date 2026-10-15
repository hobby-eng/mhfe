//! The public BIP32 master-key fingerprint: four bytes, parsed and displayed as eight hex digits.

use std::fmt;

use bitcoin_hashes::{hash160, Hash};

use super::keys::ExtendedKey;
use super::WalletError;

/// BIP32 fixes the fingerprint to the first four bytes of HASH160 of the public key.
const BYTES: usize = 4;

/// A BIP32 master-key fingerprint. It identifies a wallet with 32 bits, independently of how its
/// public text was typed. It is public data and does not grant spending authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; BYTES]);

impl Fingerprint {
    /// Reads eight hexadecimal digits, in either case, with surrounding white space allowed.
    ///
    /// Other input gives `INVALID_FINGERPRINT` without repeating anything typed.
    pub fn parse(text: &str) -> Result<Self, WalletError> {
        let text = text.trim();
        let invalid = || WalletError::Fingerprint;
        if text.len() != 2 * BYTES {
            return Err(invalid());
        }
        let mut bytes = [0; BYTES];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| invalid())?;
        Ok(Self(bytes))
    }

    /// The fingerprint of `phrase` with its BIP39 `passphrase` (empty for none). Phrase spelling
    /// follows the library's common phrase reader; no private key leaves the wallet module.
    pub fn of(phrase: &str, passphrase: &str) -> Result<Self, WalletError> {
        let master = ExtendedKey::master(phrase, passphrase)?;
        let digest = hash160::Hash::hash(&master.public_key()?).to_byte_array();
        let mut bytes = [0; BYTES];
        bytes.copy_from_slice(&digest[..BYTES]);
        Ok(Self(bytes))
    }

    /// Takes the four public bytes a wallet already supplied; every four-byte value is valid.
    pub const fn from_bytes(bytes: [u8; BYTES]) -> Self {
        Self(bytes)
    }

    /// The fingerprint's four bytes in the order BIP32 specifies.
    pub const fn bytes(self) -> [u8; BYTES] {
        self.0
    }
}

impl From<[u8; BYTES]> for Fingerprint {
    fn from(bytes: [u8; BYTES]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Display for Fingerprint {
    /// Eight lower-case hexadecimal digits, including leading zeros.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_text_preserves_leading_zeros_and_case_insensitive_input() {
        let fingerprint = Fingerprint::parse("  0000AB01\n").unwrap();
        assert_eq!(fingerprint.bytes(), [0, 0, 0xab, 1]);
        assert_eq!(fingerprint.to_string(), "0000ab01");
        assert_eq!(
            Fingerprint::parse(&fingerprint.to_string()).unwrap(),
            fingerprint
        );
        for text in [
            "",
            "0000ab",
            "0000ab0100",
            "0x00ab01",
            "0000ag01",
            "ab\n01cd2",
        ] {
            assert_eq!(
                Fingerprint::parse(text).unwrap_err().code(),
                "INVALID_FINGERPRINT"
            );
        }
    }
}
