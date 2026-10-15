//! BIP32 keys of a BIP39 phrase, and what an address commits to for a key. The private keys of
//! the wallet module live here, each wiped when dropped.

use bitcoin_hashes::{hash160, Hash};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::{Zeroize, Zeroizing};

use super::{AddressType, HARDENED};
use super::{KeyIssue, WalletError};
use crate::phrase;

type HmacSha512 = Hmac<Sha512>;

/// What an address of `address_type` commits to for this key: HASH160 of the public key, of the
/// P2WPKH script for nested SegWit, the tweaked output key for Taproot, or the last 20 bytes of
/// Keccak-256 of the uncompressed public key.
pub(super) fn program_for(
    key: &ExtendedKey,
    address_type: AddressType,
) -> Result<Vec<u8>, WalletError> {
    let public_key = key.public_key()?;
    Ok(match address_type {
        AddressType::P2pkh | AddressType::P2wpkh | AddressType::DashPlatform => {
            hash160::Hash::hash(&public_key).to_byte_array().to_vec()
        }
        AddressType::P2shP2wpkh => {
            // The redeem script is OP_0 PUSH20 <HASH160(public key)>.
            let mut script = vec![0x00, AddressType::P2wpkh.program_bytes() as u8];
            script.extend_from_slice(&hash160::Hash::hash(&public_key).to_byte_array());
            hash160::Hash::hash(&script).to_byte_array().to_vec()
        }
        AddressType::P2tr => taproot_output_key(key)?.to_vec(),
        AddressType::Keccak => {
            // The 64 bytes of the uncompressed key without its 0x04 prefix (Ethereum yellow paper).
            let uncompressed = key.uncompressed_public_key()?;
            let digest = Keccak256::digest(&uncompressed[1..]);
            digest[digest.len() - AddressType::Keccak.program_bytes()..].to_vec()
        }
    })
}

/// BIP86: the key-path-only Taproot output key `Q = P + t*G`, where `P` is the public key with
/// an even Y coordinate and `t = TaggedHash("TapTweak", x(P))` (BIP341).
fn taproot_output_key(key: &ExtendedKey) -> Result<[u8; 32], WalletError> {
    let point = key.public_point()?;
    let internal = if bool::from(point.to_affine().y_is_odd()) {
        -point
    } else {
        point
    };
    let x_only = internal.to_affine().x();
    let tweak_bytes = tagged_hash("TapTweak", &x_only);
    let tweak = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(tweak_bytes)))
        .ok_or(WalletError::Key(KeyIssue::TaprootTweak))?;
    let output = internal + ProjectivePoint::GENERATOR * tweak;
    // BIP341 fails when Q is the point at infinity, which needs t = -p: probability about 2^-256.
    if bool::from(output.is_identity()) {
        return Err(WalletError::Key(KeyIssue::TaprootInfinity));
    }
    Ok(output.to_affine().x().into())
}

/// `SHA256(SHA256(tag) || SHA256(tag) || data)`, the tagged hash of BIP340.
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_digest = Sha256::digest(tag.as_bytes());
    Sha256::new()
        .chain_update(tag_digest)
        .chain_update(tag_digest)
        .chain_update(data)
        .finalize()
        .into()
}

/// A BIP32 extended private key. Both halves are wiped when dropped.
pub(super) struct ExtendedKey {
    key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedKey {
    /// Compares a public known-answer vector without exporting either private-key half or
    /// formatting actual key material into an unwiped temporary string.
    #[cfg(any(
        not(target_arch = "wasm32"),
        feature = "browser-core",
        feature = "browser-repair",
        feature = "browser-wallet"
    ))]
    pub(super) fn matches_known_answer(&self, key_hex: &str, chain_code_hex: &str) -> bool {
        let mut key = [0; 32];
        let mut chain_code = [0; 32];
        hex::decode_to_slice(key_hex, &mut key).is_ok()
            && hex::decode_to_slice(chain_code_hex, &mut chain_code).is_ok()
            && self.key[..] == key
            && self.chain_code[..] == chain_code
    }

    /// The master key of a BIP39 phrase and passphrase: `HMAC-SHA512("Bitcoin seed", seed)`.
    ///
    /// The phrase is read by the library's one reader of phrases (AUD-010): any spacing and
    /// letter case, and four letters of a word, as every other phrase input takes it.
    pub(super) fn master(phrase: &str, passphrase: &str) -> Result<Self, WalletError> {
        let mnemonic = phrase::parse(phrase).map_err(WalletError::from)?;
        let seed = crate::bip39_seed::derive(&mnemonic, passphrase).map_err(WalletError::from)?;
        let master = Self::from_hmac(b"Bitcoin seed", &[&seed[..]])?;
        // BIP32: a master key of zero or not below n is invalid; probability below 2^-127.
        if bool::from(master.scalar()?.is_zero()) {
            return Err(WalletError::Key(KeyIssue::Master));
        }
        Ok(master)
    }

    /// Splits `HMAC-SHA512(key, parts)` into a private key and a chain code (BIP32).
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
    pub(super) fn from_hmac(key: &[u8], parts: &[&[u8]]) -> Result<Self, WalletError> {
        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
        for part in parts {
            mac.update(part);
        }
        let mut digest = mac.finalize().into_bytes();
        let mut extended = Self {
            key: Zeroizing::new([0u8; 32]),
            chain_code: Zeroizing::new([0u8; 32]),
        };
        extended.key.copy_from_slice(&digest[..32]);
        extended.chain_code.copy_from_slice(&digest[32..]);
        digest.zeroize();
        Ok(extended)
    }

    pub(super) fn derive(&self, path: &[u32]) -> Result<Self, WalletError> {
        let mut key = self.clone_key();
        for &index in path {
            key = key.child(index)?;
        }
        Ok(key)
    }

    /// Private child key derivation, CKDpriv of BIP32.
    pub(super) fn child(&self, index: u32) -> Result<Self, WalletError> {
        let index_bytes = index.to_be_bytes();
        let mut child = if index >= HARDENED {
            Self::from_hmac(&self.chain_code[..], &[&[0u8], &self.key[..], &index_bytes])?
        } else {
            Self::from_hmac(&self.chain_code[..], &[&self.public_key()?, &index_bytes])?
        };
        // The child key is IL + parent key (mod n). BIP32 declares the key at this index invalid
        // when IL is not below n or the sum is zero, which happens with probability below 2^-127,
        // and wallets then use the next index. This tool reports it instead of silently checking a
        // different index than the path says.
        let tweak = parse_scalar(&child.key)?;
        let sum = Zeroizing::new(*tweak + *self.scalar()?);
        if bool::from(sum.is_zero()) {
            return Err(WalletError::Key(KeyIssue::Child(index)));
        }
        child
            .key
            .copy_from_slice(&Zeroizing::new(sum.to_repr())[..]);
        Ok(child)
    }

    /// The private key as a scalar, wiped when dropped like every scalar binding here.
    fn scalar(&self) -> Result<Zeroizing<Scalar>, WalletError> {
        parse_scalar(&self.key)
    }

    /// The public point `k*G` of the private key `k`.
    fn public_point(&self) -> Result<ProjectivePoint, WalletError> {
        Ok(ProjectivePoint::GENERATOR * *self.scalar()?)
    }

    /// The compressed SEC1 public key, 33 bytes.
    pub(super) fn public_key(&self) -> Result<[u8; 33], WalletError> {
        let point = self.public_point()?.to_affine();
        let encoded = point.to_sec1_point(true);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| WalletError::Key(KeyIssue::CompressedLength))
    }

    /// The public key in SEC1 uncompressed form: 0x04 and both coordinates.
    fn uncompressed_public_key(&self) -> Result<[u8; 65], WalletError> {
        let point = self.public_point()?.to_affine();
        let encoded = point.to_sec1_point(false);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| WalletError::Key(KeyIssue::UncompressedLength))
    }

    fn clone_key(&self) -> Self {
        Self {
            key: self.key.clone(),
            chain_code: self.chain_code.clone(),
        }
    }
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<Zeroizing<Scalar>, WalletError> {
    let mut repr = FieldBytes::from(*bytes);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr)).map(Zeroizing::new);
    repr.zeroize();
    scalar.ok_or(WalletError::Key(KeyIssue::Scalar))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys that BIP32 calls invalid give an error, never a panic. They cannot come from a real
    /// phrase in practice, so they are made up here: zero, and the group order n.
    #[test]
    fn invalid_bip32_keys_are_errors() {
        let with_key = |key: [u8; 32]| ExtendedKey {
            key: Zeroizing::new(key),
            chain_code: Zeroizing::new([7u8; 32]),
        };
        // secp256k1 group order n (SEC 2).
        let order: [u8; 32] =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(with_key([0u8; 32]).public_key().is_err());
        assert!(with_key(order).public_key().is_err());
        assert!(with_key(order).child(0).is_err());
        assert!(with_key(order).child(HARDENED).is_err());
    }
}
