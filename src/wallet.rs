//! Public wallet data for rehearsing a recovery without showing the phrase: the BIP32 master
//! key fingerprint and Bitcoin receiving addresses on the standard paths of BIP44 (legacy),
//! BIP49 (nested SegWit), BIP84 (native SegWit) and BIP86 (Taproot).
//!
//! Private keys exist only inside this module and are wiped when dropped; only public values
//! and yes-or-no answers come out.

use std::fmt;
use std::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin_hashes::{hash160, Hash};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::MhfeError;

type HmacSha512 = Hmac<Sha512>;

/// Indexes from 2^31 up are hardened (BIP32).
pub const HARDENED: u32 = 1 << 31;
/// Receiving and change chains of a BIP44-style account.
const CHAINS: [u32; 2] = [0, 1];

/// Bitcoin network of an address; testnet also covers signet, which uses the same prefixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
}

impl Network {
    /// Coin type of the BIP44-style paths: 0' on Bitcoin, 1' on every test network.
    fn coin_type(self) -> u32 {
        match self {
            Self::Bitcoin => 0,
            Self::Testnet => 1,
        }
    }
}

/// The four single-key address types and the standard that sets their paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy address, "1..." or "m..."/"n...": BIP44, `m/44'/coin'/account'/chain/index`.
    P2pkh,
    /// Nested SegWit address, "3..." or "2...": BIP49, `m/49'/...`.
    P2shP2wpkh,
    /// Native SegWit address, "bc1q..." or "tb1q...": BIP84, `m/84'/...`.
    P2wpkh,
    /// Taproot address, "bc1p..." or "tb1p...": BIP86, `m/86'/...`.
    P2tr,
}

impl AddressType {
    fn purpose(self) -> u32 {
        match self {
            Self::P2pkh => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
            Self::P2tr => 86,
        }
    }
}

/// A receiving address the user knows, reduced to what identifies it: the network, the type
/// and the 20-byte key or script hash (32-byte output key for Taproot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAddress {
    pub network: Network,
    pub address_type: AddressType,
    program: Vec<u8>,
}

impl FromStr for BitcoinAddress {
    type Err = MhfeError;

    /// Reads a Bitcoin mainnet or testnet address of one of the four supported types.
    fn from_str(text: &str) -> Result<Self, MhfeError> {
        let text = text.trim();
        let lowercase = text.to_ascii_lowercase();
        if lowercase.starts_with("bc1") || lowercase.starts_with("tb1") {
            parse_segwit(text)
        } else {
            parse_base58(text)
        }
    }
}

fn invalid_address(reason: &str) -> MhfeError {
    MhfeError::InvalidAddress(reason.to_owned())
}

/// Bech32 and Bech32m addresses (BIP173, BIP350).
fn parse_segwit(text: &str) -> Result<BitcoinAddress, MhfeError> {
    let (hrp, version, program) = bech32::segwit::decode(text)
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    // BIP173 allows an address written all in capitals, as in QR codes; the decoder has already
    // refused mixed case, and keeps the prefix as written.
    let network = match hrp.as_str().to_ascii_lowercase().as_str() {
        "bc" => Network::Bitcoin,
        "tb" => Network::Testnet,
        _ => {
            return Err(invalid_address(
                "it is not a Bitcoin mainnet or testnet address",
            ))
        }
    };
    let address_type = match (version.to_u8(), program.len()) {
        (0, 20) => AddressType::P2wpkh,
        (1, 32) => AddressType::P2tr,
        _ => {
            return Err(invalid_address(
                "only single-key addresses (bc1q with 42 characters or bc1p) can be checked",
            ))
        }
    };
    Ok(BitcoinAddress {
        network,
        address_type,
        program,
    })
}

/// Base58Check addresses: version byte and 20-byte hash.
fn parse_base58(text: &str) -> Result<BitcoinAddress, MhfeError> {
    let decoded = bs58::decode(text)
        .with_check(None)
        .into_vec()
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    let (&version, hash) = decoded
        .split_first()
        .ok_or_else(|| invalid_address("it is empty"))?;
    if hash.len() != 20 {
        return Err(invalid_address("it has the wrong length"));
    }
    let (network, address_type) = match version {
        0x00 => (Network::Bitcoin, AddressType::P2pkh),
        0x05 => (Network::Bitcoin, AddressType::P2shP2wpkh),
        0x6f => (Network::Testnet, AddressType::P2pkh),
        0xc4 => (Network::Testnet, AddressType::P2shP2wpkh),
        _ => {
            return Err(invalid_address(
                "it is not a Bitcoin mainnet or testnet address",
            ))
        }
    };
    Ok(BitcoinAddress {
        network,
        address_type,
        program: hash.to_vec(),
    })
}

/// A BIP32 derivation path such as `m/84'/0'/0'/0/5`. Hardened steps end with `'` or `h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<u32>);

impl FromStr for DerivationPath {
    type Err = MhfeError;

    /// Strict: starts with `m`, steps separated by `/`, each a decimal number below 2^31 with an
    /// optional hardened mark; no spaces, signs or empty steps.
    fn from_str(text: &str) -> Result<Self, MhfeError> {
        let invalid = || {
            MhfeError::InvalidDerivationPath(format!(
                "\"{text}\" is not a path like m/84'/0'/0'/0/5"
            ))
        };
        let mut steps = text.split('/');
        if steps.next() != Some("m") {
            return Err(invalid());
        }
        let mut path = Vec::new();
        for step in steps {
            let (digits, hardened) = match step.strip_suffix(['\'', 'h']) {
                Some(digits) => (digits, true),
                None => (step, false),
            };
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let index: u32 = digits.parse().map_err(|_| invalid())?;
            if index >= HARDENED {
                return Err(invalid());
            }
            path.push(if hardened { index | HARDENED } else { index });
        }
        Ok(Self(path))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for &step in &self.0 {
            if step >= HARDENED {
                write!(f, "/{}'", step - HARDENED)?;
            } else {
                write!(f, "/{step}")?;
            }
        }
        Ok(())
    }
}

/// How far the address search goes: accounts `0..accounts`, both chains, indexes `0..indexes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchLimits {
    pub accounts: u32,
    pub indexes: u32,
}

impl Default for SearchLimits {
    /// Ten accounts with the first hundred receiving and change addresses each: 2,000 addresses,
    /// well under a second.
    fn default() -> Self {
        Self {
            accounts: 10,
            indexes: 100,
        }
    }
}

/// Reads a master key fingerprint written as eight hexadecimal digits, as wallets show it.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 4], MhfeError> {
    let text = text.trim();
    let bytes = hex::decode(text).ok().filter(|bytes| bytes.len() == 4);
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            MhfeError::InvalidFingerprint(format!("\"{text}\" is not eight hexadecimal digits"))
        })
}

/// The first four bytes of HASH160 of the master public key (BIP32), for `phrase` and the
/// BIP39 `passphrase` (empty when the wallet uses none).
pub fn master_fingerprint(phrase: &str, passphrase: &str) -> Result<[u8; 4], MhfeError> {
    let master = ExtendedKey::master(phrase, passphrase)?;
    let digest = hash160::Hash::hash(&master.public_key()?).to_byte_array();
    Ok([digest[0], digest[1], digest[2], digest[3]])
}

/// Looks for `address` on the standard path family of its type, within `limits`, or only at
/// `path` when one is given. Returns the path where it was found.
pub fn find_address(
    phrase: &str,
    passphrase: &str,
    address: &BitcoinAddress,
    path: Option<&DerivationPath>,
    limits: SearchLimits,
) -> Result<Option<DerivationPath>, MhfeError> {
    let master = ExtendedKey::master(phrase, passphrase)?;
    if let Some(path) = path {
        let key = master.derive(&path.0)?;
        return Ok(
            (program_for(&key, address.address_type)? == address.program).then(|| path.clone()),
        );
    }

    let purpose = address.address_type.purpose() | HARDENED;
    let coin = address.network.coin_type() | HARDENED;
    for account in 0..limits.accounts {
        let account_key = master.derive(&[purpose, coin, account | HARDENED])?;
        for chain in CHAINS {
            let chain_key = account_key.child(chain)?;
            for index in 0..limits.indexes {
                let key = chain_key.child(index)?;
                if program_for(&key, address.address_type)? == address.program {
                    return Ok(Some(DerivationPath(vec![
                        purpose,
                        coin,
                        account | HARDENED,
                        chain,
                        index,
                    ])));
                }
            }
        }
    }
    Ok(None)
}

/// The address text at `path`, for tests and for showing a user what a path gives.
pub fn address_at(
    phrase: &str,
    passphrase: &str,
    network: Network,
    address_type: AddressType,
    path: &DerivationPath,
) -> Result<String, MhfeError> {
    let key = ExtendedKey::master(phrase, passphrase)?.derive(&path.0)?;
    let program = program_for(&key, address_type)?;
    Ok(match (address_type, network) {
        (AddressType::P2pkh, Network::Bitcoin) => base58check(0x00, &program),
        (AddressType::P2pkh, Network::Testnet) => base58check(0x6f, &program),
        (AddressType::P2shP2wpkh, Network::Bitcoin) => base58check(0x05, &program),
        (AddressType::P2shP2wpkh, Network::Testnet) => base58check(0xc4, &program),
        (AddressType::P2wpkh | AddressType::P2tr, _) => {
            let hrp = match network {
                Network::Bitcoin => bech32::hrp::BC,
                Network::Testnet => bech32::hrp::TB,
            };
            let version = match address_type {
                AddressType::P2wpkh => bech32::segwit::VERSION_0,
                _ => bech32::segwit::VERSION_1,
            };
            bech32::segwit::encode(hrp, version, &program)
                .map_err(|error| MhfeError::Internal(error.to_string()))?
        }
    })
}

fn base58check(version: u8, hash: &[u8]) -> String {
    let mut payload = Vec::with_capacity(1 + hash.len());
    payload.push(version);
    payload.extend_from_slice(hash);
    bs58::encode(payload).with_check().into_string()
}

/// What an address of `address_type` commits to for this key: HASH160 of the public key, of the
/// P2WPKH script for nested SegWit, or the tweaked output key for Taproot.
fn program_for(key: &ExtendedKey, address_type: AddressType) -> Result<Vec<u8>, MhfeError> {
    let public_key = key.public_key()?;
    Ok(match address_type {
        AddressType::P2pkh | AddressType::P2wpkh => {
            hash160::Hash::hash(&public_key).to_byte_array().to_vec()
        }
        AddressType::P2shP2wpkh => {
            // The redeem script is OP_0 PUSH20 <HASH160(public key)>.
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&hash160::Hash::hash(&public_key).to_byte_array());
            hash160::Hash::hash(&script).to_byte_array().to_vec()
        }
        AddressType::P2tr => taproot_output_key(key)?.to_vec(),
    })
}

/// BIP86: the key-path-only Taproot output key `Q = P + t*G`, where `P` is the public key with
/// an even Y coordinate and `t = TaggedHash("TapTweak", x(P))` (BIP341).
fn taproot_output_key(key: &ExtendedKey) -> Result<[u8; 32], MhfeError> {
    let point = ProjectivePoint::GENERATOR * key.scalar()?;
    let internal = if bool::from(point.to_affine().y_is_odd()) {
        -point
    } else {
        point
    };
    let x_only = internal.to_affine().x();
    let tweak_bytes = tagged_hash("TapTweak", &x_only);
    let tweak = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(tweak_bytes)))
        .ok_or_else(|| MhfeError::Internal("Taproot tweak out of range".to_owned()))?;
    let output = internal + ProjectivePoint::GENERATOR * tweak;
    // BIP341 fails when Q is the point at infinity, which needs t = -p: probability about 2^-256.
    if bool::from(output.is_identity()) {
        return Err(MhfeError::Internal(
            "BIP341 gives no Taproot output key for this key".to_owned(),
        ));
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

/// The largest growth of UTF-8 text under NFKD: U+FDFA, 3 bytes, decomposes into 33 bytes.
const NFKD_MAX_GROWTH: usize = 11;

/// The passphrase in NFKD, as BIP39 requires, in a buffer that is wiped when dropped. It is
/// reserved at the largest size NFKD can produce, so it never grows and leaves no unwiped copy;
/// `Mnemonic::to_seed` would normalize into an ordinary string instead.
fn normalized_passphrase(passphrase: &str) -> Zeroizing<String> {
    let mut normalized = Zeroizing::new(String::with_capacity(passphrase.len() * NFKD_MAX_GROWTH));
    normalized.extend(passphrase.nfkd());
    normalized
}

/// A BIP32 extended private key. Both halves are wiped when dropped.
struct ExtendedKey {
    key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedKey {
    /// The master key of a BIP39 phrase and passphrase: `HMAC-SHA512("Bitcoin seed", seed)`.
    fn master(phrase: &str, passphrase: &str) -> Result<Self, MhfeError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|error| MhfeError::InvalidPhrase(error.to_string()))?;
        let normalized = normalized_passphrase(passphrase);
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(&normalized));
        let master = Self::from_hmac(b"Bitcoin seed", &[&seed[..]])?;
        // BIP32: a master key of zero or not below n is invalid; probability below 2^-127.
        let mut scalar = master.scalar()?;
        let invalid = bool::from(scalar.is_zero());
        scalar.zeroize();
        if invalid {
            return Err(MhfeError::Internal(
                "BIP32 gives no valid master key for this seed".to_owned(),
            ));
        }
        Ok(master)
    }

    /// Splits `HMAC-SHA512(key, parts)` into a private key and a chain code (BIP32).
    fn from_hmac(key: &[u8], parts: &[&[u8]]) -> Result<Self, MhfeError> {
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

    fn derive(&self, path: &[u32]) -> Result<Self, MhfeError> {
        let mut key = self.clone_key();
        for &index in path {
            key = key.child(index)?;
        }
        Ok(key)
    }

    /// Private child key derivation, CKDpriv of BIP32.
    fn child(&self, index: u32) -> Result<Self, MhfeError> {
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
        let mut tweak = parse_scalar(&child.key)?;
        let mut sum = tweak + self.scalar()?;
        tweak.zeroize();
        if bool::from(sum.is_zero()) {
            return Err(MhfeError::Internal(format!(
                "BIP32 has no valid key at index {index} of this path; wallets use the next index"
            )));
        }
        child.key.copy_from_slice(&sum.to_repr());
        sum.zeroize();
        Ok(child)
    }

    fn scalar(&self) -> Result<Scalar, MhfeError> {
        parse_scalar(&self.key)
    }

    /// The compressed SEC1 public key, 33 bytes.
    fn public_key(&self) -> Result<[u8; 33], MhfeError> {
        let mut scalar = self.scalar()?;
        let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
        scalar.zeroize();
        let encoded = point.to_sec1_point(true);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| MhfeError::Internal("a public key is not 33 bytes".to_owned()))
    }

    fn clone_key(&self) -> Self {
        Self {
            key: self.key.clone(),
            chain_code: self.chain_code.clone(),
        }
    }
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<Scalar, MhfeError> {
    Option::from(Scalar::from_repr(FieldBytes::from(*bytes)))
        .ok_or_else(|| MhfeError::Internal("BIP32 produced a key out of range".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public BIP39 test phrase of BIP84, BIP86 and many wallets.
    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn path(text: &str) -> DerivationPath {
        text.parse().unwrap()
    }

    #[test]
    fn master_fingerprints_match_known_values() {
        // 73c5da0a is the published value; b4e3f5ed was computed independently with Python's
        // hashlib from the BIP32 and BIP39 specifications.
        assert_eq!(
            hex::encode(master_fingerprint(ABANDON, "").unwrap()),
            "73c5da0a"
        );
        assert_eq!(
            hex::encode(master_fingerprint(ABANDON, "TREZOR").unwrap()),
            "b4e3f5ed"
        );
    }

    #[test]
    fn addresses_match_the_bip_test_vectors() {
        // Mainnet values are the published vectors of BIP44, BIP49, BIP84 and BIP86; the testnet
        // and passphrase values were computed independently (Python, hashlib) and agree with
        // BIP49's testnet vector.
        let cases = [
            (
                "m/44'/0'/0'/0/0",
                Network::Bitcoin,
                AddressType::P2pkh,
                "",
                "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            ),
            (
                "m/49'/0'/0'/0/0",
                Network::Bitcoin,
                AddressType::P2shP2wpkh,
                "",
                "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            ),
            (
                "m/84'/0'/0'/0/0",
                Network::Bitcoin,
                AddressType::P2wpkh,
                "",
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            ),
            (
                "m/84'/0'/0'/0/1",
                Network::Bitcoin,
                AddressType::P2wpkh,
                "",
                "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            ),
            (
                "m/84'/0'/0'/1/0",
                Network::Bitcoin,
                AddressType::P2wpkh,
                "",
                "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
            ),
            (
                "m/86'/0'/0'/0/0",
                Network::Bitcoin,
                AddressType::P2tr,
                "",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (
                "m/86'/0'/0'/1/0",
                Network::Bitcoin,
                AddressType::P2tr,
                "",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            ),
            (
                "m/44'/1'/0'/0/0",
                Network::Testnet,
                AddressType::P2pkh,
                "",
                "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
            ),
            (
                "m/49'/1'/0'/0/0",
                Network::Testnet,
                AddressType::P2shP2wpkh,
                "",
                "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
            ),
            (
                "m/84'/1'/0'/0/0",
                Network::Testnet,
                AddressType::P2wpkh,
                "",
                "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
            ),
            (
                "m/86'/1'/0'/0/0",
                Network::Testnet,
                AddressType::P2tr,
                "",
                "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
            ),
            (
                "m/84'/0'/0'/0/0",
                Network::Bitcoin,
                AddressType::P2wpkh,
                "TREZOR",
                "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu",
            ),
        ];
        for (path_text, network, address_type, passphrase, expected) in cases {
            let derived =
                address_at(ABANDON, passphrase, network, address_type, &path(path_text)).unwrap();
            assert_eq!(derived, expected, "{path_text}");
            let parsed: BitcoinAddress = expected.parse().unwrap();
            assert_eq!(
                (parsed.network, parsed.address_type),
                (network, address_type),
                "{expected}"
            );
        }
    }

    #[test]
    fn the_search_finds_an_address_on_its_standard_path() {
        // Account 2, change chain, index 19: computed independently (Python, hashlib).
        let target: BitcoinAddress = "bc1q4du7e3vw34vsflf76xf9h8gktms9wzqcl7vlh5"
            .parse()
            .unwrap();
        let found = find_address(ABANDON, "", &target, None, SearchLimits::default()).unwrap();
        assert_eq!(found, Some(path("m/84'/0'/2'/1/19")));

        let small = SearchLimits {
            accounts: 2,
            indexes: 20,
        };
        assert_eq!(
            find_address(ABANDON, "", &target, None, small).unwrap(),
            None
        );
        // A different passphrase gives a different wallet.
        assert_eq!(
            find_address(ABANDON, "TREZOR", &target, None, SearchLimits::default()).unwrap(),
            None
        );
        // An explicit path is checked alone.
        let explicit = path("m/84'/0'/2'/1/19");
        assert!(find_address(ABANDON, "", &target, Some(&explicit), small)
            .unwrap()
            .is_some());
    }

    /// The wiping normalization gives the seed that bip39 itself computes, also for a passphrase
    /// that NFKD changes, including one that grows the most.
    #[test]
    fn the_passphrase_is_normalized_as_bip39_does() {
        let mnemonic = Mnemonic::parse_in(Language::English, ABANDON).unwrap();
        for passphrase in ["", "TREZOR", "Caf\u{E9} \u{FB01}", "\u{FDFA}\u{FDFA}"] {
            let normalized = normalized_passphrase(passphrase);
            assert_eq!(
                mnemonic.to_seed_normalized(&normalized),
                mnemonic.to_seed(passphrase),
                "{passphrase:?}"
            );
        }
    }

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

    /// BIP173: an address may be written all in lower or all in upper case, never mixed.
    #[test]
    fn segwit_addresses_are_accepted_in_either_case() {
        for lower in [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        ] {
            let upper = lower.to_ascii_uppercase();
            assert_eq!(
                upper.parse::<BitcoinAddress>().unwrap(),
                lower.parse::<BitcoinAddress>().unwrap(),
                "{upper}"
            );
            let mixed = format!("{}{}", &upper[..4], &lower[4..]);
            assert!(mixed.parse::<BitcoinAddress>().is_err(), "{mixed}");
        }
    }

    #[test]
    fn rejects_unsupported_or_damaged_addresses() {
        for text in [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv", // checksum changed
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB",         // checksum changed
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", // P2WSH
            "ltc1qcr8te4kr609gcawutmrza0j4xv80jy8zkvrefp", // another coin
            "",
        ] {
            assert!(text.parse::<BitcoinAddress>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn paths_are_parsed_strictly() {
        assert_eq!(path("m/84'/0'/0'/0/5").to_string(), "m/84'/0'/0'/0/5");
        assert_eq!(path("m/84h/0h/0h/0/5").to_string(), "m/84'/0'/0'/0/5");
        assert_eq!(path("m").to_string(), "m");
        for invalid in [
            "",
            "84'/0'",
            "m/",
            "m//0",
            "m/-1",
            "m/+1",
            "m/2147483648",
            "m/0x1",
            "m/ 1",
            "M/0",
            "m/1''",
        ] {
            assert!(invalid.parse::<DerivationPath>().is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn fingerprints_are_eight_hex_digits() {
        assert_eq!(
            parse_fingerprint(" 73C5DA0A ").unwrap(),
            [0x73, 0xc5, 0xda, 0x0a]
        );
        for invalid in ["73c5da0", "73c5da0a0", "zzzzzzzz", ""] {
            assert!(parse_fingerprint(invalid).is_err(), "{invalid:?}");
        }
    }
}
