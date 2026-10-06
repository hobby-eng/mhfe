//! Public wallet data for rehearsing a recovery without showing the phrase: the BIP32 master
//! key fingerprint and the single-key receiving addresses of twelve coins on their standard
//! paths: Bitcoin on BIP44 (legacy), BIP49 (nested SegWit), BIP84 (native SegWit) and BIP86
//! (Taproot), Litecoin likewise without Taproot, BIP44 for the others ([`Coin`]), and Dash
//! Platform payment addresses on DIP17.
//!
//! Private keys exist only inside this module, and every binding that holds one, as bytes or as a
//! scalar, is wiped when dropped; only public values and yes-or-no answers come out. Copies that
//! the compiler or the curve library makes on the way, in registers or on the stack, are outside
//! this control.
//!
//! ```
//! use mhfe::wallet::{find_address, master_fingerprint, Address, Coin, SearchLimits};
//!
//! // The public test phrase of BIP84, without a BIP39 passphrase.
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
//!               abandon about";
//! let address = Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")?;
//! let found = find_address(phrase, "", &address, None, SearchLimits::default())?;
//! assert_eq!(found.map(|path| path.to_string()).as_deref(), Some("m/84'/0'/0'/0/0"));
//! assert_eq!(master_fingerprint(phrase, "")?, [0x73, 0xc5, 0xda, 0x0a]);
//! # Ok::<(), mhfe::MhfeError>(())
//! ```

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
use sha3::Keccak256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::MhfeError;

type HmacSha512 = Hmac<Sha512>;

/// Indexes from 2^31 up are hardened (BIP32).
pub const HARDENED: u32 = 1 << 31;
/// Receiving and change chains of a BIP44-style account. DIP17 calls them key classes and
/// hardens them.
const CHAINS: [u32; 2] = [0, 1];
/// The DIP9 purpose of Dash's feature paths, and the feature number of Platform payments
/// (DIP17): `m/9'/coin'/17'/account'/key_class'/index`.
const DIP9_PURPOSE: u32 = 9;
const DIP17_FEATURE: u32 = 17;

/// A coin whose single-key receiving addresses the rehearsal can look for. All of them use
/// secp256k1 keys on BIP44-style paths `m/purpose'/coin'/account'/chain/index`, or for Dash
/// Platform on DIP17 paths; they differ only in how a public key becomes an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coin {
    Bitcoin,
    /// Ethereum and every EVM network, which share its addresses.
    Ethereum,
    Xrp,
    Tron,
    /// Zcash transparent addresses; shielded ones are out of reach without its own cryptography.
    Zcash,
    Dogecoin,
    BitcoinCash,
    Litecoin,
    EthereumClassic,
    Cosmos,
    Injective,
    Dash,
}

impl Coin {
    /// Every coin, in the alphabetical order of their names, which is the order the program
    /// offers them in.
    pub const ALL: [Self; 12] = [
        Self::Bitcoin,
        Self::BitcoinCash,
        Self::Cosmos,
        Self::Dash,
        Self::Dogecoin,
        Self::Ethereum,
        Self::EthereumClassic,
        Self::Injective,
        Self::Litecoin,
        Self::Tron,
        Self::Xrp,
        Self::Zcash,
    ];

    /// The name a person knows it by.
    pub fn name(self) -> &'static str {
        match self {
            Self::Bitcoin => "Bitcoin",
            Self::Ethereum => "Ethereum and EVM networks",
            Self::Xrp => "XRP",
            Self::Tron => "Tron",
            Self::Zcash => "Zcash",
            Self::Dogecoin => "Dogecoin",
            Self::BitcoinCash => "Bitcoin Cash",
            Self::Litecoin => "Litecoin",
            Self::EthereumClassic => "Ethereum Classic",
            Self::Cosmos => "Cosmos",
            Self::Injective => "Injective",
            Self::Dash => "Dash",
        }
    }

    /// The identifier of the command line and the browser package, such as "bitcoin-cash".
    pub fn id(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Ethereum => "ethereum",
            Self::Xrp => "xrp",
            Self::Tron => "tron",
            Self::Zcash => "zcash",
            Self::Dogecoin => "dogecoin",
            Self::BitcoinCash => "bitcoin-cash",
            Self::Litecoin => "litecoin",
            Self::EthereumClassic => "ethereum-classic",
            Self::Cosmos => "cosmos",
            Self::Injective => "injective",
            Self::Dash => "dash",
        }
    }

    /// How the supported addresses begin, such as "1…, 3…, bc1q… or bc1p…".
    pub fn address_forms(self) -> &'static str {
        match self {
            Self::Bitcoin => "1…, 3…, bc1q… or bc1p…",
            Self::Ethereum | Self::EthereumClassic => "0x…",
            Self::Xrp => "r…",
            Self::Tron => "T…",
            Self::Zcash => "t1…",
            Self::Dogecoin => "D…",
            Self::BitcoinCash => "bitcoincash:q… or 1…",
            Self::Litecoin => "L…, M…, 3… or ltc1q…",
            Self::Cosmos => "cosmos1…",
            Self::Injective => "inj1…",
            Self::Dash => "X… or dash1k…",
        }
    }

    /// The coin types (SLIP-44) of the paths searched on its main network. Bitcoin Cash forked
    /// from Bitcoin and Ethereum Classic from Ethereum, and wallets made for them use either their
    /// own coin type or the one of the chain they came from, so both are searched.
    fn coin_types(self) -> &'static [u32] {
        match self {
            Self::Bitcoin => &[0],
            Self::Ethereum | Self::Injective => &[60],
            Self::Xrp => &[144],
            Self::Tron => &[195],
            Self::Zcash => &[133],
            Self::Dogecoin => &[3],
            Self::BitcoinCash => &[145, 0],
            Self::Litecoin => &[2],
            Self::EthereumClassic => &[61, 60],
            Self::Cosmos => &[118],
            Self::Dash => &[5],
        }
    }
}

impl FromStr for Coin {
    type Err = MhfeError;

    /// Reads an identifier such as "bitcoin" or "bitcoin-cash".
    fn from_str(text: &str) -> Result<Self, MhfeError> {
        let wanted = text.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|coin| coin.id() == wanted)
            .ok_or_else(|| {
                let known: Vec<&str> = Self::ALL.iter().map(|coin| coin.id()).collect();
                MhfeError::InvalidAddress(format!(
                    "\"{text}\" is not one of the coins {}",
                    known.join(", ")
                ))
            })
    }
}

/// How an address commits to a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// HASH160 of the compressed public key: legacy addresses ("1...", "L...", "D...", "X...",
    /// "t1...", a Bitcoin Cash "q..."), XRP and Cosmos. BIP44.
    P2pkh,
    /// Nested SegWit, "3..." or "M...": HASH160 of the P2WPKH script. BIP49.
    P2shP2wpkh,
    /// Native SegWit, "bc1q..." or "ltc1q...": HASH160 of the compressed public key. BIP84.
    P2wpkh,
    /// Taproot, "bc1p...": the tweaked output key. BIP86.
    P2tr,
    /// The last 20 bytes of Keccak-256 of the uncompressed public key: Ethereum and EVM
    /// networks, Ethereum Classic, Tron and Injective. BIP44 paths.
    Keccak,
    /// A Dash Platform payment address, "dash1k...": HASH160 of the compressed public key,
    /// written in Bech32m after the type byte 0xb0 (DIP18). DIP17 paths.
    DashPlatform,
}

impl AddressType {
    /// The name of a Bitcoin or Litecoin address of this type.
    pub fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "legacy",
            Self::P2shP2wpkh => "nested SegWit",
            Self::P2wpkh => "native SegWit",
            Self::P2tr => "Taproot",
            Self::Keccak => "Keccak",
            Self::DashPlatform => "Platform payment",
        }
    }

    /// The first step of its standard paths: 44, 49, 84 or 86, as in the BIP of the same number,
    /// or 9 for Dash's feature paths (DIP9).
    pub fn purpose(self) -> u32 {
        match self {
            Self::P2pkh | Self::Keccak => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
            Self::P2tr => 86,
            Self::DashPlatform => DIP9_PURPOSE,
        }
    }
}

/// A receiving address the user knows, reduced to what identifies it: the coin, whether it is a
/// Bitcoin test network address, the type and the 20-byte key or script hash (32-byte output key
/// for Taproot). It is made only by parsing an address, and its parts cannot be changed afterwards,
/// so it always describes a real address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    coin: Coin,
    /// A Bitcoin testnet or signet address, or a Dash Platform testnet address, searched under
    /// coin type 1.
    testnet: bool,
    address_type: AddressType,
    program: Vec<u8>,
}

impl Address {
    /// Reads `text` as a single-key receiving address of `coin`. Multisignature and script
    /// addresses, Zcash shielded addresses and those of other coins are refused.
    pub fn parse(coin: Coin, text: &str) -> Result<Self, MhfeError> {
        let text = text.trim();
        let address = match coin {
            Coin::Bitcoin if is_bech32(text, &["bc1", "tb1"]) => parse_segwit(coin, text)?,
            Coin::Litecoin if is_bech32(text, &["ltc1"]) => parse_segwit(coin, text)?,
            Coin::BitcoinCash if !text.starts_with('1') => parse_cashaddr(text)?,
            Coin::Ethereum | Coin::EthereumClassic => parse_hex(coin, text)?,
            Coin::Cosmos => parse_bech32_account(coin, text, "cosmos", AddressType::P2pkh)?,
            Coin::Injective => parse_bech32_account(coin, text, "inj", AddressType::Keccak)?,
            Coin::Dash if is_bech32(text, &["dash1", "tdash1"]) => parse_dash_platform(text)?,
            Coin::Zcash if is_shielded_zcash(text) => {
                return Err(invalid_address(
                    "it is shielded; use a transparent t1… address of the same wallet",
                ))
            }
            _ => parse_base58(coin, text)?,
        };
        Ok(address)
    }

    pub fn coin(&self) -> Coin {
        self.coin
    }

    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Its type, for a person, where its coin has several: "nested SegWit (BIP49)", "testnet,
    /// Taproot (BIP86)", "Platform payment (DIP17)" or, for Zcash, "transparent". `None` for a
    /// coin with one kind of address.
    pub fn type_description(&self) -> Option<String> {
        let network = if self.testnet { "testnet, " } else { "" };
        match self.coin {
            Coin::Bitcoin | Coin::Litecoin => Some(format!(
                "{network}{} (BIP{})",
                self.address_type.name(),
                self.address_type.purpose()
            )),
            Coin::Dash => Some(match self.address_type {
                AddressType::DashPlatform => format!("{network}Platform payment (DIP17)"),
                _ => "Core (BIP44)".to_owned(),
            }),
            Coin::Zcash => Some("transparent".to_owned()),
            _ => None,
        }
    }

    /// The roots of the paths searched for it, every step hardened: `[44, 5]` for `m/44'/5'`, or
    /// `[9, 5, 17]` for Dash Platform. Under a root come the account, `root/account'`, its two
    /// chains and their addresses. Coins with two coin types have a root for each.
    pub fn search_roots(&self) -> Vec<Vec<u32>> {
        // Every test network of Bitcoin, and Dash's, uses coin type 1.
        let coin_types: &[u32] = if self.testnet {
            &[1]
        } else {
            self.coin.coin_types()
        };
        let purpose = self.address_type.purpose();
        coin_types
            .iter()
            .map(|&coin| match self.address_type {
                AddressType::DashPlatform => vec![purpose, coin, DIP17_FEATURE],
                _ => vec![purpose, coin],
            })
            .collect()
    }

    /// Whether the two chains under an account are hardened: DIP17 hardens its key classes,
    /// `0'` for receiving and `1'` for change, where BIP44 has `0` and `1`.
    pub fn hardened_chains(&self) -> bool {
        self.address_type == AddressType::DashPlatform
    }
}

fn invalid_address(reason: &str) -> MhfeError {
    MhfeError::InvalidAddress(reason.to_owned())
}

fn not_of(coin: Coin) -> MhfeError {
    MhfeError::InvalidAddress(format!(
        "it is not a {} address ({})",
        coin.name(),
        coin.address_forms()
    ))
}

/// Prefixes of Zcash shielded addresses: Sapling (Bech32), unified (Bech32m) and Sprout (Base58),
/// on mainnet and testnet. Deriving them needs Zcash's own curves and key tree (ZIP-32), so a
/// check refuses them and asks for the wallet's transparent address instead of searching in vain.
const ZCASH_SHIELDED_PREFIXES: &[&str] = &["zs1", "ztestsapling1", "u1", "utest1", "zc", "zt"];

fn is_shielded_zcash(text: &str) -> bool {
    let lowercase = text.to_ascii_lowercase();
    ZCASH_SHIELDED_PREFIXES
        .iter()
        .any(|prefix| lowercase.starts_with(prefix))
}

/// The type byte that starts a Dash Platform address (DIP18): a payment address of a DIP17 key,
/// or an Orchard shielded address.
const DASH_PLATFORM_P2PKH: u8 = 0xb0;
const DASH_ORCHARD: u8 = 0x10;

/// Dash Platform addresses, Bech32m with the prefix "dash" or "tdash" (DIP18). A payment address
/// of a single key is read; an Orchard address is refused, as its keys need Orchard's own
/// cryptography, and so is any other kind.
fn parse_dash_platform(text: &str) -> Result<Address, MhfeError> {
    use bech32::primitives::decode::CheckedHrpstring;
    let decoded = CheckedHrpstring::new::<bech32::Bech32m>(text)
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    let testnet = match decoded.hrp().as_str().to_ascii_lowercase().as_str() {
        "dash" => false,
        "tdash" => true,
        _ => return Err(not_of(Coin::Dash)),
    };
    let data: Vec<u8> = decoded.byte_iter().collect();
    match data.split_first() {
        Some((&DASH_PLATFORM_P2PKH, hash)) if hash.len() != 20 => {
            Err(invalid_address("it has the wrong length"))
        }
        Some((&DASH_PLATFORM_P2PKH, _)) if !whole_payment_payload(&decoded) => {
            Err(invalid_address("its checksum or format is wrong"))
        }
        Some((&DASH_PLATFORM_P2PKH, hash)) => Ok(Address {
            coin: Coin::Dash,
            testnet,
            address_type: AddressType::DashPlatform,
            program: hash.to_vec(),
        }),
        Some((&DASH_ORCHARD, _)) => Err(invalid_address(
            "it is shielded; use a Dash Core X… or Platform dash1k… address of the same wallet",
        )),
        _ => Err(invalid_address(
            "it is not the Platform payment address of a single key",
        )),
    }
}

/// Whether a Platform payment address holds its 21 bytes, the type byte and the 160-bit hash, as
/// the one encoding Bech32 allows: 34 five-bit groups, whose last two bits are padding and zero
/// (BIP173). byte_iter alone would read the same bytes from another group added at the end or from
/// padding bits set, and take such a string for the address (AUD-008-FUN001).
fn whole_payment_payload(decoded: &bech32::primitives::decode::CheckedHrpstring) -> bool {
    /// 21 bytes are 168 bits: 34 groups of five bits, 170 bits, the last two of them padding.
    const GROUPS: usize = 34;
    const PADDING_MASK: u8 = 0b11;
    let groups = decoded.data_part_ascii_no_checksum();
    let padding_is_zero = groups
        .last()
        .and_then(|&last| bech32::Fe32::from_char(char::from(last)).ok())
        .is_some_and(|last| last.to_u8() & PADDING_MASK == 0);
    groups.len() == GROUPS && padding_is_zero
}

/// Whether `text` starts with one of the Bech32 prefixes, in either case.
fn is_bech32(text: &str, prefixes: &[&str]) -> bool {
    let lowercase = text.to_ascii_lowercase();
    prefixes.iter().any(|prefix| lowercase.starts_with(prefix))
}

/// SegWit addresses of Bitcoin and Litecoin, Bech32 and Bech32m (BIP173, BIP350).
fn parse_segwit(coin: Coin, text: &str) -> Result<Address, MhfeError> {
    let (hrp, version, program) = bech32::segwit::decode(text)
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    // BIP173 allows an address written all in capitals, as in QR codes; the decoder has already
    // refused mixed case, and keeps the prefix as written.
    let testnet = match (coin, hrp.as_str().to_ascii_lowercase().as_str()) {
        (Coin::Bitcoin, "bc") | (Coin::Litecoin, "ltc") => false,
        (Coin::Bitcoin, "tb") => true,
        _ => return Err(not_of(coin)),
    };
    let address_type =
        match (version.to_u8(), program.len(), coin) {
            (0, 20, _) => AddressType::P2wpkh,
            (1, 32, Coin::Bitcoin) => AddressType::P2tr,
            _ => return Err(invalid_address(
                "only single-key addresses (bc1q with 42 characters, bc1p or ltc1q) can be checked",
            )),
        };
    Ok(Address {
        coin,
        testnet,
        address_type,
        program,
    })
}

/// The version prefixes of a coin's Base58Check addresses: prefix, type and whether it is a
/// Bitcoin test network address. A "3..." Bitcoin or Litecoin address is taken as nested SegWit,
/// the only single-key address of that form.
fn base58_versions(coin: Coin) -> &'static [(&'static [u8], AddressType, bool)] {
    use AddressType::{Keccak, P2pkh, P2shP2wpkh};
    match coin {
        Coin::Bitcoin => &[
            (&[0x00], P2pkh, false),
            (&[0x05], P2shP2wpkh, false),
            (&[0x6f], P2pkh, true),
            (&[0xc4], P2shP2wpkh, true),
        ],
        // "L..." and "M...", and the "3..." that Litecoin used before "M...".
        Coin::Litecoin => &[
            (&[0x30], P2pkh, false),
            (&[0x32], P2shP2wpkh, false),
            (&[0x05], P2shP2wpkh, false),
        ],
        Coin::Dogecoin => &[(&[0x1e], P2pkh, false)],
        Coin::Dash => &[(&[0x4c], P2pkh, false)],
        // "t1...": a two-byte prefix.
        Coin::Zcash => &[(&[0x1c, 0xb8], P2pkh, false)],
        // The legacy form "1...", the same as Bitcoin's.
        Coin::BitcoinCash => &[(&[0x00], P2pkh, false)],
        Coin::Xrp => &[(&[0x00], P2pkh, false)],
        Coin::Tron => &[(&[0x41], Keccak, false)],
        Coin::Ethereum | Coin::EthereumClassic | Coin::Cosmos | Coin::Injective => &[],
    }
}

/// Base58Check addresses: a version prefix and a 20-byte hash. XRP writes them with its own
/// alphabet.
fn parse_base58(coin: Coin, text: &str) -> Result<Address, MhfeError> {
    let alphabet = match coin {
        Coin::Xrp => bs58::Alphabet::RIPPLE,
        _ => bs58::Alphabet::BITCOIN,
    };
    let decoded = bs58::decode(text)
        .with_alphabet(alphabet)
        .with_check(None)
        .into_vec()
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    let &(prefix, address_type, testnet) = base58_versions(coin)
        .iter()
        .find(|(prefix, _, _)| decoded.starts_with(prefix))
        .ok_or_else(|| not_of(coin))?;
    let hash = &decoded[prefix.len()..];
    if hash.len() != 20 {
        return Err(invalid_address("it has the wrong length"));
    }
    Ok(Address {
        coin,
        testnet,
        address_type,
        program: hash.to_vec(),
    })
}

/// Bech32 account addresses of Cosmos SDK chains, such as "cosmos1..." or "inj1...": a prefix and
/// a 20-byte hash.
fn parse_bech32_account(
    coin: Coin,
    text: &str,
    prefix: &str,
    address_type: AddressType,
) -> Result<Address, MhfeError> {
    const ACCOUNT_BYTES: usize = 20;
    const ACCOUNT_DATA_GROUPS: usize = ACCOUNT_BYTES * 8 / 5;
    // Cosmos SDK accounts use Bech32 (BIP173), never Bech32m: the same data with the other
    // checksum is not a valid address (AUD-007-FUN001).
    use bech32::primitives::decode::CheckedHrpstring;
    let decoded = CheckedHrpstring::new::<bech32::Bech32>(text)
        .map_err(|_| invalid_address("its checksum or format is wrong"))?;
    if decoded.hrp().as_str().to_ascii_lowercase() != prefix {
        return Err(not_of(coin));
    }
    // A 160-bit account has exactly 32 groups, with no padding. byte_iter alone discards
    // incomplete trailing bytes and would accept an extra five-bit group (AUD-007-FUN003).
    if decoded.data_part_ascii_no_checksum().len() != ACCOUNT_DATA_GROUPS {
        return Err(invalid_address("it has the wrong length"));
    }
    let program: Vec<u8> = decoded.byte_iter().collect();
    if program.len() != ACCOUNT_BYTES {
        return Err(invalid_address("it has the wrong length"));
    }
    Ok(Address {
        coin,
        testnet: false,
        address_type,
        program,
    })
}

/// Ethereum-style addresses: "0x" and 40 hexadecimal digits. In mixed case they carry the EIP-55
/// checksum, which must hold; all in lower or upper case they carry none.
fn parse_hex(coin: Coin, text: &str) -> Result<Address, MhfeError> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .ok_or_else(|| not_of(coin))?;
    let program = hex::decode(digits)
        .ok()
        .filter(|bytes| bytes.len() == 20)
        .ok_or_else(|| invalid_address("it is not 40 hexadecimal digits after 0x"))?;
    let mixed_case = digits.chars().any(|c| c.is_ascii_lowercase())
        && digits.chars().any(|c| c.is_ascii_uppercase());
    if mixed_case && eip55(&program) != digits {
        return Err(invalid_address(
            "its EIP-55 checksum, the mix of capital and small letters, is wrong",
        ));
    }
    Ok(Address {
        coin,
        testnet: false,
        address_type: AddressType::Keccak,
        program,
    })
}

/// The 40 hexadecimal digits of an address with the EIP-55 checksum: a letter is a capital where
/// the matching digit of Keccak-256 of the lowercase address is 8 or more.
fn eip55(address: &[u8]) -> String {
    let lowercase = hex::encode(address);
    let hash = Keccak256::digest(lowercase.as_bytes());
    lowercase
        .chars()
        .enumerate()
        .map(|(position, character)| {
            let byte = hash[position / 2];
            let nibble = if position % 2 == 0 {
                byte >> 4
            } else {
                byte & 0x0f
            };
            if nibble >= 8 {
                character.to_ascii_uppercase()
            } else {
                character
            }
        })
        .collect()
}

/// The CashAddr alphabet and the prefix of Bitcoin Cash addresses.
const CASHADDR_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CASHADDR_PREFIX: &str = "bitcoincash";

/// A Bitcoin Cash CashAddr address, with or without its "bitcoincash:" prefix, in either case. Only
/// a P2PKH address with a 160-bit hash (version byte 0, "q...") is single-key.
fn parse_cashaddr(text: &str) -> Result<Address, MhfeError> {
    let lowercase = text.to_ascii_lowercase();
    if lowercase != text && text.to_ascii_uppercase() != text {
        return Err(invalid_address(
            "it mixes capital and small letters, which CashAddr does not allow",
        ));
    }
    let payload = match lowercase.split_once(':') {
        Some((CASHADDR_PREFIX, payload)) => payload,
        Some(_) => return Err(not_of(Coin::BitcoinCash)),
        None => lowercase.as_str(),
    };
    let values = payload
        .bytes()
        .map(|byte| {
            CASHADDR_CHARSET
                .iter()
                .position(|&c| c == byte)
                .map(|v| v as u8)
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| not_of(Coin::BitcoinCash))?;
    // The prefix enters the checksum as the low five bits of each character, then a zero.
    let mut checked: Vec<u8> = CASHADDR_PREFIX.bytes().map(|byte| byte & 0x1f).collect();
    checked.push(0);
    checked.extend_from_slice(&values);
    // Eight five-bit values of checksum follow the data.
    if values.len() <= 8 || cashaddr_polymod(&checked) != 0 {
        return Err(invalid_address("its checksum or format is wrong"));
    }
    let data = regroup_five_to_eight(&values[..values.len() - 8])
        .ok_or_else(|| invalid_address("its checksum or format is wrong"))?;
    // Version byte 0: P2PKH with a 160-bit hash.
    match data.split_first() {
        Some((0, hash)) if hash.len() == 20 => Ok(Address {
            coin: Coin::BitcoinCash,
            testnet: false,
            address_type: AddressType::P2pkh,
            program: hash.to_vec(),
        }),
        _ => Err(invalid_address(
            "only single-key addresses (bitcoincash:q...) can be checked",
        )),
    }
}

/// The CashAddr checksum function: zero for a valid address.
fn cashaddr_polymod(values: &[u8]) -> u64 {
    const GENERATORS: [u64; 5] = [
        0x98_f2bc_8e61,
        0x79_b76d_99e2,
        0xf3_3e5f_b3c4,
        0xae_2eab_e2a8,
        0x1e_4f43_e470,
    ];
    let mut checksum: u64 = 1;
    for &value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x07_ffff_ffff) << 5) ^ u64::from(value);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum ^ 1
}

/// Five-bit values back to bytes; the padding at the end must be zero and shorter than five bits.
fn regroup_five_to_eight(values: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for &value in values {
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
        }
    }
    (bits < 5 && accumulator & ((1 << bits) - 1) == 0).then_some(bytes)
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
/// Each count is at least 1 and at most 2^31: BIP32 has 2^31 hardened account numbers and 2^31
/// ordinary address indexes, and a higher number would silently name a different path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchLimits {
    accounts: u32,
    indexes: u32,
}

impl SearchLimits {
    /// Limits for the first `accounts` accounts and the first `indexes` addresses of each chain.
    pub fn new(accounts: u32, indexes: u32) -> Result<Self, MhfeError> {
        let possible = |count: u32| (1..=HARDENED).contains(&count);
        if possible(accounts) && possible(indexes) {
            Ok(Self { accounts, indexes })
        } else {
            // The limits stand for the paths the search derives, so a count out of range is
            // reported as the invalid path it would lead to.
            Err(MhfeError::InvalidDerivationPath(format!(
                "a search covers 1 to {HARDENED} accounts and indexes, not {accounts} and {indexes}"
            )))
        }
    }

    pub fn accounts(self) -> u32 {
        self.accounts
    }

    pub fn indexes(self) -> u32 {
        self.indexes
    }
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

/// Looks for `address` on the standard paths of its type, within `limits`, or only at `path` when
/// one is given. Returns the path where it was found.
pub fn find_address(
    phrase: &str,
    passphrase: &str,
    address: &Address,
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

    let chains = if address.hardened_chains() {
        CHAINS.map(|chain| chain | HARDENED)
    } else {
        CHAINS
    };
    for root in address.search_roots() {
        let root: Vec<u32> = root.iter().map(|step| step | HARDENED).collect();
        for account in 0..limits.accounts {
            let account_path = [root.as_slice(), &[account | HARDENED]].concat();
            let account_key = master.derive(&account_path)?;
            for chain in chains {
                let chain_key = account_key.child(chain)?;
                for index in 0..limits.indexes {
                    let key = chain_key.child(index)?;
                    if program_for(&key, address.address_type)? == address.program {
                        let found = [account_path.as_slice(), &[chain, index]].concat();
                        return Ok(Some(DerivationPath(found)));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// What an address of `address_type` commits to for this key: HASH160 of the public key, of the
/// P2WPKH script for nested SegWit, the tweaked output key for Taproot, or the last 20 bytes of
/// Keccak-256 of the uncompressed public key.
fn program_for(key: &ExtendedKey, address_type: AddressType) -> Result<Vec<u8>, MhfeError> {
    let public_key = key.public_key()?;
    Ok(match address_type {
        AddressType::P2pkh | AddressType::P2wpkh | AddressType::DashPlatform => {
            hash160::Hash::hash(&public_key).to_byte_array().to_vec()
        }
        AddressType::P2shP2wpkh => {
            // The redeem script is OP_0 PUSH20 <HASH160(public key)>.
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&hash160::Hash::hash(&public_key).to_byte_array());
            hash160::Hash::hash(&script).to_byte_array().to_vec()
        }
        AddressType::P2tr => taproot_output_key(key)?.to_vec(),
        AddressType::Keccak => {
            // The 64 bytes of the uncompressed key without its 0x04 prefix (Ethereum yellow paper).
            let uncompressed = key.uncompressed_public_key()?;
            Keccak256::digest(&uncompressed[1..])[12..].to_vec()
        }
    })
}

/// BIP86: the key-path-only Taproot output key `Q = P + t*G`, where `P` is the public key with
/// an even Y coordinate and `t = TaggedHash("TapTweak", x(P))` (BIP341).
fn taproot_output_key(key: &ExtendedKey) -> Result<[u8; 32], MhfeError> {
    let point = key.public_point()?;
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
/// The BIP39 seed of a phrase and a passphrase: PBKDF2-HMAC-SHA512, 2,048 iterations, with the
/// salt "mnemonic" and the passphrase in NFKD.
pub(crate) fn bip39_seed(mnemonic: &Mnemonic, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let normalized = normalized_passphrase(passphrase);
    Zeroizing::new(mnemonic.to_seed_normalized(&normalized))
}

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
        let seed = bip39_seed(&mnemonic, passphrase);
        let master = Self::from_hmac(b"Bitcoin seed", &[&seed[..]])?;
        // BIP32: a master key of zero or not below n is invalid; probability below 2^-127.
        if bool::from(master.scalar()?.is_zero()) {
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
        let tweak = parse_scalar(&child.key)?;
        let sum = Zeroizing::new(*tweak + *self.scalar()?);
        if bool::from(sum.is_zero()) {
            return Err(MhfeError::Internal(format!(
                "BIP32 has no valid key at index {index} of this path; wallets use the next index"
            )));
        }
        child
            .key
            .copy_from_slice(&Zeroizing::new(sum.to_repr())[..]);
        Ok(child)
    }

    /// The private key as a scalar, wiped when dropped like every scalar binding here.
    fn scalar(&self) -> Result<Zeroizing<Scalar>, MhfeError> {
        parse_scalar(&self.key)
    }

    /// The public point `k*G` of the private key `k`.
    fn public_point(&self) -> Result<ProjectivePoint, MhfeError> {
        Ok(ProjectivePoint::GENERATOR * *self.scalar()?)
    }

    /// The compressed SEC1 public key, 33 bytes.
    fn public_key(&self) -> Result<[u8; 33], MhfeError> {
        let point = self.public_point()?.to_affine();
        let encoded = point.to_sec1_point(true);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| MhfeError::Internal("a public key is not 33 bytes".to_owned()))
    }

    /// The public key in SEC1 uncompressed form: 0x04 and both coordinates.
    fn uncompressed_public_key(&self) -> Result<[u8; 65], MhfeError> {
        let point = self.public_point()?.to_affine();
        let encoded = point.to_sec1_point(false);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| MhfeError::Internal("a public key is not 65 bytes".to_owned()))
    }

    fn clone_key(&self) -> Self {
        Self {
            key: self.key.clone(),
            chain_code: self.chain_code.clone(),
        }
    }
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<Zeroizing<Scalar>, MhfeError> {
    let mut repr = FieldBytes::from(*bytes);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr)).map(Zeroizing::new);
    repr.zeroize();
    scalar.ok_or_else(|| MhfeError::Internal("BIP32 produced a key out of range".to_owned()))
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

    /// Where the wallets of the public test phrase put each address: coin, BIP39 passphrase, path,
    /// address. The Bitcoin mainnet values at index 0 are the published vectors of BIP44, BIP49,
    /// BIP84 and BIP86; the other Bitcoin values were computed independently with Python's hashlib
    /// and agree with BIP49's testnet vector. The other coins were computed independently with the
    /// audited JavaScript libraries @scure/bip32, @noble/hashes, @noble/curves and @scure/base, and
    /// ethers for EIP-55, at the first address and at account 3, change chain, index 7.
    const ADDRESSES: [(Coin, &str, &str, &str); 43] = [
        (
            Coin::Bitcoin,
            "",
            "m/44'/0'/0'/0/0",
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/49'/0'/0'/0/0",
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/84'/0'/0'/0/0",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/84'/0'/0'/0/1",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/84'/0'/0'/1/0",
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/86'/0'/0'/0/0",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/86'/0'/0'/1/0",
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/44'/0'/3'/1/7",
            "12DCYXCcRpBJ5VoWDvSijepPu8mshEihvX",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/49'/0'/3'/1/7",
            "3K7gGbTWfdq3kyBgkVTMbhfftnrhxB6jpW",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/84'/0'/3'/1/7",
            "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/86'/0'/3'/1/7",
            "bc1preq6saz8z9zrn3clx9eaen0dcsynwseakek7nwqlrj52wd2dsfsqlfsyut",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/44'/1'/0'/0/0",
            "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/49'/1'/0'/0/0",
            "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/84'/1'/0'/0/0",
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        ),
        (
            Coin::Bitcoin,
            "",
            "m/86'/1'/0'/0/0",
            "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
        ),
        (
            Coin::Bitcoin,
            "TREZOR",
            "m/84'/0'/0'/0/0",
            "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu",
        ),
        (
            Coin::Ethereum,
            "",
            "m/44'/60'/0'/0/0",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        ),
        (
            Coin::Ethereum,
            "",
            "m/44'/60'/3'/1/7",
            "0xc1A30611797762aea209daC2aC7E900f0cE95f9e",
        ),
        (
            Coin::Xrp,
            "",
            "m/44'/144'/0'/0/0",
            "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        ),
        (
            Coin::Xrp,
            "",
            "m/44'/144'/3'/1/7",
            "rnU3BdqhZk8DL3FKjQcaAyf3DJSoUZD8eM",
        ),
        (
            Coin::Tron,
            "",
            "m/44'/195'/0'/0/0",
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        ),
        (
            Coin::Tron,
            "",
            "m/44'/195'/3'/1/7",
            "TTD7MudE8L26nvnrEf2LHzXm6stKRpFZH1",
        ),
        (
            Coin::Zcash,
            "",
            "m/44'/133'/0'/0/0",
            "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F",
        ),
        (
            Coin::Zcash,
            "",
            "m/44'/133'/3'/1/7",
            "t1Pii1UXFrpcFucY5NBEFa664pymr7boHq4",
        ),
        (
            Coin::Dogecoin,
            "",
            "m/44'/3'/0'/0/0",
            "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
        ),
        (
            Coin::Dogecoin,
            "",
            "m/44'/3'/3'/1/7",
            "DNuJKZiVoQ6t67t8dE4NuBDhd2FNpMBsg6",
        ),
        (
            Coin::BitcoinCash,
            "",
            "m/44'/145'/0'/0/0",
            "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
        ),
        (
            Coin::BitcoinCash,
            "",
            "m/44'/145'/3'/1/7",
            "bitcoincash:qrhejavdmlfh9eajjxra3s3mn8gxls9hkvsq2yd62y",
        ),
        (
            Coin::BitcoinCash,
            "",
            "m/44'/145'/0'/0/0",
            "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg",
        ),
        // A Bitcoin Cash wallet on Bitcoin's coin type, found under the second root.
        (
            Coin::BitcoinCash,
            "",
            "m/44'/0'/0'/0/0",
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        ),
        (
            Coin::Litecoin,
            "",
            "m/44'/2'/0'/0/0",
            "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
        ),
        (
            Coin::Litecoin,
            "",
            "m/49'/2'/0'/0/0",
            "M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM",
        ),
        (
            Coin::Litecoin,
            "",
            "m/84'/2'/3'/1/7",
            "ltc1qnnphcvq5zgyf4f0uepust6d7gyt2zl69vftnz2",
        ),
        (
            Coin::EthereumClassic,
            "",
            "m/44'/61'/0'/0/0",
            "0xFA22515E43658ce56A7682B801e9B5456f511420",
        ),
        // An Ethereum Classic wallet on Ethereum's coin type, found under the second root.
        (
            Coin::EthereumClassic,
            "",
            "m/44'/60'/0'/0/0",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        ),
        (
            Coin::Cosmos,
            "",
            "m/44'/118'/0'/0/0",
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
        ),
        (
            Coin::Cosmos,
            "",
            "m/44'/118'/3'/1/7",
            "cosmos1j8dc8g9sux68h924yj646shrsjmkd7g6fwevky",
        ),
        (
            Coin::Injective,
            "",
            "m/44'/60'/0'/0/0",
            "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
        ),
        (
            Coin::Dash,
            "",
            "m/44'/5'/0'/0/0",
            "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
        ),
        (
            Coin::Dash,
            "",
            "m/44'/5'/3'/1/7",
            "XbAei18dD6mdL9LR6sTmbFJTQAJBcpxuxL",
        ),
        // Dash Platform payment addresses: the official DIP17/DIP18 vectors, receiving key class
        // 0' and change key class 1'.
        (
            Coin::Dash,
            "",
            "m/9'/5'/17'/0'/0'/0",
            "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
        ),
        (
            Coin::Dash,
            "",
            "m/9'/5'/17'/0'/0'/1",
            "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw",
        ),
        (
            Coin::Dash,
            "",
            "m/9'/5'/17'/0'/1'/0",
            "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28",
        ),
    ];

    #[test]
    fn addresses_are_found_where_their_wallets_put_them() {
        let one = SearchLimits::new(1, 1).unwrap();
        for (coin, passphrase, path_text, text) in ADDRESSES {
            let address = Address::parse(coin, text).unwrap();
            let expected = path(path_text);
            assert_eq!(
                find_address(ABANDON, passphrase, &address, Some(&expected), one).unwrap(),
                Some(expected.clone()),
                "{text} at its path"
            );
            assert_eq!(
                find_address(ABANDON, passphrase, &address, None, SearchLimits::default()).unwrap(),
                Some(expected),
                "{text} by the search"
            );
        }
    }

    #[test]
    fn addresses_name_their_coin_and_type() {
        let described = |coin, text| Address::parse(coin, text).unwrap().type_description();
        assert_eq!(
            described(Coin::Bitcoin, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf").as_deref(),
            Some("nested SegWit (BIP49)")
        );
        assert_eq!(
            described(Coin::Bitcoin, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl").as_deref(),
            Some("testnet, native SegWit (BIP84)")
        );
        assert_eq!(
            described(Coin::Litecoin, "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez").as_deref(),
            Some("legacy (BIP44)")
        );
        assert_eq!(
            described(Coin::Zcash, "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F").as_deref(),
            Some("transparent")
        );
        assert_eq!(
            described(Coin::Ethereum, "0x9858effd232b4033e47d90003d41ec34ecaeda94"),
            None
        );
        assert_eq!(
            described(Coin::Dash, "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5").as_deref(),
            Some("Core (BIP44)")
        );
        assert_eq!(
            described(Coin::Dash, "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs").as_deref(),
            Some("Platform payment (DIP17)")
        );
        let roots = |coin, text| Address::parse(coin, text).unwrap().search_roots();
        assert_eq!(
            roots(Coin::BitcoinCash, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
            [vec![44, 145], vec![44, 0]]
        );
        assert_eq!(
            roots(Coin::Bitcoin, "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"),
            [vec![49, 1]]
        );
        assert_eq!(
            roots(Coin::Dash, "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs"),
            [vec![9, 5, 17]]
        );
    }

    #[test]
    fn a_shielded_zcash_address_is_refused_with_its_reason() {
        // Only the prefix matters: the address is refused before it is decoded.
        for text in [
            "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya",
            "u1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "zcU1Cd6zYyZCd2VJF8yKgmzjxdiiU1rgTTjEwoN1CGUWCziPkUTXUjXmX7TMqdMNsTfuiGN1jQoVN4kGxUR4sAPN4XZ7pxb",
            "ZS1Z7REJLPSA98S2RRRFKWMAXU53E4UE0ULCRW0H4X5G8JL04TAK0D3MM47VDTAHATQRLKNGH9SLYA",
        ] {
            let error = Address::parse(Coin::Zcash, text).unwrap_err().to_string();
            assert!(error.contains("it is shielded"), "{text}: {error}");
        }
        // A transparent address still reads.
        assert!(Address::parse(Coin::Zcash, "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F").is_ok());
    }

    #[test]
    fn a_dash_orchard_or_other_platform_address_is_refused_with_its_reason() {
        let encoded = |data: &[u8]| {
            bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("dash").unwrap(), data).unwrap()
        };
        let short = encoded(&[&[DASH_PLATFORM_P2PKH][..], &[0x11; 19]].concat());
        let error = Address::parse(Coin::Dash, &short).unwrap_err().to_string();
        assert!(error.contains("wrong length"), "{error}");
        // Another type byte, such as a script, is not a single key's payment address.
        let other = encoded(&[&[0x80][..], &[0x11; 20]].concat());
        let error = Address::parse(Coin::Dash, &other).unwrap_err().to_string();
        assert!(
            error.contains("not the Platform payment address"),
            "{error}"
        );
        // DIP18 uses Bech32m; the same data with a Bech32 checksum is refused.
        let bech32 = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("dash").unwrap(),
            &[&[DASH_PLATFORM_P2PKH][..], &[0x11; 20]].concat(),
        )
        .unwrap();
        assert!(Address::parse(Coin::Dash, &bech32).is_err());
        // AUD-008-FUN001: a group added at the end, or padding bits set, keep a valid checksum and
        // the same bytes for byte_iter; only the one encoding of the 21 bytes is an address.
        {
            use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
            let hrp = bech32::Hrp::parse("dash").unwrap();
            let with_checksum = |groups: &[bech32::Fe32]| -> String {
                groups
                    .iter()
                    .copied()
                    .with_checksum::<bech32::Bech32m>(&hrp)
                    .chars()
                    .collect()
            };
            let payload = [&[DASH_PLATFORM_P2PKH][..], &[0x11; 20]].concat();
            let groups: Vec<bech32::Fe32> = payload.iter().copied().bytes_to_fes().collect();
            let canonical = with_checksum(&groups);
            assert!(Address::parse(Coin::Dash, &canonical).is_ok());
            assert!(Address::parse(Coin::Dash, &canonical.to_ascii_uppercase()).is_ok());
            let mut longer = groups.clone();
            longer.push(bech32::Fe32::Q);
            let mut padded = groups.clone();
            let last = padded.len() - 1;
            padded[last] = bech32::Fe32::try_from(padded[last].to_u8() | 1).unwrap();
            for malformed in [with_checksum(&longer), with_checksum(&padded)] {
                assert!(
                    bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(
                        &malformed
                    )
                    .is_ok()
                );
                for input in [malformed.clone(), malformed.to_ascii_uppercase()] {
                    let error = Address::parse(Coin::Dash, &input).unwrap_err().to_string();
                    assert!(error.contains("checksum or format"), "{input}: {error}");
                }
            }
        }
        // The testnet Orchard address that multi-chain-wallet-tools pins for Dash's own format.
        let orchard =
            "tdash1zrhflqt5ly4r7q64wrktl6tf466x7h30vjkknaudxsckc3l28rp0qzzm27yta0683nnnd2qum8gyq";
        let error = Address::parse(Coin::Dash, orchard).unwrap_err().to_string();
        assert!(error.contains("it is shielded"), "{error}");
        let error = Address::parse(Coin::Dash, "dash1qqqqqq")
            .unwrap_err()
            .to_string();
        assert!(error.contains("checksum or format"), "{error}");
    }

    #[test]
    fn dash_platform_testnet_addresses_are_found_under_coin_type_1() {
        // The Platform address vector of Dash Desktop, a public test phrase.
        const PHRASE: &str =
            "deliver frame tomato ring tool second dream mutual fade sponsor visa teach";
        for (index, text) in [
            "tdash1kr0xt5wj85ht5u464rfysjrq75rewz9mysjwf59p",
            "tdash1kqgy7ngm2wf0zsv20k4mc62s5rapw26yeg6em4jq",
            "tdash1kzlatzl0u06uxrqz8hkc7naz9d2g3v8g7gw83ew3",
        ]
        .into_iter()
        .enumerate()
        {
            let address = Address::parse(Coin::Dash, text).unwrap();
            assert_eq!(
                address.type_description().as_deref(),
                Some("testnet, Platform payment (DIP17)")
            );
            let found = find_address(PHRASE, "", &address, None, SearchLimits::default()).unwrap();
            assert_eq!(
                found.map(|path| path.to_string()),
                Some(format!("m/9'/1'/17'/0'/0'/{index}")),
                "{text}"
            );
        }
    }

    /// AUD-007-FUN001: the public Cosmos and Injective vectors re-encoded with a Bech32m checksum.
    #[test]
    fn cosmos_accounts_refuse_a_bech32m_checksum() {
        for (coin, text) in [
            (
                Coin::Cosmos,
                "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0afua36h",
            ),
            (
                Coin::Injective,
                "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55k94rgq",
            ),
        ] {
            let error = Address::parse(coin, text).unwrap_err().to_string();
            assert!(error.contains("checksum or format"), "{text}: {error}");
        }
        // The Bech32 forms of the same data are the vectors and still read.
        assert!(Address::parse(
            Coin::Injective,
            "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz"
        )
        .is_ok());
        // A valid Bech32 string of another chain's prefix is not this coin's address.
        let cosmos = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
        let error = Address::parse(Coin::Injective, cosmos)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("checksum"), "{error}");
        // A valid Bech32 string of the right prefix whose data is not a 20-byte hash.
        let hrp = bech32::Hrp::parse("cosmos").unwrap();
        for length in [19, 21, 32] {
            let text = bech32::encode::<bech32::Bech32>(hrp, &vec![7u8; length]).unwrap();
            let error = Address::parse(Coin::Cosmos, &text).unwrap_err().to_string();
            assert!(error.contains("wrong length"), "{length} bytes: {error}");
        }
    }

    /// AUD-007-FUN003: these public vectors have a valid Bech32 checksum but an extra data group.
    #[test]
    fn cosmos_accounts_refuse_redundant_data_groups() {
        use bech32::primitives::decode::CheckedHrpstring;
        for (coin, text) in [
            (
                Coin::Cosmos,
                "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0aqyjnds4",
            ),
            (
                Coin::Cosmos,
                "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0apey8cd8",
            ),
            (
                Coin::Injective,
                "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55qhk6md7",
            ),
            (
                Coin::Injective,
                "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55p2qwwsv",
            ),
        ] {
            // Recompute neither the encoding nor checksum: retain the formerly accepted strings.
            assert!(CheckedHrpstring::new::<bech32::Bech32>(text).is_ok());
            for input in [text.to_owned(), text.to_ascii_uppercase()] {
                let error = Address::parse(coin, &input).unwrap_err().to_string();
                assert!(error.contains("wrong length"), "{input}: {error}");
            }
        }
    }

    #[test]
    fn coins_are_listed_alphabetically_by_name() {
        // As a person reads them: "Ethereum and EVM networks" before "Ethereum Classic".
        let names: Vec<String> = Coin::ALL
            .iter()
            .map(|coin| coin.name().to_lowercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn every_coin_reads_its_identifier() {
        for coin in Coin::ALL {
            assert_eq!(coin.id().parse::<Coin>().unwrap(), coin);
        }
        assert_eq!("Bitcoin-Cash".parse::<Coin>().unwrap(), Coin::BitcoinCash);
        assert!("solana".parse::<Coin>().is_err());
    }

    #[test]
    fn search_limits_stay_within_the_bip32_index_range() {
        assert!(SearchLimits::new(1, 1).is_ok());
        assert!(SearchLimits::new(HARDENED, HARDENED).is_ok());
        for (accounts, indexes) in [(0, 1), (1, 0), (HARDENED + 1, 1), (1, u32::MAX)] {
            assert!(
                matches!(
                    SearchLimits::new(accounts, indexes),
                    Err(MhfeError::InvalidDerivationPath(_))
                ),
                "{accounts} accounts, {indexes} indexes"
            );
        }
    }

    #[test]
    fn the_search_finds_an_address_on_its_standard_path() {
        // Account 2, change chain, index 19: computed independently (Python, hashlib).
        let target =
            Address::parse(Coin::Bitcoin, "bc1q4du7e3vw34vsflf76xf9h8gktms9wzqcl7vlh5").unwrap();
        let found = find_address(ABANDON, "", &target, None, SearchLimits::default()).unwrap();
        assert_eq!(found, Some(path("m/84'/0'/2'/1/19")));

        let small = SearchLimits::new(2, 20).unwrap();
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

    /// BIP173 and CashAddr: an address may be written all in lower or all in upper case, never
    /// mixed. A CashAddr address may leave out its prefix.
    #[test]
    fn bech32_and_cashaddr_addresses_are_accepted_in_either_case() {
        for (coin, lower) in [
            (Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            (
                Coin::Bitcoin,
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (Coin::Bitcoin, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"),
            (
                Coin::Litecoin,
                "ltc1qnnphcvq5zgyf4f0uepust6d7gyt2zl69vftnz2",
            ),
            (
                Coin::Cosmos,
                "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
            ),
            (
                Coin::BitcoinCash,
                "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
            ),
        ] {
            let upper = lower.to_ascii_uppercase();
            assert_eq!(
                Address::parse(coin, &upper).unwrap(),
                Address::parse(coin, lower).unwrap(),
                "{upper}"
            );
            let mixed = format!("{}{}", &upper[..14], &lower[14..]);
            assert!(Address::parse(coin, &mixed).is_err(), "{mixed}");
        }
        assert_eq!(
            Address::parse(
                Coin::BitcoinCash,
                "qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"
            )
            .unwrap(),
            Address::parse(Coin::BitcoinCash, "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg").unwrap()
        );
    }

    /// EIP-55: in mixed case the capitals are a checksum, all in one case there is none.
    #[test]
    fn ethereum_addresses_check_eip55_in_mixed_case_only() {
        let checksummed = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        let parsed = Address::parse(Coin::Ethereum, checksummed).unwrap();
        for same in [
            checksummed.to_ascii_lowercase(),
            format!("0x{}", checksummed[2..].to_ascii_uppercase()),
        ] {
            assert_eq!(
                Address::parse(Coin::Ethereum, &same).unwrap(),
                parsed,
                "{same}"
            );
        }
        // One capital made small breaks the checksum.
        let broken = "0x9858efFD232B4033E47d90003D41EC34EcaEda94";
        assert!(Address::parse(Coin::Ethereum, broken).is_err());
    }

    #[test]
    fn rejects_unsupported_or_damaged_addresses() {
        for (coin, text) in [
            (Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv"), // checksum changed
            (Coin::Bitcoin, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB"),         // checksum changed
            // P2WSH, a script rather than a single key.
            (
                Coin::Bitcoin,
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            ),
            (Coin::Bitcoin, "ltc1qcr8te4kr609gcawutmrza0j4xv80jy8zkvrefp"), // another coin
            (Coin::Bitcoin, "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"),          // another coin
            (Coin::Litecoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), // another coin
            (Coin::Tron, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),     // another coin
            (Coin::Ethereum, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),         // another coin
            (Coin::Ethereum, "0x9858EfFD232B4033E47d90003D41EC34EcaEda"),   // too short
            (Coin::Xrp, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),              // other alphabet
            (Coin::Cosmos, "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz"),   // another chain
            // A P2SH CashAddr address, a script rather than a single key.
            (
                Coin::BitcoinCash,
                "bitcoincash:pqkh9ahfj069qv8l6eysyufazpe4fdjq3u4hna323j",
            ),
            (
                Coin::BitcoinCash,
                "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q7",
            ), // checksum changed
            (Coin::Zcash, "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd"), // P2SH
            (Coin::Dash, ""),
        ] {
            assert!(Address::parse(coin, text).is_err(), "{coin:?} {text:?}");
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
