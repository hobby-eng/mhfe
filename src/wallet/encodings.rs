//! The text of an address: how the encoding of each coin, Base58Check, Bech32 and Bech32m,
//! CashAddr, EIP-55 hexadecimal and the DIP18 addresses of Dash Platform, becomes an [`Address`],
//! and the refusals of anything that is not a single-key receiving address of the coin.

use sha3::{Digest, Keccak256};

use super::{Address, AddressType, Coin};
use crate::MhfeError;

/// Reads `text` as a single-key receiving address of `coin` ([`Address::parse`]).
pub(super) fn parse(coin: Coin, text: &str) -> Result<Address, MhfeError> {
    let address = match coin {
        Coin::Bitcoin if is_bech32(text, &["bc1", "tb1"]) => parse_segwit(coin, text)?,
        Coin::Litecoin if is_bech32(text, &["ltc1"]) => parse_segwit(coin, text)?,
        Coin::BitcoinCash if !text.starts_with('1') => parse_cashaddr(text)?,
        Coin::Ethereum | Coin::EthereumClassic => parse_hex(coin, text)?,
        Coin::Cosmos => parse_bech32_account(coin, text, "cosmos", AddressType::P2pkh)?,
        Coin::Injective => parse_bech32_account(coin, text, "inj", AddressType::Keccak)?,
        Coin::Dash if is_bech32(text, &["dash1", "tdash1"]) => parse_dash_platform(text)?,
        Coin::Zcash if is_bech32(text, &["tex1", "textest1"]) => {
            return Err(invalid_address(
                "the TEX address form is not supported; give its transparent t1… form on mainnet",
            ));
        }
        Coin::Zcash if is_shielded_zcash(text) => {
            return Err(invalid_address(
                "it is shielded; use a transparent t1… address of the same wallet",
            ))
        }
        _ => parse_base58(coin, text)?,
    };
    Ok(address)
}

fn invalid_address(reason: &str) -> MhfeError {
    MhfeError::InvalidAddress(reason.to_owned())
}

/// The refusal of an address whose checksum or encoding does not decode.
fn malformed_address() -> MhfeError {
    invalid_address("its checksum or format is wrong")
}

fn not_of(coin: Coin) -> MhfeError {
    MhfeError::InvalidAddress(format!(
        // "an address of" reads right for every coin name ("a Ethereum address" would not).
        "it is not an address of {} ({})",
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
pub(super) const DASH_PLATFORM_P2PKH: u8 = 0xb0;
const DASH_ORCHARD: u8 = 0x10;

/// Dash Platform addresses, Bech32m with the prefix "dash" or "tdash" (DIP18). A payment address
/// of a single key is read; an Orchard address is refused, as its keys need Orchard's own
/// cryptography, and so is any other kind.
fn parse_dash_platform(text: &str) -> Result<Address, MhfeError> {
    use bech32::primitives::decode::CheckedHrpstring;
    let decoded =
        CheckedHrpstring::new::<bech32::Bech32m>(text).map_err(|_| malformed_address())?;
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
            Err(malformed_address())
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
    let (hrp, version, program) = bech32::segwit::decode(text).map_err(|_| malformed_address())?;
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
        .map_err(|_| malformed_address())?;
    // Dash Core testnet versions, distinct from the supported Platform testnet form.
    const DASH_TESTNET_P2PKH: u8 = 0x8c;
    const DASH_TESTNET_P2SH: u8 = 0x13;
    if coin == Coin::Dash && decoded.len() == 21 {
        match decoded[0] {
            DASH_TESTNET_P2PKH => return Err(invalid_address(
                "Dash Core testnet addresses (y…) are not supported; give a mainnet X… address",
            )),
            DASH_TESTNET_P2SH => return Err(invalid_address(
                "Dash Core testnet P2SH addresses are not supported; give a single-key mainnet X… address",
            )),
            _ => {}
        }
    }
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
    let decoded = CheckedHrpstring::new::<bech32::Bech32>(text).map_err(|_| malformed_address())?;
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
// CashTokens' token-aware single-key version, with a 160-bit hash.
const CASHADDR_TOKEN_P2PKH: u8 = 0x10;

/// A Bitcoin Cash CashAddr address, with or without its "bitcoincash:" prefix, in either case. Only
/// the legacy P2PKH form with a 160-bit hash (version byte 0, "q...") is accepted. The token-aware
/// single-key form is recognised and refused with its supported alternative.
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
        return Err(malformed_address());
    }
    let data = regroup_five_to_eight(&values[..values.len() - 8]).ok_or_else(malformed_address)?;
    // Version byte 0: P2PKH with a 160-bit hash.
    match data.split_first() {
        Some((0, hash)) if hash.len() == 20 => Ok(Address {
            coin: Coin::BitcoinCash,
            testnet: false,
            address_type: AddressType::P2pkh,
            program: hash.to_vec(),
        }),
        // CashTokens' token-aware P2PKH flag, with the same 160-bit public-key hash.
        Some((&CASHADDR_TOKEN_P2PKH, hash)) if hash.len() == 20 => Err(invalid_address(
            "the token-aware address form is not supported; give the bitcoincash:q… address of the same key",
        )),
        _ => Err(invalid_address(
            "only single-key addresses (bitcoincash:q…) can be checked",
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
