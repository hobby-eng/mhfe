//! The text of an address: how the encoding of each coin, Base58Check, Bech32 and Bech32m,
//! CashAddr, EIP-55 hexadecimal and the DIP18 addresses of Dash Platform, becomes an [`Address`],
//! and the refusals of anything that is not a single-key receiving address of the coin.

use sha3::{Digest, Keccak256};

use super::coins::{AddressFamily, Base58Rules, HumanPart, PlatformRules, WitnessRules};
use super::{Address, AddressType, Coin};
use super::{AddressIssue, WalletError};

/// Reads `text` as a single-key receiving address of `coin` ([`Address::parse`]).
pub(super) fn parse(coin: Coin, text: &str) -> Result<Address, WalletError> {
    let rules = coin.rules();
    if let Some(witness) = rules
        .witness()
        .filter(|rules| is_bech32(text, rules.hrps()))
    {
        return parse_segwit(coin, text, witness);
    }
    if let Some(platform) = rules
        .platform()
        .filter(|rules| is_bech32(text, rules.hrps()))
    {
        return parse_platform(coin, text, platform);
    }
    match rules.family() {
        AddressFamily::Hex => parse_hex(coin, text),
        AddressFamily::Account { hrp, kind } => parse_bech32_account(coin, text, hrp, kind),
        AddressFamily::Cashaddr {
            prefix,
            legacy_start,
        } if !text.starts_with(legacy_start) => parse_cashaddr(coin, text, prefix),
        AddressFamily::Transparent { refused } => {
            let lowercase = text.to_ascii_lowercase();
            for (prefixes, reason) in refused {
                if prefixes.iter().any(|prefix| lowercase.starts_with(prefix)) {
                    return Err(invalid_address(*reason));
                }
            }
            parse_base58(coin, text, rules.base58())
        }
        AddressFamily::Base58 | AddressFamily::Cashaddr { .. } => {
            parse_base58(coin, text, rules.base58())
        }
    }
}

fn invalid_address(issue: AddressIssue) -> WalletError {
    issue.into()
}

/// The refusal of an address whose checksum or encoding does not decode.
fn malformed_address() -> WalletError {
    invalid_address(AddressIssue::Malformed)
}

fn not_of(coin: Coin) -> WalletError {
    AddressIssue::NotOfCoin(coin).into()
}

/// Dash Platform addresses, Bech32m with the prefix "dash" or "tdash" (DIP18). A payment address
/// of a single key is read; an Orchard address is refused, as its keys need Orchard's own
/// cryptography, and so is any other kind.
fn parse_platform(coin: Coin, text: &str, rules: PlatformRules) -> Result<Address, WalletError> {
    use bech32::primitives::decode::CheckedHrpstring;
    let decoded =
        CheckedHrpstring::new::<bech32::Bech32m>(text).map_err(|_| malformed_address())?;
    let testnet = network_of(rules.hrps(), decoded.hrp().as_str()).ok_or_else(|| not_of(coin))?;
    let data: Vec<u8> = decoded.byte_iter().collect();
    match data.split_first() {
        Some((&kind, hash))
            if kind == rules.payment_type()
                && hash.len() != AddressType::DashPlatform.program_bytes() =>
        {
            Err(invalid_address(AddressIssue::WrongLength))
        }
        Some((&kind, _)) if kind == rules.payment_type() && !whole_payment_payload(&decoded) => {
            Err(malformed_address())
        }
        Some((&kind, hash)) if kind == rules.payment_type() => Ok(Address {
            coin,
            testnet,
            address_type: AddressType::DashPlatform,
            program: hash.to_vec(),
        }),
        Some((&kind, _)) if kind == rules.shielded_type() => {
            Err(invalid_address(rules.shielded_reason()))
        }
        _ => Err(invalid_address(AddressIssue::PlatformSingleKey)),
    }
}

/// Whether a Platform payment address holds its 21 bytes, the type byte and the 160-bit hash, as
/// the one encoding Bech32 allows: 34 five-bit groups, whose last two bits are padding and zero
/// (BIP173). byte_iter alone would read the same bytes from another group added at the end or from
/// padding bits set, and take such a string for the address (AUD-008-FUN001).
fn whole_payment_payload(decoded: &bech32::primitives::decode::CheckedHrpstring) -> bool {
    const BITS: usize = (1 + AddressType::DashPlatform.program_bytes()) * 8;
    const GROUPS: usize = BITS.div_ceil(5);
    const PADDING_MASK: u8 = (1 << (GROUPS * 5 - BITS)) - 1;
    let groups = decoded.data_part_ascii_no_checksum();
    let padding_is_zero = groups
        .last()
        .and_then(|&last| bech32::Fe32::from_char(char::from(last)).ok())
        .is_some_and(|last| last.to_u8() & PADDING_MASK == 0);
    groups.len() == GROUPS && padding_is_zero
}

/// Whether `text` starts with one of the Bech32 prefixes, in either case.
fn is_bech32(text: &str, hrps: &[HumanPart]) -> bool {
    hrps.iter().any(|hrp| hrp.starts(text))
}

/// The network of a decoded HRP, using the same parts that selected its parser.
fn network_of(hrps: &[HumanPart], text: &str) -> Option<bool> {
    hrps.iter()
        .find(|hrp| hrp.text().eq_ignore_ascii_case(text))
        .map(|hrp| hrp.testnet())
}

/// SegWit addresses of Bitcoin and Litecoin, Bech32 and Bech32m (BIP173, BIP350).
fn parse_segwit(coin: Coin, text: &str, rules: WitnessRules) -> Result<Address, WalletError> {
    let (hrp, version, program) = bech32::segwit::decode(text).map_err(|_| malformed_address())?;
    // BIP173 allows an address written all in capitals, as in QR codes; the decoder has already
    // refused mixed case, and keeps the prefix as written.
    let testnet = network_of(rules.hrps(), hrp.as_str()).ok_or_else(|| not_of(coin))?;
    let address_type = match (version.to_u8(), program.len()) {
        (0, size) if size == AddressType::P2wpkh.program_bytes() => AddressType::P2wpkh,
        (1, size) if rules.taproot() && size == AddressType::P2tr.program_bytes() => {
            AddressType::P2tr
        }
        _ => return Err(AddressIssue::WitnessForm(coin).into()),
    };
    Ok(Address {
        coin,
        testnet,
        address_type,
        program,
    })
}

/// Base58Check addresses: a version prefix and a 20-byte hash. XRP writes them with its own
/// alphabet.
fn parse_base58(coin: Coin, text: &str, rules: Base58Rules) -> Result<Address, WalletError> {
    let decoded = bs58::decode(text)
        .with_alphabet(rules.alphabet())
        .with_check(None)
        .into_vec()
        .map_err(|_| malformed_address())?;
    // A rejected network version carries its own explanation in the coin's policy.
    if decoded.len() == 1 + AddressType::P2pkh.program_bytes() {
        if let Some((_, reason)) = rules
            .refused()
            .iter()
            .find(|(version, _)| *version == decoded[0])
        {
            return Err(invalid_address(*reason));
        }
    }
    let &(prefix, address_type, testnet, _) = rules
        .versions()
        .iter()
        .find(|(prefix, _, _, _)| decoded.starts_with(prefix))
        .ok_or_else(|| not_of(coin))?;
    let hash = &decoded[prefix.len()..];
    if hash.len() != address_type.program_bytes() {
        return Err(invalid_address(AddressIssue::WrongLength));
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
) -> Result<Address, WalletError> {
    let account_bytes = address_type.program_bytes();
    let account_data_groups = account_bytes * 8 / 5;
    // Cosmos SDK accounts use Bech32 (BIP173), never Bech32m: the same data with the other
    // checksum is not a valid address (AUD-007-FUN001).
    use bech32::primitives::decode::CheckedHrpstring;
    let decoded = CheckedHrpstring::new::<bech32::Bech32>(text).map_err(|_| malformed_address())?;
    if decoded.hrp().as_str().to_ascii_lowercase() != prefix {
        return Err(not_of(coin));
    }
    // A 160-bit account has exactly 32 groups, with no padding. byte_iter alone discards
    // incomplete trailing bytes and would accept an extra five-bit group (AUD-007-FUN003).
    if decoded.data_part_ascii_no_checksum().len() != account_data_groups {
        return Err(invalid_address(AddressIssue::WrongLength));
    }
    let program: Vec<u8> = decoded.byte_iter().collect();
    if program.len() != account_bytes {
        return Err(invalid_address(AddressIssue::WrongLength));
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
fn parse_hex(coin: Coin, text: &str) -> Result<Address, WalletError> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .ok_or_else(|| not_of(coin))?;
    let program = hex::decode(digits)
        .ok()
        .filter(|bytes| bytes.len() == AddressType::Keccak.program_bytes())
        .ok_or_else(|| invalid_address(AddressIssue::HexDigits))?;
    let mixed_case = digits.chars().any(|c| c.is_ascii_lowercase())
        && digits.chars().any(|c| c.is_ascii_uppercase());
    if mixed_case && eip55(&program) != digits {
        return Err(invalid_address(AddressIssue::Eip55Checksum));
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

/// The CashAddr alphabet.
const CASHADDR_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
// CashTokens' token-aware single-key version, with a 160-bit hash.
const CASHADDR_TOKEN_P2PKH: u8 = 0x10;

/// A Bitcoin Cash CashAddr address, with or without its "bitcoincash:" prefix, in either case. Only
/// the legacy P2PKH form with a 160-bit hash (version byte 0, "q...") is accepted. The token-aware
/// single-key form is recognised and refused with its supported alternative.
fn parse_cashaddr(coin: Coin, text: &str, prefix: &str) -> Result<Address, WalletError> {
    let lowercase = text.to_ascii_lowercase();
    if lowercase != text && text.to_ascii_uppercase() != text {
        return Err(invalid_address(AddressIssue::CashaddrCase));
    }
    let payload = match lowercase.split_once(':') {
        Some((given, payload)) if given == prefix => payload,
        Some(_) => return Err(not_of(coin)),
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
        .ok_or_else(|| not_of(coin))?;
    // The prefix enters the checksum as the low five bits of each character, then a zero.
    let mut checked: Vec<u8> = prefix.bytes().map(|byte| byte & 0x1f).collect();
    checked.push(0);
    checked.extend_from_slice(&values);
    // Eight five-bit values of checksum follow the data.
    if values.len() <= 8 || cashaddr_polymod(&checked) != 0 {
        return Err(malformed_address());
    }
    let data = regroup_five_to_eight(&values[..values.len() - 8]).ok_or_else(malformed_address)?;
    // Version byte 0: P2PKH with a 160-bit hash.
    match data.split_first() {
        Some((0, hash)) if hash.len() == AddressType::P2pkh.program_bytes() => Ok(Address {
            coin,
            testnet: false,
            address_type: AddressType::P2pkh,
            program: hash.to_vec(),
        }),
        // CashTokens' token-aware P2PKH flag, with the same 160-bit public-key hash.
        Some((&CASHADDR_TOKEN_P2PKH, hash)) if hash.len() == AddressType::P2pkh.program_bytes() => {
            Err(invalid_address(AddressIssue::CashToken))
        }
        _ => Err(invalid_address(AddressIssue::CashSingleKey)),
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
