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

use bitcoin_hashes::{hash160, Hash};

use crate::MhfeError;

mod encodings;
mod keys;

pub(crate) use keys::bip39_seed;
use keys::{program_for, ExtendedKey};

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-repair",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;

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
    /// Bitcoin: "1...", "3...", "bc1q..." and "bc1p..." addresses.
    Bitcoin,
    /// Ethereum and every EVM network, which share its addresses.
    Ethereum,
    /// XRP: "r..." addresses.
    Xrp,
    /// Tron: "T..." addresses.
    Tron,
    /// Zcash transparent addresses; shielded ones are out of reach without its own cryptography.
    Zcash,
    /// Dogecoin: "D..." addresses.
    Dogecoin,
    /// Bitcoin Cash: "bitcoincash:q..." and "1..." addresses.
    BitcoinCash,
    /// Litecoin: "L...", "M...", "3..." and "ltc1q..." addresses.
    Litecoin,
    /// Ethereum Classic: "0x..." addresses.
    EthereumClassic,
    /// Cosmos: "cosmos1..." addresses.
    Cosmos,
    /// Injective: "inj1..." addresses.
    Injective,
    /// Dash and Dash Platform: "X..." and "dash1k..." addresses.
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
                MhfeError::InvalidCoin(format!("the coins are {}", known.join(", ")))
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
        encodings::parse(coin, text.trim())
    }

    /// The coin the address belongs to.
    pub fn coin(&self) -> Coin {
        self.coin
    }

    /// The kind of address, which sets the paths it is searched on.
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

/// A BIP32 derivation path such as `m/84'/0'/0'/0/5`. Hardened steps end with `'` or `h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<u32>);

impl FromStr for DerivationPath {
    type Err = MhfeError;

    /// Strict: starts with `m`, steps separated by `/`, each a decimal number below 2^31 with an
    /// optional hardened mark; no spaces, signs or empty steps.
    fn from_str(text: &str) -> Result<Self, MhfeError> {
        let invalid =
            || MhfeError::InvalidDerivationPath("it is not a path like m/84'/0'/0'/0/5".to_owned());
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
    /// The most accounts or addresses of each chain a search covers: BIP32 has 2^31 ordinary
    /// indexes below the hardened ones.
    pub const MOST: u32 = HARDENED;

    /// Limits for the first `accounts` accounts and the first `indexes` addresses of each chain.
    pub fn new(accounts: u32, indexes: u32) -> Result<Self, MhfeError> {
        let possible = |count: u32| (1..=Self::MOST).contains(&count);
        if possible(accounts) && possible(indexes) {
            Ok(Self { accounts, indexes })
        } else {
            // The limits stand for the paths the search derives, so a count out of range is
            // reported as the invalid path it would lead to.
            Err(MhfeError::InvalidDerivationPath(format!(
                "a search covers 1 to {} accounts and indexes, not {accounts} and {indexes}",
                Self::MOST
            )))
        }
    }

    /// The first account's first `gap` receiving and as many change addresses: where the decoy
    /// search of two missing words looks for an address ([`crate::search::DECOY_SCAN_GAP`] by
    /// default).
    pub fn first_account(gap: u32) -> Result<Self, MhfeError> {
        Self::new(1, gap)
    }

    /// The number of accounts searched, from account 0.
    pub fn accounts(self) -> u32 {
        self.accounts
    }

    /// The number of addresses searched on each chain of each account, from index 0.
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

/// What an address check searches, stated before the work so that a wrong address type or path
/// can still be changed: the address type, and the path pattern with the number of addresses, or
/// the one path given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressSearch {
    type_description: Option<String>,
    pattern: String,
    addresses: u128,
    only_path: bool,
}

impl AddressSearch {
    /// The search for `address` on `path`, or on the standard paths of its type within `limits`.
    pub fn new(address: &Address, path: Option<&DerivationPath>, limits: SearchLimits) -> Self {
        let type_description = address.type_description();
        if let Some(path) = path {
            return Self {
                type_description,
                pattern: path.to_string(),
                addresses: 1,
                only_path: true,
            };
        }
        let roots = address.search_roots();
        let chains = if address.hardened_chains() {
            "0'-1'"
        } else {
            "0-1"
        };
        Self {
            type_description,
            pattern: format!(
                "m/{}/0'-{}'/{chains}/0-{}",
                root_pattern(&roots),
                limits.accounts() - 1,
                limits.indexes() - 1
            ),
            // In 128 bits: at the highest limits, 2^31 accounts and indexes, a type with two roots
            // has 2^64 addresses, one more than 64 bits hold (AUD-013-API001).
            addresses: roots.len() as u128
                * CHAINS.len() as u128
                * u128::from(limits.accounts())
                * u128::from(limits.indexes()),
            only_path: false,
        }
    }

    /// What an address check of the text `address` would search with the default limits, stated
    /// before it runs: `coin` is the id of one of [`Coin::ALL`] and `path` is empty for the
    /// standard paths of the address's type, or the one path to look at. It refuses an unknown
    /// coin (INVALID_COIN), an address that is not one of the coin's (INVALID_ADDRESS) and a path
    /// that is not a valid one (INVALID_DERIVATION_PATH). The browser package's `describeAddress`
    /// gives this, and the self-check `address-search` compares it with known answers.
    pub fn describe(coin: &str, address: &str, path: &str) -> Result<Self, MhfeError> {
        Self::describe_within(coin, address, path, SearchLimits::default())
    }

    /// [`AddressSearch::describe`] for a search within `limits`, such as the decoy search of two
    /// missing words of a container phrase ([`crate::search::ContainerSearch::decoy_address_limits`]).
    pub fn describe_within(
        coin: &str,
        address: &str,
        path: &str,
        limits: SearchLimits,
    ) -> Result<Self, MhfeError> {
        let coin: Coin = coin.parse()?;
        let address = Address::parse(coin, address)?;
        let path = match path {
            "" => None,
            text => Some(text.parse::<DerivationPath>()?),
        };
        Ok(Self::new(&address, path.as_ref(), limits))
    }

    /// The address type, such as "native SegWit (BIP84)", when the coin has several.
    pub fn type_description(&self) -> Option<&str> {
        self.type_description.as_deref()
    }

    /// The path pattern searched, such as "m/84'/0'/0'-9'/0-1/0-99", or the one path given.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// How many addresses the search derives at most.
    pub fn addresses(&self) -> u128 {
        self.addresses
    }

    /// Whether only the one path given is searched.
    pub fn only_path(&self) -> bool {
        self.only_path
    }
}

/// The hardened steps of the search roots, a step's values joined in braces where they differ,
/// such as "{44,49,84,86}'/0'".
fn root_pattern(roots: &[Vec<u32>]) -> String {
    let steps = roots.first().map_or(0, Vec::len);
    (0..steps)
        .map(|step| {
            let mut values: Vec<String> = Vec::new();
            for root in roots {
                let value = root[step].to_string();
                if !values.contains(&value) {
                    values.push(value);
                }
            }
            match values.as_slice() {
                [only] => format!("{only}'"),
                several => format!("{{{}}}'", several.join(",")),
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Reads a master key fingerprint written as eight hexadecimal digits, as wallets show it.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 4], MhfeError> {
    let text = text.trim();
    let bytes = hex::decode(text).ok().filter(|bytes| bytes.len() == 4);
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            MhfeError::InvalidFingerprint("it is not eight hexadecimal digits".to_owned())
        })
}

/// A master key fingerprint as wallets show it and [`parse_fingerprint`] reads it: eight lower
/// case hexadecimal digits.
pub fn fingerprint_text(fingerprint: [u8; 4]) -> String {
    hex::encode(fingerprint)
}

/// [`master_fingerprint`] as [`fingerprint_text`] writes it.
pub fn master_fingerprint_text(phrase: &str, passphrase: &str) -> Result<String, MhfeError> {
    master_fingerprint(phrase, passphrase).map(fingerprint_text)
}

/// The first four bytes of HASH160 of the master public key (BIP32), for `phrase` and the
/// BIP39 `passphrase` (empty when the wallet uses none). The phrase is read as every phrase input
/// of this library reads it: any spacing and letter case, and four letters of a word are enough.
pub fn master_fingerprint(phrase: &str, passphrase: &str) -> Result<[u8; 4], MhfeError> {
    let master = ExtendedKey::master(phrase, passphrase)?;
    let digest = hash160::Hash::hash(&master.public_key()?).to_byte_array();
    Ok([digest[0], digest[1], digest[2], digest[3]])
}

/// Looks for `address` on the standard paths of its type, within `limits`, or only at `path` when
/// one is given. Returns the path where it was found. The phrase is read as for
/// [`master_fingerprint`].
pub fn find_address(
    phrase: &str,
    passphrase: &str,
    address: &Address,
    path: Option<&DerivationPath>,
    limits: SearchLimits,
) -> Result<Option<DerivationPath>, MhfeError> {
    find_address_until(phrase, passphrase, address, path, limits, &|| false)
}

/// [`find_address`] that asks `stopped` before each address it derives and ends with
/// [`MhfeError::Cancelled`] once it says so: a search over many addresses takes seconds, and a
/// cancel must not wait for it (AUD-016-API001).
pub fn find_address_until(
    phrase: &str,
    passphrase: &str,
    address: &Address,
    path: Option<&DerivationPath>,
    limits: SearchLimits,
    stopped: &dyn Fn() -> bool,
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
                    if stopped() {
                        return Err(MhfeError::Cancelled);
                    }
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

#[cfg(test)]
mod tests {
    use super::encodings::DASH_PLATFORM_P2PKH;
    use super::*;

    #[test]
    fn search_roots_read_as_one_pattern() {
        assert_eq!(root_pattern(&[vec![44, 5]]), "44'/5'");
        assert_eq!(root_pattern(&[vec![44, 145], vec![44, 0]]), "44'/{145,0}'");
        assert_eq!(root_pattern(&[vec![9, 5, 17]]), "9'/5'/17'");
    }

    #[test]
    fn an_address_search_states_its_scope() {
        let address =
            Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        let search = AddressSearch::new(&address, None, SearchLimits::default());
        assert!(!search.only_path());
        assert!(search.pattern().starts_with("m/84'/0'/0'-"));
        assert!(search.addresses() > 1);
        let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
        let only = AddressSearch::new(&address, Some(&path), SearchLimits::default());
        assert!(only.only_path());
        assert_eq!(only.addresses(), 1);
        assert_eq!(only.pattern(), "m/84'/0'/0'/0/0");
    }

    /// The count of the widest searches, which 64 bits do not hold for a type with two roots,
    /// stated exactly, without deriving anything (AUD-013-API001).
    #[test]
    fn the_widest_search_states_its_count_exactly() {
        let widest = SearchLimits::new(SearchLimits::MOST, SearchLimits::MOST).unwrap();
        let one_root =
            Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        let two_roots =
            Address::parse(Coin::BitcoinCash, "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg").unwrap();
        assert_eq!(two_roots.search_roots().len(), 2);
        assert_eq!(
            AddressSearch::new(&one_root, None, widest).addresses(),
            1 << 63
        );
        assert_eq!(
            AddressSearch::new(&two_roots, None, widest).addresses(),
            1 << 64
        );
        let narrower = SearchLimits::new(SearchLimits::MOST, SearchLimits::MOST - 1).unwrap();
        assert_eq!(
            AddressSearch::new(&two_roots, None, narrower).addresses(),
            (1 << 64) - (1 << 33)
        );
        let path: DerivationPath = "m/44'/145'/0'/0/0".parse().unwrap();
        assert_eq!(
            AddressSearch::new(&two_roots, Some(&path), widest).addresses(),
            1
        );
    }

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

    /// Every address of the startup and full self-checks' table (known_answers::addresses::ADDRESSES, the
    /// one copy, with where its values come from), at its path and by the search (AUD-015-ARC002).
    #[test]
    fn addresses_are_found_where_their_wallets_put_them() {
        let one = SearchLimits::new(1, 1).unwrap();
        for case in known_answers::addresses::ADDRESSES {
            let (coin, passphrase, path_text, text) =
                (case.coin, case.passphrase, case.path, case.address);
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

    /// A search that is stopped ends before its next address (AUD-016-API001).
    #[test]
    fn a_stopped_search_ends_at_once() {
        let target =
            Address::parse(Coin::Bitcoin, "bc1q4du7e3vw34vsflf76xf9h8gktms9wzqcl7vlh5").unwrap();
        let derived = std::cell::Cell::new(0);
        let stopped = || {
            derived.set(derived.get() + 1);
            derived.get() > 3
        };
        let limits = SearchLimits::default();
        assert_eq!(
            find_address_until(ABANDON, "", &target, None, limits, &stopped),
            Err(MhfeError::Cancelled)
        );
        assert_eq!(derived.get(), 4);
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

    /// The fingerprint and the address search read a phrase as every other phrase input does
    /// (AUD-010): capitals, extra spaces and tabs, and four letters of a word, give the wallet of
    /// the BIP84 test phrase, 73c5da0a with its first receiving address at m/84'/0'/0'/0/0.
    #[test]
    fn the_wallet_reads_a_phrase_as_typed() {
        let address =
            Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        let four_letters = format!("{}abou", "aban ".repeat(11));
        for typed in [
            ABANDON.to_uppercase(),
            four_letters,
            format!("  {}\t", ABANDON.replace(' ', "  ")),
        ] {
            assert_eq!(*crate::read_phrase(&typed).unwrap(), ABANDON, "{typed}");
            assert_eq!(
                hex::encode(master_fingerprint(&typed, "").unwrap()),
                "73c5da0a",
                "{typed}"
            );
            let first = path("m/84'/0'/0'/0/0");
            let found = find_address(&typed, "", &address, None, SearchLimits::new(1, 1).unwrap());
            assert_eq!(found.unwrap(), Some(first), "{typed}");
        }
        // A word of three letters that is not a word of the list stays refused, as everywhere.
        let short = ABANDON.replacen("abandon", "aba", 1);
        assert!(matches!(
            master_fingerprint(&short, ""),
            Err(MhfeError::InvalidPhrase(_))
        ));
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
