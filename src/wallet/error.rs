//! Owned failures of wallet input, address interpretation and deterministic key operations.
use super::Coin;
use crate::{ErrorCode, PhraseError};
use std::fmt;

/// A typed reason an address cannot be used. No address text enters the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressIssue {
    /// Its checksum or format is wrong.
    Malformed,
    /// It has the wrong length.
    WrongLength,
    /// It is not the Platform payment address of a single key.
    PlatformSingleKey,
    /// It is not 40 hexadecimal digits after 0x.
    HexDigits,
    /// Its EIP-55 checksum, the mix of capital and small letters, is wrong.
    Eip55Checksum,
    /// It mixes capital and small letters, which CashAddr does not allow.
    CashaddrCase,
    /// The token-aware address form is not supported; give the bitcoincash:q… address of the same key.
    CashToken,
    /// Only single-key addresses (bitcoincash:q…) can be checked.
    CashSingleKey,
    /// Dash Core testnet addresses (y…) are not supported; give a mainnet X… address.
    DashTestnet,
    /// Dash Core testnet P2SH addresses are not supported; give a single-key mainnet X… address.
    DashTestnetScript,
    /// It is shielded; use a Dash Core X… or Platform dash1k… address of the same wallet.
    DashShielded,
    /// The TEX address form is not supported; give its transparent t1… form on mainnet.
    ZcashTex,
    /// It is shielded; use a transparent t1… address of the same wallet.
    ZcashShielded,
    /// Nothing was typed.
    Empty,
    /// An address or a fingerprint is one word, without spaces.
    SeveralWords,
    /// The decoded address is not one of this coin's accepted forms.
    NotOfCoin(Coin),
    /// The address is longer than every supported form.
    TooLong(usize),
    /// The witness version/program is outside this coin's single-key forms.
    WitnessForm(Coin),
}
impl fmt::Display for AddressIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("its checksum or format is wrong"),
            Self::WrongLength => f.write_str("it has the wrong length"),
            Self::PlatformSingleKey => f.write_str("it is not the Platform payment address of a single key"),
            Self::HexDigits => f.write_str("it is not 40 hexadecimal digits after 0x"),
            Self::Eip55Checksum => f.write_str("its EIP-55 checksum, the mix of capital and small letters, is wrong"),
            Self::CashaddrCase => f.write_str("it mixes capital and small letters, which CashAddr does not allow"),
            Self::CashToken => f.write_str("the token-aware address form is not supported; give the bitcoincash:q… address of the same key"),
            Self::CashSingleKey => f.write_str("only single-key addresses (bitcoincash:q…) can be checked"),
            Self::DashTestnet => f.write_str("Dash Core testnet addresses (y…) are not supported; give a mainnet X… address"),
            Self::DashTestnetScript => f.write_str("Dash Core testnet P2SH addresses are not supported; give a single-key mainnet X… address"),
            Self::DashShielded => f.write_str("it is shielded; use a Dash Core X… or Platform dash1k… address of the same wallet"),
            Self::ZcashTex => f.write_str("the TEX address form is not supported; give its transparent t1… form on mainnet"),
            Self::ZcashShielded => f.write_str("it is shielded; use a transparent t1… address of the same wallet"),
            Self::Empty => f.write_str("nothing was typed"),
            Self::SeveralWords => f.write_str("an address or a fingerprint is one word, without spaces"),
            Self::NotOfCoin(coin) => write!(f, "it is not an address of {} ({})", coin.name(), coin.address_forms()),
            Self::TooLong(bytes) => write!(f, "it has {bytes} bytes, more than any address ({})", super::MAX_ADDRESS_BYTES),
            Self::WitnessForm(coin) => {
                let forms = coin.rules().witness().map_or_else(Vec::new, |rules| rules.forms());
                write!(f, "only single-key witness addresses ({}) can be checked", forms.join(" or "))
            }
        }
    }
}
impl std::error::Error for AddressIssue {}

/// Why a public derivation path or its search limits cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathIssue {
    /// The text does not have the BIP32 path grammar.
    Malformed,
    /// It has more than BIP32's maximum depth.
    TooDeep,
    /// The search counts are outside the BIP32 index range.
    SearchLimits {
        /// The supplied account count.
        accounts: u32,
        /// The supplied address count per chain.
        indexes: u32,
    },
}
impl fmt::Display for PathIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("it is not a path like m/84'/0'/0'/0/5"),
            Self::TooDeep => write!(
                f,
                "it has more than {} steps, the deepest a BIP32 key can be",
                super::MAX_PATH_DEPTH
            ),
            Self::SearchLimits { accounts, indexes } => write!(
                f,
                "a search covers 1 to {} accounts and indexes, not {accounts} and {indexes}",
                super::SearchLimits::MOST
            ),
        }
    }
}
impl std::error::Error for PathIssue {}

/// A deterministic-key invariant failure without private scalars or seed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyIssue {
    /// The BIP341 tweak is not a scalar.
    TaprootTweak,
    /// The BIP341 output point is infinity.
    TaprootInfinity,
    /// BIP32 gives no valid master key.
    Master,
    /// BIP32 gives no valid child at this public path index.
    Child(u32),
    /// A serialized compressed public key has the wrong size.
    CompressedLength,
    /// A serialized uncompressed public key has the wrong size.
    UncompressedLength,
    /// A BIP32 intermediate is outside the scalar field.
    Scalar,
}
impl fmt::Display for KeyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaprootTweak => f.write_str("Taproot tweak out of range"),
            Self::TaprootInfinity => f.write_str("BIP341 gives no Taproot output key for this key"),
            Self::Master => f.write_str("BIP32 gives no valid master key for this seed"),
            Self::Child(index) => write!(
                f,
                "BIP32 has no valid key at index {index} of this path; wallets use the next index"
            ),
            Self::CompressedLength => f.write_str("a public key is not 33 bytes"),
            Self::UncompressedLength => f.write_str("a public key is not 65 bytes"),
            Self::Scalar => f.write_str("BIP32 produced a key out of range"),
        }
    }
}
impl std::error::Error for KeyIssue {}

/// A wallet-module failure. Reasons contain public counts or identifiers, never typed secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletError {
    /// An address was refused.
    Address {
        /// The typed policy or encoding reason.
        issue: AddressIssue,
        /// A script omitted its coin selector; show the default and the correction once.
        assumed_coin: Option<Coin>,
    },
    /// A derivation path or search bound was refused.
    Path(PathIssue),
    /// A master-key fingerprint was not eight hexadecimal digits.
    Fingerprint,
    /// BIP39 passphrase bytes are not UTF-8.
    InvalidPassphrase,
    /// A passphrase exceeded the supported byte count.
    PassphraseTooLong(usize),
    /// A coin identifier is unknown; its input spelling is not retained.
    InvalidCoin,
    /// A phrase was refused by the common BIP39 reader.
    Phrase(PhraseError),
    /// A key operation could not return the specified key.
    Key(KeyIssue),
    /// The caller stopped the public-address search.
    Cancelled,
}
impl WalletError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Address { .. } => ErrorCode::InvalidAddress,
            Self::Path(_) => ErrorCode::InvalidDerivationPath,
            Self::Fingerprint => ErrorCode::InvalidFingerprint,
            Self::InvalidPassphrase => ErrorCode::InvalidPassphrase,
            Self::PassphraseTooLong(_) => ErrorCode::PassphraseTooLong,
            Self::InvalidCoin => ErrorCode::InvalidCoin,
            Self::Phrase(error) => error.error_code(),
            Self::Key(_) => ErrorCode::InternalError,
            Self::Cancelled => ErrorCode::Cancelled,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
    /// Adds the script's omitted-selector explanation only to an address refusal.
    pub const fn with_assumed_coin(self, coin: Coin) -> Self {
        match self {
            Self::Address { issue, .. } => Self::Address {
                issue,
                assumed_coin: Some(coin),
            },
            other => other,
        }
    }
}
impl From<AddressIssue> for WalletError {
    fn from(issue: AddressIssue) -> Self {
        Self::Address {
            issue,
            assumed_coin: None,
        }
    }
}
impl From<PathIssue> for WalletError {
    fn from(issue: PathIssue) -> Self {
        Self::Path(issue)
    }
}
impl From<KeyIssue> for WalletError {
    fn from(issue: KeyIssue) -> Self {
        Self::Key(issue)
    }
}
impl From<PhraseError> for WalletError {
    fn from(error: PhraseError) -> Self {
        Self::Phrase(error)
    }
}
impl From<crate::CancelledError> for WalletError {
    fn from(_: crate::CancelledError) -> Self {
        Self::Cancelled
    }
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address {
                issue,
                assumed_coin,
            } => {
                f.write_str("the address cannot be used for the check: ")?;
                match assumed_coin {
                    None => issue.fmt(f),
                    Some(coin) => write!(f, "without --coin a script compares with a {} address, and {issue}; name the address's coin with --coin, such as --coin ethereum", coin.name()),
                }
            }
            Self::Path(issue) => write!(f, "invalid derivation path: {issue}"),
            Self::Fingerprint => {
                f.write_str("invalid master key fingerprint: it is not eight hexadecimal digits")
            }
            Self::InvalidPassphrase => crate::PassphraseError::InvalidUtf8.fmt(f),
            Self::PassphraseTooLong(bytes) => crate::PassphraseError::TooLong(*bytes).fmt(f),
            Self::InvalidCoin => {
                let known: Vec<_> = Coin::ALL.iter().map(|coin| coin.id()).collect();
                write!(f, "unknown coin; the coins are {}", known.join(", "))
            }
            Self::Phrase(error) => error.fmt(f),
            Self::Key(issue) => write!(f, "internal error: {issue}"),
            Self::Cancelled => crate::CancelledError.fmt(f),
        }
    }
}
impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Address { issue, .. } => Some(issue),
            Self::Path(issue) => Some(issue),
            Self::Phrase(error) => Some(error),
            Self::Key(issue) => Some(issue),
            Self::Cancelled => Some(&crate::CancelledError),
            _ => None,
        }
    }
}

impl crate::ErrorIdentity for WalletError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

impl From<crate::PassphraseError> for WalletError {
    fn from(error: crate::PassphraseError) -> Self {
        match error {
            crate::PassphraseError::InvalidUtf8 => Self::InvalidPassphrase,
            crate::PassphraseError::TooLong(bytes) => Self::PassphraseTooLong(bytes),
        }
    }
}
