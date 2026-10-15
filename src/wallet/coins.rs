//! A coin's complete address policy, defined once. Encoders and presentation ask this data rather
//! than each maintaining their own coin match. The same declaration generates the enum and ALL.
//! Coin ids and protocol HRPs are distinct facts even where spelled alike: renaming an id must
//! never change the network encoding.

use super::{AddressIssue, AddressType};

/// Prefix, single-key interpretation, test-network flag and the example shown to a person.
pub(super) type Base58Version = (&'static [u8], AddressType, bool, Option<&'static str>);

#[derive(Clone, Copy)]
pub(super) struct Base58Rules {
    versions: &'static [Base58Version],
    alphabet: &'static bs58::Alphabet,
    refused: &'static [(u8, AddressIssue)],
}

impl Base58Rules {
    /// The policy's versions, read without changing the coin declaration.
    pub(super) const fn versions(self) -> &'static [Base58Version] {
        self.versions
    }

    /// The policy's alphabet, read without changing the coin declaration.
    pub(super) const fn alphabet(self) -> &'static bs58::Alphabet {
        self.alphabet
    }

    /// The policy's refused, read without changing the coin declaration.
    pub(super) const fn refused(self) -> &'static [(u8, AddressIssue)] {
        self.refused
    }
}

impl Base58Rules {
    const fn new(versions: &'static [Base58Version]) -> Self {
        Self {
            versions,
            alphabet: bs58::Alphabet::BITCOIN,
            refused: &[],
        }
    }
}

/// One HRP supplies decoding, network detection and its visible example.
#[derive(Clone, Copy)]
pub(super) struct HumanPart {
    text: &'static str,
    testnet: bool,
    shown: bool,
}

impl HumanPart {
    /// The policy's text, read without changing the coin declaration.
    pub(super) const fn text(self) -> &'static str {
        self.text
    }

    /// The policy's testnet, read without changing the coin declaration.
    pub(super) const fn testnet(self) -> bool {
        self.testnet
    }
}

impl HumanPart {
    pub(super) fn starts(self, text: &str) -> bool {
        text.get(..self.text.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(self.text))
            && text.as_bytes().get(self.text.len()) == Some(&b'1')
    }
}

#[derive(Clone, Copy)]
pub(super) struct WitnessRules {
    hrps: &'static [HumanPart],
    taproot: bool,
}

impl WitnessRules {
    /// The policy's hrps, read without changing the coin declaration.
    pub(super) const fn hrps(self) -> &'static [HumanPart] {
        self.hrps
    }

    /// The policy's taproot, read without changing the coin declaration.
    pub(super) const fn taproot(self) -> bool {
        self.taproot
    }
}

impl WitnessRules {
    pub(super) fn forms(self) -> Vec<String> {
        let mut forms = Vec::new();
        for hrp in self.hrps.iter().filter(|hrp| hrp.shown) {
            forms.push(format!("{}1q…", hrp.text));
            if self.taproot {
                forms.push(format!("{}1p…", hrp.text));
            }
        }
        forms
    }
}

#[derive(Clone, Copy)]
pub(super) struct PlatformRules {
    hrps: &'static [HumanPart],
    payment_type: u8,
    shielded_type: u8,
    shielded_reason: AddressIssue,
}

impl PlatformRules {
    /// The policy's hrps, read without changing the coin declaration.
    pub(super) const fn hrps(self) -> &'static [HumanPart] {
        self.hrps
    }

    /// The policy's payment type, read without changing the coin declaration.
    pub(super) const fn payment_type(self) -> u8 {
        self.payment_type
    }

    /// The policy's shielded type, read without changing the coin declaration.
    pub(super) const fn shielded_type(self) -> u8 {
        self.shielded_type
    }

    /// The policy's shielded reason, read without changing the coin declaration.
    pub(super) const fn shielded_reason(self) -> AddressIssue {
        self.shielded_reason
    }
}

/// DIP18's type byte; the wallet's known-answer tests use the same protocol fact.
pub(super) const DASH_PLATFORM_P2PKH: u8 = 0xb0;

#[derive(Clone, Copy)]
pub(super) enum AddressFamily {
    Base58,
    Hex,
    Account {
        hrp: &'static str,
        kind: AddressType,
    },
    Cashaddr {
        prefix: &'static str,
        legacy_start: &'static str,
    },
    Transparent {
        refused: &'static [(&'static [&'static str], AddressIssue)],
    },
}

#[derive(Clone, Copy)]
pub(super) enum TypeDescription {
    None,
    Bip,
    CoreAndPlatform,
    Transparent,
}

#[derive(Clone, Copy)]
pub(super) struct CoinRules {
    name: &'static str,
    id: &'static str,
    coin_types: &'static [u32],
    base58: Base58Rules,
    witness: Option<WitnessRules>,
    platform: Option<PlatformRules>,
    family: AddressFamily,
    description: TypeDescription,
}

impl CoinRules {
    /// The policy's base58, read without changing the coin declaration.
    pub(super) const fn base58(self) -> Base58Rules {
        self.base58
    }

    /// The policy's witness, read without changing the coin declaration.
    pub(super) const fn witness(self) -> Option<WitnessRules> {
        self.witness
    }

    /// The policy's platform, read without changing the coin declaration.
    pub(super) const fn platform(self) -> Option<PlatformRules> {
        self.platform
    }

    /// The policy's family, read without changing the coin declaration.
    pub(super) const fn family(self) -> AddressFamily {
        self.family
    }
}

impl CoinRules {
    const fn new(name: &'static str, id: &'static str, coin_types: &'static [u32]) -> Self {
        Self {
            name,
            id,
            coin_types,
            base58: Base58Rules::new(&[]),
            witness: None,
            platform: None,
            family: AddressFamily::Base58,
            description: TypeDescription::None,
        }
    }

    fn forms(self) -> Vec<String> {
        let mut forms: Vec<String> = self
            .base58
            .versions
            .iter()
            .filter_map(|(_, _, _, shown)| shown.map(str::to_owned))
            .collect();
        if let Some(witness) = self.witness {
            forms.extend(witness.forms());
        }
        if let Some(platform) = self.platform {
            // DIP18 encodes the payment type's first five bits as the first data character.
            let leading = bech32::Fe32::try_from(platform.payment_type >> 3)
                .map_or('?', bech32::Fe32::to_char);
            for hrp in platform.hrps.iter().filter(|hrp| hrp.shown) {
                forms.push(format!("{}1{leading}…", hrp.text));
            }
        }
        match self.family {
            AddressFamily::Hex => forms.push("0x…".to_owned()),
            AddressFamily::Account { hrp, .. } => forms.push(format!("{hrp}1…")),
            AddressFamily::Cashaddr { prefix, .. } => forms.insert(0, format!("{prefix}:q…")),
            AddressFamily::Base58 | AddressFamily::Transparent { .. } => {}
        }
        forms
    }
}

// Explicit variant numbers retain the existing public Rust discriminants while ALL follows
// alphabetical display order; one declaration supplies both and cannot omit a variant.
macro_rules! define_coins {
    ($visibility:vis, $($(#[$doc:meta])* $coin:ident = $index:literal => $rules:expr;)+) => {
        /// A supported coin's single-key address and search policy. Rules are held in one
        /// declaration per variant; private key derivation is shared across these policies.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $visibility enum Coin { $($(#[$doc])* $coin = $index,)+ }

        impl Coin {
            /// Every coin in alphabetical display order, generated from the variants themselves.
            $visibility const ALL: [Self; [$(stringify!($coin)),+].len()] = [$(Self::$coin),+];

            pub(super) fn rules(self) -> CoinRules {
                match self { $(Self::$coin => $rules,)+ }
            }
        }
    };
}

use AddressType::{Keccak, P2pkh, P2shP2wpkh};

define_coins! {
    pub,
    /// Bitcoin: legacy, nested/native SegWit and Taproot addresses.
    Bitcoin = 0 => CoinRules {
        base58: Base58Rules::new(&[
            (&[0x00], P2pkh, false, Some("1…")),
            (&[0x05], P2shP2wpkh, false, Some("3…")),
            (&[0x6f], P2pkh, true, None),
            (&[0xc4], P2shP2wpkh, true, None),
        ]),
        witness: Some(WitnessRules {
            hrps: &[
                HumanPart { text: "bc", testnet: false, shown: true },
                HumanPart { text: "tb", testnet: true, shown: false },
            ], taproot: true,
        }),
        description: TypeDescription::Bip,
        ..CoinRules::new("Bitcoin", "bitcoin", &[0])
    };
    /// Bitcoin Cash: CashAddr or legacy single-key addresses.
    BitcoinCash = 6 => CoinRules {
        base58: Base58Rules::new(&[(&[0x00], P2pkh, false, Some("1…"))]),
        family: AddressFamily::Cashaddr { prefix: "bitcoincash", legacy_start: "1" },
        ..CoinRules::new("Bitcoin Cash", "bitcoin-cash", &[145, 0])
    };
    /// Cosmos SDK account addresses.
    Cosmos = 9 => CoinRules {
        family: AddressFamily::Account { hrp: "cosmos", kind: P2pkh },
        ..CoinRules::new("Cosmos", "cosmos", &[118])
    };
    /// Dash Core and DIP17/DIP18 Platform payment addresses.
    Dash = 11 => CoinRules {
        base58: Base58Rules {
            refused: &[
                (0x8c, AddressIssue::DashTestnet),
                (0x13, AddressIssue::DashTestnetScript),
            ],
            ..Base58Rules::new(&[(&[0x4c], P2pkh, false, Some("X…"))])
        },
        platform: Some(PlatformRules {
            hrps: &[
                HumanPart { text: "dash", testnet: false, shown: true },
                HumanPart { text: "tdash", testnet: true, shown: true },
            ], payment_type: DASH_PLATFORM_P2PKH, shielded_type: 0x10,
            shielded_reason: AddressIssue::DashShielded,
        }),
        description: TypeDescription::CoreAndPlatform,
        ..CoinRules::new("Dash", "dash", &[5])
    };
    /// Dogecoin legacy addresses.
    Dogecoin = 5 => CoinRules {
        base58: Base58Rules::new(&[(&[0x1e], P2pkh, false, Some("D…"))]),
        ..CoinRules::new("Dogecoin", "dogecoin", &[3])
    };
    /// Ethereum and all EVM networks, which share the same address format.
    Ethereum = 1 => CoinRules {
        family: AddressFamily::Hex,
        ..CoinRules::new("Ethereum and EVM networks", "ethereum", &[60])
    };
    /// Ethereum Classic searches both its own and Ethereum's historical coin type.
    EthereumClassic = 8 => CoinRules {
        family: AddressFamily::Hex,
        ..CoinRules::new("Ethereum Classic", "ethereum-classic", &[61, 60])
    };
    /// Injective's Bech32 account form commits to an Ethereum-style hash.
    Injective = 10 => CoinRules {
        family: AddressFamily::Account { hrp: "inj", kind: Keccak },
        ..CoinRules::new("Injective", "injective", &[60])
    };
    /// Litecoin legacy and SegWit addresses, including its old P2SH version.
    Litecoin = 7 => CoinRules {
        base58: Base58Rules::new(&[
            (&[0x30], P2pkh, false, Some("L…")),
            (&[0x32], P2shP2wpkh, false, Some("M…")),
            (&[0x05], P2shP2wpkh, false, Some("3…")),
        ]),
        witness: Some(WitnessRules {
            hrps: &[HumanPart { text: "ltc", testnet: false, shown: true }], taproot: false,
        }),
        description: TypeDescription::Bip,
        ..CoinRules::new("Litecoin", "litecoin", &[2])
    };
    /// Tron Base58Check addresses commit to an Ethereum-style hash.
    Tron = 3 => CoinRules {
        base58: Base58Rules::new(&[(&[0x41], Keccak, false, Some("T…"))]),
        ..CoinRules::new("Tron", "tron", &[195])
    };
    /// XRP Base58Check addresses use the Ripple alphabet.
    Xrp = 2 => CoinRules {
        base58: Base58Rules {
            alphabet: bs58::Alphabet::RIPPLE,
            ..Base58Rules::new(&[(&[0x00], P2pkh, false, Some("r…"))])
        },
        ..CoinRules::new("XRP", "xrp", &[144])
    };
    /// Zcash transparent addresses; shielded/TEX forms require other wallet cryptography.
    Zcash = 4 => CoinRules {
        base58: Base58Rules::new(&[(&[0x1c, 0xb8], P2pkh, false, Some("t1…"))]),
        family: AddressFamily::Transparent {
            refused: &[
                (&["tex1", "textest1"], AddressIssue::ZcashTex),
                (&["zs1", "ztestsapling1", "u1", "utest1", "zc", "zt"], AddressIssue::ZcashShielded),
            ],
        },
        description: TypeDescription::Transparent,
        ..CoinRules::new("Zcash", "zcash", &[133])
    };
}

impl Coin {
    /// The name a person knows it by.
    pub fn name(self) -> &'static str {
        self.rules().name
    }

    /// The exact lower-case identifier accepted by the CLI and browser package.
    pub fn id(self) -> &'static str {
        self.rules().id
    }

    /// Supported address examples, derived from this coin's encoding and HRP metadata.
    pub fn address_forms(self) -> String {
        let mut forms = self.rules().forms();
        let last = forms.pop().unwrap_or_default();
        if forms.is_empty() {
            last
        } else {
            format!("{} or {last}", forms.join(", "))
        }
    }

    pub(super) fn coin_types(self) -> &'static [u32] {
        self.rules().coin_types
    }

    pub(super) fn type_description(self, kind: AddressType, testnet: bool) -> Option<String> {
        let network = if testnet { "testnet, " } else { "" };
        match self.rules().description {
            TypeDescription::Bip => {
                Some(format!("{network}{} (BIP{})", kind.name(), kind.purpose()))
            }
            TypeDescription::CoreAndPlatform => Some(if kind == AddressType::DashPlatform {
                format!("{network}Platform payment (DIP17)")
            } else {
                "Core (BIP44)".to_owned()
            }),
            TypeDescription::Transparent => Some("transparent".to_owned()),
            TypeDescription::None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A new synthetic variant supplies only its one policy declaration. ALL and the exhaustive
    // dispatch are generated from it; no checkout copy or mutation of shipped coins is needed.
    define_coins! {
        pub(super),
        /// A synthetic existing policy.
        Existing = 0 => CoinRules::new("Existing", "existing", &[0]);
        /// The new synthetic coin has all of its facts in this one declaration.
        Probe = 1 => CoinRules {
            family: AddressFamily::Hex,
            ..CoinRules::new("Probe", "probe", &[999])
        };
    }

    #[test]
    fn one_new_declaration_joins_the_enum_dispatch_and_list() {
        assert_eq!(Coin::ALL, [Coin::Existing, Coin::Probe]);
        let rules = Coin::Probe.rules();
        assert_eq!(rules.id, "probe");
        assert_eq!(rules.coin_types, [999]);
        assert_eq!(rules.forms(), ["0x…"]);
        assert_eq!(Coin::Existing.rules().name, "Existing");
    }
}
