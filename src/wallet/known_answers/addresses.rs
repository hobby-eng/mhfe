//! The `addresses` self-check: one receiving address of each encoding at its path, derived from the
//! test phrase, with a damaged copy of each checksum that must be refused, and in the full
//! self-test two address searches.

use super::{damaged, expect, expect_refusal, stopped, ABANDON};
use crate::self_check::{ComponentCheck, ComponentOutcome, Findings, Tier};
use crate::wallet::{
    find_address, master_fingerprint, program_for, Address, Coin, DerivationPath, ExtendedKey,
    SearchLimits,
};

/// A receiving address of the test phrase [`ABANDON`] at its path.
#[derive(Clone, Copy)]
pub(crate) struct AddressCase {
    pub(crate) coin: Coin,
    pub(crate) passphrase: &'static str,
    pub(crate) path: &'static str,
    pub(crate) address: &'static str,
    /// One of each encoding, checked at every start; the others in the full self-test.
    startup: bool,
}

const fn at(coin: Coin, path: &'static str, address: &'static str, startup: bool) -> AddressCase {
    AddressCase {
        coin,
        passphrase: "",
        path,
        address,
        startup,
    }
}

/// Where the wallets of [`ABANDON`] put each address, also the table of the wallet's unit tests.
/// Published vectors: BIP-0084's m/84'/0'/0'/0/0, 0/1 and 1/0, BIP-0086's m/86'/0'/0'/0/0 and 1/0,
/// BIP-0049's testnet m/49'/1'/0'/0/0, and the official DIP17/DIP18 vectors of Dash Platform.
/// BIP-0044 publishes no address, and BIP-0049 no mainnet one: those rows and the other Bitcoin
/// values were computed with Python's hashlib, and the other coins with the audited JavaScript
/// libraries @scure/bip32, @noble/hashes, @noble/curves and @scure/base, and ethers for EIP-55,
/// each of which first reproduced BIP84's vector.
pub(crate) const ADDRESSES: [AddressCase; 43] = [
    at(
        Coin::Bitcoin,
        "m/44'/0'/0'/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/0'/0'/0/0",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/0/0",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/0/1",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/0'/1/0",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/0'/0/0",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/0'/1/0",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/44'/0'/3'/1/7",
        "12DCYXCcRpBJ5VoWDvSijepPu8mshEihvX",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/0'/3'/1/7",
        "3K7gGbTWfdq3kyBgkVTMbhfftnrhxB6jpW",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/0'/3'/1/7",
        "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/0'/3'/1/7",
        "bc1preq6saz8z9zrn3clx9eaen0dcsynwseakek7nwqlrj52wd2dsfsqlfsyut",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/44'/1'/0'/0/0",
        "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
        false,
    ),
    at(
        Coin::Bitcoin,
        "m/49'/1'/0'/0/0",
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/84'/1'/0'/0/0",
        "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        true,
    ),
    at(
        Coin::Bitcoin,
        "m/86'/1'/0'/0/0",
        "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
        false,
    ),
    AddressCase {
        coin: Coin::Bitcoin,
        passphrase: "TREZOR",
        path: "m/84'/0'/0'/0/0",
        address: "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu",
        startup: false,
    },
    at(
        Coin::Ethereum,
        "m/44'/60'/0'/0/0",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        true,
    ),
    at(
        Coin::Ethereum,
        "m/44'/60'/3'/1/7",
        "0xc1A30611797762aea209daC2aC7E900f0cE95f9e",
        false,
    ),
    at(
        Coin::Xrp,
        "m/44'/144'/0'/0/0",
        "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        true,
    ),
    at(
        Coin::Xrp,
        "m/44'/144'/3'/1/7",
        "rnU3BdqhZk8DL3FKjQcaAyf3DJSoUZD8eM",
        false,
    ),
    at(
        Coin::Tron,
        "m/44'/195'/0'/0/0",
        "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        true,
    ),
    at(
        Coin::Tron,
        "m/44'/195'/3'/1/7",
        "TTD7MudE8L26nvnrEf2LHzXm6stKRpFZH1",
        false,
    ),
    at(
        Coin::Zcash,
        "m/44'/133'/0'/0/0",
        "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F",
        true,
    ),
    at(
        Coin::Zcash,
        "m/44'/133'/3'/1/7",
        "t1Pii1UXFrpcFucY5NBEFa664pymr7boHq4",
        false,
    ),
    at(
        Coin::Dogecoin,
        "m/44'/3'/0'/0/0",
        "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
        true,
    ),
    at(
        Coin::Dogecoin,
        "m/44'/3'/3'/1/7",
        "DNuJKZiVoQ6t67t8dE4NuBDhd2FNpMBsg6",
        false,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/0'/0/0",
        "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
        true,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/3'/1/7",
        "bitcoincash:qrhejavdmlfh9eajjxra3s3mn8gxls9hkvsq2yd62y",
        false,
    ),
    at(
        Coin::BitcoinCash,
        "m/44'/145'/0'/0/0",
        "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg",
        false,
    ),
    // A wallet of this coin on another coin's type, under the coin's second root.
    at(
        Coin::BitcoinCash,
        "m/44'/0'/0'/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        false,
    ),
    at(
        Coin::Litecoin,
        "m/44'/2'/0'/0/0",
        "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
        true,
    ),
    at(
        Coin::Litecoin,
        "m/49'/2'/0'/0/0",
        "M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM",
        true,
    ),
    at(
        Coin::Litecoin,
        "m/84'/2'/3'/1/7",
        "ltc1qnnphcvq5zgyf4f0uepust6d7gyt2zl69vftnz2",
        false,
    ),
    at(
        Coin::EthereumClassic,
        "m/44'/61'/0'/0/0",
        "0xFA22515E43658ce56A7682B801e9B5456f511420",
        false,
    ),
    // A wallet of this coin on another coin's type, under the coin's second root.
    at(
        Coin::EthereumClassic,
        "m/44'/60'/0'/0/0",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        false,
    ),
    at(
        Coin::Cosmos,
        "m/44'/118'/0'/0/0",
        "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
        true,
    ),
    at(
        Coin::Cosmos,
        "m/44'/118'/3'/1/7",
        "cosmos1j8dc8g9sux68h924yj646shrsjmkd7g6fwevky",
        false,
    ),
    at(
        Coin::Injective,
        "m/44'/60'/0'/0/0",
        "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
        true,
    ),
    at(
        Coin::Dash,
        "m/44'/5'/0'/0/0",
        "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
        true,
    ),
    at(
        Coin::Dash,
        "m/44'/5'/3'/1/7",
        "XbAei18dD6mdL9LR6sTmbFJTQAJBcpxuxL",
        false,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/0'/0",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
        true,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/0'/1",
        "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw",
        false,
    ),
    at(
        Coin::Dash,
        "m/9'/5'/17'/0'/1'/0",
        "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28",
        false,
    ),
];

/// Addresses of the table above with one character changed, one for each checksum: each must be
/// refused, never read as another address.
const DAMAGED_ADDRESSES: [(Coin, &str); 9] = [
    // Base58Check
    (Coin::Bitcoin, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB"),
    // Bech32 (BIP173)
    (Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv"),
    // Bech32m (BIP350)
    (
        Coin::Bitcoin,
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcs",
    ),
    // EIP-55: one capital made small.
    (Coin::Ethereum, "0x9858efFD232B4033E47d90003D41EC34EcaEda94"),
    // Base58Check with the other alphabet
    (Coin::Xrp, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4"),
    // CashAddr
    (
        Coin::BitcoinCash,
        "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q7",
    ),
    // Bech32 of an account
    (
        Coin::Cosmos,
        "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5",
    ),
    // Bech32m of DIP18
    (Coin::Dash, "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rt"),
    // Base58Check of a Keccak hash
    (Coin::Tron, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdJ"),
];

/// The master key fingerprint of [`ABANDON`] without a passphrase, 73c5da0a, derived from the root
/// key that BIP-0084's test vector publishes.
const ABANDON_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// Searches the full self-test runs: an address found under the second root of its coin, and one
/// at account 3, the change chain and index 7, within 4 accounts and 8 indexes.
const SEARCHES: [(usize, &str); 2] = [(29, "m/44'/0'/0'/0/0"), (9, "m/84'/0'/3'/1/7")];

/// The `addresses` check: the master fingerprint of BIP-0084's root key, each address at its path
/// derived from one master key per passphrase, and the damaged addresses refused. The full
/// self-test adds every address of the table and two searches.
pub(crate) struct AddressesCheck {
    addresses: &'static [AddressCase],
    damaged: &'static [(Coin, &'static str)],
}

impl AddressesCheck {
    pub(crate) fn new() -> Self {
        Self {
            addresses: &ADDRESSES,
            damaged: &DAMAGED_ADDRESSES,
        }
    }

    fn address(case: &AddressCase, masters: &[(&str, ExtendedKey)]) -> Result<(), String> {
        let address = Address::parse(case.coin, case.address).map_err(stopped)?;
        let path: DerivationPath = case.path.parse().map_err(|_| damaged())?;
        let master = masters
            .iter()
            .find(|(passphrase, _)| *passphrase == case.passphrase)
            .map(|(_, master)| master)
            .ok_or_else(damaged)?;
        let key = master.derive(&path.0).map_err(stopped)?;
        let program = program_for(&key, address.address_type).map_err(stopped)?;
        expect(program == address.program, "differs")
    }
}

impl ComponentCheck for AddressesCheck {
    fn id(&self) -> &'static str {
        "addresses"
    }

    fn label(&self) -> &'static str {
        "Address encodings"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let full = tier == Tier::Full;
        let mut findings = Findings::new();
        findings.one(|| {
            let fingerprint = master_fingerprint(ABANDON, "").map_err(stopped)?;
            expect(
                fingerprint == ABANDON_FINGERPRINT,
                "the master key fingerprint differs",
            )
        });
        let cases: Vec<AddressCase> = self
            .addresses
            .iter()
            .filter(|case| full || case.startup)
            .copied()
            .collect();
        // One master key for each passphrase, derived once: a BIP39 seed takes 2,048 rounds.
        let mut masters: Vec<(&str, ExtendedKey)> = Vec::new();
        for case in &cases {
            if masters
                .iter()
                .all(|(passphrase, _)| *passphrase != case.passphrase)
            {
                match ExtendedKey::master(ABANDON, case.passphrase) {
                    Ok(master) => masters.push((case.passphrase, master)),
                    Err(error) => findings.one(|| Err(stopped(error))),
                }
            }
        }
        findings.each("address", &cases, |case| Self::address(case, &masters));
        findings.each("damaged address", self.damaged, |&(coin, text)| {
            expect_refusal(Address::parse(coin, text), "INVALID_ADDRESS")
        });
        if full {
            findings.each("search", &SEARCHES, |&(index, expected)| {
                let case = self.addresses.get(index).ok_or_else(damaged)?;
                let address = Address::parse(case.coin, case.address).map_err(stopped)?;
                let limits = SearchLimits::new(4, 8).map_err(stopped)?;
                let found = find_address(ABANDON, case.passphrase, &address, None, limits)
                    .map_err(stopped)?;
                expect(
                    found.map(|path| path.to_string()).as_deref() == Some(expected),
                    "finds the address elsewhere",
                )
            });
        }
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};

    #[test]
    fn the_address_check_passes() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(
                AddressesCheck::new().run(tier),
                ComponentOutcome::Passed,
                "{tier:?}"
            );
        }
        assert_eq!(ADDRESSES.iter().filter(|case| case.startup).count(), 18);
        assert_eq!(SEARCHES[0].1, ADDRESSES[SEARCHES[0].0].path);
        assert_eq!(SEARCHES[1].1, ADDRESSES[SEARCHES[1].0].path);
    }

    #[test]
    fn a_corrupted_or_accepted_address_fails() {
        let mut addresses = ADDRESSES;
        // The address of the next index, where the wallet does not put the case's path.
        addresses[2].path = "m/84'/0'/0'/0/1";
        fails_with(
            AddressesCheck {
                addresses: leak(addresses),
                ..AddressesCheck::new()
            },
            "address 3 of 18 differs",
        );
        let mut damaged = DAMAGED_ADDRESSES;
        damaged[4].1 = "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3";
        fails_with(
            AddressesCheck {
                damaged: leak(damaged),
                ..AddressesCheck::new()
            },
            "damaged address 5 of 9 is accepted instead of refused with INVALID_ADDRESS",
        );
    }

    /// A self-check's detail never carries a coin's name or an address.
    #[test]
    fn details_name_no_coin() {
        let mut addresses = ADDRESSES;
        addresses[16].address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda95";
        let mut check = AddressesCheck {
            addresses: Box::leak(Box::new(addresses)),
            ..AddressesCheck::new()
        };
        let outcome = check.run(Tier::Startup);
        let detail = outcome.detail().unwrap();
        assert_eq!(detail, "address 7 of 18 stops with INVALID_ADDRESS");
        for coin in Coin::ALL {
            assert!(!detail.to_lowercase().contains(&coin.name().to_lowercase()));
            assert!(!detail.contains(coin.id()));
        }
        assert!(!check.label().contains("Bitcoin"));
    }
}
