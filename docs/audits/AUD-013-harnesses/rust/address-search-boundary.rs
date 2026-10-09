//! Audit-only public API probe. It describes searches without deriving keys or searching.

use std::panic::{catch_unwind, AssertUnwindSafe};

use mhfe::wallet::{Address, AddressSearch, Coin, SearchLimits};

fn check(coin: Coin, text: &str, accounts: u32, indexes: u32, roots: u128) -> bool {
    let address = Address::parse(coin, text).expect("the public fixture is a valid address");
    let limits = SearchLimits::new(accounts, indexes).expect("the documented limits are valid");
    let expected = roots * 2 * u128::from(accounts) * u128::from(indexes);
    match catch_unwind(AssertUnwindSafe(|| {
        AddressSearch::new(&address, None, limits)
    })) {
        Ok(search) => {
            let observed = u128::from(search.addresses());
            println!(
                "coin={} accounts={accounts} indexes={indexes} expected={expected} observed={observed}",
                coin.id()
            );
            observed == expected
        }
        Err(_) => {
            println!(
                "coin={} accounts={accounts} indexes={indexes} expected={expected} observed=panic",
                coin.id()
            );
            false
        }
    }
}

fn main() {
    // Public BIP84/BIP44 fixtures already retained by the production wallet known answers.
    const SEGWIT: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const LEGACY: &str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";
    const EVM: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    let most = SearchLimits::MOST;
    let results = [
        check(Coin::Bitcoin, SEGWIT, most, most, 1),
        check(Coin::BitcoinCash, LEGACY, most - 1, most, 2),
        check(Coin::EthereumClassic, EVM, most - 1, most, 2),
        check(Coin::BitcoinCash, LEGACY, most, most, 2),
        check(Coin::EthereumClassic, EVM, most, most, 2),
    ];
    if results.into_iter().any(|passed| !passed) {
        std::process::exit(1);
    }
}
