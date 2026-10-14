// AUD-024 verifier probe: does mhfe's public API accept and derive a BIP32 path deeper than 255?
// Public test data only ("abandon ... about", BIP84 first receiving address). No Argon2.
use mhfe::wallet::{find_address, find_address_until, Address, AddressSearch, Coin, DerivationPath, SearchLimits};
use std::time::Instant;

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP84_FIRST: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

fn deep(depth: usize) -> String {
    let mut text = String::from("m");
    for _ in 0..depth {
        text.push_str("/0");
    }
    text
}

fn main() {
    let mut defects = 0;
    let address = Address::parse(Coin::Bitcoin, BIP84_FIRST).expect("BIP84 vector address");
    // Control: the published path still matches.
    let good: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
    let found = find_address(ABANDON, "", &address, Some(&good), SearchLimits::default()).unwrap();
    println!("control m/84'/0'/0'/0/0: {:?}", found.map(|p| p.to_string()));

    for depth in [255usize, 256, 1000, 100_000] {
        let text = deep(depth);
        match text.parse::<DerivationPath>() {
            Ok(path) => {
                let steps = path.to_string().matches('/').count();
                println!("parse depth {depth}: accepted, {steps} steps");
                if depth > 255 {
                    defects += 1;
                }
            }
            Err(e) => println!("parse depth {depth}: refused: {e}"),
        }
        match AddressSearch::describe("bitcoin", BIP84_FIRST, &text) {
            Ok(s) => println!(
                "describe depth {depth}: accepted, only_path={}, addresses={}, pattern {} bytes",
                s.only_path(),
                s.addresses(),
                s.pattern().len()
            ),
            Err(e) => println!("describe depth {depth}: refused: {e}"),
        }
    }
    for depth in [256usize, 20_000] {
        let path: DerivationPath = deep(depth).parse().unwrap();
        let start = Instant::now();
        let result = find_address(ABANDON, "", &address, Some(&path), SearchLimits::default());
        println!("find_address depth {depth}: {:?} after {:?}", result.map(|p| p.map(|p| p.to_string().len())), start.elapsed());
    }
    // The one-path branch never asks `stopped`: a cancel already requested is not honoured.
    let path: DerivationPath = deep(20_000).parse().unwrap();
    let start = Instant::now();
    let result = find_address_until(ABANDON, "", &address, Some(&path), SearchLimits::default(), &|| true);
    println!("find_address_until depth 20000, stopped() always true: {:?} after {:?}", result.map(|p| p.is_some()), start.elapsed());
    let result = find_address_until(ABANDON, "", &address, None, SearchLimits::default(), &|| true);
    println!("find_address_until standard search, stopped() always true: {:?}", result.map(|p| p.is_some()));
    println!("{defects} path(s) deeper than 255 accepted");
    std::process::exit(if defects > 0 { 1 } else { 0 });
}
