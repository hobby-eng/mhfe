//! AUD-008 independent padding and path challenge; no Argon2 or wallet secret inputs.
//! Reviewed dirty source snapshot: HEAD 01978aa01f86cbec7dbc9fb9afd131dfa1a1d650.

use std::io::{self, BufRead};
use std::str::FromStr;

use mhfe::wallet::{Address, Coin, DerivationPath, SearchLimits};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        match fields[0] {
            "address" => {
                let canonical = Address::parse(Coin::Dash, fields[2]).unwrap();
                let parsed = Address::parse(Coin::Dash, fields[3]);
                let equal = parsed.as_ref().is_ok_and(|address| *address == canonical);
                println!("{}\t{}\t{}", fields[1], parsed.is_ok(), equal);
            }
            "path" => {
                let parsed = DerivationPath::from_str(fields[2]);
                println!("{}\t{}\t", fields[1], parsed.is_ok());
            }
            "limit" => {
                let parsed =
                    SearchLimits::new(fields[2].parse().unwrap(), fields[3].parse().unwrap());
                println!("{}\t{}\t", fields[1], parsed.is_ok());
            }
            kind => panic!("unsupported probe kind: {kind}"),
        }
    }
}
