//! AUD-008: public wallet APIs, without Argon2 or reduced-cost cryptographic engines.
//! Reads tab-separated cases from stdin. The Python companion supplies independent expectations.

use std::io::{self, BufRead};
use std::str::FromStr;

use mhfe::wallet::{self, Address, Coin, DerivationPath, SearchLimits};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        match fields[0] {
            "address" => {
                assert_eq!(fields.len(), 9);
                let coin = Coin::from_str(fields[2]).unwrap();
                let parsed = Address::parse(coin, fields[6]);
                let accepted = parsed.is_ok();
                let matched = parsed.ok().and_then(|address| {
                    let path = if fields[5].is_empty() {
                        None
                    } else {
                        Some(DerivationPath::from_str(fields[5]).unwrap())
                    };
                    wallet::find_address(
                        fields[3],
                        fields[4],
                        &address,
                        path.as_ref(),
                        SearchLimits::new(fields[7].parse().unwrap(), fields[8].parse().unwrap())
                            .unwrap(),
                    )
                    .unwrap()
                    .map(|found| found.to_string())
                });
                println!(
                    "address\t{}\t{}\t{}",
                    fields[1],
                    accepted,
                    matched.as_deref().unwrap_or("")
                );
            }
            "path" => {
                let parsed = DerivationPath::from_str(fields[2]);
                let accepted = parsed.is_ok();
                let canonical = parsed.map(|path| path.to_string()).unwrap_or_default();
                println!("path\t{}\t{}\t{}", fields[1], accepted, canonical);
            }
            "limit" => {
                let accepted =
                    SearchLimits::new(fields[2].parse().unwrap(), fields[3].parse().unwrap())
                        .is_ok();
                println!("limit\t{}\t{}\t", fields[1], accepted);
            }
            "fingerprint" => {
                let fingerprint = wallet::master_fingerprint(fields[2], fields[3]).unwrap();
                println!(
                    "fingerprint\t{}\ttrue\t{:02x}{:02x}{:02x}{:02x}",
                    fields[1], fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]
                );
            }
            other => panic!("unknown mode {other}"),
        }
    }
}
