//! AUD-024 probe: what Address::parse (the library entry the CLI and the browser use) says about
//! address forms. Public addresses of the "abandon ... about" test phrase, plus forms computed
//! independently by address_forms.py from the same HASH160.
use mhfe::wallet::{Address, Coin};

fn main() {
    let cases: [(Coin, &str, &str); 8] = [
        (Coin::BitcoinCash, "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6", "CashAddr P2PKH, version 0 (single key)"),
        (Coin::BitcoinCash, "bitcoincash:zqyx49mu0kkn9ftfj6hje6g2wfer34yfnqnpwfwhlf", "CashAddr token-aware P2PKH, version 0x10, same HASH160 (single key)"),
        (Coin::Zcash, "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F", "Zcash transparent P2PKH"),
        (Coin::Zcash, "tex1j4jdnlkjg7vxk9dz747skwcr9m4js3mvsg2wra", "Zcash ZIP-320 TEX, same HASH160 (single key)"),
        (Coin::Bitcoin, "39kh1g5VzX7eEEzAnbNZsG2w1WCYNQVu3G", "Bitcoin P2SH '3...' (AUD-023: a 1-of-1 CHECKMULTISIG script)"),
        (Coin::Dash, "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5", "Dash Core mainnet X..."),
        (Coin::Dash, "tdash1kr0xt5wj85ht5u464rfysjrq75rewz9mysjwf59p", "Dash Platform testnet tdash1k..."),
        (Coin::Dash, "yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt", "Dash Core testnet y..."),
    ];
    for (coin, text, what) in cases {
        match Address::parse(coin, text) {
            Ok(address) => println!(
                "ACCEPTED {what}: {text} -> type {:?}, described {:?}, search roots {:?}",
                address.address_type(),
                address.type_description(),
                address.search_roots()
            ),
            Err(error) => println!("REFUSED  {what}: {text} -> {} \"{error}\"", error.code()),
        }
    }
}
