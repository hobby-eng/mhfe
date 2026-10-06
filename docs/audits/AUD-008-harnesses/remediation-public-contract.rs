//! AUD-008 remediation: retained Dash aliases, wrong-card example, and source-check fixtures.
//! All inputs are published public fixtures. No Argon2 or network calls occur.

use mhfe::wallet::{Address, Coin};

fn main() {
    let canonical = "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs";
    assert!(Address::parse(Coin::Dash, canonical).is_ok());
    assert!(Address::parse(Coin::Dash, &canonical.to_ascii_uppercase()).is_ok());
    for alias in [
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y5qapwq8y",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y5pqh646k",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y4yn8p7z",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9yk2qjhsa",
        "dash1krma5z3ttj75la4m93xcndna9ullamq9yhhkxzd0",
    ] {
        assert!(Address::parse(Coin::Dash, alias).is_err());
        assert!(Address::parse(Coin::Dash, &alias.to_ascii_uppercase()).is_err());
    }
    println!("retained Dash aliases: 10 rejected, 2 canonical controls accepted");

    let prefix = "abandon ".repeat(23);
    let plate_a = format!("{prefix}art");
    let plate_b = format!("{prefix}diesel");
    let card_b = mhfe::repair::repair_words(&plate_b, 2).unwrap();
    let repaired = mhfe::repair::repair(&plate_a, &card_b).unwrap();
    assert_eq!(card_b, "minimum uncover");
    assert_eq!(repaired.container, plate_b);
    assert_eq!(repaired.plate_words, [24]);
    assert!(repaired.card_words.is_empty());
    println!(
        "wrong-card example: checksum-valid plate B produced; success does not authenticate A"
    );

    for (counter, passphrase) in [(76_562u64, "TREZOR"), (98_918u64, "")] {
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&counter.to_be_bytes());
        assert!(mhfe::wallet_check::passes(&entropy, passphrase).unwrap());
        let other = if passphrase.is_empty() { "TREZOR" } else { "" };
        assert!(!mhfe::wallet_check::passes(&entropy, other).unwrap());
    }
    let _empty_passphrase = mhfe::Reference::WalletCheck { passphrase: "" };
    println!("source checks: both public positive and crossed negative controls agree; empty Reference accepted");
}
