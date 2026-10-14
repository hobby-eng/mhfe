//! Prints the refusals of a few inputs, as mhfe words them, for the audit record.
use mhfe::search::ContainerSearch;
use mhfe::wallet::{find_address, Address, Coin, DerivationPath, SearchLimits};
fn main() {
    let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".split(' ').collect();
    let mut typed: Vec<&str> = words.clone();
    typed[0] = "?";
    typed.pop();
    match ContainerSearch::new(&typed.join(" ")) {
        Ok(s) => println!("23 words with ?: accepted {:?}", s.missing()),
        Err(e) => println!("23 words with ?: {}: {e}", e.code()),
    }
    let mut typed = words.clone();
    typed[3] = "abandonn";
    match ContainerSearch::new(&typed.join(" ")) {
        Ok(s) => println!("24 words, one misspelled, no ?: accepted {:?}", s.missing()),
        Err(e) => println!("24 words, one misspelled, no ?: {}: {e}", e.code()),
    }
    for text in ["m/1H", "m/084'/0'/0'/0/00", "m/0h/0'"] {
        match text.parse::<DerivationPath>() {
            Ok(p) => println!("path {text}: accepted as {p}"),
            Err(e) => println!("path {text}: {}: {e}", e.code()),
        }
    }
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let address = Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
    for depth in [256usize, 20_000] {
        let deep: DerivationPath = format!("m/{}", vec!["0"; depth].join("/")).parse().unwrap();
        let start = std::time::Instant::now();
        let found = find_address(phrase, "", &address, Some(&deep), SearchLimits::default());
        println!("depth {depth}: {:?} after {:?}", found.map(|f| f.is_some()), start.elapsed());
    }
    // src/wasm_api/core/check.rs:100-108 turns kind "words", reference "12" and the page's
    // passphrase into ReferenceTarget::Length(Words(12)).with(passphrase).
    let target = mhfe::ReferenceTarget::Length(mhfe::PhraseLength::Words(mhfe::WordCount::new(12).unwrap()));
    let reference = target.with("a passphrase the page gave");
    println!("words 12 with a passphrase: built-in check reference = {}, passphrase kept = {:?}, refusal rule = {:?}",
        matches!(reference, mhfe::Reference::BuiltInCheck { .. }), reference.passphrase(),
        mhfe::refuse_unused_passphrase("a passphrase the page gave", mhfe::PassphraseReferences::Check).map_err(|e| e.to_string()));
}

/// What the binding's `wallet.with(passphrase)` gives for a stated length with a passphrase.
#[allow(dead_code)]
fn unused() {}
