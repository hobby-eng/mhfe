//! Any text read as an address of any coin or of one, with any derivation path, and as a master
//! key fingerprint: each is refused or read, never a panic, and a fingerprint that is read gives
//! back its eight hexadecimal digits.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe::wallet::{Address, AddressSearch, parse_fingerprint};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(3, '\n');
    let (coin, address, path) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if let Ok(addresses) = Address::parse_any(address) {
        assert!(!addresses.is_empty());
    }
    let _ = Address::parse_with(coin, address);
    let _ = AddressSearch::describe(coin, address, path);
    if let Ok(fingerprint) = parse_fingerprint(text) {
        let hex: String = fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(parse_fingerprint(&hex).unwrap(), fingerprint);
    }
});
