//! Any text typed as a password, as dice rolls, or as a line with word hints from either list: each
//! is refused or read, never a panic, and an index of five rolls is on the list of 7,776 words.
#![no_main]
#![allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe::check_word::PasswordReview;
use mhfe::eff::index_of_rolls;
use mhfe::new_password::word_index_of_rolls;
use mhfe::strength::Strength;
use mhfe::word_hints::WordList;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = PasswordReview::of(text);
    let _ = Strength::of(text);
    for list in [WordList::Bip39, WordList::Eff] {
        let _ = list.hint(text);
        let _ = list.completion(text);
    }
    if let Some(index) = index_of_rolls(text) {
        assert!(index < 7776);
    }
    let _ = word_index_of_rolls(1, text);
});
