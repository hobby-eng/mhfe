//! Any text read as an original phrase, a container, a damaged container phrase with its card after
//! a line break, and a container with a missing word: each is refused or read, never a panic. The
//! search runs only for one unreadable word or none, as two take seconds.
#![no_main]
#![allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe::repair::{ContainerReading, card_text, repair};
use mhfe::search::ContainerSearch;
use mhfe::{ContainerFacts, OriginalFacts, check_phrase, read_phrase};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (written, card) = text.split_once('\n').unwrap_or((text, ""));
    if let Ok(words) = check_phrase(written) {
        assert!(read_phrase(written).is_ok() && words > 0);
    }
    let _ = OriginalFacts::read(written);
    let _ = ContainerFacts::read(written);
    let _ = repair(written, card);
    let _ = card_text(card);
    // Every word that cannot be read counts as missing once one is marked `?`.
    let missing = match ContainerReading::read(written) {
        ContainerReading::Marked { unreadable } => unreadable.len(),
        _ => 0,
    };
    if missing <= 1 {
        let _ = ContainerSearch::new(written);
    }
});
