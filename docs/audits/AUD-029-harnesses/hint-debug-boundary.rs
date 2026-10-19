//! Actual public hint diagnostics, using synthetic/public prefixes only.
use mhfe::word_hints::{Hint, WordList};

fn main() {
    let hint = WordList::Bip39.hint("artw");
    assert_eq!(hint, Hint::Words(&["artwork"]));
    let completion = WordList::Bip39.completion("artw");
    assert_eq!(completion.letters(), "ork");
    assert!(completion.word_ends());
    let hint_debug = format!("{hint:?}");
    let completion_debug = format!("{completion:?}");
    println!("synthetic Hint Debug: {hint_debug}; Completion Debug: {completion_debug}");
    let disclosures =
        usize::from(hint_debug.contains("artwork")) + usize::from(completion_debug.contains("ork"));
    assert_eq!(
        disclosures, 0,
        "selected words and completion letters must be redacted from Debug"
    );
}
