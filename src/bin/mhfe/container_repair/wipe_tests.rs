//! Producer cleanup controls using public vector words and their initialized index bytes.

use std::mem::size_of;

use super::print_card;
use crate::terminal::Input;
use crate::test_allocator::{index_bytes, unwiped_blocks, unwiped_matching, WATCHED};
use mhfe::repair::{RepairError, RepairWordCount};
use zeroize::Zeroizing;

// The first eight English BIP39 word indices of the published suite3 zero-12 container.
const INDEX_VALUES: [u16; 8] = [520, 1717, 1841, 1313, 946, 1465, 1859, 1593];

static INDEX_BYTES: [u8; INDEX_VALUES.len() * size_of::<u16>()] = index_bytes(&INDEX_VALUES);

#[test]
fn card_output_drops_its_word_intermediates_wiped() {
    let input = Input::terminal_only();
    assert_eq!(unwiped_blocks(|| print_card(WATCHED, &input).unwrap()), 0);
}

#[test]
fn repair_scratch_is_wiped_on_success_clone_and_refusal() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/suite3-vectors/zero-12.json"
    ))
    .unwrap();
    let container = vector["container"].as_str().unwrap();
    let list = bip39::Language::English;
    assert!(container
        .split_whitespace()
        .take(INDEX_VALUES.len())
        .map(|word| list.find_word(word).unwrap())
        .eq(INDEX_VALUES));
    let mut words: Vec<&str> = container.split_whitespace().collect();
    // Five erasures exceed a four-word card; keep the witness prefix unchanged.
    for word in words.iter_mut().rev().take(5) {
        *word = "?";
    }
    let damaged = Zeroizing::new(words.join(" "));
    let unwiped = unwiped_matching(&INDEX_BYTES, || {
        let card = Zeroizing::new(
            RepairWordCount::new(4)
                .unwrap()
                .words_of(container)
                .unwrap(),
        );
        let repaired = RepairWordCount::repair(container, &card).unwrap();
        assert_eq!(repaired.clone(), repaired);
        assert!(matches!(
            RepairWordCount::repair(&damaged, &card),
            Err(RepairError::NotPossible { repair_words: 4 })
        ));
    });
    assert_eq!(unwiped, 0);
}
