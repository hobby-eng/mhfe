//! AUD-014: an independent bit-string oracle exercising the public unchecked draw API.
//! All inputs are synthetic. The BIP39 dependency is trusted for its word list and SHA-256,
//! after the public zero and ff published BIP39 vectors are checked below.

use mhfe::wallet_check::PhraseDraw;
use mhfe::word_wishes::{Place, WordWishes};
use mhfe::MhfeError;
use std::cell::Cell;
use std::collections::HashSet;

const ENTROPY_BYTES: usize = 32;
const ENTROPY_BITS: usize = 256;
const WORD_BITS: usize = 11;
const PHRASE_WORDS: usize = 24;
const LIST_SIZE: usize = 2048;
type Entropy = [u8; ENTROPY_BYTES];

fn bit_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:08b}")).collect()
}

// Replacing a substring uses a different representation from the production byte masks.
fn overwrite(before: Entropy, position: usize, number: usize) -> Entropy {
    let mut text = bit_string(&before);
    let start = (position - 1) * WORD_BITS;
    let end = (start + WORD_BITS).min(ENTROPY_BITS);
    let word = format!("{number:011b}");
    text.replace_range(start..end, &word[..end - start]);
    let mut after = [0; ENTROPY_BYTES];
    for (byte, octet) in after.iter_mut().zip(text.as_bytes().chunks_exact(8)) {
        *byte = u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 2).unwrap();
    }
    after
}

fn word_list() -> Vec<String> {
    let words: Vec<String> = (0..LIST_SIZE)
        .map(|number| {
            let entropy = overwrite([0; ENTROPY_BYTES], 1, number);
            mhfe::phrase_from_entropy(&entropy)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(words[0], "abandon");
    assert_eq!(words[LIST_SIZE - 1], "zoo");
    assert_eq!(words.iter().collect::<HashSet<_>>().len(), LIST_SIZE);
    assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
    words
}

fn oracle_words(entropy: &Entropy, words: &[String]) -> Vec<usize> {
    mhfe::phrase_from_entropy(entropy)
        .unwrap()
        .split_whitespace()
        .map(|word| {
            words
                .binary_search_by(|candidate| candidate.as_str().cmp(word))
                .unwrap()
        })
        .collect()
}

fn one(draw: &PhraseDraw, before: Entropy) -> Result<Option<Entropy>, MhfeError> {
    let mut calls = 0;
    let mut source = |bytes: &mut [u8]| {
        calls += 1;
        assert_eq!(bytes.len(), ENTROPY_BYTES);
        bytes.copy_from_slice(&before);
        Ok(())
    };
    let result = draw
        .try_draws(&mut source, 1)
        .map(|value| value.map(|value| *value));
    assert_eq!(calls, 1);
    result
}

fn edge_entropies() -> [Entropy; 8] {
    [
        [0; ENTROPY_BYTES],
        [0xff; ENTROPY_BYTES],
        [0xaa; ENTROPY_BYTES],
        [0x55; ENTROPY_BYTES],
        [0x80; ENTROPY_BYTES],
        [0x01; ENTROPY_BYTES],
        std::array::from_fn(|index| index as u8),
        std::array::from_fn(|index| 255 - index as u8),
    ]
}

fn main() {
    let words = word_list();
    let zero = mhfe::phrase_from_entropy(&[0; ENTROPY_BYTES]).unwrap();
    assert_eq!(
        zero.split_whitespace()
            .filter(|word| *word == "abandon")
            .count(),
        23
    );
    assert_eq!(zero.split_whitespace().last(), Some("art"));
    let ones = mhfe::phrase_from_entropy(&[0xff; ENTROPY_BYTES]).unwrap();
    assert_eq!(
        ones.split_whitespace()
            .filter(|word| *word == "zoo")
            .count(),
        23
    );
    assert_eq!(ones.split_whitespace().last(), Some("vote"));

    let mut fixed_cases = 0;
    for position in 1..PHRASE_WORDS {
        for (number, word) in words.iter().enumerate() {
            let wishes = WordWishes::new(&[(Place::At(position), word)], &[]).unwrap();
            let draw = PhraseDraw::unchecked().with_wishes(wishes);
            for mut before in edge_entropies() {
                // The public API deliberately refuses a raw all-zero source. A bit entirely
                // inside the overwritten slice makes this source nonzero without changing
                // the expected all-zero free-bit case.
                if before.iter().all(|byte| *byte == 0) {
                    let start = (position - 1) * WORD_BITS;
                    before[start / 8] = 0x80 >> (start % 8);
                }
                let expected = overwrite(before, position, number);
                assert_eq!(
                    one(&draw, before).unwrap(),
                    Some(expected),
                    "position {position}, index {number}"
                );
                fixed_cases += 1;
            }
        }
    }
    println!("fixed positions 1..23: {fixed_cases} exact byte/mask cases passed");

    let mut preimage_cases = 0;
    for position in 1..PHRASE_WORDS {
        let draw = PhraseDraw::unchecked()
            .with_wishes(WordWishes::new(&[(Place::At(position), &words[1025])], &[]).unwrap());
        for base in [[0x55; ENTROPY_BYTES], [0xaa; ENTROPY_BYTES]] {
            let expected = overwrite(base, position, 1025);
            for original in 0..LIST_SIZE {
                let before = overwrite(base, position, original);
                assert_eq!(one(&draw, before).unwrap(), Some(expected));
                preimage_cases += 1;
            }
        }
    }
    println!("fixed-word equal preimages: {preimage_cases} cases passed (2048 preimages each)");

    // Collect one independently checksum-valid state for each of the 2048 final indices.
    // The BIP39 public formatter calls its dependency, rather than packing::with_checksum.
    let mut final_cases = 0;
    let mut final_refusals = 0;
    let mut final_examples = Vec::with_capacity(LIST_SIZE);
    for upper in 0..8 {
        let mut examples = [None; 256];
        let mut left = 256;
        for counter in 0u64..1_000_000 {
            let mut candidate = [0xa5; ENTROPY_BYTES];
            candidate[..8].copy_from_slice(&counter.to_be_bytes());
            candidate = overwrite(candidate, PHRASE_WORDS, upper << 8);
            let number = oracle_words(&candidate, &words)[PHRASE_WORDS - 1];
            assert_eq!(number >> 8, upper);
            let checksum = number & 255;
            if examples[checksum].is_none() {
                examples[checksum] = Some(candidate);
                left -= 1;
            }
            if left == 0 {
                break;
            }
        }
        assert_eq!(
            left, 0,
            "checksum examples not found for entropy suffix {upper}"
        );
        for (checksum, example) in examples.into_iter().enumerate() {
            let expected = example.unwrap();
            let number = upper << 8 | checksum;
            final_examples.push(expected);
            let draw = PhraseDraw::unchecked().with_wishes(
                WordWishes::new(&[(Place::At(PHRASE_WORDS), &words[number])], &[]).unwrap(),
            );
            for original in 0..8 {
                let before = overwrite(expected, PHRASE_WORDS, original << 8);
                assert_eq!(one(&draw, before).unwrap(), Some(expected));
                final_cases += 1;
            }
            let wrong = (upper << 8) | (checksum ^ 1);
            let refuse = PhraseDraw::unchecked().with_wishes(
                WordWishes::new(&[(Place::At(PHRASE_WORDS), &words[wrong])], &[]).unwrap(),
            );
            assert_eq!(one(&refuse, expected).unwrap(), None);
            final_refusals += 1;
        }
    }
    println!("final 3+8 split: {final_cases} exact/equal-preimage cases and {final_refusals} checksum refusals passed");

    let mut filters = 0;
    for (number, word) in words.iter().enumerate() {
        let other = &words[(number + 1) % LIST_SIZE];
        let anywhere = PhraseDraw::unchecked()
            .with_wishes(WordWishes::new(&[(Place::Anywhere, word)], &[]).unwrap());
        let excluded = PhraseDraw::unchecked().with_wishes(WordWishes::new(&[], &[word]).unwrap());
        let both = PhraseDraw::unchecked()
            .with_wishes(WordWishes::new(&[(Place::Anywhere, word)], &[other]).unwrap());
        for position in 1..=PHRASE_WORDS {
            let before = if position == PHRASE_WORDS {
                final_examples[number]
            } else {
                overwrite([0x5a; ENTROPY_BYTES], position, number)
            };
            let indices = oracle_words(&before, &words);
            assert!(indices.contains(&number));
            assert_eq!(one(&anywhere, before).unwrap(), Some(before));
            assert_eq!(one(&excluded, before).unwrap(), None);
            assert_eq!(
                one(&both, before).unwrap(),
                (!indices.contains(&((number + 1) % LIST_SIZE))).then_some(before)
            );
            filters += 3;
        }
        // The same oracle also tests absent wishes, absent exclusions and combined misses.
        let before = overwrite([0xa5; ENTROPY_BYTES], 1, (number + 1) % LIST_SIZE);
        let indices = oracle_words(&before, &words);
        assert_eq!(
            one(&anywhere, before).unwrap(),
            indices.contains(&number).then_some(before)
        );
        assert_eq!(
            one(&excluded, before).unwrap(),
            (!indices.contains(&number)).then_some(before)
        );
        assert_eq!(one(&both, before).unwrap(), None);
        filters += 3;
    }
    println!(
        "anywhere/exclusion/combined filters: {filters} exact acceptance/refusal cases passed"
    );

    let repeat = PhraseDraw::unchecked()
        .with_wishes(WordWishes::new(&[(Place::Anywhere, "zoo")], &[]).unwrap());
    for count in [2, 3] {
        let mut before = [0x5a; ENTROPY_BYTES];
        for position in 1..=count {
            before = overwrite(before, position, LIST_SIZE - 1);
        }
        assert_eq!(one(&repeat, before).unwrap(), Some(before));
    }
    println!("anywhere multiplicity 2 and 3: unchanged source accepted");

    for position in [0, PHRASE_WORDS + 1, usize::MAX] {
        assert!(WordWishes::new(&[(Place::At(position), "zoo")], &[]).is_err());
    }
    for (chosen, excluded) in [
        (vec![(Place::At(1), "notaword")], vec![]),
        (vec![], vec!["notaword"]),
        (vec![(Place::At(1), "zoo"), (Place::At(2), "happy")], vec![]),
        (vec![], vec!["zoo", "happy"]),
        (vec![(Place::Anywhere, "HAPP")], vec!["happy"]),
    ] {
        let text = WordWishes::new(&chosen, &excluded).unwrap_err().to_string();
        assert!(!text.contains("notaword") && !text.contains("happy") && !text.contains("zoo"));
    }
    assert!(matches!(
        one(&PhraseDraw::unchecked(), [0; ENTROPY_BYTES]),
        Err(MhfeError::RandomFailed(_))
    ));
    let nonzero_wish = PhraseDraw::unchecked()
        .with_wishes(WordWishes::new(&[(Place::At(1), "happy")], &[]).unwrap());
    assert!(matches!(
        one(&nonzero_wish, [0; ENTROPY_BYTES]),
        Err(MhfeError::RandomFailed(_))
    ));
    let called = Cell::new(false);
    let mut source = |_: &mut [u8]| {
        called.set(true);
        Err(MhfeError::RandomFailed("synthetic failure".to_owned()))
    };
    assert!(PhraseDraw::unchecked()
        .try_draws(&mut source, 0)
        .unwrap()
        .is_none());
    assert!(!called.get());
    assert!(matches!(
        PhraseDraw::unchecked().try_draws(&mut source, 1),
        Err(MhfeError::RandomFailed(_))
    ));
    println!("public range/count/conflict/redaction/source controls passed");
    println!("PASS: AUD-014 public API bit oracle; no Argon2 or wallet-check search invoked");
}
