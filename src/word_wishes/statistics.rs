//! Tests for faults that remove randomness from the chosen-word draw (owner, 2026-10-08,
//! through the mhfe_spec review). A bug that silently removed randomness would still give valid
//! BIP39 phrases, since the checksum is computed from whatever entropy results, while the screen
//! kept stating the same bits: bx's seed command (CVE-2023-39910, "Milk Sad") and Trust Wallet's
//! browser extension (CVE-2023-31290) made valid phrases from weak entropy in this way.
//!
//! Setting a word must change that word's bits and no other, and the phrases drawn with wishes must
//! look like random phrases everywhere the wishes leave free: each free entropy bit set half the
//! time (adjusted for an excluded word), the free words uniform at each position, words repeated as
//! often as chance repeats them, and a word wished "anywhere" at every position alike. Correlation
//! checks and deliberately faulty samples test the controls themselves. The fixed-seed generator
//! makes these repeatable regression tests, not a proof of entropy or cryptographic RNG quality.
//! Bounds apply to each comparison, not to the whole suite: five binomial standard deviations or a
//! conservative chi-square-model tail bound. Pearson statistics use a multinomial approximation;
//! the checksum word is treated as uniform only where SHA-256's random-looking output justifies it.

use super::{Place, WordWishes, CHECKSUM_BITS};
use crate::packing::{self, STATE_BYTES, STATE_WORDS};
use crate::phrase::{self, LIST_SIZE, WORD_BITS};
use crate::wallet_check::PhraseDraw;
use crate::MhfeError;

/// Phrases drawn for each set of wishes.
const DRAWS: usize = 20_000;
/// The bits of a new phrase's entropy.
const ENTROPY_BITS: usize = STATE_BYTES * 8;
/// The words in the list, as a count.
const WORDS: usize = LIST_SIZE as usize;
/// A per-comparison chi-square-model upper-tail bound, not a family-wide false-positive rate.
const CHI_SQUARE_TAIL: f64 = 1e-6;
/// A wide binomial regression tolerance; the fixed seeds make the verdict reproducible.
const STANDARD_DEVIATIONS: f64 = 5.0;
/// Thirty expected fixed-last-word searches make an exhausted search exceptionally unlikely.
const MOST_DRAWS: u64 = 30 * (1 << CHECKSUM_BITS);

/// SplitMix64 (Steele, Lea and Flood, 2014): a small generator of good statistical quality, with a
/// fixed seed so that every run draws the same phrases. Never used for a real phrase.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let value = self.next().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}

/// Whether bit `index` of `bytes` is set, counting from the first byte's highest bit as BIP39 does.
fn bit(bytes: &[u8], index: usize) -> bool {
    bytes[index / 8] >> (7 - index % 8) & 1 == 1
}

/// The entropy bits that a word at `position`, from 1, sets: all 11 of a word but the last, and
/// of the last only its entropy bits; its checksum bits come from the hash.
fn bits_of(position: usize) -> std::ops::Range<usize> {
    let start = (position - 1) * WORD_BITS;
    if position < STATE_WORDS {
        start..start + WORD_BITS
    } else {
        start..ENTROPY_BITS
    }
}

#[test]
fn a_chosen_word_changes_its_own_bits_and_no_other() {
    let mut random = SplitMix64(0x6d68_6665_6269_7473);
    // The extremes catch errors of masks and of one bit.
    let numbers: [u16; 5] = [0, 1, 1024, LIST_SIZE - 2, LIST_SIZE - 1];
    for _ in 0..8 {
        let mut before = [0u8; STATE_BYTES];
        random.fill(&mut before);
        for position in 1..=STATE_WORDS {
            for &number in &numbers {
                let wishes =
                    WordWishes::new(&[(Place::At(position), phrase::word(number))], &[]).unwrap();
                let mut after = before;
                wishes.apply(&mut after);
                let changed = bits_of(position);
                for index in 0..ENTROPY_BITS {
                    if !changed.contains(&index) {
                        assert_eq!(
                            bit(&before, index),
                            bit(&after, index),
                            "word {number} at {position} changed bit {index}"
                        );
                    }
                }
                let written = phrase::number_at(&packing::with_checksum(&after), position - 1);
                if position < STATE_WORDS {
                    assert_eq!(written, number, "word {number} at {position}");
                } else {
                    assert_eq!(
                        written >> CHECKSUM_BITS,
                        number >> CHECKSUM_BITS,
                        "the entropy bits of word {number} at the end"
                    );
                }
            }
        }
    }
}

/// What a set of wishes drew: the entropies and their words.
struct Drawn {
    entropies: Vec<[u8; STATE_BYTES]>,
    phrases: Vec<[u16; STATE_WORDS]>,
}

impl Drawn {
    fn new() -> Self {
        Self {
            entropies: Vec::with_capacity(DRAWS),
            phrases: Vec::with_capacity(DRAWS),
        }
    }

    fn push(&mut self, entropy: [u8; STATE_BYTES]) {
        let bits = packing::with_checksum(&entropy);
        let mut words = [0u16; STATE_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = phrase::number_at(&bits, index);
        }
        self.entropies.push(entropy);
        self.phrases.push(words);
    }

    /// Rebuild checksum-valid phrases after a fault changes the synthetic entropy.
    fn changed(&self, mut change: impl FnMut(&mut [u8; STATE_BYTES])) -> Self {
        let mut changed = Self::new();
        for entropy in &self.entropies {
            let mut entropy = *entropy;
            change(&mut entropy);
            changed.push(entropy);
        }
        changed
    }
}

/// [`DRAWS`] phrases drawn with `chosen` and `never_use`, without the wallet check.
fn draw(chosen: &[(Place, &str)], never_use: &[&str], seed: u64) -> Drawn {
    let wishes = WordWishes::new(chosen, never_use).unwrap();
    let draw = PhraseDraw::unchecked().with_wishes(wishes);
    let mut random = SplitMix64(seed);
    let mut source = |bytes: &mut [u8]| -> Result<(), MhfeError> {
        random.fill(bytes);
        Ok(())
    };
    let mut drawn = Drawn::new();
    for _ in 0..DRAWS {
        let entropy = draw.try_draws(&mut source, MOST_DRAWS).unwrap().unwrap();
        drawn.push(*entropy);
    }
    drawn
}

/// A bit of a full word conditioned on avoiding `left_out`.
fn bit_probability(offset: usize, left_out: Option<u16>) -> f64 {
    let removed = left_out.map_or(0, |word| usize::from(word >> (WORD_BITS - 1 - offset) & 1));
    (WORDS / 2 - removed) as f64 / (WORDS - usize::from(left_out.is_some())) as f64
}

fn share_matches_probability(count: usize, total: usize, expected: f64, label: &str) {
    let share = count as f64 / total as f64;
    let sigma = (expected * (1.0 - expected) / total as f64).sqrt();
    assert!(
        (share - expected).abs() < STANDARD_DEVIATIONS * sigma,
        "{label}: share {share}, expected {expected}"
    );
}

/// Every free entropy bit has its allowed-word marginal, within five standard deviations.
fn free_bits_are_balanced(drawn: &Drawn, fixed: std::ops::Range<usize>, left_out: Option<u16>) {
    for index in (0..ENTROPY_BITS).filter(|index| !fixed.contains(index)) {
        let set = drawn
            .entropies
            .iter()
            .filter(|entropy| bit(&entropy[..], index))
            .count();
        share_matches_probability(
            set,
            drawn.entropies.len(),
            bit_probability(index % WORD_BITS, left_out),
            &format!("entropy bit {index}"),
        );
    }
}

/// The chi-square of `counts` against equal counts in each of `bins` bins.
fn chi_square(counts: &[usize], bins: usize) -> f64 {
    let total: usize = counts.iter().sum();
    let expected = total as f64 / bins as f64;
    counts
        .iter()
        .map(|&count| (count as f64 - expected).powi(2) / expected)
        .sum()
}

/// Laurent-Massart's chi-square tail bound: df + 2 sqrt(df t) + 2t, t = ln(1/alpha).
/// This bounds the chi-square model; Pearson's finite multinomial statistic is approximate.
fn chi_square_bound(bins: usize) -> f64 {
    let freedom = (bins - 1) as f64;
    let tail = -CHI_SQUARE_TAIL.ln();
    freedom + 2.0 * (freedom * tail).sqrt() + 2.0 * tail
}

fn word_counts_are_uniform(counts: &[usize], left_out: &[u16], label: &str) {
    for &word in left_out {
        assert_eq!(
            counts[usize::from(word)],
            0,
            "{label}: a word never to use was drawn"
        );
    }
    let counts: Vec<usize> = counts
        .iter()
        .enumerate()
        .filter(|&(word, _)| !left_out.contains(&(word as u16)))
        .map(|(_, &count)| count)
        .collect();
    let bins = counts.len();
    let chi = chi_square(&counts, bins);
    assert!(
        chi < chi_square_bound(bins),
        "{label}: chi-square {chi} over {bins} words"
    );
}

/// Test each full free word separately before pooling: opposite position biases can cancel.
/// With 20,000 draws each allowed bin has an expected count above nine.
fn free_words_are_uniform(drawn: &Drawn, positions: &[usize], left_out: Option<u16>) {
    let mut pooled = vec![0usize; WORDS];
    let left_out: Vec<u16> = left_out.into_iter().collect();
    for &position in positions {
        let mut counts = vec![0usize; WORDS];
        for words in &drawn.phrases {
            counts[usize::from(words[position - 1])] += 1;
        }
        word_counts_are_uniform(&counts, &left_out, &format!("word position {position}"));
        for (pooled, count) in pooled.iter_mut().zip(counts) {
            *pooled += count;
        }
    }
    word_counts_are_uniform(&pooled, &left_out, "pooled free words");
}

fn bit_pairs_match(drawn: &Drawn, first: usize, second: usize, probabilities: [f64; 4]) {
    let mut counts = [0usize; 4];
    for entropy in &drawn.entropies {
        let cell = 2 * usize::from(bit(entropy, first)) + usize::from(bit(entropy, second));
        counts[cell] += 1;
    }
    let chi: f64 = counts
        .iter()
        .zip(probabilities)
        .map(|(&count, probability)| {
            let expected = drawn.entropies.len() as f64 * probability;
            (count as f64 - expected).powi(2) / expected
        })
        .sum();
    assert!(
        chi < chi_square_bound(counts.len()),
        "bits {first} and {second}: chi-square {chi}"
    );
}

/// Adjacent bits within each free full word, and equal-offset bits across neighboring free words.
/// These joint checks catch copied or correlated bits whose separate marginals remain balanced.
fn free_bits_are_uncorrelated(drawn: &Drawn, positions: &[usize], left_out: Option<u16>) {
    let allowed = WORDS - usize::from(left_out.is_some());
    for &position in positions {
        for offset in 0..WORD_BITS - 1 {
            let removed = left_out.map(|word| {
                2 * usize::from(word >> (WORD_BITS - 1 - offset) & 1)
                    + usize::from(word >> (WORD_BITS - 2 - offset) & 1)
            });
            let probabilities = std::array::from_fn(|cell| {
                (WORDS / 4 - usize::from(removed == Some(cell))) as f64 / allowed as f64
            });
            let first = (position - 1) * WORD_BITS + offset;
            bit_pairs_match(drawn, first, first + 1, probabilities);
        }
    }
    for pair in positions.windows(2) {
        for offset in 0..WORD_BITS {
            let set = bit_probability(offset, left_out);
            let probabilities = [
                (1.0 - set).powi(2),
                (1.0 - set) * set,
                set * (1.0 - set),
                set.powi(2),
            ];
            bit_pairs_match(
                drawn,
                (pair[0] - 1) * WORD_BITS + offset,
                (pair[1] - 1) * WORD_BITS + offset,
                probabilities,
            );
        }
    }
}

/// The birthday probability for 24 words, also valid with one of them fixed, under the independent
/// allowed-word model. A generator that avoids or favors repeats would differ.
fn repeats_are_as_frequent_as_chance(drawn: &Drawn, allowed: usize) {
    let distinct: f64 = (1..STATE_WORDS)
        .map(|taken| 1.0 - taken as f64 / allowed as f64)
        .product();
    let expected = 1.0 - distinct;
    let repeated = drawn
        .phrases
        .iter()
        .filter(|words| {
            let mut sorted = **words;
            sorted.sort_unstable();
            sorted.windows(2).any(|pair| pair[0] == pair[1])
        })
        .count();
    share_matches_probability(
        repeated,
        drawn.phrases.len(),
        expected,
        "phrases repeating a word",
    );
}

fn free_positions(fixed: Option<usize>) -> Vec<usize> {
    // The last word is omitted from word and joint comparisons because its checksum is derived.
    (1..STATE_WORDS)
        .filter(|&position| fixed != Some(position))
        .collect()
}

fn free_distribution_matches(drawn: &Drawn, fixed: Option<usize>, left_out: Option<u16>) {
    free_bits_are_balanced(drawn, fixed.map_or(0..0, bits_of), left_out);
    let free = free_positions(fixed);
    free_words_are_uniform(drawn, &free, left_out);
    free_bits_are_uncorrelated(drawn, &free, left_out);
    repeats_are_as_frequent_as_chance(drawn, WORDS - usize::from(left_out.is_some()));
}

/// A word at a fixed position in the middle and a word never to use: only that word's bits are
/// fixed; every other bit, word and repeat is as random as in a phrase without wishes.
#[test]
fn a_fixed_word_and_a_word_never_to_use_leave_the_rest_random() {
    const POSITION: usize = 12;
    let happy = phrase::word_number("happy").unwrap();
    let abandon = phrase::word_number("abandon").unwrap();
    let drawn = draw(&[(Place::At(POSITION), "happy")], &["abandon"], 1);
    for words in &drawn.phrases {
        assert_eq!(words[POSITION - 1], happy);
        assert!(!words.contains(&abandon));
    }
    free_distribution_matches(&drawn, Some(POSITION), Some(abandon));
}

/// A fixed last word: its entropy bits are set and its checksum bits must come out of the hash;
/// everything else stays random.
#[test]
fn a_fixed_last_word_leaves_the_rest_random() {
    let zoo = phrase::word_number("zoo").unwrap();
    let drawn = draw(&[(Place::At(STATE_WORDS), "zoo")], &[], 2);
    for words in &drawn.phrases {
        assert_eq!(words[STATE_WORDS - 1], zoo);
    }
    free_distribution_matches(&drawn, Some(STATE_WORDS), None);
}

/// A word wished "anywhere": every phrase holds it, at every position alike, and the other words
/// are uniform. Its own bits are not balanced, by design: the phrase must hold it somewhere.
fn anywhere_positions_are_uniform(drawn: &Drawn, chosen: u16) {
    let mut positions = vec![0usize; STATE_WORDS];
    for words in &drawn.phrases {
        let found: Vec<usize> = (0..STATE_WORDS).filter(|&at| words[at] == chosen).collect();
        assert!(!found.is_empty(), "a phrase without the word");
        if let [only] = found[..] {
            positions[only] += 1;
        }
    }
    let chi = chi_square(&positions, STATE_WORDS);
    assert!(
        chi < chi_square_bound(STATE_WORDS),
        "chi-square {chi} over the positions"
    );
}

fn anywhere_other_words_are_uniform(drawn: &Drawn, chosen: u16, left_out: Option<u16>) {
    let forbidden: Vec<u16> = std::iter::once(chosen).chain(left_out).collect();
    let mut pooled = vec![0usize; WORDS];
    // The last word's checksum is derived, so it is not used for word-marginal comparisons.
    for position in 0..STATE_WORDS - 1 {
        let mut counts = vec![0usize; WORDS];
        for words in &drawn.phrases {
            let word = words[position];
            if word != chosen {
                counts[usize::from(word)] += 1;
            }
        }
        word_counts_are_uniform(
            &counts,
            &forbidden,
            &format!("other word position {}", position + 1),
        );
        for (pooled, count) in pooled.iter_mut().zip(counts) {
            *pooled += count;
        }
    }
    word_counts_are_uniform(&pooled, &forbidden, "pooled other words");
}

/// Rejection conditions on at least one occurrence. Random-position insertion size-biases the
/// number of occurrences, despite producing uniform singleton positions and other-word marginals.
fn anywhere_multiplicity_matches(drawn: &Drawn, chosen: u16, allowed: usize) {
    let probability = 1.0 / allowed as f64;
    let absent = (1.0 - probability).powi(STATE_WORDS as i32);
    let singleton =
        STATE_WORDS as f64 * probability * (1.0 - probability).powi((STATE_WORDS - 1) as i32);
    let expected = 1.0 - singleton / (1.0 - absent);
    let repeated = drawn
        .phrases
        .iter()
        .filter(|words| words.iter().filter(|&&word| word == chosen).count() > 1)
        .count();
    share_matches_probability(
        repeated,
        drawn.phrases.len(),
        expected,
        "repeated anywhere word",
    );
}

fn anywhere_matches(drawn: &Drawn, chosen: u16, left_out: Option<u16>) {
    if let Some(word) = left_out {
        assert!(drawn.phrases.iter().all(|words| !words.contains(&word)));
    }
    anywhere_positions_are_uniform(drawn, chosen);
    anywhere_other_words_are_uniform(drawn, chosen, left_out);
    anywhere_multiplicity_matches(drawn, chosen, WORDS - usize::from(left_out.is_some()));
}

#[test]
fn a_word_anywhere_is_at_every_position_alike() {
    let drawn = draw(&[(Place::Anywhere, "zoo")], &[], 3);
    anywhere_matches(&drawn, phrase::word_number("zoo").unwrap(), None);
}

#[test]
fn a_word_never_to_use_alone_leaves_the_allowed_words_random() {
    let abandon = phrase::word_number("abandon").unwrap();
    let drawn = draw(&[], &["abandon"], 4);
    assert!(drawn.phrases.iter().all(|words| !words.contains(&abandon)));
    free_distribution_matches(&drawn, None, Some(abandon));
}

#[test]
fn a_word_anywhere_and_a_word_never_to_use_keep_the_conditioned_distribution() {
    let drawn = draw(&[(Place::Anywhere, "zoo")], &["abandon"], 5);
    anywhere_matches(
        &drawn,
        phrase::word_number("zoo").unwrap(),
        Some(phrase::word_number("abandon").unwrap()),
    );
}

fn rejects_fault(action: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(
        std::panic::catch_unwind(action).is_err(),
        "a deliberately faulty sample passed"
    );
}

#[test]
fn statistical_controls_refuse_clobbered_excluded_patterned_and_correlated_samples() {
    let drawn = draw(&[], &[], 6);
    let free = free_positions(None);
    // All controls first accept unmodified data from the production draw.
    free_distribution_matches(&drawn, None, None);

    // Clearing the first byte's highest bit models a neighboring-field mask clobber.
    let clobbered = drawn.changed(|entropy| entropy[0] &= 0x7f);
    rejects_fault(|| free_bits_are_balanced(&clobbered, 0..0, None));

    let forbidden = WordWishes::new(&[(Place::At(1), "abandon")], &[]).unwrap();
    let forbidden = drawn.changed(|entropy| forbidden.apply(entropy));
    rejects_fault(|| free_words_are_uniform(&forbidden, &free, Some(0)));

    let mut next = 1u64;
    let patterned = drawn.changed(|entropy| {
        entropy.fill(0);
        let counter = next.to_be_bytes();
        entropy[STATE_BYTES - counter.len()..].copy_from_slice(&counter);
        next += 1;
    });
    rejects_fault(|| free_bits_are_balanced(&patterned, 0..0, None));
    let repeated = drawn.changed(|entropy| *entropy = drawn.entropies[0]);
    rejects_fault(|| repeats_are_as_frequent_as_chance(&repeated, WORDS));

    // Copy one free bit between words. Both marginals still look balanced; their joint is not.
    let correlated = drawn.changed(|entropy| {
        let first = bit(entropy, 0);
        phrase::write_bits(entropy, WORD_BITS, 1, u16::from(first));
    });
    free_bits_are_balanced(&correlated, 0..0, None);
    free_words_are_uniform(&correlated, &free, None);
    rejects_fault(|| free_bits_are_uncorrelated(&correlated, &free, None));
}

#[test]
fn per_position_controls_refuse_opposite_biases_that_pooling_hides() {
    let drawn = draw(&[], &[], 7);
    let biased = drawn.changed(|entropy| {
        // Opposite word-parity constraints preserve each bit marginal and cancel when pooled.
        for (position, odd) in [(0, false), (1, true)] {
            let bits = packing::with_checksum(entropy);
            let word = phrase::number_at(&bits, position);
            let desired = word ^ u16::from((word.count_ones() % 2 == 1) != odd);
            phrase::write_bits(entropy, position * WORD_BITS, WORD_BITS, desired);
        }
    });
    free_bits_are_balanced(&biased, 0..0, None);
    let mut pooled = vec![0usize; WORDS];
    for words in &biased.phrases {
        pooled[usize::from(words[0])] += 1;
        pooled[usize::from(words[1])] += 1;
    }
    word_counts_are_uniform(&pooled, &[], "opposite pooled biases");
    rejects_fault(|| free_words_are_uniform(&biased, &[1, 2], None));
}

#[test]
fn anywhere_controls_refuse_fixed_placement_and_random_position_insertion() {
    let zoo = phrase::word_number("zoo").unwrap();
    let fixed = draw(&[(Place::At(1), "zoo")], &[], 8);
    rejects_fault(|| anywhere_positions_are_uniform(&fixed, zoo));

    let mut random = SplitMix64(9);
    let mut inserted = Drawn::new();
    for _ in 0..DRAWS {
        let position = (random.next() % STATE_WORDS as u64) as usize + 1;
        let wishes = WordWishes::new(&[(Place::At(position), "zoo")], &[]).unwrap();
        let mut found = false;
        for _ in 0..MOST_DRAWS {
            let mut entropy = [0u8; STATE_BYTES];
            random.fill(&mut entropy);
            wishes.apply(&mut entropy);
            if wishes.met_by(&entropy) {
                inserted.push(entropy);
                found = true;
                break;
            }
        }
        assert!(
            found,
            "the faulty insertion fixture exhausted its draw bound"
        );
    }
    // The old two controls accept this realistic biased algorithm.
    anywhere_positions_are_uniform(&inserted, zoo);
    anywhere_other_words_are_uniform(&inserted, zoo, None);
    rejects_fault(|| anywhere_multiplicity_matches(&inserted, zoo, WORDS));
}
