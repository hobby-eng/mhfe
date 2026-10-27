//! A word a person chooses for a new 24-word phrase, at a chosen position or anywhere, and a word
//! never to use, with the random bits the phrase keeps. A program feature, not part of the
//! specification, and not recommended: a chosen word that someone learns or guesses tells the right
//! password and unmasks a decoy (README, "Chosen words").
//!
//! Every phrase that meets the wishes is equally likely. The 11 bits of a word at a fixed position
//! other than the last are pure entropy, so they are set directly; a fixed last word sets the
//! entropy bits it carries and accepts only a draw whose checksum gives its other bits. Everything
//! else is rejection sampling: another draw until the phrase fits. Setting the checksum bits
//! directly, or putting an "anywhere" word at a random position, would make some phrases more
//! likely than others. The rules are those of the multi-chain Deriver's generator, which takes its
//! 24-word phrases from here.
//!
//! The owner's limits (2026-10-08): one chosen word and one word never to use at most, for every
//! length of phrase, which keeps at least 228.98 random bits with the wallet check and 244.98
//! without (a word at a fixed position, the last one included, takes 11 bits, the word never to use
//! 23 x log2(2048 / 2047), the check 16); a phrase that keeps fewer than
//! [`RECOMMENDED_RANDOM_BITS`] is not recommended. The limits keep every wish quick to draw too: a
//! fixed last word takes about 256 draws, an "anywhere" word about 85.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::packing::{self, STATE_BYTES, STATE_WORDS};
use crate::phrase::{self, LIST_SIZE, WORD_BITS};
use crate::MhfeError;

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-wallet"))]
pub(crate) mod known_answers;

/// The most words a person may choose: one, for a phrase of any length (owner, 2026-10-08).
pub const MAX_CHOSEN_WORDS: usize = 1;
/// The most words a person may name never to use: one (owner, 2026-10-08).
pub const MAX_NEVER_USE_WORDS: usize = 1;
/// The words of a new phrase: a chosen word takes a position from 1 to this.
pub const PHRASE_WORDS: usize = STATE_WORDS;
/// The random bits a new phrase keeps with the wallet check alone, 256 - 16: still far more than
/// enough. Fewer, with a chosen word, are allowed but not recommended.
pub const RECOMMENDED_RANDOM_BITS: u32 = 240;

/// The entropy bits of a new phrase.
const ENTROPY_BITS: u32 = (STATE_BYTES * 8) as u32;
/// The checksum bits the last word of a 24-word phrase carries after its entropy bits.
const CHECKSUM_BITS: usize = packing::checksum_bits(STATE_WORDS);

/// Where a chosen word goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// At this position, from 1 to 24.
    At(usize),
    /// At any position.
    Anywhere,
}

/// How much of its randomness a new phrase keeps, as a front end tells the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Randomness {
    /// All 256 bits: no word chosen and no check.
    Full,
    /// At least [`RECOMMENDED_RANDOM_BITS`]: still far more than enough.
    Ample,
    /// Fewer than [`RECOMMENDED_RANDOM_BITS`]: allowed, not recommended.
    NotRecommended,
}

/// What a new phrase keeps with these wishes, before it is drawn.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WishOdds {
    /// The random bits it keeps, about.
    pub random_bits: f64,
    /// How that compares with the recommendation, as a front end says it.
    pub randomness: Randomness,
    /// The draws it is expected to take, the wallet check's included.
    pub expected_draws: f64,
    /// Whether a chosen word makes the phrase recognisable: someone who learns or guesses it can
    /// rule out almost every wrong MHFE password with it, before any BIP39 passphrase, and tell the
    /// wallet from a decoy, whose phrase is random (mhfe_spec review, 2026-10-08). The random bits
    /// do not count this. Words never to use alone filter too little to matter.
    pub recognisable: bool,
    /// Whether the chosen word has a fixed position, where it costs more than anywhere.
    pub fixed_position: bool,
}

/// The words a person wishes for in a new 24-word phrase, checked: valid English BIP39 words, at
/// most [`MAX_CHOSEN_WORDS`] chosen and [`MAX_NEVER_USE_WORDS`] never to use, none of them both.
/// The words themselves are never named in a refusal or in `Debug`, and their numbers are wiped
/// when the wishes are dropped: they are part of a secret phrase (AUD-014-SEC002).
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct WordWishes {
    /// Word numbers by position from 0, for words at a fixed position.
    fixed: Vec<(usize, u16)>,
    anywhere: Vec<u16>,
    never_use: Vec<u16>,
}

impl std::fmt::Debug for WordWishes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WordWishes { .. }")
    }
}

impl WordWishes {
    /// No wishes: every phrase is welcome.
    pub fn none() -> Self {
        Self::default()
    }

    /// The wishes `chosen`, each a word typed as a person writes it (any letter case, four
    /// letters of a word enough) with its place, and `never_use`, words the phrase must not hold.
    pub fn new(chosen: &[(Place, &str)], never_use: &[&str]) -> Result<Self, MhfeError> {
        if chosen.len() > MAX_CHOSEN_WORDS {
            return Err(wish(format!(
                "choose at most {}",
                words_text(MAX_CHOSEN_WORDS)
            )));
        }
        if never_use.len() > MAX_NEVER_USE_WORDS {
            return Err(wish(format!(
                "name at most {} never to use",
                words_text(MAX_NEVER_USE_WORDS)
            )));
        }
        let mut wishes = Self::none();
        for typed in never_use {
            wishes
                .never_use
                .push(number_of(typed, "the word never to use")?);
        }
        for (index, &(place, typed)) in chosen.iter().enumerate() {
            let label = if MAX_CHOSEN_WORDS == 1 {
                "the chosen word".to_owned()
            } else {
                format!("chosen word {}", index + 1)
            };
            let number = number_of(typed, &label)?;
            if wishes.never_use.contains(&number) {
                return Err(wish(format!("{label} is also a word never to use")));
            }
            match place {
                Place::Anywhere => wishes.anywhere.push(number),
                Place::At(position) if !(1..=STATE_WORDS).contains(&position) => {
                    return Err(wish(format!(
                        "{label} needs a position from 1 to {STATE_WORDS}"
                    )));
                }
                Place::At(position) => wishes.fixed.push((position - 1, number)),
            }
        }
        Ok(wishes)
    }

    /// Whether there is no wish at all.
    pub fn is_empty(&self) -> bool {
        self.fixed.is_empty() && self.anywhere.is_empty() && self.never_use.is_empty()
    }

    fn chosen_numbers(&self) -> impl Iterator<Item = u16> + '_ {
        self.fixed
            .iter()
            .map(|&(_, number)| number)
            .chain(self.anywhere.iter().copied())
    }

    /// What a phrase drawn with these wishes keeps, `check_bits` taken by a check of the drawn
    /// phrase: 16 with the wallet check, 0 without. The free positions are counted as independent
    /// uniform words, which is exact for all but the last and very close for it.
    pub fn odds(&self, check_bits: u32) -> WishOdds {
        let free = (STATE_WORDS - self.fixed.len()) as i32;
        let list = f64::from(LIST_SIZE);
        // Inclusion and exclusion over the "anywhere" words: every free word is one of `allowed`,
        // and each "anywhere" word appears at least once.
        let free_odds_of = |allowed: f64| {
            let avoid = |missing: f64| ((allowed - missing) / list).powi(free);
            match self.anywhere.len() {
                0 => avoid(0.0),
                _ => avoid(0.0) - avoid(1.0),
            }
        };
        let free_odds = free_odds_of(list - self.never_use.len() as f64);
        let fixed_bits = (WORD_BITS * self.fixed.len()) as f64;
        let bits_with = |free_odds: f64| {
            f64::from(ENTROPY_BITS) - fixed_bits + free_odds.log2() - f64::from(check_bits)
        };
        let random_bits = bits_with(free_odds);
        // Rated by the chosen word and the check alone: a word never to use costs about 0.016
        // bits, which must not turn the wallet check's 240 bits into "not recommended"
        // (AUD-015-UI003).
        let rated_bits = bits_with(free_odds_of(list));
        // A fixed last word sets only its entropy bits; its checksum bits must also come out.
        let checksum_odds = if self.fixes_last_word() {
            1.0 / f64::from(1u32 << CHECKSUM_BITS)
        } else {
            1.0
        };
        let wish_draws = 1.0 / (free_odds * checksum_odds);
        let randomness = if self.is_empty() && check_bits == 0 {
            Randomness::Full
        } else if rated_bits >= f64::from(RECOMMENDED_RANDOM_BITS) {
            Randomness::Ample
        } else {
            Randomness::NotRecommended
        };
        WishOdds {
            random_bits,
            randomness,
            expected_draws: wish_draws * 2f64.powi(check_bits as i32),
            recognisable: self.chosen_numbers().next().is_some(),
            fixed_position: !self.fixed.is_empty(),
        }
    }

    fn fixes_last_word(&self) -> bool {
        self.fixed.iter().any(|&(at, _)| at == STATE_WORDS - 1)
    }

    /// Sets the bits of the words at fixed positions in a drawn `entropy`: all 11 of a word but
    /// the last, and of the last only its entropy bits, as its checksum bits come from the hash.
    pub(crate) fn apply(&self, entropy: &mut [u8; STATE_BYTES]) {
        for &(at, number) in &self.fixed {
            if at < STATE_WORDS - 1 {
                phrase::write_bits(entropy, at * WORD_BITS, WORD_BITS, number);
            } else {
                let entropy_bits = WORD_BITS - CHECKSUM_BITS;
                phrase::write_bits(
                    entropy,
                    at * WORD_BITS,
                    entropy_bits,
                    number >> CHECKSUM_BITS,
                );
            }
        }
    }

    /// Whether the phrase of `entropy` meets the wishes: its last word as chosen, no word never
    /// to use, and every "anywhere" word in it. The words are read one at a time from bits that are
    /// wiped when done, as they make up the phrase (AUD-014-SEC002).
    pub(crate) fn met_by(&self, entropy: &[u8; STATE_BYTES]) -> bool {
        if self.is_empty() {
            return true;
        }
        let bits = Zeroizing::new(packing::with_checksum(entropy));
        let word_at = |index| phrase::number_at(&bits[..], index);
        self.fixed.iter().all(|&(at, number)| word_at(at) == number)
            && (0..STATE_WORDS).all(|index| !self.never_use.contains(&word_at(index)))
            && self
                .anywhere
                .iter()
                .all(|&number| (0..STATE_WORDS).any(|index| word_at(index) == number))
    }
}

/// The number of a word as typed, `label` naming it in a refusal.
fn number_of(typed: &str, label: &str) -> Result<u16, MhfeError> {
    // The lower-case copy of a chosen word is part of a secret phrase: wiped when done.
    let lower = Zeroizing::new(typed.trim().to_lowercase());
    phrase::complete_word(&lower)
        .and_then(phrase::word_number)
        // The word itself is not repeated: it is about to become part of a secret phrase.
        .ok_or_else(|| wish(format!("{label} is not an English BIP39 word")))
}

fn wish(reason: String) -> MhfeError {
    MhfeError::InvalidWordWish(reason)
}

/// "1 word" or "2 words".
fn words_text(count: usize) -> String {
    let words = if count == 1 { "word" } else { "words" };
    format!("{count} {words}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_check::PhraseDraw;

    /// Public edge bytes exercise both setting and clearing, with different neighboring bits.
    const EDGE_ENTROPIES: [[u8; STATE_BYTES]; 8] = [
        [0; STATE_BYTES],
        [0xff; STATE_BYTES],
        [0xaa; STATE_BYTES],
        [0x55; STATE_BYTES],
        [0x80; STATE_BYTES],
        [0x01; STATE_BYTES],
        counting_entropy(false),
        counting_entropy(true),
    ];

    const fn counting_entropy(reverse: bool) -> [u8; STATE_BYTES] {
        let mut bytes = [0; STATE_BYTES];
        let mut index = 0;
        while index < STATE_BYTES {
            bytes[index] = if reverse {
                u8::MAX - index as u8
            } else {
                index as u8
            };
            index += 1;
        }
        bytes
    }

    fn bit_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:08b}")).collect()
    }

    fn bytes_of_bits<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 8);
        let mut bytes = [0; N];
        for (byte, octet) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<8>().0) {
            *byte = u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 2).unwrap();
        }
        bytes
    }

    // Deliberately independent audit oracle: replace a substring of binary text rather than
    // repeating write_bits' byte masks. The widths are the published BIP39 11 and final 3+8.
    fn expected_fixed_word(
        before: &[u8; STATE_BYTES],
        position: usize,
        number: u16,
    ) -> [u8; STATE_BYTES] {
        let mut text = bit_string(before);
        let start = (position - 1) * 11;
        let end = (start + 11).min(256);
        let word = format!("{number:011b}");
        text.replace_range(start..end, &word[..end - start]);
        bytes_of_bits(&text)
    }

    fn at(position: usize, word: &'static str) -> (Place, &'static str) {
        (Place::At(position), word)
    }

    #[test]
    fn the_owner_limits_keep_their_bits() {
        // The worst case: a word at a fixed position, a word never to use and the wallet check,
        // 256 - 11 - 23 x log2(2048 / 2047) - 16 = 228.98 bits, allowed but not recommended.
        let worst = WordWishes::new(&[at(1, "happy")], &["abandon"]).unwrap();
        let odds = worst.odds(16);
        assert!((228.98..228.99).contains(&odds.random_bits), "{odds:?}");
        assert_eq!(odds.randomness, Randomness::NotRecommended);
        // Without the check 244.98: ample. The check alone keeps 240, nothing at all 256.
        assert!((244.98..244.99).contains(&worst.odds(0).random_bits));
        assert_eq!(worst.odds(0).randomness, Randomness::Ample);
        assert_eq!(WordWishes::none().odds(16).randomness, Randomness::Ample);
        assert_eq!(WordWishes::none().odds(16).random_bits, 240.0);
        assert_eq!(WordWishes::none().odds(0).randomness, Randomness::Full);
        // A word anywhere instead keeps 233.56 with the check and 249.56 without.
        let anywhere = WordWishes::new(&[(Place::Anywhere, "happy")], &["abandon"]).unwrap();
        assert!((233.55..233.57).contains(&anywhere.odds(16).random_bits));
        assert!((249.55..249.57).contains(&anywhere.odds(0).random_bits));
        assert!(worst.odds(16).fixed_position && !anywhere.odds(16).fixed_position);
    }

    /// A word never to use costs about 0.016 bits, which the rating leaves out: with the wallet
    /// check it is as recommended as the check alone, though the bits it keeps are told exactly
    /// (AUD-015-UI003).
    #[test]
    fn a_word_never_to_use_does_not_change_the_rating() {
        let never = WordWishes::new(&[], &["abandon"]).unwrap();
        let checked = never.odds(16);
        assert!(
            (239.98..239.99).contains(&checked.random_bits),
            "{checked:?}"
        );
        assert_eq!(checked.randomness, Randomness::Ample);
        assert!(!checked.fixed_position && !checked.recognisable);
        assert_eq!(never.odds(0).randomness, Randomness::Ample);
    }

    /// The wishes name no word in `Debug` and are wiped by `zeroize`, as on drop
    /// (AUD-014-SEC002).
    #[test]
    fn wishes_tell_no_word_and_are_wiped() {
        let mut wishes = WordWishes::new(&[at(3, "happy")], &["abandon"]).unwrap();
        assert_eq!(format!("{wishes:?}"), "WordWishes { .. }");
        wishes.zeroize();
        assert!(wishes.is_empty());
    }

    #[test]
    fn chosen_words_make_a_phrase_recognisable() {
        assert!(!WordWishes::none().odds(16).recognisable);
        let never = WordWishes::new(&[], &["abandon"]).unwrap();
        assert!(!never.odds(0).recognisable);
        let fixed = WordWishes::new(&[at(3, "happy")], &[]).unwrap();
        assert!(fixed.odds(0).recognisable);
        let anywhere = WordWishes::new(&[(Place::Anywhere, "happy")], &[]).unwrap();
        assert!(anywhere.odds(16).recognisable);
    }

    #[test]
    fn every_wish_is_quick_to_draw() {
        // A fixed last word: its 8 checksum bits must come out of the hash, 256 draws.
        let last = WordWishes::new(&[at(24, "zoo")], &[]).unwrap();
        assert_eq!(last.odds(0).expected_draws, 256.0);
        assert_eq!(last.odds(0).random_bits, 245.0);
        // A word anywhere: about 85 draws; with a word never to use a little more.
        let anywhere = WordWishes::new(&[(Place::Anywhere, "happy")], &["abandon"]).unwrap();
        let odds = anywhere.odds(0);
        assert!((80.0..90.0).contains(&odds.expected_draws), "{odds:?}");
        // The wallet check multiplies them by 65,536.
        assert_eq!(last.odds(16).expected_draws, 256.0 * 65_536.0);
    }

    #[test]
    fn wrong_wishes_are_refused_without_naming_the_words() {
        let refused = |chosen: &[(Place, &str)], never: &[&str]| {
            WordWishes::new(chosen, never).unwrap_err().to_string()
        };
        assert_eq!(
            refused(&[at(1, "happy"), at(2, "zoo")], &[]),
            "the wishes for the new phrase cannot be used: choose at most 1 word"
        );
        assert_eq!(
            refused(&[], &["abandon", "zoo"]),
            "the wishes for the new phrase cannot be used: name at most 1 word never to use"
        );
        assert_eq!(
            refused(&[], &["notaword"]),
            "the wishes for the new phrase cannot be used: the word never to use is not an English \
             BIP39 word"
        );
        assert_eq!(
            refused(&[at(1, "notaword")], &[]),
            "the wishes for the new phrase cannot be used: the chosen word is not an English BIP39 word"
        );
        assert_eq!(
            refused(&[at(25, "happy")], &[]),
            "the wishes for the new phrase cannot be used: the chosen word needs a position from 1 to 24"
        );
        assert_eq!(
            refused(&[at(2, "happ")], &["happy"]),
            "the wishes for the new phrase cannot be used: the chosen word is also a word never to use"
        );
        // Four letters of a word are enough, in any case.
        assert!(WordWishes::new(&[at(2, "HAPP")], &[]).is_ok());
    }

    #[test]
    fn fixed_words_are_set_and_met() {
        let first = WordWishes::new(&[at(1, "happy")], &["abandon"]).unwrap();
        let mut entropy = [0x5a; STATE_BYTES];
        first.apply(&mut entropy);
        let bits = packing::with_checksum(&entropy);
        assert_eq!(phrase::word(phrase::number_at(&bits, 0)), "happy");
        let has_abandon = (0..STATE_WORDS).any(|index| phrase::number_at(&bits, index) == 0);
        assert_eq!(first.met_by(&entropy), !has_abandon);
        // The last word's entropy bits are zoo's; its checksum bits come from the hash.
        let wishes = WordWishes::new(&[at(24, "zoo")], &[]).unwrap();
        wishes.apply(&mut entropy);
        let bits = packing::with_checksum(&entropy);
        let zoo = phrase::word_number("zoo").unwrap();
        assert_eq!(
            phrase::number_at(&bits, 23) >> CHECKSUM_BITS,
            zoo >> CHECKSUM_BITS
        );
        assert_eq!(wishes.met_by(&entropy), phrase::number_at(&bits, 23) == zoo);
        assert!(WordWishes::none().met_by(&entropy));
    }

    #[test]
    fn every_fixed_word_index_preserves_every_neighboring_entropy_bit() {
        assert_eq!(
            (STATE_BYTES, STATE_WORDS, WORD_BITS, CHECKSUM_BITS),
            (32, 24, 11, 8)
        );
        for position in 1..=STATE_WORDS {
            for number in 0..LIST_SIZE {
                let wishes =
                    WordWishes::new(&[(Place::At(position), phrase::word(number))], &[]).unwrap();
                for before in EDGE_ENTROPIES {
                    let expected = expected_fixed_word(&before, position, number);
                    let mut after = before;
                    wishes.apply(&mut after);
                    assert_eq!(after, expected, "position {position}, index {number}");
                }
            }
        }
    }

    #[test]
    fn every_word_index_is_read_msb_first_at_every_byte_boundary() {
        for position in 1..=STATE_WORDS {
            for number in 0..LIST_SIZE {
                for entropy in EDGE_ENTROPIES {
                    let mut before = [entropy[0]; STATE_BYTES + 1];
                    before[..STATE_BYTES].copy_from_slice(&entropy);
                    let mut text = bit_string(&before);
                    let start = (position - 1) * 11;
                    text.replace_range(start..start + 11, &format!("{number:011b}"));
                    before = bytes_of_bits(&text);
                    assert_eq!(
                        phrase::number_at(&before, position - 1),
                        number,
                        "position {position}, index {number}"
                    );
                }
            }
        }
    }

    #[test]
    fn wishes_filter_checksum_exclusions_and_repeated_anywhere_words() {
        let zero = [0; STATE_BYTES];
        // Published BIP39 zero-entropy vector: 23 abandon words, then art (index 102).
        let last = WordWishes::new(&[at(STATE_WORDS, "art")], &[]).unwrap();
        assert!(last.met_by(&zero));
        assert!(!WordWishes::new(&[at(STATE_WORDS, "abandon")], &[])
            .unwrap()
            .met_by(&zero));
        assert!(!WordWishes::new(&[], &["art"]).unwrap().met_by(&zero));
        assert!(!WordWishes::new(&[], &["abandon"]).unwrap().met_by(&zero));
        assert!(WordWishes::new(&[], &["zoo"]).unwrap().met_by(&zero));
        assert!(WordWishes::new(&[(Place::Anywhere, "abandon")], &[])
            .unwrap()
            .met_by(&zero));
        assert!(!WordWishes::new(&[(Place::Anywhere, "zoo")], &[])
            .unwrap()
            .met_by(&zero));
        let anywhere = WordWishes::new(&[(Place::Anywhere, "zoo")], &[]).unwrap();
        let zoo = phrase::word_number("zoo").unwrap();
        for count in [2, 3] {
            let mut entropy = [0x5a; STATE_BYTES];
            for position in 1..=count {
                entropy = expected_fixed_word(&entropy, position, zoo);
            }
            assert!(anywhere.met_by(&entropy));
        }
    }

    #[test]
    fn positions_zero_and_usize_max_are_refused_before_bit_slicing() {
        for position in [0, usize::MAX] {
            assert!(matches!(
                WordWishes::new(&[at(position, "happy")], &[]),
                Err(MhfeError::InvalidWordWish(_))
            ));
        }
    }

    // The statistical tests, for faults that remove randomness from the chosen-word draw (owner,
    // 2026-10-08, through the mhfe_spec review). A bug that silently removed randomness would still
    // give valid BIP39 phrases, since the checksum is computed from whatever entropy results, while
    // the screen kept stating the same bits: bx's seed command (CVE-2023-39910, "Milk Sad") and
    // Trust Wallet's browser extension (CVE-2023-31290) made valid phrases from weak entropy in
    // this way.
    //
    // Setting a word must change that word's bits and no other, and the phrases drawn with wishes
    // must look like random phrases everywhere the wishes leave free: each free entropy bit set
    // half the time (adjusted for an excluded word), the free words uniform at each position, words
    // repeated as often as chance repeats them, and a word wished "anywhere" at every position
    // alike. Correlation checks and deliberately faulty samples test the controls themselves. The
    // fixed-seed generator makes these repeatable regression tests, not a proof of entropy or
    // cryptographic RNG quality. Bounds apply to each comparison, not to the whole suite: five
    // binomial standard deviations or a conservative chi-square-model tail bound. Pearson
    // statistics use a multinomial approximation; the checksum word is treated as uniform only
    // where SHA-256's random-looking output justifies it.

    /// Phrases drawn for each set of wishes.
    const DRAWS: usize = 20_000;
    /// The bits of a new phrase's entropy, as a `usize` for indexing: it hides the module's `u32`
    /// constant of the same value.
    const ENTROPY_BITS: usize = STATE_BYTES * 8;
    /// The words in the list, as a count.
    const WORDS: usize = LIST_SIZE as usize;
    /// A per-comparison chi-square-model upper-tail bound, not a family-wide false-positive rate.
    const CHI_SQUARE_TAIL: f64 = 1e-6;
    /// A wide binomial regression tolerance; the fixed seeds make the verdict reproducible.
    const STANDARD_DEVIATIONS: f64 = 5.0;
    /// Thirty expected fixed-last-word searches make an exhausted search exceptionally unlikely.
    const MOST_DRAWS: u64 = 30 * (1 << CHECKSUM_BITS);

    /// SplitMix64 (Steele, Lea and Flood, 2014): a small generator of good statistical quality,
    /// with a fixed seed so that every run draws the same phrases. Never used for a real phrase.
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

    /// Whether bit `index` of `bytes` is set, counting from the first byte's highest bit as BIP39
    /// does.
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
                        WordWishes::new(&[(Place::At(position), phrase::word(number))], &[])
                            .unwrap();
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

    /// Adjacent bits within each free full word, and equal-offset bits across neighboring free
    /// words. These joint checks catch copied or correlated bits whose separate marginals remain
    /// balanced.
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

    /// The birthday probability for 24 words, also valid with one of them fixed, under the
    /// independent allowed-word model. A generator that avoids or favors repeats would differ.
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

    /// A word wished "anywhere": every phrase holds it, at every position alike, and the other
    /// words are uniform. Its own bits are not balanced, by design: the phrase must hold it
    /// somewhere.
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
    /// number of occurrences, despite producing uniform singleton positions and other-word
    /// marginals.
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
}
