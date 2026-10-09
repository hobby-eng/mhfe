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
#[cfg(test)]
mod statistics;

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
}
