//! Repair words for a container plate: the optional profile MHFE-REPAIR-1 of the specification
//! (README, "Optional repair words"), outside suites 3 and 4.
//!
//! A plate can rust, be scratched or be copied with a wrong word. A few extra English BIP39 words,
//! kept on a card apart from the plate, let any program repair it without the password and without
//! Argon2. They are the parity of a Reed–Solomon code over the container's words: the BIP39 list
//! has 2,048 words, exactly the elements of GF(2^11), so each word is a field element and each
//! repair word is a word of the same list.
//!
//! The code, byte for byte:
//!
//! - the field GF(2^11) with the primitive polynomial x^11 + x^2 + 1, and alpha = x;
//! - the data: the container's word numbers d_0 to d_(n-1) in the list, the first word first, as
//!   the coefficients of m(x) from x^(n-1) down to x^0;
//! - k repair words, 2, 4, 6 or 8: the remainder r(x) of m(x) * x^k divided by
//!   g(x) = (x + alpha) (x + alpha^2) ... (x + alpha^k), its coefficients from x^(k-1) down to x^0.
//!
//! The words of the plate followed by the repair words are then a codeword: they vanish at alpha to
//! alpha^k. Any 2e + s <= k damaged words are repaired, e of them wrong at unknown places and s of
//! them unreadable, marked as such; a wrong or unreadable repair word counts the same. More damage
//! may be repaired wrongly; the repaired container must then still pass its BIP39 checksum.
//!
//! The card holds nothing secret beyond what the plate holds: with the plate, it adds nothing; on
//! its own it gives k of the plate's word values in mixed form. But a container is what a guesser
//! of passwords needs, and the card repairs a damaged or partial copy of the plate for whoever has
//! both, as it does for the owner. It belongs apart from the plate, so that one accident or one
//! thief does not take both, and is guarded like the plate.

use bip39::{Language, Mnemonic};

use crate::phrase::{self, WORD_COUNTS};
use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-repair"
))]
pub(crate) mod known_answers;

/// The numbers of repair words a card can have: each repairs one unreadable word, and two repair
/// one wrong word.
pub const REPAIR_WORD_COUNTS: [usize; 4] = [2, 4, 6, 8];
/// Four repair words repair four unreadable words or two wrong ones: enough for the usual damage
/// of a plate at a card of four words.
pub const RECOMMENDED_REPAIR_WORDS: usize = 4;

/// What a card of `count` repair words repairs: as many unreadable words, or half as many wrong
/// ones.
pub fn capacity(count: usize) -> (usize, usize) {
    (count, count / 2)
}

/// Elements of GF(2^11): 2,048, as many as the words of the BIP39 list.
const FIELD_SIZE: usize = 2048;
/// The order of the multiplicative group, 2^11 - 1.
const ORDER: usize = FIELD_SIZE - 1;
/// x^11 + x^2 + 1, a primitive polynomial of degree 11.
const POLYNOMIAL: usize = 0x805;

/// GF(2^11) by its tables of powers and logarithms of alpha.
struct Field {
    /// alpha^i for i from 0 to 2 * ORDER - 1, so that a sum of two logarithms needs no reduction.
    exp: Vec<u16>,
    /// The logarithm of each nonzero element; log[0] is unused.
    log: Vec<u16>,
}

impl Field {
    fn new() -> Self {
        let mut exp = vec![0u16; 2 * ORDER];
        let mut log = vec![0u16; FIELD_SIZE];
        let mut value = 1usize;
        let (powers, repeated) = exp.split_at_mut(ORDER);
        for (power, slot) in powers.iter_mut().enumerate() {
            *slot = value as u16;
            log[value] = power as u16;
            value <<= 1;
            if value & FIELD_SIZE != 0 {
                value ^= POLYNOMIAL;
            }
        }
        repeated.copy_from_slice(powers);
        Self { exp, log }
    }

    fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)])]
    }

    fn div(&self, a: u16, b: u16) -> u16 {
        assert!(b != 0, "division by zero in GF(2^11)");
        if a == 0 {
            return 0;
        }
        let power =
            usize::from(self.log[usize::from(a)]) + ORDER - usize::from(self.log[usize::from(b)]);
        self.exp[power]
    }

    /// alpha^power.
    fn alpha(&self, power: usize) -> u16 {
        self.exp[power % ORDER]
    }

    /// The value at `x` of the polynomial with `coefficients`, the highest degree first.
    fn eval(&self, coefficients: &[u16], x: u16) -> u16 {
        coefficients
            .iter()
            .fold(0, |sum, &coefficient| self.mul(sum, x) ^ coefficient)
    }

    /// g(x) = (x + alpha)(x + alpha^2)...(x + alpha^k), the highest degree first.
    fn generator(&self, k: usize) -> Vec<u16> {
        let mut g = vec![1u16];
        for power in 1..=k {
            let root = self.alpha(power);
            let mut next = vec![0u16; g.len() + 1];
            for (i, &coefficient) in g.iter().enumerate() {
                next[i] ^= coefficient;
                next[i + 1] ^= self.mul(coefficient, root);
            }
            g = next;
        }
        g
    }

    /// The k parity symbols of `data`: the remainder of m(x) * x^k by g(x), highest degree first.
    fn parity(&self, data: &[u16], k: usize) -> Vec<u16> {
        let g = self.generator(k);
        let mut remainder = vec![0u16; k];
        for &symbol in data {
            let feedback = symbol ^ remainder[0];
            for i in 0..k - 1 {
                remainder[i] = remainder[i + 1] ^ self.mul(feedback, g[i + 1]);
            }
            remainder[k - 1] = self.mul(feedback, g[k]);
        }
        remainder
    }

    /// S_j = c(alpha^j) for j from 1 to k; all zero for a codeword.
    fn syndromes(&self, codeword: &[u16], k: usize) -> Vec<u16> {
        (1..=k)
            .map(|power| self.eval(codeword, self.alpha(power)))
            .collect()
    }

    /// Corrects `received` when every damaged symbol is among `positions` and there are at most k
    /// of them (erasure decoding, Forney's formula); `None` when no codeword results.
    fn correct_at(&self, received: &[u16], positions: &[usize], k: usize) -> Option<Vec<u16>> {
        let n = received.len();
        let syndromes = self.syndromes(received, k);
        let mut corrected = received.to_vec();
        if syndromes.iter().all(|&syndrome| syndrome == 0) {
            return Some(corrected);
        }
        // The locator of a position: alpha to the power of the degree of its term.
        let locators: Vec<u16> = positions.iter().map(|&i| self.alpha(n - 1 - i)).collect();
        // Gamma(x) = prod (1 + X_i x), and Omega(x) = S(x) Gamma(x) mod x^k with
        // S(x) = S_1 + S_2 x + ... + S_k x^(k-1); both lowest degree first.
        let mut gamma = vec![1u16];
        for &locator in &locators {
            let mut next = vec![0u16; gamma.len() + 1];
            for (i, &coefficient) in gamma.iter().enumerate() {
                next[i] ^= coefficient;
                next[i + 1] ^= self.mul(coefficient, locator);
            }
            gamma = next;
        }
        let mut omega = vec![0u16; k];
        for (i, &syndrome) in syndromes.iter().enumerate() {
            for (j, &coefficient) in gamma.iter().enumerate() {
                if i + j < k {
                    omega[i + j] ^= self.mul(syndrome, coefficient);
                }
            }
        }
        let low_first = |coefficients: &[u16], x: u16| {
            coefficients
                .iter()
                .rev()
                .fold(0, |sum, &coefficient| self.mul(sum, x) ^ coefficient)
        };
        // Gamma'(x): in characteristic 2 only the odd powers survive the derivative.
        let derivative: Vec<u16> = gamma
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, &coefficient)| if i % 2 == 1 { coefficient } else { 0 })
            .collect();
        for (&position, &locator) in positions.iter().zip(&locators) {
            let inverse = self.div(1, locator);
            let denominator = low_first(&derivative, inverse);
            if denominator == 0 {
                return None;
            }
            // Forney with the first root alpha^1: e = Omega(X^-1) / Gamma'(X^-1).
            corrected[position] ^= self.div(low_first(&omega, inverse), denominator);
        }
        self.syndromes(&corrected, k)
            .iter()
            .all(|&syndrome| syndrome == 0)
            .then_some(corrected)
    }

    /// Repairs `received`, whose `unreadable` positions are known, by trying every set of e wrong
    /// positions with 2e + s <= k, fewest first. The first codeword found is the only one within
    /// that distance, as the code's minimum distance is k + 1. A codeword has at most 32 symbols
    /// and k is at most 8, so trying the sets takes milliseconds.
    fn repair(&self, received: &[u16], unreadable: &[usize], k: usize) -> Option<Vec<u16>> {
        if unreadable.len() > k {
            return None;
        }
        let readable: Vec<usize> = (0..received.len())
            .filter(|position| !unreadable.contains(position))
            .collect();
        for wrong in 0..=(k - unreadable.len()) / 2 {
            let mut found = None;
            for_each_subset(&readable, wrong, &mut |chosen| {
                if found.is_none() {
                    let positions: Vec<usize> = unreadable.iter().chain(chosen).copied().collect();
                    found = self.correct_at(received, &positions, k);
                }
            });
            if found.is_some() {
                return found;
            }
        }
        None
    }
}

/// Calls `visit` with every subset of `items` that has `size` elements.
fn for_each_subset(items: &[usize], size: usize, visit: &mut dyn FnMut(&[usize])) {
    fn walk(
        items: &[usize],
        size: usize,
        start: usize,
        chosen: &mut Vec<usize>,
        visit: &mut dyn FnMut(&[usize]),
    ) {
        if chosen.len() == size {
            visit(chosen);
            return;
        }
        for i in start..items.len() {
            chosen.push(items[i]);
            walk(items, size, i + 1, chosen, visit);
            chosen.pop();
        }
    }
    walk(items, size, 0, &mut Vec::with_capacity(size), visit);
}

/// The repair words of `container`, a valid container of 12 to 24 words: `count` English BIP39
/// words, one space apart.
pub fn repair_words(container: &str, count: usize) -> Result<String, MhfeError> {
    if !REPAIR_WORD_COUNTS.contains(&count) {
        return Err(MhfeError::InvalidRepairWords(format!(
            "a card has 2, 4, 6 or 8 repair words, not {count}"
        )));
    }
    let mnemonic = phrase::parse_container(container).map_err(MhfeError::InvalidContainer)?;
    let data: Vec<u16> = mnemonic
        .words()
        .map(|word| word_number(word).expect("a parsed word is in the list"))
        .collect();
    let field = Field::new();
    let parity = field.parity(&data, count);
    check_card(&field, &data, &parity)?;
    Ok(words_of(&parity))
}

/// Reads a new card back before it is given out: the plate and its repair words must form a
/// codeword, and the card must restore the plate's first words when they are unreadable, as many
/// as it has words. A fault in the field's tables or in the division would otherwise give a card
/// that repairs nothing, which nobody notices until the plate is damaged.
fn check_card(field: &Field, data: &[u16], parity: &[u16]) -> Result<(), MhfeError> {
    let count = parity.len();
    let codeword: Vec<u16> = data.iter().chain(parity).copied().collect();
    let is_codeword = field
        .syndromes(&codeword, count)
        .iter()
        .all(|&syndrome| syndrome == 0);
    let unreadable: Vec<usize> = (0..count).collect();
    let mut erased = codeword.clone();
    unreadable.iter().for_each(|&position| erased[position] = 0);
    let restores = field.repair(&erased, &unreadable, count).as_deref() == Some(&codeword[..]);
    if is_codeword && restores {
        Ok(())
    } else {
        Err(MhfeError::Internal(
            "the new repair words do not repair their plate".to_owned(),
        ))
    }
}

/// A container repaired with its repair words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    /// The container, every word in full and in lower case, one space apart.
    pub container: String,
    /// The positions of the container's words that were repaired, from 1, in order.
    pub plate_words: Vec<usize>,
    /// The positions of the repair words that were wrong or unreadable, from 1, in order.
    pub card_words: Vec<usize>,
    /// Every repaired word with what was read there, plate first: a repair is never silent.
    pub changes: Vec<Change>,
}

/// One repaired word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// A word of the card rather than of the plate.
    pub on_card: bool,
    /// Its position on the plate or the card, from 1.
    pub position: usize,
    /// The word that was read there, or `None` when it could not be read.
    pub read: Option<String>,
    /// The word it is now.
    pub word: String,
}

/// The name of the profile, which the card carries; a reader of a card skips it.
pub const PROFILE: &str = "MHFE-REPAIR-1";

/// Repairs a container from its words as read from the plate and its repair words as read from the
/// card. A word that cannot be read is typed as `?`; a word that is not in the English BIP39 list
/// counts as unreadable too, and the first four letters of a word are enough, as for a container.
/// Fails when no repair within the code's bound gives a container that passes its BIP39 checksum.
/// Damage beyond the bound, or a card of another plate, usually fails so, but can also give
/// another container that passes the checksum: a repair does not show that the card belongs to the
/// plate or that the container is the original, which only a rehearsal against the wallet does
/// (AUD-008-DOC001).
pub fn repair(plate: &str, card: &str) -> Result<Repaired, MhfeError> {
    let (plate_words, plate_unreadable) = read_words(plate);
    if !WORD_COUNTS.contains(&plate_words.len()) {
        return Err(MhfeError::InvalidContainer(format!(
            "it has {} words, but a container has 12, 15, 18, 21 or 24; type ? for a word that \
             cannot be read",
            plate_words.len()
        )));
    }
    let (card_words, card_unreadable) = read_words(&card_text(card));
    let count = card_words.len();
    if !REPAIR_WORD_COUNTS.contains(&count) {
        return Err(MhfeError::InvalidRepairWords(format!(
            "a card has 2, 4, 6 or 8 repair words, not {count}; type ? for a word that cannot be \
             read"
        )));
    }
    let received: Vec<u16> = plate_words.iter().chain(&card_words).copied().collect();
    let unreadable: Vec<usize> = plate_unreadable
        .iter()
        .copied()
        .chain(card_unreadable.iter().map(|&i| i + plate_words.len()))
        .collect();
    let field = Field::new();
    let corrected =
        field
            .repair(&received, &unreadable, count)
            .ok_or(MhfeError::RepairNotPossible {
                repair_words: count,
            })?;
    let (data, parity) = corrected.split_at(plate_words.len());
    let container = words_of(data);
    // Damage beyond the code's reach can end in another codeword; the BIP39 checksum of the
    // container still catches most of those.
    Mnemonic::parse_in_normalized(Language::English, &container).map_err(|_| {
        MhfeError::RepairNotPossible {
            repair_words: count,
        }
    })?;
    let list = Language::English.word_list();
    let changed = |on_card: bool, was: &[u16], now: &[u16], unreadable: &[usize]| -> Vec<Change> {
        (0..was.len())
            .filter(|&i| was[i] != now[i] || unreadable.contains(&i))
            .map(|i| Change {
                on_card,
                position: i + 1,
                read: (!unreadable.contains(&i)).then(|| list[usize::from(was[i])].to_owned()),
                word: list[usize::from(now[i])].to_owned(),
            })
            .collect()
    };
    let mut changes = changed(false, &plate_words, data, &plate_unreadable);
    changes.extend(changed(true, &card_words, parity, &card_unreadable));
    let positions = |on_card: bool| -> Vec<usize> {
        changes
            .iter()
            .filter(|change| change.on_card == on_card)
            .map(|change| change.position)
            .collect()
    };
    Ok(Repaired {
        container,
        plate_words: positions(false),
        card_words: positions(true),
        changes,
    })
}

/// The words of a card as written: the profile's name and the numbers such as "1/4" before each
/// word are left out, so that a card can be typed as it is.
pub fn card_text(card: &str) -> String {
    card.split_whitespace()
        .filter(|token| {
            let numbered = token.split_once('/').is_some_and(|(left, right)| {
                !left.is_empty()
                    && !right.is_empty()
                    && left
                        .chars()
                        .chain(right.chars())
                        .all(|c| c.is_ascii_digit())
            });
            !numbered && !token.eq_ignore_ascii_case(PROFILE)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The word numbers of `text` and the positions, from 0, that are unreadable: `?` or not a word
/// of the list. An unreadable word stands as 0 until it is repaired.
fn read_words(text: &str) -> (Vec<u16>, Vec<usize>) {
    let mut numbers = Vec::new();
    let mut unreadable = Vec::new();
    for (position, typed) in text.split_whitespace().enumerate() {
        let number = phrase::complete_word(&typed.to_ascii_lowercase()).and_then(word_number);
        match number {
            Some(number) if typed != "?" => numbers.push(number),
            _ => {
                numbers.push(0);
                unreadable.push(position);
            }
        }
    }
    (numbers, unreadable)
}

fn word_number(word: &str) -> Option<u16> {
    Language::English.find_word(word)
}

fn words_of(numbers: &[u16]) -> String {
    let list = Language::English.word_list();
    numbers
        .iter()
        .map(|&number| list[usize::from(number)])
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public container of the suite 3 vector zero-12.
    fn zero_12_container() -> String {
        let json = include_str!("../tests/fixtures/suite3-vectors/zero-12.json");
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["container"].as_str().unwrap().to_owned()
    }

    #[test]
    fn alpha_generates_the_whole_field() {
        let field = Field::new();
        let mut seen = vec![false; FIELD_SIZE];
        for power in 0..ORDER {
            seen[usize::from(field.alpha(power))] = true;
        }
        assert_eq!(
            seen.iter().filter(|&&s| s).count(),
            ORDER,
            "x^11 + x^2 + 1 is primitive"
        );
    }

    #[test]
    fn a_plate_and_its_card_form_a_codeword() {
        let field = Field::new();
        let container = zero_12_container();
        for count in REPAIR_WORD_COUNTS {
            let card = repair_words(&container, count).unwrap();
            let (plate, _) = read_words(&container);
            let (parity, _) = read_words(&card);
            let codeword: Vec<u16> = plate.iter().chain(&parity).copied().collect();
            assert!(field.syndromes(&codeword, count).iter().all(|&s| s == 0));
            let repaired = repair(&container, &card).unwrap();
            assert_eq!(repaired.container, container);
            assert!(repaired.plate_words.is_empty() && repaired.card_words.is_empty());
        }
    }

    /// Every pattern of damage within 2e + s <= k, at random places of a few containers, is
    /// repaired; the places are drawn by a fixed generator, so the test is the same every run.
    #[test]
    fn damage_within_the_bound_is_repaired() {
        let field = Field::new();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        for words in WORD_COUNTS {
            for count in REPAIR_WORD_COUNTS {
                for _ in 0..300 {
                    let data: Vec<u16> = (0..words).map(|_| next(FIELD_SIZE) as u16).collect();
                    let parity = field.parity(&data, count);
                    let codeword: Vec<u16> = data.iter().chain(&parity).copied().collect();
                    let unreadable_count = next(count + 1);
                    let wrong_count = next((count - unreadable_count) / 2 + 1);
                    let mut received = codeword.clone();
                    let mut unreadable = Vec::new();
                    let mut damaged = Vec::new();
                    while damaged.len() < unreadable_count + wrong_count {
                        let position = next(codeword.len());
                        if !damaged.contains(&position) {
                            damaged.push(position);
                        }
                    }
                    for (i, &position) in damaged.iter().enumerate() {
                        if i < unreadable_count {
                            received[position] = 0;
                            unreadable.push(position);
                        } else {
                            // A different word, never the right one.
                            received[position] ^= 1 + next(FIELD_SIZE - 1) as u16;
                        }
                    }
                    let repaired = field.repair(&received, &unreadable, count);
                    assert_eq!(repaired.as_deref(), Some(&codeword[..]));
                }
            }
        }
    }

    fn fixture_container(json: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["container"].as_str().unwrap().to_owned()
    }

    /// Repair words computed by an independent Python implementation, written from the profile's
    /// description without this code, for public containers of 24, 12 and 21 words.
    #[test]
    fn repair_words_match_the_independent_vectors() {
        let cases = [
            (
                fixture_container(include_str!(
                    "../tests/fixtures/suite3-vectors/zero-12.json"
                )),
                [
                    "labor extra",
                    "shaft pupil patient jewel",
                    "credit buzz orbit tired sail coffee",
                    "appear include vicious move uphold tiger song satoshi",
                ],
            ),
            (
                fixture_container(include_str!(
                    "../tests/fixtures/suite4-vectors/same-length-nonzero-12.json"
                )),
                [
                    "motor renew",
                    "pitch lonely onion erode",
                    "toe rather ribbon run enforce notice",
                    "tilt object execute change cube domain vehicle hour",
                ],
            ),
            (
                fixture_container(include_str!(
                    "../tests/fixtures/suite4-vectors/same-length-nonzero-21.json"
                )),
                [
                    "glove blossom",
                    "share mask pave crystal",
                    "slow issue fame census cabbage clarify",
                    "potato enemy similar myself check gesture fortune shiver",
                ],
            ),
            (
                format!("{} art", ["abandon"; 23].join(" ")),
                [
                    "clever gravity",
                    "letter wealth borrow cable",
                    "clap try lift setup innocent gather",
                    "mirror coffee census note proof zebra begin barrel",
                ],
            ),
        ];
        for (container, cards) in cases {
            for (count, card) in REPAIR_WORD_COUNTS.into_iter().zip(cards) {
                assert_eq!(
                    repair_words(&container, count).unwrap(),
                    card,
                    "{count} words"
                );
            }
        }
    }

    /// The independent implementation's repair cases on zero-12 and same-length-nonzero-21.
    #[test]
    fn repairs_match_the_independent_vectors() {
        let zero_12 = zero_12_container();
        let cases: [(&str, &str, Vec<usize>, Vec<usize>); 6] = [
            (
                "donate stove ? picnic iron rescue trick shrimp roof rib home cigar bag pledge \
                 also nerve ? famous provide heart ahead chunk caution peace",
                "shaft pupil patient jewel",
                vec![3, 17],
                vec![],
            ),
            (
                "donate stove tower picnic zoo rescue trick shrimp roof rib home cigar bag pledge \
                 also nerve cycle famous provide abandon ahead chunk caution peace",
                "shaft pupil patient jewel",
                vec![5, 20],
                vec![],
            ),
            (
                "? stove tower picnic iron rescue trick shrimp legal rib home cigar bag pledge \
                 also nerve cycle famous provide heart ahead chunk caution ?",
                "shaft pupil patient jewel",
                vec![1, 9, 24],
                vec![],
            ),
            (
                "? stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also \
                 nerve cycle famous provide heart ahead chunk caution peace",
                "shaft ? patient jewel",
                vec![1],
                vec![2],
            ),
            (&zero_12, "zoo extra", vec![], vec![1]),
            (
                "donate abandon tower picnic iron rescue trick shrimp roof rib zoo cigar bag \
                 pledge also nerve cycle famous provide heart ahead chunk legal peace",
                "appear include vicious move uphold abandon song satoshi",
                vec![2, 11, 23],
                vec![6],
            ),
        ];
        for (plate, card, plate_words, card_words) in cases {
            let repaired = repair(plate, card).unwrap();
            assert_eq!(repaired.container, zero_12);
            assert_eq!(repaired.plate_words, plate_words, "{plate}");
            assert_eq!(repaired.card_words, card_words, "{card}");
        }
        let nonzero_21 = fixture_container(include_str!(
            "../tests/fixtures/suite4-vectors/same-length-nonzero-21.json"
        ));
        let repaired = repair(
            "seat govern run ? flag fragile horse night simple luggage vacuum warfare ? permit gym \
             upset average blade pen blue zoo",
            "slow issue fame census ? clarify",
        )
        .unwrap();
        assert_eq!(repaired.container, nonzero_21);
        assert_eq!(repaired.plate_words, vec![4, 13, 21]);
        assert_eq!(repaired.card_words, vec![5]);
    }

    /// Each repaired word is reported with what was read there (the specification asks that no
    /// repair be silent), and a card typed with its name and numbers is read as its words.
    #[test]
    fn every_repair_is_reported_and_a_written_card_is_read() {
        let container = zero_12_container();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[8] = "legal";
        let repaired = repair(
            &words.join(" "),
            "MHFE-REPAIR-1 1/4 shaft 2/4 ? 3/4 patient 4/4 jewel",
        )
        .unwrap();
        assert_eq!(repaired.container, container);
        let shown: Vec<(bool, usize, Option<&str>, &str)> = repaired
            .changes
            .iter()
            .map(|c| (c.on_card, c.position, c.read.as_deref(), c.word.as_str()))
            .collect();
        assert_eq!(
            shown,
            vec![
                (false, 1, None, "donate"),
                (false, 9, Some("legal"), "roof"),
                (true, 2, None, "pupil"),
            ]
        );
    }

    #[test]
    fn unreadable_and_unknown_words_are_marked_and_repaired() {
        let container = zero_12_container();
        let card = repair_words(&container, 4).unwrap();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[2] = "?";
        words[16] = "notaword";
        let repaired = repair(&words.join(" "), &card).unwrap();
        assert_eq!(repaired.container, container);
        assert_eq!(repaired.plate_words, vec![3, 17]);
    }

    /// A card is read back before it is given out: one with a changed word is refused.
    #[test]
    fn a_card_that_does_not_repair_its_plate_is_refused() {
        let field = Field::new();
        let (data, _) = read_words(&zero_12_container());
        for count in REPAIR_WORD_COUNTS {
            let mut parity = field.parity(&data, count);
            assert_eq!(check_card(&field, &data, &parity), Ok(()));
            parity[count - 1] ^= 1;
            assert_eq!(
                check_card(&field, &data, &parity).unwrap_err().code(),
                "INTERNAL_ERROR"
            );
        }
    }

    #[test]
    fn too_much_damage_or_a_wrong_card_is_refused() {
        let container = zero_12_container();
        let card = repair_words(&container, 2).unwrap();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[1] = "?";
        words[2] = "?";
        assert_eq!(
            repair(&words.join(" "), &card),
            Err(MhfeError::RepairNotPossible { repair_words: 2 })
        );
        assert!(matches!(
            repair(&container, "abandon abandon abandon"),
            Err(MhfeError::InvalidRepairWords(_))
        ));
        assert!(matches!(
            repair_words(&container, 3),
            Err(MhfeError::InvalidRepairWords(_))
        ));
    }

    /// AUD-008-DOC001: a card of another plate is not always refused. The plates of the zero
    /// entropy and of entropy 00…01 differ in their last word only; with the other plate's two
    /// repair words, that word is "repaired" into a container that passes its checksum but is not
    /// the plate's. A repair never proves the container; a rehearsal against the wallet does.
    #[test]
    fn a_card_of_another_plate_can_give_another_valid_container() {
        let plate = [vec!["abandon"; 23], vec!["art"]].concat().join(" ");
        let other = [vec!["abandon"; 23], vec!["diesel"]].concat().join(" ");
        let card = repair_words(&other, 2).unwrap();
        let repaired = repair(&plate, &card).unwrap();
        assert_eq!(repaired.container, other);
        assert_eq!(repaired.plate_words, [24]);
    }
}
