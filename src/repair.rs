//! Repair words for a container phrase: the optional profile MHFE-REPAIR-1 of the specification
//! (README, "Optional repair words"), outside suites 3 and 4.
//!
//! A written container phrase can fade, rust, be scratched or be copied with a wrong word. A few
//! extra English BIP39 words, kept on a card apart from the container phrase, let any program
//! repair it without the password and without Argon2. They are the parity of a Reed–Solomon code
//! over the container's words: the BIP39 list has 2,048 words, exactly the elements of GF(2^11), so
//! each word is a field element and each repair word is a word of the same list.
//!
//! The code, byte for byte:
//!
//! - the field GF(2^11) with the primitive polynomial x^11 + x^2 + 1, and alpha = x;
//! - the data: the container's word numbers d_0 to d_(n-1) in the list, the first word first, as
//!   the coefficients of m(x) from x^(n-1) down to x^0;
//! - k repair words, 2, 4, 6 or 8: the remainder r(x) of m(x) * x^k divided by
//!   g(x) = (x + alpha) (x + alpha^2) ... (x + alpha^k), its coefficients from x^(k-1) down to x^0.
//!
//! The words of the container phrase followed by the repair words are then a codeword: they vanish
//! at alpha to alpha^k. Any 2e + s <= k damaged words are repaired, e of them wrong at unknown
//! places and s of them unreadable, marked as such; a wrong or unreadable repair word counts the
//! same. More damage may be repaired wrongly; the repaired container must then still pass its BIP39
//! checksum.
//!
//! The card holds nothing secret beyond what the container phrase holds: with the container phrase,
//! it adds nothing; on its own it gives k of the container phrase's word values in mixed form. But
//! a container is what a guesser of passwords needs, and the card repairs a damaged or partial copy
//! of the container phrase for whoever has both, as it does for the owner. It belongs apart from
//! the container phrase, so that one accident or one thief does not take both, and is guarded like
//! the container phrase.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::input_text::InputText;
use crate::memory::LockedText;
use crate::phrase::{self, WORD_COUNTS};
mod error;
pub use error::RepairError;

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
/// of a container phrase at a card of four words.
pub const RECOMMENDED_REPAIR_WORDS: usize = 4;

/// A supported repair-card size. Construction validates it once; capacity and parity generation
/// then use this value rather than accepting arbitrary counts. It owns the MHFE-REPAIR-1 entry
/// points, including repair from a card whose size is read from its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairWordCount(usize);

impl RepairWordCount {
    /// Refuses a number of repair words that no card has (`INVALID_REPAIR_WORDS`): 2, 4, 6 or 8
    /// ([`REPAIR_WORD_COUNTS`]).
    pub fn new(count: usize) -> Result<Self, RepairError> {
        if !REPAIR_WORD_COUNTS.contains(&count) {
            return Err(RepairError::WordCount {
                count,
                unreadable_hint: false,
            });
        }
        Ok(Self(count))
    }

    /// Every supported count, in the profile's order, without repeating their values.
    pub fn offered() -> [Self; REPAIR_WORD_COUNTS.len()] {
        REPAIR_WORD_COUNTS.map(Self)
    }

    /// The count as a number of words.
    pub const fn get(self) -> usize {
        self.0
    }

    /// The unreadable and wrong words this card can repair, respectively.
    pub const fn capacity(self) -> (usize, usize) {
        (self.0, self.0 / 2)
    }

    /// The repair words of `container`, a valid container of 12 to 24 words: this many English
    /// BIP39 words, one space apart.
    ///
    /// # Panics
    ///
    /// Never: every word of a parsed container is in the list.
    #[expect(
        clippy::expect_used,
        reason = "every word of a parsed container is in the BIP39 list"
    )]
    pub fn words_of(self, container: &str) -> Result<String, RepairError> {
        let count = self.0;
        let mnemonic = phrase::parse_container(container)?;
        let mut data = Zeroizing::new(Vec::with_capacity(mnemonic.word_count()));
        for word in mnemonic.words() {
            data.push(phrase::word_number(word).expect("a parsed word is in the list"));
        }
        let field = Field::new();
        let parity = field.parity(&data, count);
        check_card(&field, &data, &parity)?;
        Ok(phrase::words_of(&parity))
    }

    /// Repairs a container from its words as read from the container phrase and its repair words as
    /// read from the card. A word that cannot be read is typed as `?`; a word that is not in the
    /// English BIP39 list counts as unreadable too, and the first four letters of a word are enough, as
    /// for a container. Fails when no repair within the code's bound gives a container that passes its
    /// BIP39 checksum. Damage beyond the bound, or a card of another container phrase, usually fails
    /// so, but can also give another container that passes the checksum: a repair does not show that
    /// the card belongs to the container phrase or that the container is the original, which only a
    /// rehearsal against the wallet does (AUD-008-DOC001).
    pub fn repair(written: &str, card: &str) -> Result<Repaired, RepairError> {
        InputText::read(written)?;
        let written_count = written.split_whitespace().count();
        if !WORD_COUNTS.contains(&written_count) {
            return Err(RepairError::ContainerLength(written_count));
        }
        let typed_card = CardWords::read(card)?;
        let count = typed_card.count();
        Self::new(count).map_err(RepairError::with_unreadable_hint)?;
        let (container_words, container_unreadable) = phrase::word_numbers(written)?;
        let (card_words, card_unreadable) = phrase::word_numbers(typed_card.words())?;
        let mut received = Zeroizing::new(Vec::with_capacity(container_words.len() + count));
        received.extend(container_words.iter().chain(card_words.iter()).copied());
        let mut unreadable = Zeroizing::new(Vec::with_capacity(
            container_unreadable.len() + card_unreadable.len(),
        ));
        unreadable.extend(container_unreadable.iter().copied());
        unreadable.extend(card_unreadable.iter().map(|&i| i + container_words.len()));
        let field = Field::new();
        let corrected =
            field
                .repair(&received, &unreadable, count)
                .ok_or(RepairError::NotPossible {
                    repair_words: count,
                })?;
        let (data, parity) = corrected.split_at(container_words.len());
        let container = zeroize::Zeroizing::new(phrase::words_of(data));
        // Damage beyond the code's reach can end in another codeword; the BIP39 checksum of the
        // container still catches most of those.
        Mnemonic::parse_in_normalized(Language::English, &container).map_err(|_| {
            RepairError::NotPossible {
                repair_words: count,
            }
        })?;
        let mut changes = Vec::with_capacity(received.len());
        let mut changed = |on_card: bool, was: &[u16], now: &[u16], unreadable: &[usize]| {
            for i in (0..was.len()).filter(|&i| was[i] != now[i] || unreadable.contains(&i)) {
                changes.push(Change {
                    on_card,
                    position: Zeroizing::new(i + 1),
                    read: (!unreadable.contains(&i))
                        .then(|| zeroize::Zeroizing::new(phrase::word(was[i]).to_owned())),
                    word: zeroize::Zeroizing::new(phrase::word(now[i]).to_owned()),
                });
            }
        };
        changed(false, &container_words, data, &container_unreadable);
        changed(true, &card_words, parity, &card_unreadable);
        let positions = |on_card: bool| {
            let mut positions = Zeroizing::new(Vec::with_capacity(changes.len()));
            positions.extend(
                changes
                    .iter()
                    .filter(|change| change.on_card == on_card)
                    .map(Change::position),
            );
            positions
        };
        Ok(Repaired {
            container,
            container_words: positions(false),
            card_words: positions(true),
            changes,
        })
    }
}

/// Elements of GF(2^11): 2,048, as many as the words of the BIP39 list, which [`POLYNOMIAL`]
/// fixes too, so that the size is checked against the list rather than derived from it.
const FIELD_SIZE: usize = 2048;
const _: () = assert!(FIELD_SIZE == crate::phrase::LIST_SIZE as usize);
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

    /// `a / b`; `None` for a division by zero, which the callers rule out (AUD-024-API016).
    fn div(&self, a: u16, b: u16) -> Option<u16> {
        if b == 0 {
            return None;
        }
        if a == 0 {
            return Some(0);
        }
        let power =
            usize::from(self.log[usize::from(a)]) + ORDER - usize::from(self.log[usize::from(b)]);
        Some(self.exp[power])
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
    fn parity(&self, data: &[u16], k: usize) -> Zeroizing<Vec<u16>> {
        let g = self.generator(k);
        let mut remainder = Zeroizing::new(vec![0u16; k]);
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
    fn syndromes(&self, codeword: &[u16], k: usize) -> Zeroizing<Vec<u16>> {
        let mut syndromes = Zeroizing::new(Vec::with_capacity(k));
        syndromes.extend((1..=k).map(|power| self.eval(codeword, self.alpha(power))));
        syndromes
    }

    /// Corrects `received` when every damaged symbol is among `positions` and there are at most k
    /// of them (erasure decoding, Forney's formula); `None` when no codeword results.
    fn correct_at(
        &self,
        received: &[u16],
        positions: &[usize],
        k: usize,
    ) -> Option<Zeroizing<Vec<u16>>> {
        let n = received.len();
        let syndromes = self.syndromes(received, k);
        let mut corrected = Zeroizing::new(received.to_vec());
        if syndromes.iter().all(|&syndrome| syndrome == 0) {
            return Some(corrected);
        }
        // The locator of a position: alpha to the power of the degree of its term.
        let mut locators = Zeroizing::new(Vec::with_capacity(positions.len()));
        locators.extend(positions.iter().map(|&i| self.alpha(n - 1 - i)));
        // Gamma(x) = prod (1 + X_i x), and Omega(x) = S(x) Gamma(x) mod x^k with
        // S(x) = S_1 + S_2 x + ... + S_k x^(k-1); both lowest degree first.
        let mut gamma = Zeroizing::new(vec![1u16]);
        for &locator in locators.iter() {
            let mut next = Zeroizing::new(vec![0u16; gamma.len() + 1]);
            for (i, &coefficient) in gamma.iter().enumerate() {
                next[i] ^= coefficient;
                next[i + 1] ^= self.mul(coefficient, locator);
            }
            gamma = next;
        }
        let mut omega = Zeroizing::new(vec![0u16; k]);
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
        let mut derivative = Zeroizing::new(Vec::with_capacity(gamma.len() - 1));
        derivative.extend(gamma.iter().enumerate().skip(1).map(|(i, &coefficient)| {
            if i % 2 == 1 {
                coefficient
            } else {
                0
            }
        }));
        for (&position, &locator) in positions.iter().zip(locators.iter()) {
            let inverse = self.div(1, locator)?;
            let denominator = low_first(&derivative, inverse);
            if denominator == 0 {
                return None;
            }
            // Forney with the first root alpha^1: e = Omega(X^-1) / Gamma'(X^-1).
            corrected[position] ^= self.div(low_first(&omega, inverse), denominator)?;
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
    fn repair(
        &self,
        received: &[u16],
        unreadable: &[usize],
        k: usize,
    ) -> Option<Zeroizing<Vec<u16>>> {
        if unreadable.len() > k {
            return None;
        }
        let mut readable = Zeroizing::new(Vec::with_capacity(received.len()));
        readable.extend((0..received.len()).filter(|position| !unreadable.contains(position)));
        for wrong in 0..=(k - unreadable.len()) / 2 {
            let mut found = None;
            for_each_subset(&readable, wrong, &mut |chosen| {
                if found.is_none() {
                    let mut positions =
                        Zeroizing::new(Vec::with_capacity(unreadable.len() + chosen.len()));
                    positions.extend(unreadable.iter().chain(chosen).copied());
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
    walk(
        items,
        size,
        0,
        &mut Zeroizing::new(Vec::with_capacity(size)),
        visit,
    );
}

/// Reads a new card back before it is given out: the container phrase and its repair words must
/// form a codeword, and the card must restore the container phrase's first words when they are
/// unreadable, as many as it has words. A fault in the field's tables or in the division would
/// otherwise give a card that repairs nothing, which nobody notices until the container phrase is
/// damaged.
fn check_card(field: &Field, data: &[u16], parity: &[u16]) -> Result<(), RepairError> {
    let count = parity.len();
    let mut codeword = Zeroizing::new(Vec::with_capacity(data.len() + parity.len()));
    codeword.extend(data.iter().chain(parity).copied());
    let is_codeword = field
        .syndromes(&codeword, count)
        .iter()
        .all(|&syndrome| syndrome == 0);
    let unreadable = Zeroizing::new((0..count).collect::<Vec<_>>());
    let mut erased = codeword.clone();
    unreadable.iter().for_each(|&position| erased[position] = 0);
    let restores = field
        .repair(&erased, &unreadable, count)
        .as_ref()
        .map(|words| words.as_slice())
        == Some(codeword.as_slice());
    if is_codeword && restores {
        Ok(())
    } else {
        Err(RepairError::ParityReadback)
    }
}

/// A container repaired with its repair words.
#[derive(Clone, PartialEq, Eq)]
pub struct Repaired {
    /// The container, every word in full and in lower case, one space apart.
    container: zeroize::Zeroizing<String>,
    /// The positions of the container's words that were repaired, from 1, in order.
    container_words: Zeroizing<Vec<usize>>,
    /// The positions of the repair words that were wrong or unreadable, from 1, in order.
    card_words: Zeroizing<Vec<usize>>,
    /// Every repaired word with what was read there, container phrase first: a repair is never
    /// silent.
    changes: Vec<Change>,
}

impl std::fmt::Debug for Repaired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repaired")
            .field("container_words", &*self.container_words)
            .field("card_words", &*self.card_words)
            .field("changes", &self.changes)
            .finish_non_exhaustive()
    }
}

impl Repaired {
    /// The repaired container, with full lower-case words separated by one space.
    pub fn container(&self) -> &str {
        &self.container
    }

    /// Repaired container-word positions, counted from one and ordered.
    pub fn container_words(&self) -> &[usize] {
        &self.container_words
    }

    /// Wrong or unreadable card-word positions, counted from one and ordered.
    pub fn card_words(&self) -> &[usize] {
        &self.card_words
    }

    /// Every reported correction, container first; the original result cannot be altered.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
}

/// One repaired word.
#[derive(Clone, PartialEq, Eq)]
pub struct Change {
    /// A word of the card rather than of the container phrase.
    on_card: bool,
    /// Its position on the container phrase or the card, from 1.
    position: Zeroizing<usize>,
    /// The word that was read there, or `None` when it could not be read.
    read: Option<zeroize::Zeroizing<String>>,
    /// The word it is now.
    word: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Change")
            .field("on_card", &self.on_card)
            .field("position", &*self.position)
            .finish_non_exhaustive()
    }
}

impl Change {
    /// Whether the corrected word belongs to the card instead of the container.
    pub fn on_card(&self) -> bool {
        self.on_card
    }

    /// The corrected word's position, counted from one.
    pub fn position(&self) -> usize {
        *self.position
    }

    /// The word read there, or none when it was unreadable.
    pub fn read(&self) -> Option<&str> {
        self.read.as_deref().map(String::as_str)
    }

    /// The corrected word.
    pub fn word(&self) -> &str {
        &self.word
    }
}

/// What a container phrase as typed is, before anything is computed with it: a container as it
/// stands, or words that its repair words may repair. A front end that reads a container asks for
/// the card at once when the owner marked words with `?`, and offers it when the words have a
/// container's length but are not a container, which may be a typing mistake as well.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerReading {
    /// A valid container: nothing to repair.
    Container,
    /// Words typed as `?`: the owner marked them as unreadable. `unreadable` lists every word that
    /// cannot be read, from 1, words outside the BIP39 list included.
    Marked {
        /// The places of the unreadable words, counted from 1.
        unreadable: Vec<usize>,
    },
    /// A container's length, but not a container: a word outside the BIP39 list or a BIP39
    /// checksum that fails, from a typing mistake or from a damaged or miscopied container phrase.
    NotAContainer,
    /// Not 12, 15, 18, 21 or 24 words, `?` included: nothing that repair words could repair.
    WrongLength(usize),
}

impl ContainerReading {
    /// Reads `written` as [`RepairWordCount::repair`] reads a container phrase: `?` for a word that cannot be read,
    /// any spacing and letter case, and the first four letters of a word.
    /// Raw input above [`InputText::MAX_BYTES`] fails before collection; other unsupported counts
    /// remain the [`Self::WrongLength`] outcome with their exact count.
    pub fn read(written: &str) -> Result<Self, RepairError> {
        InputText::read(written)?;
        let count = written.split_whitespace().count();
        if !WORD_COUNTS.contains(&count) {
            return Ok(Self::WrongLength(count));
        }
        if written.split_whitespace().any(|word| word == UNREADABLE) {
            let (_, unreadable) = phrase::word_numbers(written)?;
            return Ok(Self::Marked {
                unreadable: unreadable.iter().map(|position| position + 1).collect(),
            });
        }
        Ok(if phrase::parse_container(written).is_ok() {
            Self::Container
        } else {
            Self::NotAContainer
        })
    }

    /// Whether repair words may make a container of these words.
    pub fn can_be_repaired(&self) -> bool {
        matches!(self, Self::Marked { .. } | Self::NotAContainer)
    }
}

/// What stands for a word that cannot be read, on the container phrase and on the card.
pub const UNREADABLE: &str = "?";

/// The name of the profile, which the card carries; a reader of a card skips it.
pub const PROFILE: &str = "MHFE-REPAIR-1";

/// The words as written on a repair card, without its profile and numbered labels. Unknown words
/// stay as typed for the repair operation to validate. The text is locked and wiped by its owner.
pub struct CardWords {
    text: LockedText,
}

impl CardWords {
    /// Reads only the words from a printed or plain card, retaining the original spelling.
    ///
    /// Refuses raw UTF-8 input above [`InputText::MAX_BYTES`] or more than the largest supported
    /// card's token count before copying. Smaller counts are left for the repair operation to judge.
    pub fn read(written: &str) -> Result<Self, RepairError> {
        InputText::read(written)?;
        let count = Self::tokens(written).count();
        if count > REPAIR_WORD_COUNTS[REPAIR_WORD_COUNTS.len() - 1] {
            return Err(RepairError::WordCount {
                count,
                unreadable_hint: true,
            });
        }
        let bytes = Self::tokens(written).map(str::len).sum::<usize>() + count.saturating_sub(1);
        let text = LockedText::build::<std::convert::Infallible>(bytes, |text| {
            for token in Self::tokens(written) {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(token);
            }
            Ok(())
        })
        .unwrap_or_else(|never| match never {});
        Ok(Self { text })
    }

    /// The words as typed, without presentation labels.
    pub fn words(&self) -> &str {
        &self.text
    }

    /// The number of word tokens, before the repair operation checks the card's supported size.
    pub fn count(&self) -> usize {
        self.text.split_whitespace().count()
    }

    /// One borrowed extraction rule for counting, sizing and writing a printed card.
    fn tokens(card: &str) -> impl Iterator<Item = &str> {
        card.split_whitespace().filter(|token| {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::zero_12_container;

    #[test]
    fn oversized_card_text_is_refused_before_repair() {
        let card = format!(
            "{} abacus",
            "x".repeat(crate::input_text::InputText::MAX_BYTES)
        );
        let error = RepairWordCount::repair(crate::test_support::ABANDON_12, &card).unwrap_err();
        assert_eq!(error.error_code(), crate::ErrorCode::InvalidRequest);
    }

    #[test]
    fn repair_readers_keep_exact_counts_and_bound_raw_bytes_before_copying() {
        let limit = InputText::MAX_BYTES;
        let too_long = "é".repeat(limit / "é".len()) + "x";
        for error in [
            ContainerReading::read(&too_long).unwrap_err(),
            CardWords::read(&too_long).err().unwrap(),
            RepairWordCount::repair(&too_long, "abandon about").unwrap_err(),
        ] {
            assert_eq!(
                error,
                RepairError::Text(crate::input_text::TextSizeError::TooLong { bytes: limit + 1 })
            );
        }
        assert_eq!(
            ContainerReading::read(&"x".repeat(limit)).unwrap(),
            ContainerReading::WrongLength(1)
        );
        for count in [0, 1, 3, 8] {
            let text = "abandon ".repeat(count);
            assert_eq!(CardWords::read(&text).unwrap().count(), count);
        }
        for count in [9, 25, 1000] {
            let text = "? ".repeat(count);
            assert_eq!(
                ContainerReading::read(&text).unwrap(),
                ContainerReading::WrongLength(count)
            );
            assert!(
                matches!(CardWords::read(&text), Err(RepairError::WordCount { count: actual, .. }) if actual == count)
            );
        }
        let printed = " mhfe-repair-1\n1/4\tabandon 2/4 about 3/4\u{2003}? 4/4 XyZ ";
        let card = CardWords::read(printed).unwrap();
        assert_eq!(card.words(), "abandon about ? XyZ");
        assert_eq!(card.count(), 4);
        let padding = " ".repeat(limit - "abandon about".len());
        assert_eq!(
            CardWords::read(&(padding + "abandon about"))
                .unwrap()
                .words(),
            "abandon about"
        );
        assert!(phrase::word_numbers(&"abandon ".repeat(25)).is_err());
        // A huge single token is never lowercased or copied as a selected word.
        let (numbers, missing) = phrase::word_numbers(&"X".repeat(limit + 1)).unwrap();
        assert_eq!(&*numbers, &[0]);
        assert_eq!(&*missing, &[0]);
    }

    #[test]
    fn repaired_results_and_their_clones_hide_words_in_debug_text() {
        let original = crate::test_support::ABANDON_12;
        let card = RepairWordCount::new(2).unwrap().words_of(original).unwrap();
        for wrong in ["?", "ability"] {
            let damaged = original.replacen("abandon", wrong, 1);
            let repaired = RepairWordCount::repair(&damaged, &card).unwrap();
            let copy = repaired.clone();
            assert_eq!(copy, repaired);
            assert_eq!(copy.container(), original);
            assert_eq!(copy.changes().len(), 1);
            assert_eq!(copy.changes()[0].read(), (wrong != "?").then_some(wrong));
            for item in [&repaired, &copy] {
                let text = format!("{item:?}");
                for word in original.split(' ').chain(card.split(' ')) {
                    assert!(!text.contains(word));
                }
                for change in item.changes() {
                    let text = format!("{change:?}");
                    assert!(!text.contains(change.word()));
                    if let Some(read) = change.read() {
                        assert!(!text.contains(read));
                    }
                }
            }
        }
    }

    #[test]
    fn a_typed_card_count_has_only_the_profiles_supported_capacities() {
        let offered = RepairWordCount::offered();
        assert_eq!(offered.map(RepairWordCount::get), REPAIR_WORD_COUNTS);
        assert_eq!(
            offered.map(RepairWordCount::capacity),
            [(2, 1), (4, 2), (6, 3), (8, 4)]
        );
        for count in [0, 1, 3, 5, 7, 9, usize::MAX] {
            assert!(matches!(
                RepairWordCount::new(count),
                Err(RepairError::WordCount { .. })
            ));
        }
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
    fn a_container_phrase_and_its_card_form_a_codeword() {
        let field = Field::new();
        let container = zero_12_container();
        for count in REPAIR_WORD_COUNTS {
            let card = RepairWordCount::new(count)
                .and_then(|count| count.words_of(&container))
                .unwrap();
            let (words, _) = phrase::word_numbers(&container).unwrap();
            let (parity, _) = phrase::word_numbers(&card).unwrap();
            let codeword: Vec<u16> = words.iter().chain(parity.iter()).copied().collect();
            assert!(field.syndromes(&codeword, count).iter().all(|&s| s == 0));
            let repaired = RepairWordCount::repair(&container, &card).unwrap();
            assert_eq!(repaired.container(), container);
            assert!(repaired.container_words().is_empty() && repaired.card_words().is_empty());
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
                    let codeword: Vec<u16> = data.iter().chain(parity.iter()).copied().collect();
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
                    assert_eq!(
                        repaired.as_ref().map(|words| words.as_slice()),
                        Some(&codeword[..])
                    );
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
        for row in known_answers::CARDS {
            for (count, card) in REPAIR_WORD_COUNTS.into_iter().zip(row.cards) {
                assert_eq!(
                    RepairWordCount::new(count)
                        .and_then(|count| count.words_of(row.container))
                        .unwrap(),
                    card,
                    "{count} words"
                );
            }
        }
        // The reference inputs are also bound to the published fixture bytes.
        let fixtures = [
            include_str!("../tests/fixtures/suite3-vectors/zero-12.json"),
            include_str!("../tests/fixtures/suite4-vectors/same-length-nonzero-12.json"),
            include_str!("../tests/fixtures/suite4-vectors/same-length-nonzero-21.json"),
        ];
        for (row, json) in known_answers::CARDS.iter().zip(fixtures) {
            assert_eq!(row.container, fixture_container(json));
        }
    }

    /// Each repaired word is reported with what was read there (the specification asks that no
    /// repair be silent), and a card typed with its name and numbers is read as its words.
    #[test]
    fn every_repair_is_reported_and_a_written_card_is_read() {
        let container = zero_12_container();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[8] = "legal";
        let repaired = RepairWordCount::repair(
            &words.join(" "),
            "MHFE-REPAIR-1 1/4 shaft 2/4 ? 3/4 patient 4/4 jewel",
        )
        .unwrap();
        assert_eq!(repaired.container(), container);
        let shown: Vec<(bool, usize, Option<&str>, &str)> = repaired
            .changes()
            .iter()
            .map(|c| (c.on_card(), c.position(), c.read(), c.word()))
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
        let card = RepairWordCount::new(4)
            .and_then(|count| count.words_of(&container))
            .unwrap();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[2] = "?";
        words[16] = "notaword";
        let repaired = RepairWordCount::repair(&words.join(" "), &card).unwrap();
        assert_eq!(repaired.container(), container);
        assert_eq!(repaired.container_words(), vec![3, 17]);
    }

    /// A card is read back before it is given out: one with a changed word is refused.
    #[test]
    fn a_card_that_does_not_repair_its_container_phrase_is_refused() {
        let field = Field::new();
        let (data, _) = phrase::word_numbers(&zero_12_container()).unwrap();
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
        let card = RepairWordCount::new(2)
            .and_then(|count| count.words_of(&container))
            .unwrap();
        let mut words: Vec<&str> = container.split(' ').collect();
        words[0] = "?";
        words[1] = "?";
        words[2] = "?";
        assert_eq!(
            RepairWordCount::repair(&words.join(" "), &card),
            Err(RepairError::NotPossible { repair_words: 2 })
        );
        assert!(matches!(
            RepairWordCount::repair(&container, "abandon abandon abandon"),
            Err(RepairError::WordCount { .. })
        ));
        assert!(matches!(
            RepairWordCount::new(3).and_then(|count| count.words_of(&container)),
            Err(RepairError::WordCount { .. })
        ));
    }

    /// AUD-008-DOC001: a card of another container phrase is not always refused. The container
    /// phrases of the zero entropy and of entropy 00…01 differ in their last word only; with the
    /// other container phrase's two repair words, that word is "repaired" into a container that
    /// passes its checksum but is not the container phrase's. A repair never proves the container;
    /// a rehearsal against the wallet does.
    #[test]
    fn a_card_of_another_container_phrase_can_give_another_valid_container() {
        let container = [vec!["abandon"; 23], vec!["art"]].concat().join(" ");
        let other = [vec!["abandon"; 23], vec!["diesel"]].concat().join(" ");
        let card = RepairWordCount::new(2)
            .and_then(|count| count.words_of(&other))
            .unwrap();
        let repaired = RepairWordCount::repair(&container, &card).unwrap();
        assert_eq!(repaired.container(), other);
        assert_eq!(repaired.container_words(), [24]);
    }

    /// A container phrase as typed is read as a container, as words marked with `?`, as words
    /// that are not a container, or as a length no container has; the last two kinds that a card
    /// may repair, it repairs.
    #[test]
    fn a_container_phrase_is_read_before_it_is_used() {
        let container = zero_12_container();
        let with = |changes: &[(usize, &'static str)]| {
            let mut words: Vec<&str> = container.split(' ').collect();
            for &(position, word) in changes {
                words[position - 1] = word;
            }
            words.join(" ")
        };
        assert_eq!(
            ContainerReading::read(&container).unwrap(),
            ContainerReading::Container
        );
        // Capitals, extra spaces and four letters a word, as for any container.
        let typed: Vec<String> = container
            .split(' ')
            .map(|word| word[..word.len().min(4)].to_uppercase())
            .collect();
        assert_eq!(
            ContainerReading::read(&typed.join("   ")).unwrap(),
            ContainerReading::Container
        );
        assert_eq!(
            ContainerReading::read(&with(&[(3, "?"), (17, "?")])).unwrap(),
            ContainerReading::Marked {
                unreadable: vec![3, 17]
            }
        );
        // A word outside the list is unreadable too once the owner has marked another.
        assert_eq!(
            ContainerReading::read(&with(&[(3, "?"), (9, "towr")])).unwrap(),
            ContainerReading::Marked {
                unreadable: vec![3, 9]
            }
        );
        for unmarked in [with(&[(9, "towr")]), with(&[(24, "abandon")])] {
            assert_eq!(
                ContainerReading::read(&unmarked).unwrap(),
                ContainerReading::NotAContainer
            );
            assert!(ContainerReading::read(&unmarked).unwrap().can_be_repaired());
            let repaired =
                RepairWordCount::repair(&unmarked, known_answers::ZERO_12_CARD.1).unwrap();
            assert_eq!(repaired.container(), container);
        }
        let shorter: Vec<&str> = container.split(' ').take(23).collect();
        assert_eq!(
            ContainerReading::read(&shorter.join(" ")).unwrap(),
            ContainerReading::WrongLength(23)
        );
        assert_eq!(
            ContainerReading::read(&format!("{container} ?")).unwrap(),
            ContainerReading::WrongLength(25)
        );
        assert!(!ContainerReading::Container.can_be_repaired());
        assert!(!ContainerReading::WrongLength(23).can_be_repaired());
    }
}
