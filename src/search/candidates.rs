//! Bounded candidate selections for a damaged container, held in one wiping allocation.

use std::ops::Index;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{SearchError, MAX_MISSING_FOR_DECOY};
use crate::packing::{self, STATE_BYTES};
use crate::phrase::{self, LIST_SIZE, WORD_BITS};

/// The missing word values of every checksum-valid candidate, in lexicographic list order.
pub(super) struct Candidates {
    values: Zeroizing<Vec<[u16; MAX_MISSING_FOR_DECOY]>>,
    width: usize,
}

impl Candidates {
    pub(super) fn new(words: &[u16], missing: &[usize]) -> Result<Self, SearchError> {
        if missing.len() > MAX_MISSING_FOR_DECOY {
            return Err(SearchError::TooManyMissing {
                missing: missing.len(),
                limit: MAX_MISSING_FOR_DECOY,
            });
        }
        // Reserve the whole combination bound, not an expected checksum pass fraction. At most
        // 2048^2 entries of two u16 values occupy 16 MiB; no selected values ever move on growth.
        let capacity = usize::from(LIST_SIZE).pow(missing.len() as u32);
        let mut found = Self {
            values: Zeroizing::new(Vec::with_capacity(capacity)),
            width: missing.len(),
        };
        let mut known = Zeroizing::new(Vec::with_capacity(words.len()));
        known.extend_from_slice(words);
        for &position in missing {
            known[position] = 0;
        }
        let base = pack(&known);
        let mut values = Zeroizing::new([0_u16; MAX_MISSING_FOR_DECOY]);
        loop {
            let mut bits = base.clone();
            for (&position, &value) in missing.iter().zip(&values[..found.width]) {
                set_word(&mut bits, position, value);
            }
            if passes_checksum(&bits, words.len()) {
                found.values.push(*values);
            }
            let mut place = found.width;
            loop {
                if place == 0 {
                    return Ok(found);
                }
                place -= 1;
                values[place] += 1;
                if values[place] < LIST_SIZE {
                    break;
                }
                values[place] = 0;
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.values.len()
    }

    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = &[u16]> {
        self.values.iter().map(|values| &values[..self.width])
    }
}

impl Index<usize> for Candidates {
    type Output = [u16];

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index][..self.width]
    }
}

/// The bits of up to 24 words: 32 entropy bytes and one checksum byte.
type WordBits = [u8; STATE_BYTES + 1];

pub(super) fn pack(numbers: &[u16]) -> Zeroizing<WordBits> {
    let mut bits = Zeroizing::new([0_u8; STATE_BYTES + 1]);
    for (index, &number) in numbers.iter().enumerate() {
        set_word(&mut bits, index, number);
    }
    bits
}

fn set_word(bits: &mut WordBits, index: usize, number: u16) {
    phrase::write_bits(bits, index * WORD_BITS, WORD_BITS, number);
}

/// BIP39 compares the high checksum bits of SHA-256(entropy) with the last word's low bits.
pub(super) fn passes_checksum(bits: &WordBits, words: usize) -> bool {
    let entropy_bytes = packing::entropy_of_words(words);
    let hash = Zeroizing::new(Sha256::digest(&bits[..entropy_bytes]));
    let shift = 8 - packing::checksum_bits(words);
    hash[0] >> shift == bits[entropy_bytes] >> shift
}
