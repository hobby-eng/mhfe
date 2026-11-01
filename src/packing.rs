//! The sizes of a BIP39 phrase and of the 256-bit state `X`, which mhfe-core packs and reads.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::MhfeError;

// The sizes here are deliberate copies of those in the core's src/packing.rs, which keeps them
// private: a change goes to both.
pub const STATE_BYTES: usize = 32;
pub type State = [u8; STATE_BYTES];
/// The words of a phrase that fills the whole state, three for every four bytes (BIP39): a suite 3
/// container, and the longest original seed phrase, which has no room left for a built-in check.
pub const STATE_WORDS: usize = words_of_entropy(STATE_BYTES);

/// The words of a BIP39 phrase of `bytes` bytes of entropy: three for every four bytes, as BIP39
/// adds one checksum bit for every 32 bits of entropy and each word carries 11 bits.
pub const fn words_of_entropy(bytes: usize) -> usize {
    bytes / 4 * 3
}

/// Short phrase lengths, in the order automatic detection tests them.
pub const SHORT_WORD_COUNTS: [usize; 4] = [12, 15, 18, 21];

/// The entropy bytes of a BIP39 phrase of `words` words, four for every three: the inverse of
/// [`words_of_entropy`].
pub const fn entropy_of_words(words: usize) -> usize {
    words / 3 * 4
}

/// The checksum bits of a BIP39 phrase of `words` words: one for every three words, 4 for 12 words
/// and 8 for 24 (BIP39: CS = ENT / 32 and words = (ENT + CS) / 11).
pub const fn checksum_bits(words: usize) -> usize {
    words / 3
}

/// The bits a 24-word phrase's words read: its entropy and, in the byte after it, its BIP39
/// checksum, the first byte of the entropy's SHA-256.
pub(crate) fn with_checksum(entropy: &State) -> [u8; STATE_BYTES + 1] {
    let mut bits = [0u8; STATE_BYTES + 1];
    bits[..STATE_BYTES].copy_from_slice(entropy);
    bits[STATE_BYTES] = sha256(entropy)[0];
    bits
}

/// Entropy size `ENT / 8` of a phrase with `words` words.
pub fn entropy_bytes(words: usize) -> Result<usize, MhfeError> {
    if !crate::phrase::WORD_COUNTS.contains(&words) {
        return Err(MhfeError::InvalidWordCount(words));
    }
    Ok(entropy_of_words(words))
}

/// SHA-256 of a phrase's entropy, in a buffer that is wiped when dropped.
fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(data).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_lengths() {
        assert_eq!(entropy_bytes(13), Err(MhfeError::InvalidWordCount(13)));
    }
}
