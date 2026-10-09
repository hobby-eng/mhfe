//! The 256-bit state `X` (specification: "Packing" and step 3 of "Recovering a mnemonic").
//!
//! `X = E || Trunc_r(SHA-256(E))` with `r = 256 - ENT`. For a short phrase the free bits hold a
//! verifier: an internal consistency check that screens out wrong passwords and most corruption
//! and reveals the length, but does not authenticate the password (a wrong one passes with
//! probability about 2^-r for each length). A 24-word phrase fills `X` alone and has no verifier.

use std::convert::Infallible;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::memory::LockedBytes;
use crate::MhfeError;

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

/// Packs the entropy `E` of a phrase into `X`, which is the phrase in all but form: it is written
/// into a buffer locked first, which the caller holds through the rounds.
pub fn pack(entropy: &[u8]) -> Result<LockedBytes, MhfeError> {
    let length = entropy.len();
    if entropy_bytes(words_of_entropy(length)) != Ok(length) {
        return Err(MhfeError::Internal(format!(
            "BIP39 entropy of {length} bytes cannot be packed"
        )));
    }
    let Ok(state) = LockedBytes::build::<Infallible>(STATE_BYTES, |state| {
        state.extend_from_slice(entropy);
        if length < STATE_BYTES {
            let digest = sha256(entropy);
            state.extend_from_slice(&digest[..STATE_BYTES - length]);
        }
        Ok(())
    });
    Ok(state)
}

/// SHA-256 in a buffer that is wiped when dropped; for a short phrase it is secret.
fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(data).into())
}

/// Reads `X` as the entropy of a phrase with `words` words: its first `ENT / 8` bytes, read in
/// place, since a copy would lie outside the locked buffer that holds `X`. For a short phrase all
/// `r` verifier bits must match, otherwise the result is [`MhfeError::VerifierMismatch`].
pub fn unpack(state: &State, words: usize) -> Result<&[u8], MhfeError> {
    let length = entropy_bytes(words)?;
    let (entropy, verifier) = state.split_at(length);
    if length < STATE_BYTES {
        let digest = sha256(entropy);
        if *verifier != digest[..STATE_BYTES - length] {
            return Err(MhfeError::VerifierMismatch);
        }
    }
    Ok(entropy)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Public states that pass two short checks at once. Each packs a short phrase whose state
    /// happens to carry a valid 21-word verifier too, which occurs for about one state in 2^32;
    /// they were found by searching counters after the ASCII text "MHFE ambiguous".
    pub(crate) const AMBIGUOUS_STATES: [(&str, [usize; 2]); 3] = [
        (
            "4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad",
            [12, 21],
        ),
        (
            "4d48464520616d626967756f00000000d7215b3cc350c32cc955fd4e3e272edf",
            [15, 21],
        ),
        (
            "4d48464520616d626967756f7573207400000000643a0b3e565fd3c1659f6749",
            [18, 21],
        ),
    ];

    pub(crate) fn state_from_hex(text: &str) -> State {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// A packed state as the fixed array that `unpack` and detection read.
    pub(crate) fn state_of(packed: &LockedBytes) -> &State {
        packed[..].try_into().unwrap()
    }

    /// Public test entropy of `length` bytes, every byte different.
    pub(crate) fn entropy(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect()
    }

    #[test]
    fn short_phrases_get_a_sha256_verifier() {
        let zero = [0u8; 16];
        let state = pack(&zero).unwrap();
        let digest = Sha256::digest(zero);
        assert_eq!(state[..16], zero);
        assert_eq!(state[16..], digest[..16]);
        assert_eq!(unpack(state_of(&state), 12).unwrap(), zero);
    }

    #[test]
    fn verifier_bytes_keep_digest_order() {
        // SHA-256 of 00 01 .. 1b starts with dc 27 f8 e8; the 21-word verifier is these four
        // bytes in digest order, never an integer read in host byte order.
        let source: Vec<u8> = (0u8..28).collect();
        let state = pack(&source).unwrap();
        assert_eq!(state[28..], [0xdc, 0x27, 0xf8, 0xe8]);
    }

    /// `X` is the phrase in all but form: it is packed into memory locked before it is written,
    /// and a reading of it is no copy but the start of the same buffer (AUD-010).
    #[test]
    fn the_state_is_packed_into_locked_memory_and_read_in_place() {
        let state = pack(&entropy(20)).unwrap();
        assert_eq!(state.is_locked(), cfg!(unix));
        let reading = unpack(state_of(&state), 15).unwrap();
        assert_eq!(reading.as_ptr(), state.as_ptr(), "the reading is a copy");
        assert_eq!(reading, entropy(20));
    }

    #[test]
    fn a_24_word_phrase_fills_the_state_alone() {
        let source = entropy(32);
        let state = pack(&source).unwrap();
        assert_eq!(state[..], source[..]);
        assert_eq!(unpack(state_of(&state), 24).unwrap(), source);
    }

    #[test]
    fn any_changed_verifier_bit_is_rejected() {
        let state = pack(&entropy(28)).unwrap();
        for byte in 28..32 {
            for bit in 0..8 {
                let mut corrupted = *state_of(&state);
                corrupted[byte] ^= 1 << bit;
                assert_eq!(
                    unpack(&corrupted, 21).unwrap_err(),
                    MhfeError::VerifierMismatch
                );
            }
        }
    }

    #[test]
    fn rejects_unknown_lengths() {
        assert_eq!(entropy_bytes(13), Err(MhfeError::InvalidWordCount(13)));
        assert!(pack(&[0u8; 17]).is_err());
    }
}
