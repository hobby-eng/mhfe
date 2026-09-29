//! The 256-bit state `X` (specification: "Packing" and step 3 of "Recovering a mnemonic").
//!
//! `X = E || Trunc_r(SHA-256(E))` with `r = 256 - ENT`. For a short phrase the free bits hold a
//! verifier that confirms the password and reveals the length; a 24-word phrase fills `X` alone.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::MhfeError;

pub const STATE_BYTES: usize = 32;
pub type State = [u8; STATE_BYTES];

/// Short phrase lengths, in the order automatic detection tests them.
pub const SHORT_WORD_COUNTS: [usize; 4] = [12, 15, 18, 21];

/// Entropy size `ENT / 8` of a phrase with `words` words.
pub fn entropy_bytes(words: usize) -> Result<usize, MhfeError> {
    match words {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        other => Err(MhfeError::InvalidWordCount(other)),
    }
}

/// Packs the entropy `E` of a phrase into `X`.
pub fn pack(entropy: &[u8]) -> Result<Zeroizing<State>, MhfeError> {
    let length = entropy.len();
    if !matches!(length, 16 | 20 | 24 | 28 | 32) {
        return Err(MhfeError::Internal(format!(
            "BIP39 entropy of {length} bytes cannot be packed"
        )));
    }
    let mut state = Zeroizing::new([0u8; STATE_BYTES]);
    state[..length].copy_from_slice(entropy);
    if length < STATE_BYTES {
        let digest = sha256(entropy);
        state[length..].copy_from_slice(&digest[..STATE_BYTES - length]);
    }
    Ok(state)
}

/// SHA-256 in a buffer that is wiped when dropped; for a short phrase it is secret.
fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(data).into())
}

/// Reads `X` as the entropy of a phrase with `words` words. For a short phrase all `r`
/// verifier bits must match, otherwise the result is [`MhfeError::VerifierMismatch`].
pub fn unpack(state: &State, words: usize) -> Result<Zeroizing<Vec<u8>>, MhfeError> {
    let length = entropy_bytes(words)?;
    let entropy = Zeroizing::new(state[..length].to_vec());
    if length < STATE_BYTES {
        let digest = sha256(&entropy);
        if state[length..] != digest[..STATE_BYTES - length] {
            return Err(MhfeError::VerifierMismatch);
        }
    }
    Ok(entropy)
}

/// Every short length whose verifier matches `X`, in ascending order.
pub fn matching_short_lengths(state: &State) -> Vec<usize> {
    SHORT_WORD_COUNTS
        .into_iter()
        .filter(|&words| unpack(state, words).is_ok())
        .collect()
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

    #[test]
    fn the_known_ambiguous_states_match_exactly_two_lengths() {
        for (text, lengths) in AMBIGUOUS_STATES {
            assert_eq!(matching_short_lengths(&state_from_hex(text)), lengths);
        }
    }

    fn entropy(length: usize) -> Vec<u8> {
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
        assert_eq!(*unpack(&state, 12).unwrap(), zero);
    }

    #[test]
    fn verifier_bytes_keep_digest_order() {
        // SHA-256 of 00 01 .. 1b starts with dc 27 f8 e8; the 21-word verifier is these four
        // bytes in digest order, never an integer read in host byte order.
        let source: Vec<u8> = (0u8..28).collect();
        let state = pack(&source).unwrap();
        assert_eq!(state[28..], [0xdc, 0x27, 0xf8, 0xe8]);
    }

    #[test]
    fn a_24_word_phrase_fills_the_state_alone() {
        let source = entropy(32);
        let state = pack(&source).unwrap();
        assert_eq!(state[..], source[..]);
        assert_eq!(*unpack(&state, 24).unwrap(), source);
    }

    #[test]
    fn any_changed_verifier_bit_is_rejected() {
        let state = pack(&entropy(28)).unwrap();
        for byte in 28..32 {
            for bit in 0..8 {
                let mut corrupted = *state;
                corrupted[byte] ^= 1 << bit;
                assert_eq!(
                    unpack(&corrupted, 21).unwrap_err(),
                    MhfeError::VerifierMismatch
                );
            }
        }
    }

    #[test]
    fn detection_finds_the_packed_length() {
        for (length, words) in [(16, 12), (20, 15), (24, 18), (28, 21)] {
            let state = pack(&entropy(length)).unwrap();
            assert_eq!(matching_short_lengths(&state), vec![words]);
        }
        assert!(matching_short_lengths(&pack(&entropy(32)).unwrap()).is_empty());
    }

    #[test]
    fn rejects_unknown_lengths() {
        assert_eq!(entropy_bytes(13), Err(MhfeError::InvalidWordCount(13)));
        assert!(pack(&[0u8; 17]).is_err());
    }
}
