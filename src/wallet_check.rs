//! The wallet check of a new seed phrase: a DRAFT, not yet part of the specification. Its
//! supplement records it under Research directions, "A check for new 24-word and suite 4 sources by
//! choosing the entropy", as a creation mode the owner chooses.
//!
//! A new phrase is drawn at random until its check passes. The check, byte for byte: the SHA-256
//! digest of
//!
//! - the ASCII tag `MHFE-WALLET-CHECK-SEED-1`, 24 bytes, with no terminating NUL;
//! - `BE32(ENT)`, the entropy's length in bits as a 4-byte big-endian number, 256 for 24 words;
//! - the raw 64-byte BIP39 seed: PBKDF2-HMAC-SHA512 with 2,048 iterations of the canonical English
//!   phrase of the entropy (its words in lower case, one space apart), with the salt "mnemonic"
//!   followed by the BIP39 passphrase in NFKD;
//!
//! starts with 16 zero bits: its first two bytes are zero. The passphrase may be empty, as for a
//! wallet without one: the seed is then a function of the phrase alone, and the check confirms the
//! MHFE password on its own, as the built-in check of a 12- to 21-word phrase does, at the same
//! cost to decoys and to an attacker's search. The owner chooses it knowing that.
//!
//! A pass is statistical evidence, not proof. A random phrase with a given passphrase passes once
//! in about 65,536, so a wrong MHFE password or passphrase slips through at that rate, and a
//! passphrase that passes with a given phrase is found after about 65,536 tries by anyone who
//! searches for one. With a passphrase that is not empty, a guess of the MHFE password can be
//! tested only together with a guess of the passphrase. Drawing the phrase this way leaves about
//! 240 of its 256 bits of entropy for a given passphrase. The specification's deniability results
//! assume a uniformly random phrase; they do not by themselves cover a phrase drawn to pass the
//! check. The check never identifies the wallet: only an address or the fingerprint does that.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use bip39::{Language, Mnemonic};

use crate::{phrase, wallet, MhfeError};

/// The bits the check fixes: 16, so that a wrong password passes once in 65,536, at a cost of 16
/// of the 256 bits of a 24-word phrase. A new phrase takes about 65,536 BIP39 seeds to find.
pub const WALLET_CHECK_BITS: u32 = 16;
/// The domain tag, which keeps the check apart from every other hash of the seed. Draft.
const DOMAIN: &[u8] = b"MHFE-WALLET-CHECK-SEED-1";
/// The entropy of a new 24-word phrase: 256 bits.
pub const NEW_ENTROPY_BYTES: usize = 32;

/// Whether `entropy` passes the wallet check with `passphrase`, which is empty for a wallet without
/// one.
pub fn passes(entropy: &[u8], passphrase: &str) -> Result<bool, MhfeError> {
    let bits = u32::try_from(entropy.len() * 8).unwrap_or(u32::MAX);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|error| MhfeError::Internal(error.to_string()))?;
    let seed = wallet::bip39_seed(&mnemonic, passphrase);
    Ok(tagged_hash_passes(bits, &seed[..]))
}

/// Whether a seed phrase passes the wallet check with `passphrase`.
pub fn phrase_passes(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    let mnemonic = phrase::parse(text).map_err(MhfeError::InvalidPhrase)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    passes(&entropy, passphrase)
}

/// Whether `SHA-256(DOMAIN || BE32(bits) || seed)` starts with [`WALLET_CHECK_BITS`] zero bits.
fn tagged_hash_passes(bits: u32, seed: &[u8]) -> bool {
    let digest = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bits.to_be_bytes())
        .chain_update(seed)
        .finalize();
    let zero_bytes = (WALLET_CHECK_BITS / 8) as usize;
    digest[..zero_bytes].iter().all(|&byte| byte == 0)
}

/// A new 24-word seed phrase from `fill`, which must give uniformly random bytes, such as the
/// operating system's generator. With a `passphrase`, entropies are drawn until one passes the
/// wallet check with it, about 65,536 BIP39 seeds; every passing entropy is then equally likely.
/// `on_draw` hears of every draw, for a progress display.
pub fn new_phrase(
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), MhfeError>,
    passphrase: Option<&str>,
    on_draw: &mut dyn FnMut(u64),
) -> Result<Zeroizing<String>, MhfeError> {
    let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
    for draw in 1u64.. {
        on_draw(draw);
        fill(&mut entropy[..])?;
        let found = match passphrase {
            None => true,
            Some(passphrase) => passes(&entropy[..], passphrase)?,
        };
        if found {
            return crate::mhfe::phrase_from_entropy(&entropy[..]);
        }
    }
    unreachable!("the draws are not bounded")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entropies of 32 bytes with `counter` in the last eight, as a deterministic stand-in for a
    /// random generator.
    fn counted(counter: u64) -> [u8; 32] {
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&counter.to_be_bytes());
        entropy
    }

    /// The first counter whose phrase passes with the public test passphrase "TREZOR": entropy of
    /// 24 zero bytes and 76,562, "abandon" 21 times, "above proof fatigue". Found once with the
    /// release build, about 65,536 BIP39 seeds, and confirmed by an independent computation.
    const TREZOR_COUNTER: u64 = 76_562;

    /// The first counter whose phrase passes with an empty passphrase: 24 zero bytes and 98,918,
    /// "abandon" 21 times, "absorb another spoil". Found with an independent Python computation
    /// (digest 0000ede7…), which also confirmed that it fails with "TREZOR" (8d2b97fb…).
    const EMPTY_COUNTER: u64 = 98_918;

    #[test]
    fn about_one_seed_in_65536_passes() {
        // The criterion alone, over counted 64-byte seeds: fast, unlike a BIP39 seed each.
        const TRIES: u64 = 1 << 20;
        let passing = (0..TRIES)
            .filter(|&counter| {
                let mut seed = [0u8; 64];
                seed[56..].copy_from_slice(&counter.to_be_bytes());
                tagged_hash_passes(256, &seed)
            })
            .count();
        // 16 expected; far outside 4 to 40 would mean the criterion is not uniform.
        assert!((4..=40).contains(&passing), "{passing}");
    }

    #[test]
    fn the_check_binds_the_passphrase() {
        let entropy = counted(TREZOR_COUNTER);
        assert!(passes(&entropy, "TREZOR").unwrap());
        assert!(!passes(&entropy, "trezor").unwrap());
        // Without the passphrase it is another seed, which fails: 0 leading zero bits.
        assert!(!passes(&entropy, "").unwrap());
        let phrase = crate::mhfe::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(phrase_passes(&phrase, "TREZOR").unwrap());
    }

    #[test]
    fn a_wallet_without_a_passphrase_has_its_check_too() {
        let entropy = counted(EMPTY_COUNTER);
        assert!(passes(&entropy, "").unwrap());
        assert!(!passes(&entropy, "TREZOR").unwrap());
        let phrase = crate::mhfe::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon absorb another spoil"));
        assert!(phrase_passes(&phrase, "").unwrap());
    }

    #[test]
    fn a_new_phrase_passes_and_an_unchecked_one_takes_the_first_draw() {
        // The counter starts just before the known passing one, so the search is short.
        let counter = std::cell::Cell::new(TREZOR_COUNTER - 3);
        let mut fill = |bytes: &mut [u8]| {
            counter.set(counter.get() + 1);
            bytes.copy_from_slice(&counted(counter.get()));
            Ok(())
        };
        let mut draws = 0;
        let checked = new_phrase(&mut fill, Some("TREZOR"), &mut |draw| draws = draw).unwrap();
        assert_eq!(draws, 3);
        assert!(phrase_passes(&checked, "TREZOR").unwrap());
        let unchecked = new_phrase(&mut fill, None, &mut |_| {}).unwrap();
        assert_eq!(counter.get(), TREZOR_COUNTER + 1);
        assert_eq!(unchecked.split(' ').count(), 24);
    }
}
