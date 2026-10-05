//! The wallet check of a new seed phrase: a DRAFT, not yet part of the specification. Its
//! supplement records it under Research directions, "A check for new 24-word and suite 4 sources by
//! choosing the entropy", as a creation mode the owner chooses.
//!
//! A new phrase is drawn at random until `SHA-256("MHFE-WALLET-CHECK-SEED-1" || BE32(ENT) || seed)`
//! starts with 16 zero bits, where `seed` is the BIP39 seed of the phrase and the owner's BIP39
//! passphrase, and `ENT` the entropy's length in bits. The passphrase may not be empty: the seed
//! with an empty one is a function of the phrase alone, and the check would then confirm the MHFE
//! password on its own, which makes an attacker's two searches add instead of multiplying. Only the right phrase
//! with the right passphrase passes, so an attacker's searches for the MHFE password and for the
//! passphrase still multiply. A recovered phrase that passes with the passphrase was very likely
//! made that way, as a random one passes once in 65,536. The check never identifies the wallet:
//! only an address or the fingerprint does that.

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

/// Whether `entropy` passes the wallet check with `passphrase`, which may not be empty.
pub fn passes(entropy: &[u8], passphrase: &str) -> Result<bool, MhfeError> {
    if passphrase.is_empty() {
        return Err(MhfeError::WalletCheckNeedsPassphrase);
    }
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
    fn the_check_needs_the_passphrase() {
        let entropy = counted(TREZOR_COUNTER);
        assert!(passes(&entropy, "TREZOR").unwrap());
        assert!(!passes(&entropy, "trezor").unwrap());
        // With an empty passphrase the check would confirm the phrase alone, so it is refused.
        assert!(matches!(
            passes(&entropy, ""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        // The seed with "" does not pass the check either: 0 leading zero bits.
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
        assert!(!tagged_hash_passes(
            256,
            &wallet::bip39_seed(&mnemonic, "")[..]
        ));
        let phrase = crate::mhfe::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(phrase_passes(&phrase, "TREZOR").unwrap());
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
