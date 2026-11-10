//! The wallet check of a 24-word seed phrase: the DRAFT profile MHFE-WALLET-CHECK-SEED-1, which
//! the specification defines as an optional source profile ("Optional source profile: a recovery
//! check for new 24-word phrases"). It is still experimental. MHFE checks a recovered phrase
//! against it; it draws no new phrase.
//!
//! The check itself, on the BIP39 seed of the phrase and a passphrase, is the core's:
//! [`mhfe_core::wallet_check`] gives it byte for byte.
//!
//! The check is defined for a 24-word phrase, whose entropy has 256 bits, and this library offers
//! it only with a BIP39 passphrase that is not empty, as the specification allows: one rule for
//! every front end, owned by [`require_passphrase`] and [`verify`]. A recovery is checked against
//! it only as 24 words and with a passphrase ([`verify`], and the rehearsal's
//! `Reference::WalletCheck`), never as a shorter reading. Without a passphrase the seed would be a
//! function of the phrase alone, and anyone who saw the phrase could test the check.
//! [`phrase_passes`] computes the criterion itself for any passphrase, the empty one included: a
//! recovery reports a pass without a passphrase for a phrase that another program made in that
//! form, and a hidden wallet may pass neither form.
//!
//! A pass is statistical evidence, not proof. A random phrase with a given passphrase passes once
//! in about 65,536, so a wrong MHFE password or passphrase slips through at that rate, and a
//! passphrase that passes with a given phrase is found after about 65,536 tries by anyone who
//! searches for one. With a passphrase that is not empty, a guess of the MHFE password can be
//! tested only together with a guess of the passphrase. A phrase drawn to pass keeps about 240 of
//! its 256 bits of entropy for a given passphrase. The specification's deniability results assume
//! a uniformly random phrase; they do not by themselves cover a phrase drawn to pass the check.
//! The check never identifies the wallet: only an address or the fingerprint does that.

use mhfe_core::wallet_check::Seed;
use mhfe_core::Phrase;

use crate::{read_phrase, MhfeError};

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;

/// The bits the check fixes: 16, so that a wrong password passes once in 65,536, at a cost of 16 of
/// the 256 bits of a 24-word phrase drawn to pass it. A deliberate copy of `CHECK_BITS` in the
/// core's src/wallet_check.rs, which keeps it private, for what the front ends say of the check: a
/// change goes to both.
pub const WALLET_CHECK_BITS: u32 = 16;
/// One in this many wrong passwords passes the check: 2^[`WALLET_CHECK_BITS`], 65,536.
pub const WALLET_CHECK_ODDS: u64 = 1 << WALLET_CHECK_BITS;
/// Whether a seed phrase passes the criterion of the wallet check with `passphrase`, which may be
/// empty here. The profile defines it for 24 words alone, so a phrase of another length does not
/// pass. A program that checks a recovery uses [`verify`], which holds the profile's rule.
pub fn phrase_passes(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    Ok(meets_criterion(&read_phrase(text)?, passphrase))
}

/// The criterion itself. The core has no answer below 24 words, which is no pass.
fn meets_criterion(phrase: &Phrase, passphrase: &str) -> bool {
    Seed::derive(phrase, passphrase).passes() == Some(true)
}

/// The rule of the passphrase, for every front end: the wallet check is offered only with a BIP39
/// passphrase that is not empty (`WALLET_CHECK_NEEDS_PASSPHRASE` otherwise). A front end can ask
/// this before anything else, as the rehearsal does before any Argon2 work.
pub fn require_passphrase(passphrase: &str) -> Result<(), MhfeError> {
    if passphrase.is_empty() {
        return Err(MhfeError::WalletCheckNeedsPassphrase);
    }
    Ok(())
}

/// Whether a recovered 24-word phrase passes the wallet check with the passphrase the owner gives.
/// An empty passphrase is refused ([`require_passphrase`]), and so is a phrase of another length.
pub fn verify(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    require_passphrase(passphrase)?;
    let phrase = read_phrase(text)?;
    if phrase.words() != crate::packing::STATE_WORDS {
        return Err(MhfeError::NoWalletCheckAtLength(phrase.words()));
    }
    Ok(meets_criterion(&phrase, passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entropies of 32 bytes with `counter` in the last eight, as the published vectors give them.
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
    fn the_check_binds_the_passphrase() {
        let phrase = Phrase::from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        let phrase = phrase.as_str();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(phrase_passes(phrase, "TREZOR").unwrap());
        assert!(!phrase_passes(phrase, "trezor").unwrap());
        // Without the passphrase it is another seed, which fails: 0 leading zero bits.
        assert!(!phrase_passes(phrase, "").unwrap());
    }

    #[test]
    fn a_wallet_without_a_passphrase_has_its_check_too() {
        let phrase = Phrase::from_entropy(&counted(EMPTY_COUNTER)).unwrap();
        let phrase = phrase.as_str();
        assert!(phrase.ends_with("abandon absorb another spoil"));
        assert!(phrase_passes(phrase, "").unwrap());
        assert!(!phrase_passes(phrase, "TREZOR").unwrap());
    }

    #[test]
    fn the_check_needs_a_passphrase_and_24_words() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        assert!(matches!(
            verify(twelve, "TREZOR"),
            Err(MhfeError::NoWalletCheckAtLength(12))
        ));
        let phrase = Phrase::from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        assert!(matches!(
            verify(phrase.as_str(), ""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        assert_eq!(
            require_passphrase(""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(require_passphrase("TREZOR"), Ok(()));
    }

    /// The library's messages write the odds out, as "65,536"; they must stay the check's.
    #[test]
    fn messages_give_the_odds_of_the_check() {
        assert_eq!(WALLET_CHECK_ODDS, 65_536);
        assert!(MhfeError::HiddenWalletPassesCheck
            .to_string()
            .contains("once in 65,536"));
    }

    /// A short phrase has no check (AUD-010): a public passphrase with which the 12-word test
    /// phrase would pass under BE32(128), which the profile does not define, does not pass, and
    /// `verify` refuses the length.
    #[test]
    fn a_short_phrase_has_no_check() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        let passphrase = "aud010 public probe 11656";
        assert_eq!(phrase_passes(twelve, passphrase), Ok(false));
        assert_eq!(
            verify(twelve, passphrase),
            Err(MhfeError::NoWalletCheckAtLength(12))
        );
    }
}
