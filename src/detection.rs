//! Automatic detection of an original seed phrase's length (specification: recovery, step 3). A
//! 24-word container holds a phrase of 12 to 24 words. A 12- to 21-word phrase leaves a built-in
//! check in the recovered state `X`, which another length passes only by accident, about once in
//! 2^32; a 24-word phrase fills `X` and has none, so it is the reading left when no shorter one
//! passes. With its BIP39 passphrase, a 24-word phrase drawn to pass the phrase + passphrase check
//! ([`crate::wallet_check`]) can still be told, by 16 bits.
//!
//! [`Recovery`] detects the length, and every operation that reads one from `X` goes through it: a
//! recovery with [`crate::PhraseLength::Detect`], a check and what it shows beside its reference,
//! the search for missing words, and a rekey of a phrase whose length is not stated. This module
//! holds what they ask of a recovery beside that.

use mhfe_core::Recovery;

use crate::mhfe::{readings, RecoveredPhrase};
use crate::packing::STATE_WORDS;
use crate::wallet_check;
use crate::MhfeError;

/// The 24-word reading of a 24-word container, whose entropy is `X` itself: the last of the
/// readings for 24 stated words, whatever short lengths pass before it.
#[expect(clippy::expect_used, reason = "24 stated words end with that reading")]
pub(crate) fn twenty_four_word_reading(recovery: &Recovery) -> Result<RecoveredPhrase, MhfeError> {
    let mut readings = readings(recovery, Some(STATE_WORDS))?;
    Ok(readings
        .pop()
        .expect("24 stated words end with that reading"))
}

/// Whether a recovery would read the state as a phrase that passes a check: a short length's
/// built-in check, or the 24-word reading's phrase + passphrase check with `passphrase`, which
/// may be empty here, or without one, which `mhfe decrypt` reports whatever the passphrase. A
/// hidden wallet must pass none of them (rule I29).
pub(crate) fn reads_as_checked(recovery: &Recovery, passphrase: &str) -> Result<bool, MhfeError> {
    if !recovery.detected_lengths().is_empty() {
        return Ok(true);
    }
    let reading = twenty_four_word_reading(recovery)?;
    Ok(wallet_check::phrase_passes(reading.phrase(), passphrase)?
        || (!passphrase.is_empty() && wallet_check::phrase_passes(reading.phrase(), "")?))
}

#[cfg(test)]
mod tests {
    use mhfe_core::{Mhfe, Phrase, Suite, WorkFactor};

    use super::*;
    use crate::encrypt;
    use crate::mhfe::recover_state;
    use crate::packing::{State, STATE_BYTES};
    use crate::test_support::{
        entropy, state_from_hex, test_password, HashEngine, AMBIGUOUS_STATES,
    };
    use crate::Unstopped as _;

    /// The recovery of the 24-word container of the phrase of `entropy`, made with a test engine. A
    /// short phrase packs into its state, and a 24-word phrase is its state.
    fn recovery_of(entropy: &[u8]) -> Recovery {
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let password = test_password();
        let container = encrypt(
            &mut mhfe,
            Phrase::from_entropy(entropy).unwrap().as_str(),
            &password,
            Suite::TwentyFourWords,
            &mut |_, _| crate::GO_ON,
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        recover_state(
            &mut mhfe,
            container.as_str(),
            &password,
            None,
            &mut |_, _| crate::GO_ON,
        )
        .unstopped()
        .unwrap()
    }

    /// The length of every reading worth comparing with a wallet, in their order.
    fn reading_lengths(recovery: &Recovery) -> Vec<usize> {
        let readings = readings(recovery, Some(STATE_WORDS)).unwrap();
        readings.iter().map(RecoveredPhrase::words).collect()
    }

    #[test]
    fn detection_finds_the_packed_length() {
        for (length, words) in [(16, 12), (20, 15), (24, 18), (28, 21)] {
            let recovery = recovery_of(&entropy(length));
            assert_eq!(recovery.detected_lengths(), [words]);
            assert_eq!(reading_lengths(&recovery), [words, STATE_WORDS]);
        }
        let recovery = recovery_of(&entropy(STATE_BYTES));
        assert!(recovery.detected_lengths().is_empty());
        assert_eq!(reading_lengths(&recovery), [STATE_WORDS]);
    }

    #[test]
    fn the_known_ambiguous_states_match_exactly_two_lengths() {
        for (text, lengths) in AMBIGUOUS_STATES {
            let recovery = recovery_of(&state_from_hex(text));
            assert_eq!(recovery.detected_lengths(), lengths);
            assert_eq!(
                reading_lengths(&recovery),
                [lengths[0], lengths[1], STATE_WORDS]
            );
        }
    }

    /// The 24-word reading is told by the phrase + passphrase check only with the passphrase the
    /// phrase was drawn with.
    #[test]
    fn a_24_word_reading_passes_its_own_checks_only_with_its_passphrase() {
        // The public fixture of the wallet check's tests: 24 zero bytes and the counter 76,562,
        // the first whose phrase passes with "TREZOR".
        let mut state: State = [0; STATE_BYTES];
        state[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let recovery = recovery_of(&state);
        assert!(recovery.detected_lengths().is_empty());
        let reading = twenty_four_word_reading(&recovery).unwrap();
        assert_eq!(reading.passes_wallet_check("TREZOR"), Ok(Some(true)));
        assert_eq!(reading.passes_wallet_check("trezor"), Ok(Some(false)));
        assert_eq!(reading.passes_wallet_check(""), Ok(Some(false)));
    }

    /// A hidden wallet's state is refused when a recovery would read it as checked (rule I29).
    #[test]
    fn a_state_that_passes_the_wallet_check_reads_as_checked() {
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut state: State = [0; STATE_BYTES];
        state[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let reads =
            |state: &[u8], passphrase| reads_as_checked(&recovery_of(state), passphrase).unwrap();
        assert!(reads(&state, "TREZOR"));
        // The same reading with the main wallet's empty passphrase is another seed, which fails.
        assert!(!reads(&state, ""));
        state[24..].copy_from_slice(&76_561u64.to_be_bytes());
        assert!(!reads(&state, "TREZOR"));
        // A reading that passes the check without a passphrase is refused as well, also when the
        // main wallet has one: mhfe decrypt would report that pass.
        state[24..].copy_from_slice(&98_918u64.to_be_bytes());
        assert!(reads(&state, ""));
        assert!(reads(&state, "TREZOR"));
        // A short reading that passes its built-in check reads as checked with any passphrase.
        assert!(reads(&entropy(16), ""));
    }
}
