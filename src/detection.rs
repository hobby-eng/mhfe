//! Automatic detection of an original seed phrase's length (specification: recovery, step 3). A
//! 24-word container holds a phrase of 12 to 24 words. A 12- to 21-word phrase leaves a built-in
//! check in the recovered state `X`, which another length passes only by accident, about once in
//! 2^32; a 24-word phrase fills `X` and has none, so it is the reading left when no shorter one
//! passes. With its BIP39 passphrase, a 24-word phrase drawn to pass the phrase + passphrase check
//! ([`crate::wallet_check`]) can still be told, by 16 bits.
//!
//! Every operation that reads a length from `X` takes it from here: a recovery with
//! [`crate::PhraseLength::Detect`], a check and what it shows beside its reference, the search for
//! missing words, a rekey of a phrase whose length is not stated, and the warning at encryption
//! about a phrase that detection would misread.

use crate::packing::{self, State, STATE_WORDS};
use crate::wallet_check;
use crate::MhfeError;

/// What detection finds in one recovered state `X` of a 24-word container.
pub(crate) struct LengthDetection<'a> {
    state: &'a State,
    /// The 12- to 21-word lengths whose built-in check passes, in ascending order.
    short: Vec<usize>,
}

impl<'a> LengthDetection<'a> {
    pub(crate) fn of(state: &'a State) -> Self {
        let short = packing::SHORT_WORD_COUNTS
            .into_iter()
            .filter(|&words| packing::unpack(state, words).is_ok())
            .collect();
        Self { state, short }
    }

    /// The 12- to 21-word lengths whose built-in check passes: one for a short original, none for
    /// a 24-word one or a wrong password, and more than one only by accident.
    pub(crate) fn short_lengths(&self) -> &[usize] {
        &self.short
    }

    /// Whether `words` is a short length whose built-in check passes.
    pub(crate) fn passes_built_in_check(&self, words: usize) -> bool {
        self.short.contains(&words)
    }

    /// Every reading worth comparing with a wallet, in the order recovery lists them: each short
    /// length that passes its built-in check, then the 24-word reading, so that no accidental
    /// match hides the real phrase.
    pub(crate) fn readings(&self) -> impl Iterator<Item = usize> + '_ {
        self.short.iter().copied().chain([STATE_WORDS])
    }

    /// Whether the 24-word reading passes the phrase + passphrase check with `passphrase`, which
    /// may not be empty. The profile defines the check for that reading alone, whose entropy is
    /// `X` itself: a shorter reading would be a construction it does not define, and a match of
    /// its own about once in 65,536 (AUD-010).
    pub(crate) fn passes_wallet_check(&self, passphrase: &str) -> Result<bool, MhfeError> {
        wallet_check::verify_entropy(self.state, passphrase)
    }

    /// Whether the 24-word reading passes the 16-bit source check with `passphrase`, which may be
    /// empty here: every recovery evaluates it on the 24-word reading with the passphrase given or
    /// the empty one, as the container does not show whether the phrase was made with the check
    /// (the specification's recovery rules). Only a pass means something to an owner who does not
    /// know.
    pub(crate) fn source_check(&self, passphrase: &str) -> Result<bool, MhfeError> {
        wallet_check::passes(self.state, passphrase)
    }

    /// Whether a recovery would read the state as a phrase that passes a check: a short length's
    /// built-in check, or the 24-word reading's phrase + passphrase check with `passphrase`, which
    /// may be empty here, or without one, which `mhfe decrypt` reports whatever the passphrase. A
    /// hidden wallet must pass none of them (rule I29).
    pub(crate) fn reads_as_checked(&self, passphrase: &str) -> Result<bool, MhfeError> {
        if !self.short.is_empty() || wallet_check::passes(self.state, passphrase)? {
            return Ok(true);
        }
        Ok(!passphrase.is_empty() && self.passes_without_passphrase())
    }

    /// Whether the 24-word reading passes the criterion of the phrase + passphrase check without
    /// a passphrase, as a phrase another program made in that form does, which `mhfe decrypt`
    /// reports. A failure says nothing: a phrase made without the check fails it.
    pub(crate) fn passes_without_passphrase(&self) -> bool {
        // A state always has the entropy of a 24-word phrase, so the test cannot fail.
        wallet_check::passes(self.state, "").unwrap_or(false)
    }

    /// Whether the phrase's own checks pass, its length detected: the built-in check of a short
    /// length, or else, with a `passphrase`, the 24-word reading's phrase + passphrase check.
    /// Several short lengths that pass by accident pass all the same.
    pub(crate) fn passes_own_checks(&self, passphrase: Option<&str>) -> Result<bool, MhfeError> {
        if !self.short.is_empty() {
            return Ok(true);
        }
        match passphrase {
            Some(passphrase) => self.passes_wallet_check(passphrase),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packing::tests::{entropy, state_from_hex, state_of, AMBIGUOUS_STATES};
    use crate::packing::{pack, STATE_BYTES};

    #[test]
    fn detection_finds_the_packed_length() {
        for (length, words) in [(16, 12), (20, 15), (24, 18), (28, 21)] {
            let packed = pack(&entropy(length)).unwrap();
            let detection = LengthDetection::of(state_of(&packed));
            assert_eq!(detection.short_lengths(), [words]);
            assert!(detection.passes_built_in_check(words));
            assert_eq!(
                detection.readings().collect::<Vec<_>>(),
                [words, STATE_WORDS]
            );
            assert!(detection.passes_own_checks(None).unwrap());
        }
        let packed = pack(&entropy(STATE_BYTES)).unwrap();
        let detection = LengthDetection::of(state_of(&packed));
        assert!(detection.short_lengths().is_empty());
        assert_eq!(detection.readings().collect::<Vec<_>>(), [STATE_WORDS]);
        assert!(!detection.passes_own_checks(None).unwrap());
    }

    #[test]
    fn the_known_ambiguous_states_match_exactly_two_lengths() {
        for (text, lengths) in AMBIGUOUS_STATES {
            let state = state_from_hex(text);
            let detection = LengthDetection::of(&state);
            assert_eq!(detection.short_lengths(), lengths);
            assert_eq!(
                detection.readings().collect::<Vec<_>>(),
                [lengths[0], lengths[1], STATE_WORDS]
            );
        }
    }

    /// The 24-word reading is told by the phrase + passphrase check only with the passphrase the
    /// phrase was drawn with, and an empty passphrase is refused as the check refuses it.
    #[test]
    fn a_24_word_reading_passes_its_own_checks_only_with_its_passphrase() {
        // The public fixture of the wallet check's tests: 24 zero bytes and the counter 76,562,
        // the first whose phrase passes with "TREZOR".
        let mut state: State = [0; STATE_BYTES];
        state[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let detection = LengthDetection::of(&state);
        assert!(detection.short_lengths().is_empty());
        assert!(detection.passes_wallet_check("TREZOR").unwrap());
        assert!(detection.passes_own_checks(Some("TREZOR")).unwrap());
        assert!(!detection.passes_own_checks(Some("trezor")).unwrap());
        assert!(!detection.passes_own_checks(None).unwrap());
        assert_eq!(
            detection.passes_own_checks(Some("")),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
    }

    /// A hidden wallet's state is refused when a recovery would read it as checked (rule I29).
    #[test]
    fn a_state_that_passes_the_wallet_check_reads_as_checked() {
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut state: State = [0; STATE_BYTES];
        state[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let reads = |state: &State, passphrase| {
            LengthDetection::of(state)
                .reads_as_checked(passphrase)
                .unwrap()
        };
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
        let packed = pack(&entropy(16)).unwrap();
        assert!(reads(state_of(&packed), ""));
    }
}
