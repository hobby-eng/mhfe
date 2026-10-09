//! What a container or an original phrase tells before any Argon2 work: the facts that a front
//! end shows and decides its questions by, kept here so that no front end keeps a copy of the
//! rules behind them.

use zeroize::Zeroizing;

use crate::memory::LockedText;
use crate::packing;
use crate::phrase::{self, WORD_COUNTS};
use crate::suite::Suite;
use crate::{other_detected_lengths, read_phrase, wallet, MhfeError, PhraseLength};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// The lengths of an original that has a built-in check in a 24-word container: 12, 15, 18 and
/// 21 words. A 24-word original fills the container's state and leaves no room for one.
pub const BUILT_IN_CHECK_WORD_COUNTS: [usize; 4] = packing::SHORT_WORD_COUNTS;

/// A container as read, with what its words alone tell: its suite, the lengths its original may
/// have and the checks a recovery of it can be compared with.
pub struct ContainerFacts {
    /// Every word written out in full and in lower case, one space apart.
    words: Zeroizing<String>,
    word_count: usize,
    suite: Suite,
}

/// How a phrase recovered to be encrypted again is confirmed before it is (the re-encryption
/// guard of [`crate::Mhfe::recover_confirmed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationNeeded {
    /// Its built-in check at the length the owner states: a 12- to 21-word original of a 24-word
    /// container.
    BuiltInCheck,
    /// A receiving address or the master key fingerprint of the wallet, or the owner, who compares
    /// the phrase with their backup: a 24-word original and a same-length container have no check,
    /// and a detected length is not confirmed by one, as a 24-word original may pass a short check
    /// by chance (AUD-017-FUN001).
    WalletOrOwner,
}

impl ContainerFacts {
    /// Reads a container, refusing anything but a valid English BIP39 phrase of 12, 15, 18, 21
    /// or 24 words with [`MhfeError::InvalidContainer`]. Any spacing and letter case and the first
    /// four letters of a word are accepted, as for an original phrase.
    pub fn read(text: &str) -> Result<Self, MhfeError> {
        let container = phrase::parse_container(text).map_err(MhfeError::InvalidContainer)?;
        let word_count = container.word_count();
        Ok(Self {
            words: phrase::phrase_text(&container),
            word_count,
            suite: Suite::of_container(word_count)?,
        })
    }

    /// The container as read: every word written out in full and in lower case, one space apart,
    /// so that a person can compare it with the backup.
    pub fn words(&self) -> &str {
        &self.words
    }

    /// The number of words of the container: 24, or 12 to 21 for a same-length container.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// The suite, which the word count selects: 24 words are suite 3, 12 to 21 words suite 4.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The lengths the original phrase may have: any of the five for a 24-word container, whose
    /// owner states the length where it matters, and the container's own for a same-length one.
    pub fn phrase_lengths(&self) -> &[usize] {
        match self.suite {
            Suite::TwentyFourWords => &WORD_COUNTS,
            Suite::SameLength => std::slice::from_ref(&self.word_count),
        }
    }

    /// The lengths of an original whose built-in check a recovery can be compared with: 12 to 21
    /// words for a 24-word container, none for a same-length container, which has no check.
    pub fn built_in_check_lengths(&self) -> &'static [usize] {
        self.suite.built_in_check_lengths()
    }

    /// Whether other passwords open hidden wallets on this container
    /// ([`crate::Mhfe::derive_wallet`]): on a 24-word container only, for now.
    pub fn opens_hidden_wallets(&self) -> bool {
        self.suite.holds_full_state()
    }

    /// Refuses a `length` the phrase of this container cannot have: a same-length container keeps
    /// the length of its original (`LENGTH_CHOICE_NOT_APPLICABLE`), which detection gives.
    pub fn require_length(&self, length: PhraseLength) -> Result<(), MhfeError> {
        match length {
            PhraseLength::Words(words) if !self.phrase_lengths().contains(&words.get()) => {
                Err(MhfeError::LengthChoiceNotApplicable {
                    container_words: self.word_count,
                })
            }
            _ => Ok(()),
        }
    }

    /// Refuses a reference this container cannot be checked with, before any Argon2 work, as a
    /// check refuses it: the built-in check or the phrase's own checks of a same-length container,
    /// a length without a built-in check, and the wallet check where it does not apply or has no
    /// passphrase.
    pub fn require_reference(&self, reference: &crate::Reference<'_>) -> Result<(), MhfeError> {
        crate::rehearsal::refuse_impossible(self.word_count, reference)
    }

    /// Refuses hidden wallets on a container that opens none, before any Argon2 work.
    pub fn require_hidden_wallets(&self) -> Result<(), MhfeError> {
        if !self.opens_hidden_wallets() {
            return Err(MhfeError::NoHiddenWallets {
                container_words: self.word_count,
            });
        }
        Ok(())
    }

    /// Whether a recovery can be compared with the wallet check of a phrase drawn to pass it
    /// ([`crate::wallet_check`]). Such a phrase has 24 words, so only a 24-word container holds it.
    pub fn offers_wallet_check(&self) -> bool {
        self.suite.holds_full_state()
    }

    /// How a phrase of the given `length` recovered from this container is confirmed before it is
    /// encrypted again. A same-length container keeps the length of its original, so another
    /// length is refused with [`MhfeError::LengthChoiceNotApplicable`], and detection gives that
    /// length.
    pub fn confirmation_needed(
        &self,
        length: PhraseLength,
    ) -> Result<ConfirmationNeeded, MhfeError> {
        self.require_length(length)?;
        let words = match (length, self.suite) {
            (PhraseLength::Words(words), _) => words.get(),
            (PhraseLength::Detect, Suite::SameLength) => self.word_count,
            (PhraseLength::Detect, Suite::TwentyFourWords) => {
                return Ok(ConfirmationNeeded::WalletOrOwner)
            }
        };
        if self.built_in_check_lengths().contains(&words) {
            Ok(ConfirmationNeeded::BuiltInCheck)
        } else {
            Ok(ConfirmationNeeded::WalletOrOwner)
        }
    }

    /// The master key fingerprint of the wallet that the container's own words open without a
    /// BIP39 passphrase. A container is a valid phrase too, but that wallet is not the owner's.
    /// It costs one PBKDF2-HMAC-SHA512 of 2,048 iterations, as BIP39 seeds do.
    pub fn fingerprint(&self) -> Result<[u8; 4], MhfeError> {
        wallet::master_fingerprint(&self.words, "")
    }
}

/// An original seed phrase as read, with what it tells before it is encrypted: its length, the
/// other lengths a recovery with automatic detection would take it for, and the containers it can
/// have.
pub struct OriginalFacts {
    /// Every word written out in full and in lower case, one space apart. It is the secret, so it
    /// is kept out of swap and wiped when dropped.
    words: LockedText,
    word_count: usize,
    other_lengths: Vec<usize>,
}

/// A container an original phrase can have, with what a person needs to know to choose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerChoice {
    suite: Suite,
    word_count: usize,
    wrong_word_passes_one_in: u32,
}

impl OriginalFacts {
    /// Reads an original phrase, refusing anything but a valid English BIP39 phrase of 12, 15,
    /// 18, 21 or 24 words with [`MhfeError::InvalidPhrase`]. Any spacing and letter case and the
    /// first four letters of a word are accepted.
    pub fn read(phrase: &str) -> Result<Self, MhfeError> {
        let words = LockedText::copy_of(&read_phrase(phrase)?);
        Ok(Self {
            word_count: words.split(' ').count(),
            other_lengths: other_detected_lengths(&words)?,
            words,
        })
    }

    /// The phrase as read: every word written out in full and in lower case, one space apart, so
    /// that a person can see what was understood.
    pub fn words(&self) -> &str {
        &self.words
    }

    /// The number of words of the phrase: 12, 15, 18, 21 or 24.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// The lengths other than the phrase's own that a recovery with automatic detection would
    /// also accept from a 24-word container: empty for almost every phrase
    /// ([`crate::other_detected_lengths`]). When not, the owner keeps the word count and states it
    /// during recovery.
    pub fn other_lengths(&self) -> &[usize] {
        &self.other_lengths
    }

    /// [`Self::other_lengths`] for a container of `suite`: only a 24-word container carries the
    /// built-in checks that detection could misread, so a same-length container has none.
    pub fn other_lengths_in(&self, suite: Suite) -> &[usize] {
        if suite.built_in_check_lengths().is_empty() {
            return &[];
        }
        &self.other_lengths
    }

    /// The containers this phrase can have, the recommended one first: 24 words, and for a 12- to
    /// 21-word phrase a container as long as the phrase, which only the person's own choice may
    /// select.
    pub fn container_choices(&self) -> Vec<ContainerChoice> {
        let mut choices = vec![ContainerChoice::new(
            Suite::TwentyFourWords,
            packing::STATE_WORDS,
        )];
        // A 24-word phrase fills the whole state: its only container has 24 words.
        if self.word_count < packing::STATE_WORDS {
            choices.push(ContainerChoice::new(Suite::SameLength, self.word_count));
        }
        choices
    }
}

impl ContainerChoice {
    fn new(suite: Suite, word_count: usize) -> Self {
        Self {
            suite,
            word_count,
            wrong_word_passes_one_in: 1 << packing::checksum_bits(word_count),
        }
    }

    /// The suite of the container: [`Suite::SameLength`] only for the phrase's own length.
    pub fn suite(self) -> Suite {
        self.suite
    }

    /// The number of words of the container.
    pub fn word_count(self) -> usize {
        self.word_count
    }

    /// How rarely a word copied wrongly still passes the container's BIP39 checksum: about once
    /// in 256 for 24 words, but once in 16 for 12, whose checksum is shorter.
    pub fn wrong_word_passes_one_in(self) -> u32 {
        self.wrong_word_passes_one_in
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WordCount;

    const ZERO_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const LEGAL_24: &str = "legal winner thank year wave sausage worth useful legal winner thank year \
                            wave sausage worth useful legal winner thank year wave sausage worth title";

    /// A valid phrase of `words` words: all-zero entropy, as in the BIP39 test vectors.
    fn zero_phrase(words: usize) -> Zeroizing<String> {
        let bytes = packing::entropy_bytes(words).unwrap();
        crate::phrase_from_entropy(&vec![0; bytes]).unwrap()
    }

    fn words(count: usize) -> PhraseLength {
        PhraseLength::Words(WordCount::new(count).unwrap())
    }

    #[test]
    fn a_container_is_read_as_typed_and_written_out() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon abandon abou ";
        let container = ContainerFacts::read(typed).unwrap();
        assert_eq!(container.words(), ZERO_12);
        assert_eq!(container.word_count(), 12);
        let bad_checksum = ZERO_12.replace("about", "abandon");
        for bad in ["abandon abandon", &bad_checksum] {
            let refused = ContainerFacts::read(bad).err().unwrap();
            assert_eq!(refused.code(), "INVALID_CONTAINER", "{bad}");
        }
    }

    #[test]
    fn a_24_word_container_holds_any_length_and_offers_every_check() {
        let container = ContainerFacts::read(LEGAL_24).unwrap();
        assert_eq!(container.suite(), Suite::TwentyFourWords);
        assert_eq!(container.phrase_lengths(), [12, 15, 18, 21, 24]);
        assert_eq!(container.built_in_check_lengths(), [12, 15, 18, 21]);
        assert!(container.opens_hidden_wallets());
        assert!(container.offers_wallet_check());
        for short in BUILT_IN_CHECK_WORD_COUNTS {
            assert_eq!(
                container.confirmation_needed(words(short)),
                Ok(ConfirmationNeeded::BuiltInCheck)
            );
        }
        assert_eq!(
            container.confirmation_needed(words(24)),
            Ok(ConfirmationNeeded::WalletOrOwner)
        );
        assert_eq!(
            container.confirmation_needed(PhraseLength::Detect),
            Ok(ConfirmationNeeded::WalletOrOwner)
        );
    }

    #[test]
    fn a_same_length_container_keeps_its_length_and_has_no_check() {
        for count in BUILT_IN_CHECK_WORD_COUNTS {
            let container = ContainerFacts::read(&zero_phrase(count)).unwrap();
            assert_eq!(container.suite(), Suite::SameLength);
            assert_eq!(container.phrase_lengths(), [count]);
            assert!(container.built_in_check_lengths().is_empty());
            assert!(!container.opens_hidden_wallets());
            assert!(!container.offers_wallet_check());
            for length in [words(count), PhraseLength::Detect] {
                assert_eq!(
                    container.confirmation_needed(length),
                    Ok(ConfirmationNeeded::WalletOrOwner)
                );
            }
            for other in WORD_COUNTS.into_iter().filter(|&other| other != count) {
                assert_eq!(
                    container.confirmation_needed(words(other)),
                    Err(MhfeError::LengthChoiceNotApplicable {
                        container_words: count
                    })
                );
            }
        }
    }

    /// The well-known fingerprint of the all-zero 12-word phrase without a passphrase.
    #[test]
    fn a_container_has_the_fingerprint_of_its_own_words() {
        let container = ContainerFacts::read(ZERO_12).unwrap();
        assert_eq!(container.fingerprint(), Ok([0x73, 0xc5, 0xda, 0x0a]));
    }

    #[test]
    fn an_original_is_read_as_typed_into_locked_memory() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon abandon abou ";
        let original = OriginalFacts::read(typed).unwrap();
        assert_eq!(original.words(), ZERO_12);
        assert_eq!(original.word_count(), 12);
        assert!(original.other_lengths().is_empty());
        // Reserved at its final size, so that no growing copy of the words is left behind.
        assert_eq!(original.words.capacity(), ZERO_12.len());
        assert_eq!(original.words.is_locked(), cfg!(unix));
        let refused = OriginalFacts::read(&ZERO_12.replace("about", "abandon"))
            .err()
            .unwrap();
        assert_eq!(refused.code(), "INVALID_PHRASE");
    }

    #[test]
    fn a_short_original_can_keep_its_length_at_the_cost_of_a_weaker_checksum() {
        for (count, one_in) in [(12, 16), (15, 32), (18, 64), (21, 128)] {
            let original = OriginalFacts::read(&zero_phrase(count)).unwrap();
            assert_eq!(
                original.container_choices(),
                [
                    ContainerChoice::new(Suite::TwentyFourWords, 24),
                    ContainerChoice::new(Suite::SameLength, count),
                ]
            );
            let same_length = original.container_choices()[1];
            assert_eq!(same_length.suite(), Suite::SameLength);
            assert_eq!(same_length.word_count(), count);
            assert_eq!(same_length.wrong_word_passes_one_in(), one_in);
        }
        // A 24-word phrase has one container, of 24 words.
        let choices = OriginalFacts::read(LEGAL_24).unwrap().container_choices();
        assert_eq!(choices, [ContainerChoice::new(Suite::TwentyFourWords, 24)]);
        assert_eq!(choices[0].suite(), Suite::TwentyFourWords);
        assert_eq!(choices[0].word_count(), 24);
        assert_eq!(choices[0].wrong_word_passes_one_in(), 256);
    }

    #[test]
    fn an_original_names_the_other_lengths_detection_would_take() {
        use crate::packing::tests::{state_from_hex, AMBIGUOUS_STATES};
        for (text, [short, long]) in AMBIGUOUS_STATES {
            let state = state_from_hex(text);
            let bytes = packing::entropy_bytes(short).unwrap();
            let phrase = crate::phrase_from_entropy(&state[..bytes]).unwrap();
            assert_eq!(
                OriginalFacts::read(&phrase).unwrap().other_lengths(),
                [long]
            );
        }
    }
}
