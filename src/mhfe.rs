//! Creating a container and recovering a phrase (specification: "Creating a container",
//! "Recovering a mnemonic" and their suite 4 forms).

use bip39::Mnemonic;
use zeroize::{Zeroize, Zeroizing};

use crate::container::ContainerFacts;
use crate::detection::LengthDetection;
use crate::engine::Argon2Engine;
#[cfg(not(target_arch = "wasm32"))]
use crate::engine::NativeEngine;
use crate::feistel::{Geometry, Permutation};
use crate::memory::{LockedBytes, LockedText};
use crate::packing::{self, State, STATE_WORDS};
use crate::phrase::{self, locked_phrase_from_entropy, phrase_from_entropy};
use crate::suite::{Suite, ROUNDS};
use crate::wallet_check;
use crate::{MhfeError, Password, WorkFactor};

// The self-checks of the cipher and the published vectors they replay; see known_answers.rs.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
mod published_rounds;

/// Called with the number of the round about to start and the number of rounds in the whole
/// operation: 12 for a recovery or a check, 24 for an encryption, which recovers its result once
/// more to check it. Returning an error, such as [`MhfeError::Cancelled`], stops before that round.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(u32, u32) -> Result<(), MhfeError>;

/// Rounds of an encryption: twelve to encrypt and twelve to check the result.
pub const ENCRYPTION_ROUNDS: u32 = 2 * ROUNDS;

/// The length of an original phrase: 12, 15, 18, 21 or 24 words, the BIP39 lengths MHFE takes.
/// It is made only by [`WordCount::new`], so it never holds any other number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordCount(usize);

impl WordCount {
    /// Refuses every other number with [`MhfeError::InvalidWordCount`].
    pub fn new(words: usize) -> Result<Self, MhfeError> {
        packing::entropy_bytes(words)?;
        Ok(Self(words))
    }

    pub fn get(self) -> usize {
        self.0
    }

    /// The bytes of entropy a BIP39 phrase of this length carries: 16 for 12 words, 32 for 24.
    pub fn entropy_bytes(self) -> usize {
        packing::entropy_of_words(self.0)
    }
}

/// How recovery of a 24-word container learns the length of the original phrase. A same-length
/// container keeps its original's length and takes only [`PhraseLength::Detect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseLength {
    /// Tests the 12-, 15-, 18- and 21-word layouts and falls back to 24 words.
    Detect,
    /// The length the user states. The layouts are tested all the same, and a built-in check that
    /// passes takes precedence over the stated length (the specification's recovery rules): a
    /// person can misremember a length, while a check passes by chance at most once in 2^32.
    Words(WordCount),
}

impl PhraseLength {
    /// The word count a front end passes as a number, 0 standing for detection, as the browser
    /// package and `--words auto` take it.
    pub fn from_count(count: usize) -> Result<Self, MhfeError> {
        match count {
            0 => Ok(Self::Detect),
            words => WordCount::new(words).map(Self::Words),
        }
    }
}

/// One phrase produced by recovery, read-only: its text stays in the buffer that was locked
/// before the words were written into it, which no caller can grow or replace (AUD-012-SEC002).
///
/// It is read through its methods:
///
/// ```
/// fn length(recovered: &mhfe::RecoveredPhrase) -> usize {
///     recovered.phrase().len()
/// }
/// ```
///
/// and its phrase can be neither grown nor replaced:
///
/// ```compile_fail
/// fn grow(recovered: &mut mhfe::RecoveredPhrase) {
///     recovered.phrase.push_str(" more");
/// }
/// ```
pub struct RecoveredPhrase {
    words: usize,
    verified: bool,
    phrase: LockedText,
    suite: Suite,
    /// The length the person stated, where the built-in checks gave this reading another.
    stated_words: Option<usize>,
    /// The other 12- to 21-word lengths whose built-in check passes too, by chance.
    other_lengths: Vec<usize>,
}

/// What a recovered phrase is known to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// A 12- to 21-word phrase that passed its built-in check: the password and settings are
    /// right, though which wallet it is only a rehearsal against the wallet shows.
    Verified,
    /// From a same-length container, which has no built-in check.
    NoBuiltInCheck,
    /// Read as 24 words by automatic detection: for a shorter original the password or a setting
    /// is wrong.
    ReadAs24Detected,
    /// Read as 24 words, as the person stated.
    ReadAs24Chosen,
}

impl RecoveredPhrase {
    /// The words of the phrase.
    pub fn words(&self) -> usize {
        self.words
    }

    /// Whether the phrase passed its check value. Never true for 24 words or for a same-length
    /// container, which have none.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// The phrase, with every word written out.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The suite of the container it came from.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The phrase alone, still in its locked buffer, for a caller that keeps it.
    pub fn into_phrase(self) -> LockedText {
        self.phrase
    }

    /// What the phrase is known to be, for a recovery that took `length`.
    pub fn status(&self, length: PhraseLength) -> RecoveryStatus {
        if self.suite == Suite::SameLength {
            RecoveryStatus::NoBuiltInCheck
        } else if self.verified {
            RecoveryStatus::Verified
        } else if length == PhraseLength::Words(WordCount(STATE_WORDS)) {
            RecoveryStatus::ReadAs24Chosen
        } else {
            // Detected, or a short length stated whose check failed among others that pass.
            RecoveryStatus::ReadAs24Detected
        }
    }

    /// Whether a 24-word reading passes the 16-bit source check of `MHFE-WALLET-CHECK-SEED-1`
    /// with `passphrase`, the wallet's BIP39 passphrase or the empty one; `None` for another
    /// length, where it does not apply. Every recovery evaluates it on each 24-word reading, as
    /// the container does not show whether the phrase was made with the check (the
    /// specification's recovery rules). A pass makes a right password very likely; a phrase made
    /// without the check fails it, so a failure means something only to an owner who knows the
    /// wallet was made with it. One BIP39 seed: milliseconds.
    pub fn passes_wallet_check(&self, passphrase: &str) -> Result<Option<bool>, MhfeError> {
        if !self.offers_wallet_check() {
            return Ok(None);
        }
        wallet_check::phrase_passes(&self.phrase, passphrase).map(Some)
    }

    /// Whether this is a 24-word reading of a 24-word container, which the 16-bit source check
    /// applies to: a front end asks for the wallet's BIP39 passphrase whenever one comes out.
    pub fn offers_wallet_check(&self) -> bool {
        self.words == STATE_WORDS && self.suite == Suite::TwentyFourWords
    }

    /// The length the person stated, where it is not this reading's: the built-in checks found
    /// this length instead and took precedence, or, for the 24-word reading, another was stated.
    /// A front end says so; the phrase is right only if the stated length was misremembered, so
    /// a receiving address of the wallet should confirm it.
    pub fn stated_words(&self) -> Option<usize> {
        self.stated_words
    }

    /// The other 12- to 21-word lengths whose built-in check passes too, by chance, about once in
    /// 2^32 phrases: a stated length or the person's choice took this reading among them.
    pub fn other_lengths(&self) -> &[usize] {
        &self.other_lengths
    }

    /// Takes over `phrase`, whose buffer was locked before the words were written into it.
    fn new(words: usize, verified: bool, phrase: LockedText, suite: Suite) -> Self {
        Self {
            words,
            verified,
            phrase,
            suite,
            stated_words: None,
            other_lengths: Vec::new(),
        }
    }

    /// The reading as a recovery with `stated` gave it, beside the 12- to 21-word lengths `short`
    /// whose built-in check passes.
    fn compared_with(mut self, stated: Option<usize>, short: &[usize]) -> Self {
        self.stated_words = stated.filter(|&stated| stated != self.words);
        self.other_lengths = short
            .iter()
            .copied()
            .filter(|&words| words != self.words)
            .collect();
        self
    }
}

/// The result of recovery.
pub enum Recovery {
    /// One phrase: a short original that passed its check, or the 24-word reading, which
    /// cannot be verified. For a short original an unverified result usually means a wrong
    /// password, PIM, memory level or container. Its [`RecoveredPhrase::stated_words`] says when
    /// the check found another length than the one stated.
    Phrase(RecoveredPhrase),
    /// Several short lengths passed their check by accident, about once in four billion
    /// containers, or one did where 24 words were stated. Every candidate is listed, the checked
    /// ones first, followed by the unverified 24-word reading; the user picks the right one with
    /// public wallet data, such as a receiving address, or by stating a length that passes.
    Ambiguous(Vec<RecoveredPhrase>),
}

/// A container that has been computed but not yet checked (creation steps 1 to 5). It may be
/// shown to a person while [`Mhfe::check_new_container`] runs, clearly marked as not verified;
/// a program that receives it for further use should wait for the check.
pub struct NewContainer {
    /// The words of the container: 24, or as many as the original for a same-length container.
    pub words: Zeroizing<String>,
    /// The suite it was made with, which an application shows after creating it.
    pub suite: Suite,
    /// The state `X` the check must get back: the packed original, or the entropy itself. It is
    /// kept out of swap from before the first round until the check is done.
    source: LockedBytes,
}

/// MHFE at one work factor, together with the Argon2 engine that computes it.
pub struct Mhfe<E: Argon2Engine> {
    work: WorkFactor,
    engine: E,
}

#[cfg(not(target_arch = "wasm32"))]
impl Mhfe<NativeEngine> {
    /// Checks that the computer has the memory the settings need and reserves it once for all
    /// twelve rounds.
    pub fn new(work: WorkFactor) -> Result<Self, MhfeError> {
        Ok(Self {
            work,
            engine: NativeEngine::new(work)?,
        })
    }
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Uses `engine`, which must compute Argon2id at `work.argon2_cost()`: the browser engine,
    /// the engine of the self-checks that answers only published rounds, or a cheaper one in tests.
    #[cfg(any(test, not(target_arch = "wasm32"), feature = "browser-core"))]
    pub(crate) fn with_engine(work: WorkFactor, engine: E) -> Self {
        Self { work, engine }
    }

    /// The engine that computes the rounds, such as the browser engine, whose known answer an
    /// operation runs again after its last round.
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// The settings and the engine, for a wrapper that watches the engine's calls without
    /// changing them, as the self-test's witness of the round keys does.
    #[cfg(any(test, not(target_arch = "wasm32"), feature = "browser-core"))]
    pub(crate) fn parts_mut(&mut self) -> (WorkFactor, &mut E) {
        (self.work, &mut self.engine)
    }

    pub fn work_factor(&self) -> WorkFactor {
        self.work
    }

    /// Encrypts an original phrase and checks the result: [`Mhfe::encrypt_unchecked`] followed
    /// by [`Mhfe::check_new_container`], 24 rounds in all. With [`Suite::TwentyFourWords`], the
    /// default, any original of 12 to 24 words becomes a 24-word container; with
    /// [`Suite::SameLength`], which only the user's own choice may select, a 12- to 21-word
    /// original becomes a container of its own length.
    pub fn encrypt(
        &mut self,
        original: &str,
        password: &Password,
        suite: Suite,
        on_progress: ProgressCallback<'_>,
    ) -> Result<Zeroizing<String>, MhfeError> {
        let new = self.encrypt_unchecked(original, password, suite, on_progress)?;
        self.check_new_container(&new, password, on_progress)?;
        Ok(new.words)
    }

    /// Creation steps 1 to 5: rounds 1 to 12 of the 24 of an encryption. The result is not yet
    /// checked.
    pub fn encrypt_unchecked(
        &mut self,
        original: &str,
        password: &Password,
        suite: Suite,
        on_progress: ProgressCallback<'_>,
    ) -> Result<NewContainer, MhfeError> {
        // The entropy and the state are phrase in all but form: both are locked before they are
        // written, and stay locked through the twelve rounds, while the work area of Argon2 puts
        // the most pressure on memory.
        let entropy = locked_entropy(&phrase::parse(original).map_err(MhfeError::InvalidPhrase)?);
        suite.require_original(packing::words_of_entropy(entropy.len()))?;
        let (geometry, x) = match suite {
            Suite::TwentyFourWords => (Geometry::SUITE_3, packing::pack(&entropy)?),
            // Suite 4 encrypts the entropy itself: there is no room for a check value.
            Suite::SameLength => (Geometry::same_length(entropy.len())?, entropy),
        };
        let y = self.permutation(password, geometry).forward(
            &x,
            &mut |round| on_progress(round, ENCRYPTION_ROUNDS),
            None,
        )?;
        reject_fixed_point(&x, &y)?;
        Ok(NewContainer {
            words: phrase_from_entropy(&y)?,
            suite,
            source: x,
        })
    }

    /// Creation step 6, rounds 13 to 24: reads the container's words again, recovers them and
    /// compares the result with the original. A memory error or another fault during the long
    /// computation would otherwise give a container that no longer turns back into the original.
    pub fn check_new_container(
        &mut self,
        new: &NewContainer,
        password: &Password,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(), MhfeError> {
        // Starting from the words covers their encoding as well as the rounds.
        let container =
            phrase::parse_container(&new.words).map_err(|_| MhfeError::VerificationFailed)?;
        let (suite, y) = container_state(&container)?;
        if suite != new.suite {
            return Err(MhfeError::VerificationFailed);
        }
        let recovered = self.permutation(password, geometry(suite, &y)?).inverse(
            &y,
            &mut |round| on_progress(ROUNDS + round, ENCRYPTION_ROUNDS),
            None,
        )?;
        if recovered[..] == new.source[..] {
            Ok(())
        } else {
            Err(MhfeError::VerificationFailed)
        }
    }

    /// Recovers the original phrase from a container. Its word count selects the suite: 24 words
    /// are suite 3, and 12 to 21 words a same-length container, which gives a phrase of the same
    /// length that nothing confirms.
    pub fn decrypt(
        &mut self,
        container: &str,
        password: &Password,
        length: PhraseLength,
        on_progress: ProgressCallback<'_>,
    ) -> Result<Recovery, MhfeError> {
        self.decrypt_as(container, password, None, length, on_progress)
    }

    /// [`Mhfe::decrypt`] for a suite the user selected: a container of the other suite's word
    /// count is refused before any Argon2 work instead of being read with the other suite.
    pub fn decrypt_as(
        &mut self,
        container: &str,
        password: &Password,
        selected: Option<Suite>,
        length: PhraseLength,
        on_progress: ProgressCallback<'_>,
    ) -> Result<Recovery, MhfeError> {
        // Every input is checked before the first Argon2 call; a WordCount is valid already. A
        // suite selected against the container's words is refused as the container is read.
        if selected != Some(Suite::TwentyFourWords) {
            ContainerFacts::read(container)?.require_length(length)?;
        }
        let (suite, x) = self.recover_state(container, password, selected, on_progress)?;
        match suite {
            Suite::TwentyFourWords => recover(suite_3_state(&x)?, length),
            Suite::SameLength => Ok(Recovery::Phrase(read_same_length(&x)?)),
        }
    }

    /// Steps 1 and 2 of recovery: checks the container, then computes `X = Perm^-1(Y)` with the
    /// suite its word count selects. `X` is written into locked memory, which the caller holds
    /// while it compares or reads it.
    pub(crate) fn recover_state(
        &mut self,
        container: &str,
        password: &Password,
        selected: Option<Suite>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(Suite, LockedBytes), MhfeError> {
        let container = phrase::parse_container(container).map_err(MhfeError::InvalidContainer)?;
        let (suite, y) = container_state(&container)?;
        match selected {
            Some(Suite::TwentyFourWords) if suite != Suite::TwentyFourWords => {
                return Err(MhfeError::InvalidContainer(format!(
                    "it has {} words, but a 24-word container always has 24",
                    container.word_count()
                )))
            }
            Some(Suite::SameLength) if suite != Suite::SameLength => {
                return Err(MhfeError::InvalidContainer(format!(
                    "it has {STATE_WORDS} words, but a same-length container has {}",
                    phrase::counts_text(&packing::SHORT_WORD_COUNTS)
                )))
            }
            _ => {}
        }
        let x = self.permutation(password, geometry(suite, &y)?).inverse(
            &y,
            &mut |round| on_progress(round, ROUNDS),
            None,
        )?;
        Ok((suite, x))
    }

    pub(crate) fn permutation<'a>(
        &'a mut self,
        password: &'a Password,
        geometry: Geometry,
    ) -> Permutation<'a> {
        Permutation {
            engine: &mut self.engine,
            password,
            work: self.work,
            geometry,
        }
    }
}

/// The permutation of a suite for a state `y` of the container's size.
fn geometry(suite: Suite, y: &[u8]) -> Result<Geometry, MhfeError> {
    match suite {
        Suite::TwentyFourWords => Ok(Geometry::SUITE_3),
        Suite::SameLength => Geometry::same_length(y.len()),
    }
}

/// A recovered suite 3 state as the fixed 256-bit array the packing works on, read in place: a
/// copy would lie outside the locked buffer that holds it.
pub(crate) fn suite_3_state(x: &[u8]) -> Result<&State, MhfeError> {
    x.try_into()
        .map_err(|_| MhfeError::Internal(format!("a suite 3 state has 32 bytes, not {}", x.len())))
}

/// Step 3 of recovery: reads `X` as the chosen length, or tests the short layouts.
/// Reads the state `x` of a 24-word container as the specification's recovery does (step 3 and
/// the stated length after it). Every short length's built-in check is tested, also when the
/// person stated a length, and a check that passes takes precedence over the stated length.
pub(crate) fn recover(x: &State, length: PhraseLength) -> Result<Recovery, MhfeError> {
    let detection = LengthDetection::of(x);
    let short = detection.short_lengths();
    let stated = match length {
        PhraseLength::Words(words) => Some(words.get()),
        PhraseLength::Detect => None,
    };
    let read = |words| Ok(read_as(x, words)?.compared_with(stated, short));
    match (stated, short) {
        // A stated length whose check passes is the result, also among others that pass by
        // chance.
        (Some(words), _) if short.contains(&words) => Ok(Recovery::Phrase(read(words)?)),
        // No check passes: the 24-word reading, unless a short length was stated, whose check
        // then fails: a wrong password or setting, or a 24-word phrase.
        (None | Some(STATE_WORDS), []) => Ok(Recovery::Phrase(read(STATE_WORDS)?)),
        (Some(_), []) => Err(MhfeError::VerifierMismatch),
        // One check passes, at another short length than the one stated, or with none stated.
        (None, [words]) => Ok(Recovery::Phrase(read(*words)?)),
        (Some(stated), [words]) if stated != STATE_WORDS => Ok(Recovery::Phrase(read(*words)?)),
        // Several checks pass, or one beside 24 stated words, which pass a short check by chance
        // about once in 2^32: every reading, the checked ones first and the 24-word one last.
        _ => Ok(Recovery::Ambiguous(
            detection
                .readings()
                .map(read)
                .collect::<Result<Vec<_>, MhfeError>>()?,
        )),
    }
}

/// Refuses a container equal to the original. A working implementation meets `Y = X` with
/// probability 2^-256 (2^-ENT for a same-length container); the check stops a broken engine that
/// returns its input from exposing the original phrase.
pub(crate) fn reject_fixed_point(x: &[u8], y: &[u8]) -> Result<(), MhfeError> {
    if x == y {
        Err(MhfeError::FixedPoint)
    } else {
        Ok(())
    }
}

/// Creation, before the expensive work: the lengths other than the original's own that automatic
/// detection would also accept after recovery. Empty for almost every phrase; a random phrase
/// hits this with probability about 2^-32. When it is not empty, recovery with detection would
/// report a shorter reading or several candidates, so the owner should record the word count and
/// select it during recovery. This matters most for a 24-word original, which detection would
/// otherwise read as a verified shorter phrase.
pub fn other_detected_lengths(original: &str) -> Result<Vec<usize>, MhfeError> {
    let source = phrase::parse(original).map_err(MhfeError::InvalidPhrase)?;
    let words = source.word_count();
    let x = packing::pack(&locked_entropy(&source))?;
    Ok(LengthDetection::of(suite_3_state(&x)?)
        .short_lengths()
        .iter()
        .copied()
        .filter(|&length| length != words)
        .collect())
}

/// The suite and the encrypted state `Y` of a container: its entropy.
pub(crate) fn container_state(
    container: &Mnemonic,
) -> Result<(Suite, Zeroizing<Vec<u8>>), MhfeError> {
    let suite = Suite::of_container(container.word_count())?;
    Ok((suite, Zeroizing::new(container.to_entropy())))
}

/// Reads the state `x` of a same-length container as its only reading, the phrase of its own
/// length, which has no built-in check.
pub(crate) fn read_same_length(x: &[u8]) -> Result<RecoveredPhrase, MhfeError> {
    Ok(RecoveredPhrase::new(
        packing::words_of_entropy(x.len()),
        false,
        locked_phrase_from_entropy(x)?,
        Suite::SameLength,
    ))
}

/// Reads `X` as a phrase of `words` words; a short length must pass its check.
pub(crate) fn read_as(x: &State, words: usize) -> Result<RecoveredPhrase, MhfeError> {
    Ok(RecoveredPhrase::new(
        words,
        // A short length carries a built-in check, which unpack has passed.
        Suite::TwentyFourWords
            .built_in_check_lengths()
            .contains(&words),
        locked_phrase_from_entropy(packing::unpack(x, words)?)?,
        Suite::TwentyFourWords,
    ))
}

/// The entropy of `phrase` in a buffer that is locked before it is written into it, read from the
/// array that bip39 fills on the stack, which is wiped here, rather than from a vector it would
/// leave unlocked.
fn locked_entropy(phrase: &Mnemonic) -> LockedBytes {
    let (mut array, length) = phrase.to_entropy_array();
    let entropy = LockedBytes::copy_of(&array[..length]);
    array.zeroize();
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feistel::tests::HashEngine;
    use crate::test_support::{reduced, test_password, wrong_password};

    const ZERO_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const LEGAL_24: &str = "legal winner thank year wave sausage worth useful legal winner thank year \
                            wave sausage worth useful legal winner thank year wave sausage worth title";

    #[test]
    fn creation_warns_when_detection_would_accept_another_length() {
        use crate::packing::tests::{state_from_hex, AMBIGUOUS_STATES};
        assert!(other_detected_lengths(ZERO_12).unwrap().is_empty());
        assert!(other_detected_lengths(LEGAL_24).unwrap().is_empty());
        for (text, [short, long]) in AMBIGUOUS_STATES {
            let state = state_from_hex(text);
            // The short original of this state also passes the 21-word check.
            let bytes = packing::entropy_bytes(short).unwrap();
            let original = phrase_from_entropy(&state[..bytes]).unwrap();
            assert_eq!(other_detected_lengths(&original).unwrap(), [long]);
            // A 24-word original equal to the whole state would be detected as both lengths.
            let original = phrase_from_entropy(&state[..]).unwrap();
            assert_eq!(other_detected_lengths(&original).unwrap(), [short, long]);
        }
    }

    fn no_progress() -> impl FnMut(u32, u32) -> Result<(), MhfeError> {
        |_, _| Ok(())
    }

    /// A phrase of `words` words whose entropy bytes all differ, another for every length.
    fn varied_phrase(words: usize) -> Zeroizing<String> {
        let entropy: Vec<u8> = (0..packing::entropy_bytes(words).unwrap())
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(words as u8))
            .collect();
        phrase_from_entropy(&entropy).unwrap()
    }

    /// The recovery of `container` at the stated length `words`.
    fn decrypt_as(
        mhfe: &mut Mhfe<NativeEngine>,
        container: &str,
        password: &Password,
        words: WordCount,
    ) -> RecoveredPhrase {
        let length = PhraseLength::Words(words);
        only_phrase(
            mhfe.decrypt(container, password, length, &mut no_progress())
                .unwrap(),
        )
    }

    fn only_phrase(recovery: Recovery) -> RecoveredPhrase {
        match recovery {
            Recovery::Phrase(phrase) => phrase,
            Recovery::Ambiguous(_) => panic!("unexpected ambiguous result"),
        }
    }

    /// The entropy and the state of an encryption are locked before the first round and stay so
    /// until its check is done, and a recovered state is written into locked memory (AUD-010).
    #[test]
    fn the_state_of_an_operation_is_held_in_locked_memory() {
        let password = test_password();
        let mut mhfe = reduced();
        for suite in [Suite::TwentyFourWords, Suite::SameLength] {
            let new = mhfe
                .encrypt_unchecked(ZERO_12, &password, suite, &mut no_progress())
                .unwrap();
            assert_eq!(new.source.is_locked(), cfg!(unix));
            mhfe.check_new_container(&new, &password, &mut no_progress())
                .unwrap();
            let (_, x) = mhfe
                .recover_state(&new.words, &password, None, &mut no_progress())
                .unwrap();
            assert_eq!(x[..], new.source[..]);
            assert_eq!(x.is_locked(), cfg!(unix));
        }
        let entropy = locked_entropy(&phrase::parse(LEGAL_24).unwrap());
        assert_eq!(entropy[..], [0x7f; 32]);
        assert_eq!(entropy.is_locked(), cfg!(unix));
    }

    #[test]
    fn round_trips_every_phrase_length_with_the_c_engine() {
        let password = test_password();
        let mut mhfe = reduced();
        for words in [12, 15, 18, 21, 24] {
            let original = varied_phrase(words);
            let container = mhfe
                .encrypt(
                    &original,
                    &password,
                    Suite::TwentyFourWords,
                    &mut no_progress(),
                )
                .unwrap();
            assert_eq!(container.split(' ').count(), 24);

            let detected = only_phrase(
                mhfe.decrypt(
                    &container,
                    &password,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unwrap(),
            );
            assert_eq!(*detected.phrase, *original);
            assert_eq!(detected.words, words);
            assert_eq!(detected.verified, words < 24);

            // Stating the length gives the same phrase.
            let chosen = decrypt_as(
                &mut mhfe,
                &container,
                &password,
                WordCount::new(words).unwrap(),
            );
            assert_eq!(*chosen.phrase, *original);
        }
    }

    /// The same container must come out of every engine at this reduced cost: the native build
    /// here, and both Emscripten builds in scripts/verify-browser-package.mjs.
    pub(crate) const REDUCED_COST_CONTAINER: &str =
        "slush crime nose carry menu cabbage already cart \
        lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope \
        dream sweet";

    #[test]
    fn the_reduced_cost_container_is_the_same_everywhere() {
        let password = test_password();
        let container = reduced()
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        assert_eq!(*container, REDUCED_COST_CONTAINER);
    }

    #[test]
    fn a_wrong_password_ends_unverified_or_as_a_mismatch() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();

        let detected = only_phrase(
            mhfe.decrypt(&container, &wrong, PhraseLength::Detect, &mut no_progress())
                .unwrap(),
        );
        assert_eq!(detected.words, 24);
        assert!(!detected.verified);
        assert_eq!(
            mhfe.decrypt(
                &container,
                &wrong,
                PhraseLength::Words(WordCount::new(12).unwrap()),
                &mut no_progress()
            )
            .err(),
            Some(MhfeError::VerifierMismatch)
        );
    }

    /// The length rules of recovery (AUD-015-FUN001): every short length's check is tested also
    /// when a length is stated, and one that passes takes precedence over the stated length.
    #[test]
    fn a_check_that_passes_takes_precedence_over_a_stated_length() {
        let password = test_password();
        let mut mhfe = reduced();
        let mut stated = |container: &str, words: usize| {
            mhfe.decrypt(
                container,
                &password,
                PhraseLength::Words(WordCount::new(words).unwrap()),
                &mut no_progress(),
            )
        };
        let twelve = reduced()
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        // Another short length stated: the 12-word reading, which says what was stated.
        for words in [15, 18, 21] {
            let found = only_phrase(stated(&twelve, words).unwrap());
            assert_eq!((found.words, found.verified), (12, true), "{words}");
            assert_eq!(*found.phrase, *ZERO_12);
            assert_eq!(found.stated_words(), Some(words));
            assert!(found.other_lengths().is_empty());
        }
        // The right length stated: the same reading, with nothing to say.
        let found = only_phrase(stated(&twelve, 12).unwrap());
        assert_eq!((found.words, found.stated_words()), (12, None));
        // 24 words stated: the checked 12-word reading first, then the 24-word one, unverified.
        let Recovery::Ambiguous(readings) = stated(&twelve, 24).unwrap() else {
            panic!("24 stated beside a passing check must offer both readings");
        };
        let shape: Vec<_> = readings
            .iter()
            .map(|reading| (reading.words, reading.verified, reading.stated_words()))
            .collect();
        assert_eq!(shape, [(12, true, Some(24)), (24, false, None)]);
        assert_eq!(*readings[0].phrase, *ZERO_12);
        assert!(readings[1]
            .phrase
            .starts_with("abandon abandon abandon abandon abandon abandon"));
        // A 24-word original passes no short check: a stated short length is refused, as a
        // wrong password or setting would be, and 24 stated words give its reading alone.
        let twenty_four = reduced()
            .encrypt(
                LEGAL_24,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        assert_eq!(
            stated(&twenty_four, 12).err(),
            Some(MhfeError::VerifierMismatch)
        );
        let found = only_phrase(stated(&twenty_four, 24).unwrap());
        assert_eq!(
            (found.words, found.verified, found.stated_words()),
            (24, false, None)
        );
        assert_eq!(*found.phrase, *LEGAL_24);
    }

    /// Every 24-word reading offers the 16-bit source check with any passphrase, the empty one
    /// included; a short reading does not. The phrase is the published wallet-check vector:
    /// "abandon" 21 times and "above proof fatigue", which passes with "TREZOR" and fails without
    /// a passphrase (vectors/profiles, src/wallet_check/known_answers.rs).
    #[test]
    fn a_24_word_reading_offers_the_source_check() {
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let phrase = phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        let password = test_password();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(
                &phrase,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        let read = only_phrase(
            mhfe.decrypt(
                &container,
                &password,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unwrap(),
        );
        assert!(read.offers_wallet_check());
        assert_eq!(read.passes_wallet_check("TREZOR"), Ok(Some(true)));
        assert_eq!(read.passes_wallet_check(""), Ok(Some(false)));
        let short = reduced()
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        let read = only_phrase(
            mhfe.decrypt(&short, &password, PhraseLength::Detect, &mut no_progress())
                .unwrap(),
        );
        assert!(!read.offers_wallet_check());
        assert_eq!(read.passes_wallet_check("TREZOR"), Ok(None));
    }

    /// A decoy password opens a container as another valid 24-word phrase, and a container
    /// created from that phrase with the decoy password is the same container. This is the
    /// consistency lemma of the deniability analysis in the specification's supplement: an owner
    /// can disclose the decoy password instead of the real one.
    #[test]
    fn a_decoy_password_gives_a_phrase_that_encrypts_back_to_the_same_container() {
        let password = test_password();
        let decoy = Password::new("another public test password").unwrap();
        let mut mhfe = reduced();
        for original in [ZERO_12, LEGAL_24] {
            let container = mhfe
                .encrypt(
                    original,
                    &password,
                    Suite::TwentyFourWords,
                    &mut no_progress(),
                )
                .unwrap();
            let opened = only_phrase(
                mhfe.decrypt(
                    &container,
                    &decoy,
                    PhraseLength::Words(WordCount::new(24).unwrap()),
                    &mut no_progress(),
                )
                .unwrap(),
            );
            assert_eq!(opened.words, 24);
            assert!(!opened.verified);
            assert_ne!(opened.phrase(), original);
            // An ordinary BIP39 phrase with a valid checksum, usable as a wallet of its own.
            assert_eq!(phrase::check_phrase(&opened.phrase).unwrap(), 24);

            // Automatic detection gives the same unverified 24-word reading, just as for an
            // honest 24-word original.
            let detected = only_phrase(
                mhfe.decrypt(&container, &decoy, PhraseLength::Detect, &mut no_progress())
                    .unwrap(),
            );
            assert_eq!((detected.words, detected.verified), (24, false));
            assert_eq!(detected.phrase(), opened.phrase());

            let again = mhfe
                .encrypt(
                    &opened.phrase,
                    &decoy,
                    Suite::TwentyFourWords,
                    &mut no_progress(),
                )
                .unwrap();
            assert_eq!(*again, *container);
        }
    }

    #[test]
    fn ambiguity_lists_every_candidate_and_the_24_word_reading() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        for (text, lengths) in packing::tests::AMBIGUOUS_STATES {
            // Encrypt the ambiguous state X directly, as if a phrase had packed into it.
            let x = packing::tests::state_from_hex(text);
            let y = mhfe
                .permutation(&password, Geometry::SUITE_3)
                .forward(&x, &mut |_| Ok(()), None)
                .unwrap();
            let container = phrase_from_entropy(&y[..]).unwrap();

            let Recovery::Ambiguous(candidates) = mhfe
                .decrypt(
                    &container,
                    &password,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unwrap()
            else {
                panic!("expected an ambiguous result for {lengths:?}");
            };
            let found: Vec<_> = candidates.iter().map(|candidate| candidate.words).collect();
            assert_eq!(found, [lengths[0], lengths[1], 24]);
            let verified: Vec<_> = candidates
                .iter()
                .map(|candidate| candidate.verified)
                .collect();
            assert_eq!(verified, [true, true, false]);
            for candidate in &candidates {
                let entropy = &x[..packing::entropy_bytes(candidate.words).unwrap()];
                assert_eq!(*candidate.phrase, *phrase_from_entropy(entropy).unwrap());
            }

            // A length stated among those that pass resolves the ambiguity, and names the other.
            let chosen = only_phrase(
                mhfe.decrypt(
                    &container,
                    &password,
                    PhraseLength::Words(WordCount::new(lengths[0]).unwrap()),
                    &mut no_progress(),
                )
                .unwrap(),
            );
            assert_eq!(chosen.words, lengths[0]);
            assert_eq!(chosen.other_lengths(), [lengths[1]]);
            assert_eq!(chosen.stated_words(), None);
            // A short length stated that does not pass leaves every reading to choose from.
            let other = [12, 15, 18, 21]
                .into_iter()
                .find(|words| !lengths.contains(words))
                .unwrap();
            let Recovery::Ambiguous(readings) = mhfe
                .decrypt(
                    &container,
                    &password,
                    PhraseLength::Words(WordCount::new(other).unwrap()),
                    &mut no_progress(),
                )
                .unwrap()
            else {
                panic!("a stated length that fails leaves the ambiguity");
            };
            let found: Vec<_> = readings.iter().map(|reading| reading.words).collect();
            assert_eq!(found, [lengths[0], lengths[1], 24]);
            assert!(readings
                .iter()
                .all(|reading| reading.stated_words() == Some(other)));
        }
    }

    #[test]
    fn invalid_inputs_fail_before_any_argon2_call() {
        struct NoCallsEngine;
        impl Argon2Engine for NoCallsEngine {
            fn derive(
                &mut self,
                _: &[u8],
                _: &[u8; 16],
                _: &mut [u8; 32],
            ) -> Result<(), MhfeError> {
                panic!("Argon2 was called for an invalid input");
            }
        }
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoCallsEngine);
        let bad_checksum = LEGAL_24.replace("title", "thank");

        assert!(matches!(
            mhfe.encrypt(
                "abandon abandon",
                &password,
                Suite::TwentyFourWords,
                &mut no_progress()
            ),
            Err(MhfeError::InvalidPhrase(_))
        ));
        assert!(matches!(
            mhfe.decrypt(
                &bad_checksum,
                &password,
                PhraseLength::Detect,
                &mut no_progress()
            ),
            Err(MhfeError::InvalidContainer(_))
        ));
        assert!(matches!(
            mhfe.decrypt(
                "abandon abandon abandon",
                &password,
                PhraseLength::Detect,
                &mut no_progress()
            ),
            Err(MhfeError::InvalidContainer(_))
        ));
        assert_eq!(
            mhfe.encrypt(LEGAL_24, &password, Suite::SameLength, &mut no_progress())
                .err(),
            Some(MhfeError::SameLengthNeedsShortPhrase)
        );
        assert_eq!(
            mhfe.decrypt(
                ZERO_12,
                &password,
                PhraseLength::Words(WordCount::new(24).unwrap()),
                &mut no_progress()
            )
            .err(),
            Some(MhfeError::LengthChoiceNotApplicable {
                container_words: 12
            })
        );
        assert_eq!(WordCount::new(13), Err(MhfeError::InvalidWordCount(13)));

        // A chosen length n accepts a container of exactly n words or of 24 words; any other
        // container, shorter or of another short length, is refused before any Argon2 work.
        for chosen in [12, 15, 18, 21] {
            for container_words in [12, 15, 18, 21] {
                if container_words == chosen {
                    continue;
                }
                let entropy = vec![7u8; packing::entropy_bytes(container_words).unwrap()];
                let container = phrase_from_entropy(&entropy).unwrap();
                assert_eq!(
                    mhfe.decrypt(
                        &container,
                        &password,
                        PhraseLength::Words(WordCount::new(chosen).unwrap()),
                        &mut no_progress()
                    )
                    .err(),
                    Some(MhfeError::LengthChoiceNotApplicable { container_words }),
                    "{container_words}-word container with {chosen} chosen"
                );
            }
        }

        // A selected suite never switches to the other one because of the word count: 24 words
        // select suite 3 only, and every other length is refused under it.
        let mut cases = vec![(LEGAL_24.to_owned(), Suite::SameLength)];
        for words in [12, 15, 18, 21] {
            let entropy = vec![7u8; packing::entropy_bytes(words).unwrap()];
            let short = phrase_from_entropy(&entropy).unwrap().to_string();
            cases.push((short, Suite::TwentyFourWords));
        }
        for (container, selected) in &cases {
            let (container, selected) = (container.as_str(), *selected);
            assert!(matches!(
                mhfe.decrypt_as(
                    container,
                    &password,
                    Some(selected),
                    PhraseLength::Detect,
                    &mut no_progress()
                ),
                Err(MhfeError::InvalidContainer(_))
            ));
        }
    }

    #[test]
    fn refuses_a_container_equal_to_the_original() {
        let state = [7u8; packing::STATE_BYTES];
        assert_eq!(
            reject_fixed_point(&state, &state),
            Err(MhfeError::FixedPoint)
        );
        let mut different = state;
        different[31] ^= 1;
        assert_eq!(reject_fixed_point(&state, &different), Ok(()));
    }

    #[test]
    fn encryption_checks_its_result_in_24_rounds() {
        let password = test_password();
        let mut steps = Vec::new();
        reduced()
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut |round, rounds| {
                    steps.push((round, rounds));
                    Ok(())
                },
            )
            .unwrap();
        let expected: Vec<(u32, u32)> = (1..=24).map(|round| (round, 24)).collect();
        assert_eq!(steps, expected);
    }

    #[test]
    fn a_fault_during_encryption_is_caught_by_the_check() {
        // An engine that gives a different key on every call, like a memory error would: the
        // container then does not turn back into the original and must not be shown.
        struct FlakyEngine(u8);
        impl Argon2Engine for FlakyEngine {
            fn derive(
                &mut self,
                password: &[u8],
                salt: &[u8; 16],
                key: &mut [u8; 32],
            ) -> Result<(), MhfeError> {
                HashEngine.derive(password, salt, key)?;
                self.0 = self.0.wrapping_add(1);
                key[0] ^= self.0;
                Ok(())
            }
        }
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), FlakyEngine(0));
        assert_eq!(
            mhfe.encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress()
            )
            .err(),
            Some(MhfeError::VerificationFailed)
        );
    }

    #[test]
    fn the_two_steps_give_the_same_container_as_encrypt() {
        let password = test_password();
        let mut mhfe = reduced();
        let new = mhfe
            .encrypt_unchecked(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        assert_eq!(*new.words, REDUCED_COST_CONTAINER);
        let mut rounds = Vec::new();
        mhfe.check_new_container(&new, &password, &mut |round, _| {
            rounds.push(round);
            Ok(())
        })
        .unwrap();
        assert_eq!(rounds, (13..=24).collect::<Vec<u32>>());

        // A container changed after it was computed, as by a fault in memory, fails the check.
        let mut changed = mhfe
            .encrypt_unchecked(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        changed.words = Zeroizing::new(changed.words.replacen("slush", "crime", 1));
        let wrong_password = Password::new("another password").unwrap();
        assert_eq!(
            mhfe.check_new_container(&new, &wrong_password, &mut no_progress()),
            Err(MhfeError::VerificationFailed)
        );
        assert_eq!(
            mhfe.check_new_container(&changed, &password, &mut no_progress()),
            Err(MhfeError::VerificationFailed)
        );
    }

    #[test]
    fn cancellation_stops_between_rounds() {
        let password = test_password();
        let mut mhfe = reduced();
        let result = mhfe.encrypt(
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                if round == 2 {
                    Err(MhfeError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.err(), Some(MhfeError::Cancelled));
    }

    /// The same container must come out of every engine at this reduced cost, as
    /// [`REDUCED_COST_CONTAINER`] for suite 3.
    pub(crate) const REDUCED_COST_SAME_LENGTH_CONTAINER: &str =
        "program adjust rain raven flip eternal spider bulb under soup enrich ensure";

    #[test]
    fn same_length_round_trips_every_short_length_with_the_c_engine() {
        let password = test_password();
        let mut mhfe = reduced();
        for words in [12, 15, 18, 21] {
            let original = varied_phrase(words);
            let new = mhfe
                .encrypt_unchecked(&original, &password, Suite::SameLength, &mut no_progress())
                .unwrap();
            assert_eq!(new.suite, Suite::SameLength);
            assert_eq!(new.words.split(' ').count(), words);
            assert_ne!(*new.words, *original);
            mhfe.check_new_container(&new, &password, &mut no_progress())
                .unwrap();

            let recovered = only_phrase(
                mhfe.decrypt(
                    &new.words,
                    &password,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unwrap(),
            );
            assert_eq!(*recovered.phrase, *original);
            assert_eq!(recovered.words, words);
            assert_eq!(recovered.suite, Suite::SameLength);
            // Nothing in a same-length container confirms a recovery.
            assert!(!recovered.verified);
            // Choosing the container's own length changes nothing.
            // Stating the length gives the same phrase.
            let chosen = decrypt_as(
                &mut mhfe,
                &new.words,
                &password,
                WordCount::new(words).unwrap(),
            );
            assert_eq!(*chosen.phrase, *original);
        }
    }

    #[test]
    fn the_reduced_cost_same_length_container_is_the_same_everywhere() {
        let password = test_password();
        let container = reduced()
            .encrypt(ZERO_12, &password, Suite::SameLength, &mut no_progress())
            .unwrap();
        assert_eq!(*container, REDUCED_COST_SAME_LENGTH_CONTAINER);
    }

    /// A wrong password opens a same-length container as another valid phrase of the same
    /// length, and encrypting that phrase with the wrong password gives the same container back:
    /// every password is a possible decoy, and nothing tells a wrong one apart.
    #[test]
    fn a_wrong_password_gives_another_valid_phrase_of_the_same_length() {
        let password = test_password();
        let decoy = Password::new("another public test password").unwrap();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(ZERO_12, &password, Suite::SameLength, &mut no_progress())
            .unwrap();
        let opened = only_phrase(
            mhfe.decrypt(&container, &decoy, PhraseLength::Detect, &mut no_progress())
                .unwrap(),
        );
        assert_eq!((opened.words, opened.verified), (12, false));
        assert_ne!(opened.phrase(), ZERO_12);
        assert_eq!(phrase::check_phrase(&opened.phrase).unwrap(), 12);
        let again = mhfe
            .encrypt(
                &opened.phrase,
                &decoy,
                Suite::SameLength,
                &mut no_progress(),
            )
            .unwrap();
        assert_eq!(*again, *container);
    }

    #[test]
    fn the_two_suites_give_different_containers() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let standard = mhfe
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        let same_length = mhfe
            .encrypt(ZERO_12, &password, Suite::SameLength, &mut no_progress())
            .unwrap();
        assert_eq!(standard.split(' ').count(), 24);
        assert_eq!(same_length.split(' ').count(), 12);
        assert!(!standard.starts_with(same_length.as_str()));
    }
}
