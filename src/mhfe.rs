//! Creating a container and recovering a phrase (specification: "Creating a container",
//! "Recovering a mnemonic" and their suite 4 forms).

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::engine::Argon2Engine;
#[cfg(not(target_arch = "wasm32"))]
use crate::engine::NativeEngine;
use crate::feistel::{Geometry, Permutation};
use crate::memory::LockedPages;
use crate::packing::{self, State};
use crate::suite::{Suite, ROUNDS};
use crate::{phrase, MhfeError, Password, WorkFactor};

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
}

/// How recovery of a 24-word container learns the length of the original phrase. A same-length
/// container keeps its original's length and takes only [`PhraseLength::Detect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseLength {
    /// Tests the 12-, 15-, 18- and 21-word layouts and falls back to 24 words.
    Detect,
    /// The user knows the length. A short length must pass its check; 24 words have none.
    Words(WordCount),
}

/// One phrase produced by recovery.
pub struct RecoveredPhrase {
    pub words: usize,
    /// True when the phrase passed its check value. Never true for 24 words or for a
    /// same-length container, which have none.
    pub verified: bool,
    pub phrase: Zeroizing<String>,
    /// The suite of the container it came from.
    pub suite: Suite,
    // The pages of `phrase`, kept out of swap; declared after it, so they are unlocked once wiped.
    _locked: LockedPages,
}

impl RecoveredPhrase {
    fn new(words: usize, verified: bool, phrase: Zeroizing<String>, suite: Suite) -> Self {
        let locked = LockedPages::of_string(&phrase);
        Self {
            words,
            verified,
            phrase,
            suite,
            _locked: locked,
        }
    }
}

/// The result of recovery.
pub enum Recovery {
    /// One phrase: a short original that passed its check, or the 24-word reading, which
    /// cannot be verified. For a short original an unverified result usually means a wrong
    /// password, PIM, memory level or container.
    Phrase(RecoveredPhrase),
    /// Several short lengths passed their check by accident, about once in four billion
    /// containers. Every candidate is listed, followed by the unverified 24-word reading; the
    /// user picks the right one with public wallet data or by choosing the known length.
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
    /// The state `X` the check must get back: the packed original, or the entropy itself.
    source: Zeroizing<Vec<u8>>,
    // The pages of `source`, kept out of swap while the check runs.
    _locked: LockedPages,
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
    /// or a cheaper one in tests.
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn with_engine(work: WorkFactor, engine: E) -> Self {
        Self { work, engine }
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
        let source = phrase::parse(original).map_err(MhfeError::InvalidPhrase)?;
        let entropy = Zeroizing::new(source.to_entropy());
        let (geometry, x) = match suite {
            Suite::TwentyFourWords => (
                Geometry::SUITE_3,
                Zeroizing::new(packing::pack(&entropy)?.to_vec()),
            ),
            // Suite 4 encrypts the entropy itself: there is no room for a check value.
            Suite::SameLength if entropy.len() == packing::STATE_BYTES => {
                return Err(MhfeError::SameLengthNeedsShortPhrase)
            }
            Suite::SameLength => (Geometry::same_length(entropy.len())?, entropy.clone()),
        };
        let y = self.permutation(password, geometry).forward(
            &x,
            &mut |round| on_progress(round, ENCRYPTION_ROUNDS),
            None,
        )?;
        reject_fixed_point(&x, &y)?;
        let locked = LockedPages::of_vec(&x);
        Ok(NewContainer {
            words: phrase_from_entropy(&y)?,
            suite,
            source: x,
            _locked: locked,
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
        if *recovered == *new.source {
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
        // Every input is checked before the first Argon2 call; a WordCount is valid already.
        let container_words = container.split_whitespace().count();
        if let (Ok(Suite::SameLength), PhraseLength::Words(chosen)) =
            (Suite::of_container(container_words), length)
        {
            if chosen.get() != container_words && selected != Some(Suite::TwentyFourWords) {
                return Err(MhfeError::LengthChoiceNotApplicable { container_words });
            }
        }
        let (suite, x) = self.recover_state(container, password, selected, on_progress)?;
        match suite {
            Suite::TwentyFourWords => {
                let x = suite_3_state(&x)?;
                recover(&x, length)
            }
            Suite::SameLength => Ok(Recovery::Phrase(RecoveredPhrase::new(
                x.len() / 4 * 3,
                false,
                phrase_from_entropy(&x)?,
                suite,
            ))),
        }
    }

    /// Steps 1 and 2 of recovery: checks the container, then computes `X = Perm^-1(Y)` with the
    /// suite its word count selects.
    pub(crate) fn recover_state(
        &mut self,
        container: &str,
        password: &Password,
        selected: Option<Suite>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(Suite, Zeroizing<Vec<u8>>), MhfeError> {
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
                return Err(MhfeError::InvalidContainer(
                    "it has 24 words, but a same-length container has 12, 15, 18 or 21".to_owned(),
                ))
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

/// A recovered suite 3 state as the fixed 256-bit array the packing works on.
pub(crate) fn suite_3_state(x: &[u8]) -> Result<Zeroizing<State>, MhfeError> {
    let mut state = Zeroizing::new([0u8; packing::STATE_BYTES]);
    if x.len() != state.len() {
        return Err(MhfeError::Internal(format!(
            "a suite 3 state has 32 bytes, not {}",
            x.len()
        )));
    }
    state.copy_from_slice(x);
    Ok(state)
}

/// Step 3 of recovery: reads `X` as the chosen length, or tests the short layouts.
pub(crate) fn recover(x: &State, length: PhraseLength) -> Result<Recovery, MhfeError> {
    if let PhraseLength::Words(words) = length {
        return Ok(Recovery::Phrase(read_as(x, words.get())?));
    }
    let matches = packing::matching_short_lengths(x);
    match matches.as_slice() {
        [] => Ok(Recovery::Phrase(read_as(x, 24)?)),
        [words] => Ok(Recovery::Phrase(read_as(x, *words)?)),
        _ => {
            let mut candidates = matches
                .iter()
                .map(|&words| read_as(x, words))
                .collect::<Result<Vec<_>, _>>()?;
            candidates.push(read_as(x, 24)?);
            Ok(Recovery::Ambiguous(candidates))
        }
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
    let entropy = Zeroizing::new(source.to_entropy());
    let x = packing::pack(&entropy)?;
    Ok(packing::matching_short_lengths(&x)
        .into_iter()
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

/// Reads `X` as a phrase of `words` words; a short length must pass its check.
pub(crate) fn read_as(x: &State, words: usize) -> Result<RecoveredPhrase, MhfeError> {
    let entropy = packing::unpack(x, words)?;
    Ok(RecoveredPhrase::new(
        words,
        words < 24,
        phrase_from_entropy(&entropy)?,
        Suite::TwentyFourWords,
    ))
}

/// The English BIP39 phrase of `entropy`, 16 to 32 bytes in steps of four, written into a buffer
/// that is reserved at its final size and wiped when dropped, so that no growing copy of the words
/// is left in freed memory (AUD-005-SEC001, AUD-008-SEC002). For a program that draws its own
/// entropy, as `mhfe new` does. Another length is a programming error: `MhfeError::Internal`.
pub fn phrase_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, MhfeError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|error| MhfeError::Internal(error.to_string()))?;
    Ok(phrase::phrase_text(&mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Argon2Cost;
    use crate::feistel::tests::HashEngine;

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

    /// The real C engine at a tiny cost: fast, but still the code path of every release.
    fn reduced() -> Mhfe<NativeEngine> {
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        Mhfe::with_engine(
            WorkFactor::default(),
            NativeEngine::reduced_for_tests(cost).unwrap(),
        )
    }

    fn only_phrase(recovery: Recovery) -> RecoveredPhrase {
        match recovery {
            Recovery::Phrase(phrase) => phrase,
            Recovery::Ambiguous(_) => panic!("unexpected ambiguous result"),
        }
    }

    #[test]
    fn round_trips_every_phrase_length_with_the_c_engine() {
        let password = Password::new("public test password").unwrap();
        let mut mhfe = reduced();
        for words in [12, 15, 18, 21, 24] {
            let entropy: Vec<u8> = (0..packing::entropy_bytes(words).unwrap())
                .map(|index| (index as u8).wrapping_mul(29).wrapping_add(words as u8))
                .collect();
            let original = phrase_from_entropy(&entropy).unwrap();
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

            let chosen = only_phrase(
                mhfe.decrypt(
                    &container,
                    &password,
                    PhraseLength::Words(WordCount::new(words).unwrap()),
                    &mut no_progress(),
                )
                .unwrap(),
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
        let wrong = Password::new("public test passwore").unwrap();
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

    #[test]
    fn manual_24_words_is_always_accepted_and_unverified() {
        let password = Password::new("public test password").unwrap();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
            )
            .unwrap();
        let as_24 = only_phrase(
            mhfe.decrypt(
                &container,
                &password,
                PhraseLength::Words(WordCount::new(24).unwrap()),
                &mut no_progress(),
            )
            .unwrap(),
        );
        assert_eq!(as_24.words, 24);
        assert!(!as_24.verified);
        assert!(as_24
            .phrase
            .starts_with("abandon abandon abandon abandon abandon abandon"));
    }

    /// A decoy password opens a container as another valid 24-word phrase, and a container
    /// created from that phrase with the decoy password is the same container. This is the
    /// consistency lemma of the deniability analysis in the specification's supplement: an owner
    /// can disclose the decoy password instead of the real one.
    #[test]
    fn a_decoy_password_gives_a_phrase_that_encrypts_back_to_the_same_container() {
        let password = Password::new("public test password").unwrap();
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
            assert_ne!(*opened.phrase, original);
            // An ordinary BIP39 phrase with a valid checksum, usable as a wallet of its own.
            assert_eq!(phrase::check_phrase(&opened.phrase).unwrap(), 24);

            // Automatic detection gives the same unverified 24-word reading, just as for an
            // honest 24-word original.
            let detected = only_phrase(
                mhfe.decrypt(&container, &decoy, PhraseLength::Detect, &mut no_progress())
                    .unwrap(),
            );
            assert_eq!((detected.words, detected.verified), (24, false));
            assert_eq!(*detected.phrase, *opened.phrase);

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
        let password = Password::new("public test password").unwrap();
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

            // Choosing a length by hand resolves the ambiguity.
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
        let mut mhfe = reduced();
        for words in [12, 15, 18, 21] {
            let entropy: Vec<u8> = (0..packing::entropy_bytes(words).unwrap())
                .map(|index| (index as u8).wrapping_mul(29).wrapping_add(words as u8))
                .collect();
            let original = phrase_from_entropy(&entropy).unwrap();
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
            let chosen = only_phrase(
                mhfe.decrypt(
                    &new.words,
                    &password,
                    PhraseLength::Words(WordCount::new(words).unwrap()),
                    &mut no_progress(),
                )
                .unwrap(),
            );
            assert_eq!(*chosen.phrase, *original);
        }
    }

    #[test]
    fn the_reduced_cost_same_length_container_is_the_same_everywhere() {
        let password = Password::new("public test password").unwrap();
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
        let password = Password::new("public test password").unwrap();
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
        assert_ne!(*opened.phrase, ZERO_12);
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
        let password = Password::new("public test password").unwrap();
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
