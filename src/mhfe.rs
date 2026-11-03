//! Creating a container and recovering a phrase (specification: "Creating a container",
//! "Recovering a mnemonic" and their suite 4 forms). The cipher is [`mhfe_core::Mhfe`]: this module
//! takes the phrases as typed, keeps mhfe's refusals and tells a front end what a reading is.

use std::cell::Cell;
use std::ops::ControlFlow;

use mhfe_core::{Argon2Engine, Mhfe, Password, Phrase, Reading, Suite};

use crate::container::ContainerFacts;
use crate::engine::error_of;
use crate::packing::{self, STATE_WORDS};
use crate::phrase::{self, read_phrase};
use crate::suite::{memory_bytes, ROUNDS};
use crate::wallet_check;
use crate::MhfeError;

// The self-checks of the cipher and the published vectors they replay; see known_answers.rs.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
mod published_rounds;

/// Called with the number of the round about to start and the number of rounds in the whole
/// operation: 12 for a recovery or a check, 24 for an encryption, which recovers its result once
/// more to check it. `Break` stops before that round, and an error refuses the operation there.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(u32, u32) -> crate::Outcome;

/// Rounds of an encryption: twelve to encrypt and twelve to check the result. A deliberate copy of
/// `2 * ROUNDS` in the core's src/cipher.rs, which has no name for it: a change goes to both.
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

    /// The number of words.
    pub fn get(self) -> usize {
        self.0
    }

    /// The bytes of entropy a BIP39 phrase of this length carries: 16 for 12 words, 32 for 24.
    pub fn entropy_bytes(self) -> usize {
        packing::entropy_of_words(self.0)
    }
}

/// How recovery of a 24-word container learns the length of the original phrase. A same-length
/// container keeps its original's length, which a stated length must equal.
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

    /// The number of words the person stated, if any.
    pub(crate) fn stated(self) -> Option<usize> {
        match self {
            Self::Words(words) => Some(words.get()),
            Self::Detect => None,
        }
    }
}

/// One phrase produced by recovery, read-only: its text stays in the core's [`Phrase`], which no
/// caller can grow or replace (AUD-012-SEC002).
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
    phrase: Phrase,
    verified: bool,
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
        self.phrase.words()
    }

    /// Whether the phrase passed its check value. Never true for 24 words or for a same-length
    /// container, which have none.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// The phrase, with every word written out.
    pub fn phrase(&self) -> &str {
        self.phrase.as_str()
    }

    /// The suite of the container it came from.
    pub fn suite(&self) -> Suite {
        self.suite
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

    /// Whether a 24-word reading passes the 16-bit wallet check of `MHFE-WALLET-CHECK-SEED-1`
    /// with `passphrase`, the wallet's BIP39 passphrase or the empty one; `None` for another
    /// length, where it does not apply. Every recovery evaluates it on each 24-word reading, as
    /// the container does not show whether the phrase was made with the check (the
    /// specification's recovery rules). A pass makes a right password very likely; a phrase made
    /// without the check almost always fails it, so a failure means something only to an owner who knows the
    /// wallet was made with it. One BIP39 seed: milliseconds.
    pub fn passes_wallet_check(&self, passphrase: &str) -> Result<Option<bool>, MhfeError> {
        if !self.offers_wallet_check() {
            return Ok(None);
        }
        wallet_check::phrase_passes(self.phrase(), passphrase).map(Some)
    }

    /// Whether this is a 24-word reading of a 24-word container, which the 16-bit wallet check
    /// applies to: a front end asks for the wallet's BIP39 passphrase whenever one comes out.
    pub fn offers_wallet_check(&self) -> bool {
        self.words() == STATE_WORDS && self.suite == Suite::TwentyFourWords
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

    /// `reading` of a container of `suite`, from a recovery with `stated`, beside the 12- to 21-word
    /// lengths `short` whose built-in check passes.
    fn new(reading: Reading, suite: Suite, stated: Option<usize>, short: &[usize]) -> Self {
        let verified = reading.is_verified();
        let phrase = reading.into_phrase();
        let words = phrase.words();
        Self {
            phrase,
            verified,
            suite,
            stated_words: stated.filter(|&stated| stated != words),
            other_lengths: short
                .iter()
                .copied()
                .filter(|&other| other != words)
                .collect(),
        }
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

/// Encrypts an original phrase and checks the result (creation steps 1 to 6), 24 rounds in
/// all. With [`Suite::TwentyFourWords`], the default, any original of 12 to 24 words becomes a
/// 24-word container; with [`Suite::SameLength`], which only the user's own choice may select,
/// a 12- to 21-word original becomes a container of its own length.
///
/// `on_round` comes before each round. `on_unchecked` comes once with the container, after
/// round 12 and before the check of rounds 13 to 24: it may be shown to a person during the
/// check, clearly marked as not verified, while a program that receives it for further use
/// should wait for the check. `Break` from either stops the encryption there, and the container
/// then stays unchecked; an error refuses it.
pub fn encrypt<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    original: &str,
    password: &Password,
    suite: Suite,
    on_round: ProgressCallback<'_>,
    on_unchecked: &mut dyn FnMut(&Phrase) -> crate::Outcome,
) -> crate::Outcome<Phrase> {
    let original = read_phrase(original)?;
    let work = mhfe.work_factor();
    let stopped = Stopped::default();
    let flow = mhfe
        .encrypt(
            &original,
            password,
            suite,
            &mut |round, rounds| stopped.answer(on_round(round, rounds)),
            &mut |container| stopped.answer(on_unchecked(container)),
        )
        .map_err(|refusal| error_of(refusal, memory_bytes(work)))?;
    stopped.finished(flow)
}

/// Recovers the original phrase from a container. Its word count selects the suite: 24 words
/// are suite 3, and 12 to 21 words a same-length container, which gives a phrase of the same
/// length that nothing confirms.
pub fn decrypt<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    length: PhraseLength,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<Recovery> {
    decrypt_as(mhfe, container, password, None, length, on_progress)
}

/// [`decrypt`] for a suite the user selected: a container of the other suite's word count is
/// refused before any Argon2 work instead of being read with the other suite.
pub fn decrypt_as<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    selected: Option<Suite>,
    length: PhraseLength,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<Recovery> {
    // Every input is checked before the first Argon2 call; a WordCount is valid already. A
    // suite selected against the container's words is refused as the container is read.
    if selected != Some(Suite::TwentyFourWords) {
        ContainerFacts::read(container)?.require_length(length)?;
    }
    let recovery = proceed!(recover_state(
        mhfe,
        container,
        password,
        selected,
        on_progress
    ));
    let mut readings = readings(&recovery, length.stated())?;
    if readings.len() == 1 {
        Ok(ControlFlow::Continue(Recovery::Phrase(readings.remove(0))))
    } else {
        Ok(ControlFlow::Continue(Recovery::Ambiguous(readings)))
    }
}

/// Steps 1 and 2 of recovery, of a container as typed: computes `X = Perm^-1(Y)` with the suite its
/// word count selects, refusing a container of another suite than `selected`. Every operation that
/// recovers one reads it here.
pub(crate) fn recover_state<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    container: &str,
    password: &Password,
    selected: Option<Suite>,
    on_progress: ProgressCallback<'_>,
) -> crate::Outcome<mhfe_core::Recovery> {
    let container = phrase::read(container, MhfeError::InvalidContainer)?;
    let work = mhfe.work_factor();
    let stopped = Stopped::default();
    let flow = mhfe
        .decrypt(
            &container,
            password,
            None,
            selected,
            &mut |round, rounds| stopped.answer(on_progress(round, rounds)),
        )
        .map_err(|refusal| match refusal {
            mhfe_core::Error::SuiteNotAdmitted { container_words } => {
                MhfeError::InvalidContainer(if selected == Some(Suite::TwentyFourWords) {
                    format!("it has {container_words} words, but a 24-word container always has 24")
                } else {
                    format!(
                        "it has {STATE_WORDS} words, but a same-length container has {}",
                        phrase::counts_text(&packing::SHORT_WORD_COUNTS)
                    )
                })
            }
            other => error_of(other, memory_bytes(work)),
        })?;
    stopped.finished(flow)
}

/// Step 3 of recovery: the readings of `recovery` for `stated`, in their order, under the core's
/// length rules. A same-length container gives one, of its own length, the only one
/// [`ContainerFacts::require_length`] lets a person state. In a 24-word container 24 stated words
/// end with the 24-word reading, and a short length stated where no check passes gives
/// [`MhfeError::VerifierMismatch`] and no reading.
pub(crate) fn readings(
    recovery: &mhfe_core::Recovery,
    stated: Option<usize>,
) -> Result<Vec<RecoveredPhrase>, MhfeError> {
    let (suite, short) = (recovery.suite(), recovery.detected_lengths());
    Ok(recovery
        .readings(stated)?
        .into_iter()
        .map(|reading| RecoveredPhrase::new(reading, suite, stated, short))
        .collect())
}

/// The first error of a callback of an operation, kept across the core, whose callbacks can only
/// say `Break`, which comes back as the core's result: the error is the result instead.
#[derive(Default)]
struct Stopped(Cell<Option<MhfeError>>);

impl Stopped {
    /// What a callback of the core answers for `outcome`.
    fn answer(&self, outcome: crate::Outcome) -> ControlFlow<()> {
        outcome.unwrap_or_else(|error| {
            self.0.set(Some(error));
            ControlFlow::Break(())
        })
    }

    /// What an operation the core ended with `flow` comes to: the error of a callback that failed,
    /// or `flow` itself.
    fn finished<T>(&self, flow: ControlFlow<(), T>) -> crate::Outcome<T> {
        self.0.take().map_or(Ok(flow), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        reduced, state_from_hex, test_password, wrong_password, HashEngine, NoArgon2Calls,
        ReducedEngine, AMBIGUOUS_STATES,
    };
    use crate::Unstopped as _;
    use mhfe_core::WorkFactor;

    const ZERO_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const LEGAL_24: &str = "legal winner thank year wave sausage worth useful legal winner thank year \
                            wave sausage worth useful legal winner thank year wave sausage worth title";

    fn no_progress() -> impl FnMut(u32, u32) -> crate::Outcome {
        |_, _| crate::GO_ON
    }

    /// The container of `original` under `password` in `suite`, with no progress to report.
    fn sealed<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        original: &str,
        password: &Password,
        suite: Suite,
    ) -> Phrase {
        encrypt(
            mhfe,
            original,
            password,
            suite,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap()
    }

    /// A phrase of `words` words whose entropy bytes all differ, another for every length.
    fn varied_phrase(words: usize) -> String {
        let entropy: Vec<u8> = (0..packing::entropy_bytes(words).unwrap())
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(words as u8))
            .collect();
        Phrase::from_entropy(&entropy).unwrap().as_str().to_owned()
    }

    /// The recovery of `container` at the stated length `words`.
    fn recovery_at(
        mhfe: &mut Mhfe<ReducedEngine>,
        container: &str,
        password: &Password,
        words: WordCount,
    ) -> RecoveredPhrase {
        let length = PhraseLength::Words(words);
        only_phrase(
            decrypt(mhfe, container, password, length, &mut no_progress())
                .unstopped()
                .unwrap(),
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
        let password = test_password();
        let mut mhfe = reduced();
        for words in [12, 15, 18, 21, 24] {
            let original = varied_phrase(words);
            let container = sealed(&mut mhfe, &original, &password, Suite::TwentyFourWords);
            assert_eq!(container.words(), 24);

            let detected = only_phrase(
                decrypt(
                    &mut mhfe,
                    container.as_str(),
                    &password,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unstopped()
                .unwrap(),
            );
            assert_eq!(detected.phrase(), original);
            assert_eq!(detected.words(), words);
            assert_eq!(detected.verified, words < 24);

            // Stating the length gives the same phrase.
            let chosen = recovery_at(
                &mut mhfe,
                container.as_str(),
                &password,
                WordCount::new(words).unwrap(),
            );
            assert_eq!(chosen.phrase(), original);
        }
    }

    /// The same container must come out of every engine at this reduced cost: the native build
    /// here, and both Emscripten builds in `cargo xtask package-check`.
    pub(crate) const REDUCED_COST_CONTAINER: &str =
        "slush crime nose carry menu cabbage already cart \
        lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope \
        dream sweet";

    #[test]
    fn the_reduced_cost_container_is_the_same_everywhere() {
        let password = test_password();
        let container = encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        assert_eq!(container.as_str(), REDUCED_COST_CONTAINER);
    }

    #[test]
    fn a_wrong_password_ends_unverified_or_as_a_mismatch() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = sealed(&mut mhfe, ZERO_12, &password, Suite::TwentyFourWords);

        let detected = only_phrase(
            decrypt(
                &mut mhfe,
                container.as_str(),
                &wrong,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unstopped()
            .unwrap(),
        );
        assert_eq!(detected.words(), 24);
        assert!(!detected.verified);
        assert_eq!(
            decrypt(
                &mut mhfe,
                container.as_str(),
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
            decrypt(
                &mut mhfe,
                container,
                &password,
                PhraseLength::Words(WordCount::new(words).unwrap()),
                &mut no_progress(),
            )
            .unstopped()
        };
        let twelve = encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let twelve = twelve.as_str();
        // Another short length stated: the 12-word reading, which says what was stated.
        for words in [15, 18, 21] {
            let found = only_phrase(stated(twelve, words).unwrap());
            assert_eq!((found.words(), found.verified), (12, true), "{words}");
            assert_eq!(found.phrase(), ZERO_12);
            assert_eq!(found.stated_words(), Some(words));
            assert!(found.other_lengths().is_empty());
        }
        // The right length stated: the same reading, with nothing to say.
        let found = only_phrase(stated(twelve, 12).unwrap());
        assert_eq!((found.words(), found.stated_words()), (12, None));
        // 24 words stated: the checked 12-word reading first, then the 24-word one, unverified.
        let Recovery::Ambiguous(readings) = stated(twelve, 24).unwrap() else {
            panic!("24 stated beside a passing check must offer both readings");
        };
        let shape: Vec<_> = readings
            .iter()
            .map(|reading| (reading.words(), reading.verified, reading.stated_words()))
            .collect();
        assert_eq!(shape, [(12, true, Some(24)), (24, false, None)]);
        assert_eq!(readings[0].phrase(), ZERO_12);
        assert!(readings[1]
            .phrase()
            .starts_with("abandon abandon abandon abandon abandon abandon"));
        // A 24-word original passes no short check: a stated short length is refused, as a
        // wrong password or setting would be, and 24 stated words give its reading alone.
        let twenty_four = encrypt(
            &mut reduced(),
            LEGAL_24,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let twenty_four = twenty_four.as_str();
        assert_eq!(
            stated(twenty_four, 12).err(),
            Some(MhfeError::VerifierMismatch)
        );
        let found = only_phrase(stated(twenty_four, 24).unwrap());
        assert_eq!(
            (found.words(), found.verified, found.stated_words()),
            (24, false, None)
        );
        assert_eq!(found.phrase(), LEGAL_24);
    }

    /// Every 24-word reading offers the 16-bit wallet check with any passphrase, the empty one
    /// included; a short reading does not. The phrase is the published wallet-check vector:
    /// "abandon" 21 times and "above proof fatigue", which passes with "TREZOR" and fails without
    /// a passphrase (vectors/profiles, src/wallet_check/known_answers.rs).
    #[test]
    fn a_24_word_reading_offers_the_source_check() {
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let phrase = Phrase::from_entropy(&entropy).unwrap();
        assert!(phrase.as_str().ends_with("abandon above proof fatigue"));
        let password = test_password();
        let mut mhfe = reduced();
        let container = sealed(
            &mut mhfe,
            phrase.as_str(),
            &password,
            Suite::TwentyFourWords,
        );
        let read = only_phrase(
            decrypt(
                &mut mhfe,
                container.as_str(),
                &password,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unstopped()
            .unwrap(),
        );
        assert!(read.offers_wallet_check());
        assert_eq!(read.passes_wallet_check("TREZOR"), Ok(Some(true)));
        assert_eq!(read.passes_wallet_check(""), Ok(Some(false)));
        let short = encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let read = only_phrase(
            decrypt(
                &mut mhfe,
                short.as_str(),
                &password,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unstopped()
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
            let container = sealed(&mut mhfe, original, &password, Suite::TwentyFourWords);
            let opened = only_phrase(
                decrypt(
                    &mut mhfe,
                    container.as_str(),
                    &decoy,
                    PhraseLength::Words(WordCount::new(24).unwrap()),
                    &mut no_progress(),
                )
                .unstopped()
                .unwrap(),
            );
            assert_eq!(opened.words(), 24);
            assert!(!opened.verified);
            assert_ne!(opened.phrase(), original);
            // An ordinary BIP39 phrase with a valid checksum, usable as a wallet of its own.
            assert_eq!(phrase::check_phrase(opened.phrase()).unwrap(), 24);

            // Automatic detection gives the same unverified 24-word reading, just as for an
            // honest 24-word original.
            let detected = only_phrase(
                decrypt(
                    &mut mhfe,
                    container.as_str(),
                    &decoy,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unstopped()
                .unwrap(),
            );
            assert_eq!((detected.words(), detected.verified), (24, false));
            assert_eq!(detected.phrase(), opened.phrase());

            let again = encrypt(
                &mut mhfe,
                opened.phrase(),
                &decoy,
                Suite::TwentyFourWords,
                &mut no_progress(),
                &mut |_| crate::GO_ON,
            )
            .unstopped()
            .unwrap();
            assert_eq!(again.as_str(), container.as_str());
        }
    }

    #[test]
    fn ambiguity_lists_every_candidate_and_the_24_word_reading() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        for (text, lengths) in AMBIGUOUS_STATES {
            // A 24-word phrase fills the state alone, so that its container holds this very X.
            let x = state_from_hex(text);
            let original = Phrase::from_entropy(&x).unwrap();
            let container = sealed(
                &mut mhfe,
                original.as_str(),
                &password,
                Suite::TwentyFourWords,
            );
            let container = container.as_str();

            let Recovery::Ambiguous(candidates) = decrypt(
                &mut mhfe,
                container,
                &password,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unstopped()
            .unwrap() else {
                panic!("expected an ambiguous result for {lengths:?}");
            };
            let found: Vec<_> = candidates.iter().map(RecoveredPhrase::words).collect();
            assert_eq!(found, [lengths[0], lengths[1], 24]);
            let verified: Vec<_> = candidates
                .iter()
                .map(|candidate| candidate.verified)
                .collect();
            assert_eq!(verified, [true, true, false]);
            for candidate in &candidates {
                let entropy = &x[..packing::entropy_bytes(candidate.words()).unwrap()];
                assert_eq!(
                    candidate.phrase(),
                    Phrase::from_entropy(entropy).unwrap().as_str()
                );
            }

            // A length stated among those that pass resolves the ambiguity, and names the other.
            let chosen = only_phrase(
                decrypt(
                    &mut mhfe,
                    container,
                    &password,
                    PhraseLength::Words(WordCount::new(lengths[0]).unwrap()),
                    &mut no_progress(),
                )
                .unstopped()
                .unwrap(),
            );
            assert_eq!(chosen.words(), lengths[0]);
            assert_eq!(chosen.other_lengths(), [lengths[1]]);
            assert_eq!(chosen.stated_words(), None);
            // A short length stated that does not pass leaves every reading to choose from.
            let other = [12, 15, 18, 21]
                .into_iter()
                .find(|words| !lengths.contains(words))
                .unwrap();
            let Recovery::Ambiguous(readings) = decrypt(
                &mut mhfe,
                container,
                &password,
                PhraseLength::Words(WordCount::new(other).unwrap()),
                &mut no_progress(),
            )
            .unstopped()
            .unwrap() else {
                panic!("a stated length that fails leaves the ambiguity");
            };
            let found: Vec<_> = readings.iter().map(RecoveredPhrase::words).collect();
            assert_eq!(found, [lengths[0], lengths[1], 24]);
            assert!(readings
                .iter()
                .all(|reading| reading.stated_words() == Some(other)));
        }
    }

    #[test]
    fn invalid_inputs_fail_before_any_argon2_call() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        let bad_checksum = LEGAL_24.replace("title", "thank");

        assert!(matches!(
            encrypt(
                &mut mhfe,
                "abandon abandon",
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
                &mut |_| crate::GO_ON
            ),
            Err(MhfeError::InvalidPhrase(_))
        ));
        assert!(matches!(
            decrypt(
                &mut mhfe,
                &bad_checksum,
                &password,
                PhraseLength::Detect,
                &mut no_progress()
            ),
            Err(MhfeError::InvalidContainer(_))
        ));
        assert!(matches!(
            decrypt(
                &mut mhfe,
                "abandon abandon abandon",
                &password,
                PhraseLength::Detect,
                &mut no_progress()
            ),
            Err(MhfeError::InvalidContainer(_))
        ));
        assert_eq!(
            encrypt(
                &mut mhfe,
                LEGAL_24,
                &password,
                Suite::SameLength,
                &mut no_progress(),
                &mut |_| crate::GO_ON
            )
            .err(),
            Some(MhfeError::SameLengthNeedsShortPhrase)
        );
        assert_eq!(
            decrypt(
                &mut mhfe,
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
                let container = Phrase::from_entropy(&entropy).unwrap();
                assert_eq!(
                    decrypt(
                        &mut mhfe,
                        container.as_str(),
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
            let short = Phrase::from_entropy(&entropy).unwrap().as_str().to_owned();
            cases.push((short, Suite::TwentyFourWords));
        }
        for (container, selected) in &cases {
            let (container, selected) = (container.as_str(), *selected);
            assert!(matches!(
                decrypt_as(
                    &mut mhfe,
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
    fn encryption_checks_its_result_in_24_rounds() {
        let password = test_password();
        let mut steps = Vec::new();
        encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut |round, rounds| {
                steps.push((round, rounds));
                crate::GO_ON
            },
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let expected: Vec<(u32, u32)> = (1..=24).map(|round| (round, 24)).collect();
        assert_eq!(steps, expected);
    }

    #[test]
    fn a_fault_during_encryption_is_caught_by_the_check() {
        // Fault: an engine that gives a different key on every call, as a memory error would:
        // the container then does not turn back into the original and must not be shown.
        struct FlakyEngine(u8);
        impl Argon2Engine for FlakyEngine {
            fn argon2id(
                &mut self,
                password: &[u8],
                salt: &[u8; 16],
                memory_kib: u32,
                passes: u32,
                key: &mut [u8; 32],
            ) -> Result<(), mhfe_core::Error> {
                HashEngine.argon2id(password, salt, memory_kib, passes, key)?;
                self.0 = self.0.wrapping_add(1);
                key[0] ^= self.0;
                Ok(())
            }
        }
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), FlakyEngine(0));
        assert_eq!(
            encrypt(
                &mut mhfe,
                ZERO_12,
                &password,
                Suite::TwentyFourWords,
                &mut no_progress(),
                &mut |_| crate::GO_ON
            )
            .err(),
            Some(MhfeError::VerificationFailed)
        );
    }

    /// The container comes out once, between rounds 12 and 13: the one `encrypt` then returns.
    #[test]
    fn the_unchecked_container_comes_between_rounds_12_and_13() {
        let password = test_password();
        let last_round = std::cell::Cell::new(0);
        let mut shown = Vec::new();
        let container = encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                last_round.set(round);
                crate::GO_ON
            },
            &mut |container| {
                shown.push((last_round.get(), container.as_str().to_owned()));
                crate::GO_ON
            },
        )
        .unstopped()
        .unwrap();
        assert_eq!(container.as_str(), REDUCED_COST_CONTAINER);
        assert_eq!(shown, [(12, REDUCED_COST_CONTAINER.to_owned())]);
    }

    #[test]
    fn cancellation_stops_between_rounds() {
        let password = test_password();
        let mut mhfe = reduced();
        let result = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                if round == 2 {
                    Ok(ControlFlow::Break(()))
                } else {
                    crate::GO_ON
                }
            },
            &mut |_| crate::GO_ON,
        );
        assert!(matches!(result, Ok(ControlFlow::Break(()))));

        // The container's callback stops it too: the check never starts.
        let mut last_round = 0;
        let result = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                last_round = round;
                crate::GO_ON
            },
            &mut |_| Ok(ControlFlow::Break(())),
        );
        assert!(matches!(result, Ok(ControlFlow::Break(()))));
        assert_eq!(last_round, 12);
    }

    /// Every round asks for the memory and the passes of the work factor. The other test engines
    /// ignore what is asked, so no other fast test sees a wrong cost.
    #[test]
    fn every_round_asks_for_the_cost_of_the_work_factor() {
        struct Costs(Vec<(u32, u32)>);
        // A deliberate copy of the trait's signature, which an implementation repeats.
        impl Argon2Engine for Costs {
            fn argon2id(
                &mut self,
                password: &[u8],
                salt: &[u8; 16],
                memory_kib: u32,
                passes: u32,
                key: &mut [u8; 32],
            ) -> Result<(), mhfe_core::Error> {
                self.0.push((memory_kib, passes));
                HashEngine.argon2id(password, salt, memory_kib, passes, key)
            }
        }
        let work = WorkFactor::new(2, 1).unwrap();
        let mut mhfe = Mhfe::with_engine(work, Costs(Vec::new()));
        encrypt(
            &mut mhfe,
            ZERO_12,
            &test_password(),
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        // Memory level 1 is 3 GiB, and PIM 2 is three times the 12 passes.
        assert_eq!(mhfe.engine().0, [(3 << 20, 36); 24]);
    }

    /// An error of a callback comes back as it is, though the core only knows a stop.
    #[test]
    fn a_callback_s_own_error_comes_back_as_it_is() {
        let own = || MhfeError::Internal("a stop of the test".to_owned());
        let password = test_password();
        let suite = Suite::TwentyFourWords;
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let at_a_round = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            suite,
            &mut |_, _| Err(own()),
            &mut |_| crate::GO_ON,
        );
        assert_eq!(at_a_round.err(), Some(own()));
        let at_the_container = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            suite,
            &mut no_progress(),
            &mut |_| Err(own()),
        );
        assert_eq!(at_the_container.err(), Some(own()));
        let in_a_recovery = decrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            PhraseLength::Detect,
            &mut |_, _| Err(own()),
        );
        assert_eq!(in_a_recovery.err(), Some(own()));
    }

    /// An engine that cannot get its memory is reported with the memory of the settings, which the
    /// core does not name.
    #[test]
    fn a_refused_work_area_names_the_memory_of_the_settings() {
        struct NoMemory;
        // A deliberate copy of the trait's signature, which an implementation repeats.
        impl Argon2Engine for NoMemory {
            fn argon2id(
                &mut self,
                _: &[u8],
                _: &[u8; 16],
                _: u32,
                _: u32,
                _: &mut [u8; 32],
            ) -> Result<(), mhfe_core::Error> {
                Err(mhfe_core::Error::OutOfMemory)
            }
        }
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::new(0, 1).unwrap(), NoMemory);
        let refusal = Some(MhfeError::MemoryAllocation { bytes: 3 << 30 });
        let encrypted = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        );
        assert_eq!(encrypted.err(), refusal);
        let recovered = decrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            PhraseLength::Detect,
            &mut no_progress(),
        );
        assert_eq!(recovered.err(), refusal);
    }

    /// A selected suite refuses a container of the other one in mhfe's words, which say what its
    /// containers have.
    #[test]
    fn a_selected_suite_says_what_its_containers_have() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        let mut refused = |container, selected| {
            let length = PhraseLength::Detect;
            decrypt_as(
                &mut mhfe,
                container,
                &password,
                Some(selected),
                length,
                &mut no_progress(),
            )
            .err()
        };
        assert_eq!(
            refused(ZERO_12, Suite::TwentyFourWords),
            Some(MhfeError::InvalidContainer(
                "it has 12 words, but a 24-word container always has 24".to_owned()
            ))
        );
        assert_eq!(
            refused(LEGAL_24, Suite::SameLength),
            Some(MhfeError::InvalidContainer(
                "it has 24 words, but a same-length container has 12, 15, 18 or 21".to_owned()
            ))
        );
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
            let container = sealed(&mut mhfe, &original, &password, Suite::SameLength);
            assert_eq!(container.words(), words);
            assert_ne!(container.as_str(), original);

            let recovered = only_phrase(
                decrypt(
                    &mut mhfe,
                    container.as_str(),
                    &password,
                    PhraseLength::Detect,
                    &mut no_progress(),
                )
                .unstopped()
                .unwrap(),
            );
            assert_eq!(recovered.phrase(), original);
            assert_eq!(recovered.words(), words);
            assert_eq!(recovered.suite, Suite::SameLength);
            // Nothing in a same-length container confirms a recovery.
            assert!(!recovered.verified);
            // Choosing the container's own length changes nothing.
            // Stating the length gives the same phrase.
            let chosen = recovery_at(
                &mut mhfe,
                container.as_str(),
                &password,
                WordCount::new(words).unwrap(),
            );
            assert_eq!(chosen.phrase(), original);
        }
    }

    #[test]
    fn the_reduced_cost_same_length_container_is_the_same_everywhere() {
        let password = test_password();
        let container = encrypt(
            &mut reduced(),
            ZERO_12,
            &password,
            Suite::SameLength,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        assert_eq!(container.as_str(), REDUCED_COST_SAME_LENGTH_CONTAINER);
    }

    /// A wrong password opens a same-length container as another valid phrase of the same
    /// length, and encrypting that phrase with the wrong password gives the same container back:
    /// every password is a possible decoy, and nothing tells a wrong one apart.
    #[test]
    fn a_wrong_password_gives_another_valid_phrase_of_the_same_length() {
        let password = test_password();
        let decoy = Password::new("another public test password").unwrap();
        let mut mhfe = reduced();
        let container = sealed(&mut mhfe, ZERO_12, &password, Suite::SameLength);
        let opened = only_phrase(
            decrypt(
                &mut mhfe,
                container.as_str(),
                &decoy,
                PhraseLength::Detect,
                &mut no_progress(),
            )
            .unstopped()
            .unwrap(),
        );
        assert_eq!((opened.words(), opened.verified), (12, false));
        assert_ne!(opened.phrase(), ZERO_12);
        assert_eq!(phrase::check_phrase(opened.phrase()).unwrap(), 12);
        let again = encrypt(
            &mut mhfe,
            opened.phrase(),
            &decoy,
            Suite::SameLength,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        assert_eq!(again.as_str(), container.as_str());
    }

    #[test]
    fn the_two_suites_give_different_containers() {
        let password = test_password();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let standard = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            Suite::TwentyFourWords,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        let same_length = encrypt(
            &mut mhfe,
            ZERO_12,
            &password,
            Suite::SameLength,
            &mut no_progress(),
            &mut |_| crate::GO_ON,
        )
        .unstopped()
        .unwrap();
        assert_eq!(standard.words(), 24);
        assert_eq!(same_length.words(), 12);
        assert!(!standard.as_str().starts_with(same_length.as_str()));
    }

    /// A shared validation fixture, `tests/spec/vectors/suite3/validation-cases.json` or
    /// `tests/spec/vectors/suite4/validation-cases.json`, whose known answers were computed
    /// independently (Python `hashlib`, `hmac` and `unicodedata`).
    fn fixture_of(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    fn cases<'a>(fixture: &'a serde_json::Value, section: &str) -> &'a Vec<serde_json::Value> {
        fixture[section].as_array().unwrap()
    }

    fn text<'a>(case: &'a serde_json::Value, field: &str) -> &'a str {
        case[field].as_str().unwrap()
    }

    /// The fixture's refused phrases and containers of suite 3; [`NoArgon2Calls`] fails the test if
    /// any case reaches Argon2: every refusal must come first.
    #[test]
    fn bad_phrases_and_containers_fail_before_argon2() {
        let fixture = fixture_of(crate::validation_fixtures::SUITE_3);
        let password = Password::new("public test password").unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        for case in cases(&fixture, "phrases") {
            let id = text(case, "id");
            let error = match text(case, "operation") {
                "encrypt" => encrypt(
                    &mut mhfe,
                    text(case, "phrase"),
                    &password,
                    Suite::TwentyFourWords,
                    &mut |_, _| crate::GO_ON,
                    &mut |_| crate::GO_ON,
                )
                .err(),
                "decrypt" => {
                    // A wrong word count is refused when the length is made, before decrypt runs.
                    let length = match case.get("words") {
                        Some(words) => WordCount::new(words.as_u64().unwrap() as usize)
                            .map(PhraseLength::Words),
                        None => Ok(PhraseLength::Detect),
                    };
                    length
                        .and_then(|length| {
                            // These are suite 3 cases: the suite is selected, not taken from the
                            // word count.
                            decrypt_as(
                                &mut mhfe,
                                text(case, "container"),
                                &password,
                                Some(Suite::TwentyFourWords),
                                length,
                                &mut |_, _| crate::GO_ON,
                            )
                        })
                        .err()
                }
                other => panic!("{id}: unknown operation {other}"),
            };
            let error = error.unwrap_or_else(|| panic!("{id}: accepted"));
            assert_eq!(error.code(), text(case, "expected_error"), "{id}");
        }
    }

    /// The fixture's refusals of suite 4, before Argon2 as well.
    #[test]
    fn suite_4_refusals_come_before_argon2() {
        let fixture = fixture_of(crate::validation_fixtures::SUITE_4);
        let password = Password::new("public test password").unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
        for case in cases(&fixture, "refusals") {
            let id = text(case, "id");
            assert_eq!(text(case, "expected"), "rejected", "{id}");
            let result = match text(case, "operation") {
                "encrypt-same-length" => encrypt(
                    &mut mhfe,
                    text(case, "text"),
                    &password,
                    Suite::SameLength,
                    &mut no_progress(),
                    &mut |_| crate::GO_ON,
                )
                .map(|_| ()),
                "decrypt" => {
                    let length = match case.get("words") {
                        Some(words) => PhraseLength::Words(
                            WordCount::new(words.as_u64().unwrap() as usize).unwrap(),
                        ),
                        None => PhraseLength::Detect,
                    };
                    let suite = case.get("suite").map(|suite| match suite.as_u64() {
                        Some(3) => Suite::TwentyFourWords,
                        Some(4) => Suite::SameLength,
                        other => panic!("{id}: unknown suite {other:?}"),
                    });
                    decrypt_as(
                        &mut mhfe,
                        text(case, "text"),
                        &password,
                        suite,
                        length,
                        &mut |_, _| crate::GO_ON,
                    )
                    .map(|_| ())
                }
                other => panic!("{id}: unknown operation {other}"),
            };
            // NoArgon2Calls panics if Argon2 is reached, so an error here came before it.
            let error = result.err().unwrap_or_else(|| panic!("{id}: accepted"));
            assert!(
                matches!(
                    error,
                    MhfeError::SameLengthNeedsShortPhrase
                        | MhfeError::LengthChoiceNotApplicable { .. }
                        | MhfeError::InvalidContainer(_)
                ),
                "{id}: {error}"
            );
        }
    }
}
