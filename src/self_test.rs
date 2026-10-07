//! The self-test: two published test vectors at their full cost on this computer, an encryption
//! of suite 3 and a recovery of suite 4. A program that passes computes MHFE as the specification
//! says, here and now; a build or computer fault that the round trip of an encryption cannot see,
//! because it would encrypt and decrypt the same wrong way, shows here. The vectors are public, so
//! no secret is involved. It takes minutes, so a front end runs it only when the person asks.
//!
//! A witness watches every Argon2id call, without changing its cost or its key, and compares it
//! with the round the published vectors record at that place. A failure names the first round that
//! left the published path and how: Argon2id was given another input than the vector records, so
//! the fault lies before Argon2id, or it was given the recorded input and returned another key, so
//! the fault lies in Argon2id at full size. See [`SelfTestFault`].

use std::fmt;

use serde_json::Value;

use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::mhfe::known_answers::{published_table, PublishedRound, PublishedVector};
use crate::operation::{RoundCounter, Stage, StageCallback};
use crate::{Mhfe, MhfeError, Password, PhraseLength, Recovery, Suite, ENCRYPTION_ROUNDS, ROUNDS};

/// The public vectors, as the repository and the specification publish them.
const SUITE_3_VECTOR: &str = include_str!("../tests/fixtures/suite3-vectors/zero-12.json");
const SUITE_4_VECTOR: &str =
    include_str!("../tests/fixtures/suite4-vectors/same-length-zero-12.json");

/// What a vector gives: its name, phrase, password and container.
struct Vector {
    name: String,
    phrase: String,
    password: String,
    container: String,
}

impl Vector {
    fn read(json: &str) -> Result<Self, MhfeError> {
        let value: Value = serde_json::from_str(json).map_err(|error| {
            MhfeError::Internal(format!("a built-in vector is damaged: {error}"))
        })?;
        let text = |pointer: &str| {
            value
                .pointer(pointer)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| MhfeError::Internal(format!("a built-in vector lacks {pointer}")))
        };
        Ok(Self {
            name: text("/name")?,
            phrase: text("/inputs/phrase")?,
            password: text("/inputs/password")?,
            container: text("/container")?,
        })
    }
}

/// The two published vectors and how to run them.
pub struct SelfTest {
    suite_3: Vector,
    suite_4: Vector,
}

impl SelfTest {
    /// The vectors built into the program. Both use the default settings, PIM 0 and memory level
    /// 0, at 2 GiB: [`WorkFactor::default`](crate::WorkFactor::default).
    pub fn published() -> Result<Self, MhfeError> {
        Ok(Self {
            suite_3: Vector::read(SUITE_3_VECTOR)?,
            suite_4: Vector::read(SUITE_4_VECTOR)?,
        })
    }

    pub fn suite_3_vector(&self) -> &str {
        &self.suite_3.name
    }

    pub fn suite_4_vector(&self) -> &str {
        &self.suite_4.name
    }

    /// Encrypts the suite 3 vector (rounds 1 to 12 of 24, [`Stage::Encrypt`]) and recovers the
    /// suite 4 vector (rounds 13 to 24, [`Stage::Recover`]) with `mhfe`, which must be at
    /// the default settings, and compares both results with the published ones.
    pub fn run<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        progress: StageCallback<'_>,
    ) -> Result<SelfTestResult, MhfeError> {
        let expected = self.expected_calls(published_table())?;
        let (work, engine) = mhfe.parts_mut();
        let mut watched = Mhfe::with_engine(work, RoundKeyWitness::new(engine, expected));
        let (suite_3, suite_4) = self.replay(&mut watched, progress)?;
        Ok(watched.engine().verdict(suite_3, suite_4))
    }

    /// The encryption of suite 3 and the recovery of suite 4 with `mhfe`: whether each gave the
    /// published result.
    fn replay<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        progress: StageCallback<'_>,
    ) -> Result<(bool, bool), MhfeError> {
        let rounds = RoundCounter::starting_after(0, ENCRYPTION_ROUNDS);
        let password = Password::new(&self.suite_3.password)?;
        let encrypted = mhfe.encrypt_unchecked(
            &self.suite_3.phrase,
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| rounds.report(Stage::Encrypt, round, &mut *progress),
        )?;
        let suite_3 = *encrypted.words == self.suite_3.container;

        let rounds = RoundCounter::starting_after(ROUNDS, ENCRYPTION_ROUNDS);
        let password = Password::new(&self.suite_4.password)?;
        let recovered = mhfe.decrypt(
            &self.suite_4.container,
            &password,
            PhraseLength::Detect,
            &mut |round, _| rounds.report(Stage::Recover, round, &mut *progress),
        )?;
        let suite_4 =
            matches!(&recovered, Recovery::Phrase(phrase) if *phrase.phrase == self.suite_4.phrase);
        Ok((suite_3, suite_4))
    }

    /// The Argon2id calls of the self-test in their order, as `table` records them: the suite 3
    /// vector's rounds 0 to 11 for its encryption, then the suite 4 vector's rounds 11 to 0 for
    /// its recovery, which runs the rounds backwards.
    fn expected_calls(
        &self,
        table: &'static [PublishedVector],
    ) -> Result<Vec<ExpectedCall>, MhfeError> {
        let vector = |name: &str| {
            table
                .iter()
                .find(|vector| vector.name == name)
                .ok_or_else(|| MhfeError::Internal("a built-in vector is missing".to_owned()))
        };
        let suite_3 = vector(&self.suite_3.name)?;
        let suite_4 = vector(&self.suite_4.name)?;
        let call =
            |vector: &'static PublishedVector, round: &'static PublishedRound| ExpectedCall {
                password_nfkd: vector.password_nfkd,
                round,
            };
        Ok(suite_3
            .rounds
            .iter()
            .map(|round| call(suite_3, round))
            .chain(
                suite_4
                    .rounds
                    .iter()
                    .rev()
                    .map(|round| call(suite_4, round)),
            )
            .collect())
    }
}

/// One Argon2id call as a published vector records it: the password after NFKD, and the round's
/// salt and key.
struct ExpectedCall {
    password_nfkd: &'static [u8],
    round: &'static PublishedRound,
}

/// An engine wrapper that passes every call on unchanged and records the first call, counted from
/// 1 over the whole self-test, that left the published path: its input, password and salt, is not
/// the one the published vectors record at that place, or its key differs from the recorded one.
struct RoundKeyWitness<'a, E: Argon2Engine> {
    engine: &'a mut E,
    expected: Vec<ExpectedCall>,
    calls: u32,
    first_fault: Option<SelfTestFault>,
}

impl<'a, E: Argon2Engine> RoundKeyWitness<'a, E> {
    fn new(engine: &'a mut E, expected: Vec<ExpectedCall>) -> Self {
        Self {
            engine,
            expected,
            calls: 0,
            first_fault: None,
        }
    }

    /// How call number `round` compares with the published one. A call beyond the recorded ones
    /// has no published input, so it counts as another input.
    fn judge(
        &self,
        round: u32,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &[u8; KEY_BYTES],
    ) -> Option<SelfTestFault> {
        let expected = usize::try_from(round - 1)
            .ok()
            .and_then(|index| self.expected.get(index));
        match expected {
            Some(call) if call.password_nfkd == password && call.round.salt == *salt => {
                (call.round.key != *key).then_some(SelfTestFault::Argon2Key { round })
            }
            _ => Some(SelfTestFault::Argon2Input { round }),
        }
    }

    /// The result of a self-test that this witness watched.
    fn verdict(&self, suite_3: bool, suite_4: bool) -> SelfTestResult {
        SelfTestResult {
            suite_3,
            suite_4,
            first_round_fault: self.first_fault,
        }
    }
}

impl<E: Argon2Engine> Argon2Engine for RoundKeyWitness<'_, E> {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        self.engine.derive(password, salt, key)?;
        self.calls += 1;
        if self.first_fault.is_none() {
            self.first_fault = self.judge(self.calls, password, salt, key);
        }
        Ok(())
    }
}

/// The rounds of the self-test: 12 of the encryption and 12 of the recovery.
const SELF_TEST_ROUNDS: u32 = 2 * ROUNDS;

/// Where a self-test that did not pass first left the published path. The round is counted over
/// the whole self-test: 1 to 12 the suite 3 encryption, 13 to 24 the suite 4 recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestFault {
    /// Argon2id was given another input, password or salt, than the published vector records for
    /// this round. Argon2id had not run on it yet, so the fault lies before it: in this round's
    /// salt, or in the state the round started from, which the round before made with its mask
    /// and state update, or which the packing of the phrase or container and the encoding of the
    /// password made for the first round of an operation.
    Argon2Input { round: u32 },
    /// Argon2id was given the input the published vector records for this round and returned
    /// another key: the fault lies in Argon2id.
    Argon2Key { round: u32 },
    /// Every round gave Argon2id its published input and got its published key, yet a result
    /// differs: the fault lies after the last Argon2id call of an operation, in its last mask and
    /// state update or in writing the container or the phrase.
    AfterArgon2,
}

impl SelfTestFault {
    /// The round, 1 to 24, where the fault showed; `None` for [`SelfTestFault::AfterArgon2`].
    pub fn round(self) -> Option<u32> {
        match self {
            Self::Argon2Input { round } | Self::Argon2Key { round } => Some(round),
            Self::AfterArgon2 => None,
        }
    }

    /// A fixed name for the kind of fault, for a front end that passes it on as data:
    /// "argon2-input", "argon2-key" or "after-argon2".
    pub fn id(self) -> &'static str {
        match self {
            Self::Argon2Input { .. } => "argon2-input",
            Self::Argon2Key { .. } => "argon2-key",
            Self::AfterArgon2 => "after-argon2",
        }
    }
}

/// The sentence a front end shows, such as "first wrong round 14 of 24: Argon2id returned another
/// key for the published input, so the fault is in Argon2id".
impl fmt::Display for SelfTestFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Argon2Input { round } => write!(
                f,
                "first wrong round {round} of {SELF_TEST_ROUNDS}: Argon2id was given an input \
                 that the published vector does not have, so the fault is before Argon2id, in \
                 this round's password or salt or in the state before it"
            ),
            Self::Argon2Key { round } => write!(
                f,
                "first wrong round {round} of {SELF_TEST_ROUNDS}: Argon2id returned another key \
                 for the published input, so the fault is in Argon2id"
            ),
            Self::AfterArgon2 => f.write_str(
                "every Argon2id input and key as published, so the fault is after the last \
                 Argon2id call of an operation",
            ),
        }
    }
}

/// Whether each vector came out as published, and where a self-test that did not pass left the
/// published path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfTestResult {
    suite_3: bool,
    suite_4: bool,
    /// What the witness found, [`SelfTestFault::Argon2Input`] or [`SelfTestFault::Argon2Key`].
    first_round_fault: Option<SelfTestFault>,
}

impl SelfTestResult {
    /// Where the self-test first left the published path: `None` when it passed. A round where
    /// Argon2id was given another input than the published one points to the rest of the cipher
    /// before it; a round where the published input gave another key points to Argon2id; when
    /// every input and key was as published, the fault is after the last Argon2id call.
    pub fn fault(self) -> Option<SelfTestFault> {
        if self.passed() {
            return None;
        }
        Some(self.first_round_fault.unwrap_or(SelfTestFault::AfterArgon2))
    }

    /// The round of [`SelfTestResult::fault`], 1 to 12 the suite 3 encryption and 13 to 24 the
    /// suite 4 recovery, whether Argon2id's input or its key differed there; `None` when the
    /// self-test passed or when the fault is after the last Argon2id call. Only
    /// [`SelfTestResult::fault`] tells a fault in Argon2id from one before it.
    pub fn first_wrong_round(self) -> Option<u32> {
        self.fault().and_then(SelfTestFault::round)
    }

    /// Whether the suite 3 encryption gave the published container.
    pub fn suite_3_as_published(self) -> bool {
        self.suite_3
    }

    /// Whether the suite 4 recovery gave the published phrase.
    pub fn suite_4_as_published(self) -> bool {
        self.suite_4
    }

    pub fn passed(self) -> bool {
        self.suite_3 && self.suite_4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mhfe::known_answers::{published, PublishedRoundKeys};
    use crate::WorkFactor;

    fn leaked(vectors: Vec<PublishedVector>) -> &'static [PublishedVector] {
        Box::leak(vectors.into_boxed_slice())
    }

    /// A stand-in for Argon2id at full size: the recorded key for a published input and, for any
    /// other input, a hash of it, as Argon2id gives some key for any input.
    struct StandIn;

    impl Argon2Engine for StandIn {
        fn derive(
            &mut self,
            password: &[u8],
            salt: &[u8; SALT_BYTES],
            key: &mut [u8; KEY_BYTES],
        ) -> Result<(), MhfeError> {
            if PublishedRoundKeys::of(published_table())
                .derive(password, salt, key)
                .is_err()
            {
                use sha2::Digest;
                key.copy_from_slice(&sha2::Sha256::digest([password, &salt[..]].concat()));
            }
            Ok(())
        }
    }

    /// What a [`Fault`] changes in its call.
    #[derive(Clone, Copy)]
    enum Change {
        /// The salt it passes on, as a fault in the salt's derivation would.
        Salt,
        /// The key it returns, as a fault in Argon2id would, or, seen from before a witness that
        /// checked the right key, a fault in the mask the key makes.
        Key,
    }

    /// An engine layer that passes every call on to `engine` but changes one: call number `at`.
    struct Fault<E> {
        engine: E,
        change: Change,
        at: u32,
        calls: u32,
    }

    impl<E> Fault<E> {
        fn new(engine: E, change: Change, at: u32) -> Self {
            Self {
                engine,
                change,
                at,
                calls: 0,
            }
        }
    }

    impl<E: Argon2Engine> Argon2Engine for Fault<E> {
        fn derive(
            &mut self,
            password: &[u8],
            salt: &[u8; SALT_BYTES],
            key: &mut [u8; KEY_BYTES],
        ) -> Result<(), MhfeError> {
            self.calls += 1;
            let here = self.calls == self.at;
            let mut salt = *salt;
            if here && matches!(self.change, Change::Salt) {
                salt[0] ^= 1;
            }
            self.engine.derive(password, &salt, key)?;
            if here && matches!(self.change, Change::Key) {
                key[0] ^= 1;
            }
            Ok(())
        }
    }

    /// The self-test with a fault behind the witness, in what the engine computes.
    fn with_fault_in_the_engine(change: Change, at: u32) -> SelfTestResult {
        let test = SelfTest::published().unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), Fault::new(StandIn, change, at));
        test.run(&mut mhfe, &mut |_, _, _| Ok(())).unwrap()
    }

    /// The self-test with a fault before the witness, in what the cipher hands to Argon2id or
    /// does with its key.
    fn with_fault_in_the_cipher(change: Change, at: u32) -> SelfTestResult {
        let test = SelfTest::published().unwrap();
        let mut stand_in = StandIn;
        let expected = test.expected_calls(published_table()).unwrap();
        let witness = RoundKeyWitness::new(&mut stand_in, expected);
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), Fault::new(witness, change, at));
        let (suite_3, suite_4) = test.replay(&mut mhfe, &mut |_, _, _| Ok(())).unwrap();
        mhfe.engine().engine.verdict(suite_3, suite_4)
    }

    /// The self-test's verdict with the recorded round keys in place of Argon2 at full size: as
    /// published, with no wrong round.
    #[test]
    fn the_self_test_reports_as_published_with_the_recorded_keys() {
        let test = SelfTest::published().unwrap();
        let mut mhfe = Mhfe::with_engine(
            WorkFactor::default(),
            PublishedRoundKeys::of(published_table()),
        );
        let mut rounds = Vec::new();
        let result = test
            .run(&mut mhfe, &mut |stage, round, total| {
                rounds.push((stage, round, total));
                Ok(())
            })
            .unwrap();
        assert!(result.passed());
        assert!(result.suite_3_as_published() && result.suite_4_as_published());
        assert_eq!(result.fault(), None);
        assert_eq!(result.first_wrong_round(), None);
        assert_eq!(rounds.len(), 24);
        assert_eq!(rounds[0], (Stage::Encrypt, 1, 24));
        assert_eq!(rounds[23], (Stage::Recover, 24, 24));
        // The stand-in gives the recorded keys too.
        assert!(with_fault_in_the_engine(Change::Key, 0).passed());
    }

    /// An engine that gives a wrong key in one round: the witness names that round as a fault in
    /// Argon2id, in the encryption of suite 3 and in the recovery of suite 4, whose rounds run
    /// backwards.
    #[test]
    fn a_wrong_round_key_is_named() {
        let test = SelfTest::published().unwrap();
        // The encryption's last round is round 12 of the self-test; the recovery runs round 11
        // of its vector first and round 0 last, which is round 24.
        for (name, round, step, suite_3, suite_4) in [
            ("zero-12", 11, 12, false, true),
            ("same-length-zero-12", 0, 24, true, false),
        ] {
            let mut vectors = published_table().to_vec();
            let index = vectors
                .iter()
                .position(|vector| vector.name == name)
                .unwrap();
            vectors[index].rounds[round].key[0] ^= 1;
            let mut mhfe = Mhfe::with_engine(
                WorkFactor::default(),
                PublishedRoundKeys::of(leaked(vectors)),
            );
            let result = test.run(&mut mhfe, &mut |_, _, _| Ok(())).unwrap();
            assert!(!result.passed(), "{name}");
            assert_eq!(result.suite_3_as_published(), suite_3, "{name}");
            assert_eq!(result.suite_4_as_published(), suite_4, "{name}");
            assert_eq!(
                result.fault(),
                Some(SelfTestFault::Argon2Key { round: step }),
                "{name}"
            );
            assert_eq!(result.first_wrong_round(), Some(step), "{name}");
        }
        assert!(published("zero-12").is_ok());
    }

    /// A wrong key from Argon2id in round 4 is named as a fault in Argon2id, although round 5 then
    /// gets a salt that no vector records.
    #[test]
    fn a_fault_in_argon2_is_named_as_one() {
        let result = with_fault_in_the_engine(Change::Key, 4);
        assert!(!result.suite_3_as_published() && result.suite_4_as_published());
        let fault = result.fault().unwrap();
        assert_eq!(fault, SelfTestFault::Argon2Key { round: 4 });
        assert_eq!(fault.id(), "argon2-key");
        assert_eq!(
            fault.to_string(),
            "first wrong round 4 of 24: Argon2id returned another key for the published input, \
             so the fault is in Argon2id"
        );
        // A salt changed between the witness and Argon2id is Argon2id's input gone wrong after
        // the cipher handed it over: the witness sees the published input and another key.
        assert_eq!(
            with_fault_in_the_engine(Change::Salt, 4).fault(),
            Some(SelfTestFault::Argon2Key { round: 4 })
        );
    }

    /// A wrong salt from the cipher is named as a fault before Argon2id, in the round where it
    /// shows: here in the encryption and in the recovery.
    #[test]
    fn a_fault_in_the_salt_is_named_as_one_before_argon2() {
        let result = with_fault_in_the_cipher(Change::Salt, 4);
        assert!(!result.suite_3_as_published() && result.suite_4_as_published());
        let fault = result.fault().unwrap();
        assert_eq!(fault, SelfTestFault::Argon2Input { round: 4 });
        assert_eq!(fault.id(), "argon2-input");
        assert_eq!(fault.round(), Some(4));
        assert_eq!(result.first_wrong_round(), Some(4));
        assert_eq!(
            fault.to_string(),
            "first wrong round 4 of 24: Argon2id was given an input that the published vector \
             does not have, so the fault is before Argon2id, in this round's password or salt or in \
             the state before it"
        );
        let recovery = with_fault_in_the_cipher(Change::Salt, 15);
        assert!(recovery.suite_3_as_published() && !recovery.suite_4_as_published());
        assert_eq!(
            recovery.fault(),
            Some(SelfTestFault::Argon2Input { round: 15 })
        );
    }

    /// A fault after Argon2id in round 4, in the mask its key makes, changes the state round 5
    /// starts from: round 5 is named, as a fault before Argon2id, and never Argon2id itself.
    #[test]
    fn a_fault_in_the_mask_shows_in_the_next_rounds_input() {
        let result = with_fault_in_the_cipher(Change::Key, 4);
        assert_eq!(
            result.fault(),
            Some(SelfTestFault::Argon2Input { round: 5 })
        );
    }

    /// A fault after the last Argon2id call of the encryption leaves every input and key as
    /// published: the fault is named as after Argon2id, with no round.
    #[test]
    fn a_fault_after_the_last_argon2_call_is_named() {
        let result = with_fault_in_the_cipher(Change::Key, 12);
        assert!(!result.suite_3_as_published() && result.suite_4_as_published());
        let fault = result.fault().unwrap();
        assert_eq!(fault, SelfTestFault::AfterArgon2);
        assert_eq!((fault.round(), fault.id()), (None, "after-argon2"));
        assert_eq!(result.first_wrong_round(), None);
        assert_eq!(
            fault.to_string(),
            "every Argon2id input and key as published, so the fault is after the last Argon2id \
             call of an operation"
        );
    }

    /// The witness compares each call with the round recorded at its place: a published round's
    /// input in the wrong place, or a call beyond the 24, is another input.
    #[test]
    fn the_witness_compares_each_call_with_its_own_round() {
        let test = SelfTest::published().unwrap();
        let expected = test.expected_calls(published_table()).unwrap();
        assert_eq!(expected.len(), 24);
        let first = (expected[0].password_nfkd, expected[0].round);
        let second = expected[1].round;
        let mut stand_in = StandIn;
        let witness = RoundKeyWitness::new(&mut stand_in, expected);
        assert_eq!(witness.judge(1, first.0, &first.1.salt, &first.1.key), None);
        assert_eq!(
            witness.judge(1, first.0, &second.salt, &second.key),
            Some(SelfTestFault::Argon2Input { round: 1 })
        );
        assert_eq!(
            witness.judge(1, b"another password", &first.1.salt, &first.1.key),
            Some(SelfTestFault::Argon2Input { round: 1 })
        );
        assert_eq!(
            witness.judge(25, first.0, &first.1.salt, &first.1.key),
            Some(SelfTestFault::Argon2Input { round: 25 })
        );
    }

    #[test]
    fn the_built_in_vectors_read() {
        let test = SelfTest::published().unwrap();
        assert_eq!(test.suite_3_vector(), "zero-12");
        assert_eq!(test.suite_3.container.split(' ').count(), 24);
        assert_eq!(test.suite_4.container.split(' ').count(), 12);
        assert_eq!(test.suite_4.phrase, test.suite_3.phrase);
    }
}
