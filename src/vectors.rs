//! Test vectors: every intermediate value of one encryption and of the matching recovery, for
//! suite 3 and for the same-length containers of suite 4.
//!
//! A vector contains the password and every round key by design. It must only ever be made from
//! public test inputs; the command-line tool therefore builds vectors only from the fixed
//! public inputs in its source code and never from anything a user types.

mod error;
pub use error::VectorError;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::engine::{Argon2Engine, KEY_BYTES, LANES};
use crate::feistel::{Geometry, RoundTrace};
use crate::memory::LockedBytes;
use crate::mhfe::{self, RecoveredPhrase, Recovery};
use crate::packing;
use crate::{
    phrase, Mhfe, MhfeError, Password, PhraseLength, Suite, WordCount, WorkFactor,
    SAME_LENGTH_SUITE_ID, SUITE_ID,
};

pub(crate) mod inputs;

// The public inputs reused by native unit tests under their existing names.
#[cfg(test)]
pub(crate) use inputs::{
    AMBIGUOUS_12_21, NONZERO_12, TEST_PASSWORD, ZERO_12, ZERO_12_FINGERPRINT, ZERO_24,
};
pub use inputs::{NEGATIVE_INPUTS, PUBLIC_INPUTS, SAME_LENGTH_INPUTS, SAME_LENGTH_NEGATIVE_INPUTS};

/// Identifies this file layout; a changed layout gets a new name.
pub const SCHEMA: &str = "mhfe-suite-3-vector-v2";
/// The layout of a negative case.
pub const NEGATIVE_SCHEMA: &str = "mhfe-suite-3-negative-case-v2";
/// The layout of a suite 4 vector.
pub const SAME_LENGTH_SCHEMA: &str = "mhfe-suite-4-vector-v1";
/// The layout of a suite 4 negative case.
pub const SAME_LENGTH_NEGATIVE_SCHEMA: &str = "mhfe-suite-4-negative-case-v1";
/// The checksum list shared by the vector writer and replays.
pub const CHECKSUM_FILE: &str = "SHA256SUMS";
/// The negative cases' file stem, also accepted by the writer's selection option.
pub const NEGATIVE_CASES_STEM: &str = "negative-cases";
const FILE_EXTENSION: &str = "json";

impl Vector {
    /// The JSON filename of a vector or of the negative cases, from its published stem.
    pub fn file_name(stem: &str) -> String {
        format!("{stem}.{FILE_EXTENSION}")
    }
}
const WARNING: &str = "Public test data only. This file contains the password and every round \
                       key by design; never use its phrase or password for real funds.";
/// Argon2 version 1.3, written as the number the specification and RFC 9106 use (0x13).
const ARGON2_VERSION: u32 = 0x13;

/// What wrote a vector. The exact source revision is the commit that adds the files; an
/// independent check records its own revision next to them (independent-verification.json).
#[derive(Serialize)]
struct Generator {
    /// The program and command that wrote it.
    program: &'static str,
    /// The program's version.
    version: &'static str,
    /// The Argon2 implementation the program used.
    argon2: &'static str,
}

const GENERATOR: Generator = Generator {
    program: "mhfe test-vectors",
    version: env!("CARGO_PKG_VERSION"),
    argon2: "reference C implementation, P-H-C/phc-winner-argon2 commit \
             f57e61e19229e23c4445b85494dbf7c07de721cb",
};

/// A suite 3 vector: one encryption and the matching recovery, with every intermediate value.
#[derive(Serialize)]
pub struct Vector {
    /// The file layout, [`SCHEMA`].
    schema: &'static str,
    /// The suite, [`SUITE_ID`].
    suite_id: &'static str,
    /// The vector's name, also its file name without `.json`.
    name: String,
    /// That the file is public test data only.
    warning: &'static str,
    /// What wrote the file.
    generator: Generator,
    /// The phrase, the password and the settings.
    inputs: Inputs,
    /// The parameters of every Argon2id call.
    argon2: Argon2Parameters,
    /// How the phrase became the state the rounds start from.
    packing: Packing,
    /// The rounds of the encryption.
    encryption: Pass,
    /// The container, 24 words.
    container: String,
    /// The rounds of the recovery.
    decryption: Pass,
    /// Every reading the recovery gives, as its length detection finds them.
    recovery: Vec<RecoveredCandidate>,
}

impl Vector {
    /// The container recorded by this public-input vector.
    pub fn container(&self) -> &str {
        &self.container
    }
}

/// The public inputs of a vector.
#[derive(Serialize)]
struct Inputs {
    /// The original seed phrase.
    phrase: String,
    /// The password as typed; `password_nfkd_utf8_hex` is `P_enc`, what Argon2 receives.
    password: String,
    /// The password as typed, its UTF-8 bytes in hexadecimal.
    password_utf8_hex: String,
    /// `P_enc`: the password after NFKD normalization, its UTF-8 bytes in hexadecimal.
    password_nfkd_utf8_hex: String,
    /// The PIM.
    pim: u32,
    /// The memory level.
    memory_level: u32,
}

/// The parameters of every Argon2 call of a vector.
#[derive(Serialize)]
struct Argon2Parameters {
    /// The Argon2 variant, "Argon2id".
    variant: &'static str,
    /// The Argon2 version as RFC 9106 numbers it, 0x13.
    version: u32,
    /// Memory in KiB.
    memory_kib: u32,
    /// Passes over the memory, `t`.
    passes: u32,
    /// Lanes, `p`.
    lanes: u32,
    /// The length of each key in bytes.
    output_bytes: usize,
}

/// How a suite 3 vector's phrase becomes the state the rounds start from.
#[derive(Serialize)]
struct Packing {
    /// The phrase's word count.
    words: usize,
    /// `E`, the phrase's entropy.
    entropy_hex: String,
    /// `V_r`; empty for a 24-word phrase.
    verifier_hex: String,
    /// `X = E || V_r`.
    state_hex: String,
}

/// One direction of the permutation. Rounds appear in the order they run: 0 to 11 when
/// encrypting, 11 down to 0 when decrypting.
#[derive(Serialize)]
struct Pass {
    /// The state before the first round.
    input_state_hex: String,
    /// Every round, in the order it ran.
    rounds: Vec<Round>,
    /// The state after the last round.
    output_state_hex: String,
}

/// Every value of one Feistel round.
#[derive(Serialize)]
struct Round {
    /// The round number `i`, 0 to 11.
    round: u32,
    /// `L` before the round.
    left_before_hex: String,
    /// `R` before the round.
    right_before_hex: String,
    /// The BLAKE2b-256 input `DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R`.
    salt_input_hex: String,
    /// `S_i`, the Argon2 salt.
    salt_hex: String,
    /// `K_i`, the key Argon2id returned.
    argon2_key_hex: String,
    /// The HMAC-SHA-256 message `DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R`.
    mask_input_hex: String,
    /// `M_i`, the mask.
    mask_hex: String,
    /// `L` after the round.
    left_after_hex: String,
    /// `R` after the round.
    right_after_hex: String,
}

/// One reading of a recovery.
#[derive(Serialize)]
struct RecoveredCandidate {
    /// Its length in words.
    words: usize,
    /// Whether a built-in check verifies it.
    verified: bool,
    /// The phrase.
    phrase: String,
}

impl RecoveredCandidate {
    /// A recovered phrase as a vector records it.
    fn of(recovered: &RecoveredPhrase) -> Self {
        Self {
            words: recovered.words(),
            verified: recovered.verified(),
            phrase: recovered.phrase().to_string(),
        }
    }
}

/// A suite 4 vector: the state is the entropy itself, without a verifier, and every round
/// message carries `BE32(ENT)`.
#[derive(Serialize)]
pub struct SameLengthVector {
    /// The file layout, [`SAME_LENGTH_SCHEMA`].
    schema: &'static str,
    /// The suite, [`SAME_LENGTH_SUITE_ID`].
    suite_id: &'static str,
    /// The vector's name, also its file name without `.json`.
    name: String,
    /// That the file is public test data only.
    warning: &'static str,
    /// What wrote the file.
    generator: Generator,
    /// The phrase, the password and the settings.
    inputs: Inputs,
    /// The parameters of every Argon2id call.
    argon2: Argon2Parameters,
    /// The state the rounds start from.
    state: SameLengthState,
    /// The rounds of the encryption.
    encryption: Pass,
    /// As many words as the phrase.
    container: String,
    /// The rounds of the recovery.
    decryption: Pass,
    /// The one reading of a same-length container: never verified, since it has no check.
    recovery: RecoveredCandidate,
}

impl SameLengthVector {
    /// The container recorded by this public-input vector.
    pub fn container(&self) -> &str {
        &self.container
    }
}

/// The state of a suite 4 vector and the geometry it gives.
#[derive(Serialize)]
struct SameLengthState {
    /// The phrase's word count.
    words: usize,
    /// `ENT`, which every salt and mask message carries as `BE32(ENT)`.
    entropy_bits: u32,
    /// `h / 8`, the size of each Feistel half.
    half_bytes: usize,
    /// `X = E`.
    state_hex: String,
}

impl Vector {
    /// Encrypts the phrase of a public input under its password, recovers it again with automatic
    /// length detection and records every value. Fails if the round trip does not return the
    /// original.
    pub fn generate<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        input: &PublicInput,
    ) -> Result<Vector, MhfeError> {
        ensure_public(
            PUBLIC_INPUTS.contains(input),
            input.pim,
            input.memory_level,
            mhfe.work_factor(),
        )?;
        record(mhfe, input)
    }
}

/// Writes the transcript of one input; [`Vector::generate`] makes sure that it is a public one.
fn record<E: Argon2Engine>(mhfe: &mut Mhfe<E>, input: &PublicInput) -> Result<Vector, MhfeError> {
    let work = mhfe.work_factor();
    let (password, entropy) = input.password_and_entropy()?;
    let x = packing::pack(&entropy)?;
    let trip = RoundTrip::run(mhfe, &password, Geometry::SUITE_3, &x[..])?;
    let recovered_state = mhfe::suite_3_state(&trip.recovered)?;
    let recovery = match mhfe::recover(recovered_state, PhraseLength::Detect)? {
        Recovery::Phrase(phrase) => vec![phrase],
        Recovery::Ambiguous(candidates) => candidates,
    };

    Ok(Vector {
        schema: SCHEMA,
        suite_id: SUITE_ID,
        name: input.name.to_owned(),
        warning: WARNING,
        generator: GENERATOR,
        inputs: inputs_of(input, &password, work),
        argon2: argon2_of(work),
        packing: Packing {
            words: packing::words_of_entropy(entropy.len()),
            entropy_hex: hex::encode(&entropy[..]),
            verifier_hex: hex::encode(&x[entropy.len()..]),
            state_hex: hex::encode(&x[..]),
        },
        encryption: pass(Geometry::SUITE_3, &x[..], &trip.encryption_rounds, &trip.y),
        container: phrase::phrase_from_entropy(&trip.y)?.to_string(),
        decryption: pass(
            Geometry::SUITE_3,
            &trip.y,
            &trip.decryption_rounds,
            &recovered_state[..],
        ),
        recovery: recovery.iter().map(RecoveredCandidate::of).collect(),
    })
}

impl SameLengthVector {
    /// Encrypts the phrase of a public suite 4 input into a container of its own length, recovers it
    /// and records every value. Fails if the round trip does not return the original.
    pub fn generate<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        input: &PublicInput,
    ) -> Result<SameLengthVector, MhfeError> {
        ensure_public(
            SAME_LENGTH_INPUTS.contains(input),
            input.pim,
            input.memory_level,
            mhfe.work_factor(),
        )?;
        record_same_length(mhfe, input)
    }
}

/// Writes the transcript of one suite 4 input; [`SameLengthVector::generate`] makes sure it is public.
fn record_same_length<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    input: &PublicInput,
) -> Result<SameLengthVector, MhfeError> {
    let work = mhfe.work_factor();
    // The state of a same-length container is the entropy itself.
    let (password, x) = input.password_and_entropy()?;
    let words = packing::words_of_entropy(x.len());
    Suite::SameLength.require_original(words)?;
    let geometry = Geometry::same_length(x.len())?;
    let trip = RoundTrip::run(mhfe, &password, geometry, &x)?;
    Ok(SameLengthVector {
        schema: SAME_LENGTH_SCHEMA,
        suite_id: SAME_LENGTH_SUITE_ID,
        name: input.name.to_owned(),
        warning: WARNING,
        generator: GENERATOR,
        inputs: inputs_of(input, &password, work),
        argon2: argon2_of(work),
        state: SameLengthState {
            words,
            entropy_bits: 8 * x.len() as u32,
            half_bytes: geometry.half_bytes(),
            state_hex: hex::encode(&x[..]),
        },
        encryption: pass(geometry, &x, &trip.encryption_rounds, &trip.y),
        container: phrase::phrase_from_entropy(&trip.y)?.to_string(),
        decryption: pass(geometry, &trip.y, &trip.decryption_rounds, &trip.recovered),
        recovery: RecoveredCandidate {
            words,
            verified: false,
            phrase: phrase::phrase_from_entropy(&trip.recovered)?.to_string(),
        },
    })
}

/// One round trip of the permutation of `geometry` with the trace of every round: the state `x`
/// forward to a container's state `y`, refused when it would be `x` itself, and back, which must
/// give `x` again.
struct RoundTrip {
    y: LockedBytes,
    encryption_rounds: Vec<RoundTrace>,
    recovered: LockedBytes,
    decryption_rounds: Vec<RoundTrace>,
}

impl RoundTrip {
    fn run<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        password: &Password,
        geometry: Geometry,
        x: &[u8],
    ) -> Result<Self, MhfeError> {
        let mut encryption_rounds = Vec::new();
        let y = mhfe.permutation(password, geometry).forward(
            x,
            &mut |_| Ok(()),
            Some(&mut encryption_rounds),
        )?;
        mhfe::reject_fixed_point(x, &y)?;
        let mut decryption_rounds = Vec::new();
        let recovered = mhfe.permutation(password, geometry).inverse(
            &y,
            &mut |_| Ok(()),
            Some(&mut decryption_rounds),
        )?;
        if recovered[..] != *x {
            return Err(MhfeError::Vector(VectorError::RoundTrip));
        }
        Ok(Self {
            y,
            encryption_rounds,
            recovered,
            decryption_rounds,
        })
    }
}

fn inputs_of(input: &PublicInput, password: &Password, work: WorkFactor) -> Inputs {
    Inputs {
        phrase: phrase::parse(input.phrase)
            .map(|source| source.to_string())
            .unwrap_or_default(),
        password: input.password.to_owned(),
        password_utf8_hex: hex::encode(input.password.as_bytes()),
        password_nfkd_utf8_hex: hex::encode(password.as_bytes()),
        pim: work.pim(),
        memory_level: work.memory_level(),
    }
}

fn argon2_of(work: WorkFactor) -> Argon2Parameters {
    let cost = work.argon2_cost();
    Argon2Parameters {
        variant: "Argon2id",
        version: ARGON2_VERSION,
        memory_kib: cost.memory_kib(),
        passes: cost.passes(),
        lanes: LANES,
        output_bytes: KEY_BYTES,
    }
}

fn pass(geometry: Geometry, input: &[u8], rounds: &[RoundTrace], output: &[u8]) -> Pass {
    let half = geometry.half_bytes();
    Pass {
        input_state_hex: hex::encode(input),
        rounds: rounds
            .iter()
            .map(|trace| Round {
                round: trace.round(),
                left_before_hex: hex::encode(&trace.state_before()[..half]),
                right_before_hex: hex::encode(&trace.state_before()[half..]),
                salt_input_hex: hex::encode([geometry.ds_salt(), trace.message()].concat()),
                salt_hex: hex::encode(trace.salt()),
                argon2_key_hex: hex::encode(trace.key()),
                mask_input_hex: hex::encode([geometry.ds_mask(), trace.message()].concat()),
                mask_hex: hex::encode(trace.mask()),
                left_after_hex: hex::encode(&trace.state_after()[..half]),
                right_after_hex: hex::encode(&trace.state_after()[half..]),
            })
            .collect(),
        output_state_hex: hex::encode(output),
    }
}

/// Refuses to write a transcript for anything but a fixed public case at its own settings. The
/// private fields already prevent it; this check keeps it so if the types ever change.
fn ensure_public(
    listed: bool,
    pim: u32,
    memory_level: u32,
    work: WorkFactor,
) -> Result<(), MhfeError> {
    if listed && work.pim() == pim && work.memory_level() == memory_level {
        Ok(())
    } else {
        Err(MhfeError::Vector(VectorError::PublicInputRequired))
    }
}

/// One public test case. The phrases are BIP39 test phrases and the passwords are public.
///
/// The fields are private and can only be read, so no code outside this crate can make or change
/// a `PublicInput`, and [`Vector::generate`] also refuses anything that is not in [`PUBLIC_INPUTS`]: the
/// specification forbids exporting intermediate states, salts, keys or masks of anything else.
#[derive(PartialEq, Eq)]
pub struct PublicInput {
    name: &'static str,
    phrase: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
}

impl PublicInput {
    /// The vector's name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The original seed phrase.
    pub const fn phrase(&self) -> &'static str {
        self.phrase
    }

    // Deliberate copy: distinct public fixture record types expose their own fields.
    /// The password.
    pub const fn password(&self) -> &'static str {
        self.password
    }

    /// Its PIM and memory level.
    pub fn work(&self) -> Result<WorkFactor, MhfeError> {
        WorkFactor::new(self.pim, self.memory_level).map_err(Into::into)
    }

    /// Its password and the entropy of its phrase, which a record encrypts.
    fn password_and_entropy(&self) -> Result<(Password, Zeroizing<Vec<u8>>), MhfeError> {
        let password = Password::new(self.password)?;
        let source = phrase::parse(self.phrase).map_err(MhfeError::from)?;
        Ok((password, Zeroizing::new(source.to_entropy())))
    }
}

/// A negative case: a recovery of the container of the positive vector that `container_of`
/// names, with a wrong password or setting, or with a length stated or chosen that is not the
/// original's. Most give another phrase or an error. With 24 words stated for a 12-word
/// original, recovery gives the verified original first, beside the unverified 24-word reading;
/// `stated-24-words` records both, and `selected-24-words` the 24-word reading alone.
///
/// Like [`PublicInput`], it can only be read outside this crate, and [`NegativeCase::generate`] refuses
/// anything that is not in [`NEGATIVE_INPUTS`].
#[derive(PartialEq, Eq)]
pub struct NegativeInput {
    name: &'static str,
    container_of: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
    /// 0 for automatic detection, otherwise the chosen length.
    words: usize,
}

impl NegativeInput {
    /// The case's name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The name of the positive vector whose container this case recovers.
    pub const fn container_of(&self) -> &'static str {
        self.container_of
    }

    /// The password the case recovers with.
    pub const fn password(&self) -> &'static str {
        self.password
    }

    /// Its PIM and memory level.
    pub fn work(&self) -> Result<WorkFactor, MhfeError> {
        WorkFactor::new(self.pim, self.memory_level).map_err(Into::into)
    }

    /// 0 for automatic detection, otherwise the chosen length.
    pub const fn words(&self) -> usize {
        self.words
    }
}

/// Negative cases recorded before the length rules of recovery, which keep the reading of the
/// stated length alone; the corpus holds them byte for byte (mhfe_spec vectors/suite3/README.md).
/// scripts/independent-suite3.py, the independent oracle, keeps its own copy, as it shares no code
/// with this one; a test keeps the two equal. Its bytes are bound by the record of the full
/// verification (tests/fixtures/suite3-vectors/independent-verification.json), so the link is
/// told here only.
const STATED_READING_ONLY: [&str; 1] = ["selected-24-words"];

/// The recorded outcome of a negative case: the phrases recovery produced, or its error code. For
/// a case of `STATED_READING_ONLY` it keeps only the reading of the stated length.
#[derive(Serialize)]
pub struct NegativeCase {
    /// The file layout, [`NEGATIVE_SCHEMA`] or [`SAME_LENGTH_NEGATIVE_SCHEMA`].
    schema: &'static str,
    /// The suite, [`SUITE_ID`] or [`SAME_LENGTH_SUITE_ID`].
    suite_id: &'static str,
    /// The case's name.
    name: String,
    /// What wrote the file.
    generator: Generator,
    /// The container recovered.
    container: String,
    /// The password as typed.
    password: String,
    /// `P_enc`: the password after NFKD normalization, its UTF-8 bytes in hexadecimal.
    password_nfkd_utf8_hex: String,
    /// The PIM.
    pim: u32,
    /// The memory level.
    memory_level: u32,
    /// 0 for automatic detection.
    words: usize,
    /// The readings the recovery gave; empty where it failed.
    recovery: Vec<RecoveredCandidate>,
    /// The error code of a recovery that failed ([`MhfeError::code`]).
    error_code: Option<&'static str>,
}

impl NegativeCase {
    /// Runs one suite 3 negative case at full size and records what recovery gives; for a case of
    /// `STATED_READING_ONLY`, only the reading of the stated length, as the historical record keeps
    /// it.
    pub fn generate<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        input: &NegativeInput,
        container: &str,
    ) -> Result<NegativeCase, MhfeError> {
        ensure_public(
            NEGATIVE_INPUTS.contains(input),
            input.pim,
            input.memory_level,
            mhfe.work_factor(),
        )?;
        run_negative(mhfe, input, container, Suite::TwentyFourWords)
    }
}

impl NegativeCase {
    /// Runs one suite 4 negative case at full size and records what recovery gives.
    pub fn generate_same_length<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        input: &NegativeInput,
        container: &str,
    ) -> Result<NegativeCase, MhfeError> {
        ensure_public(
            SAME_LENGTH_NEGATIVE_INPUTS.contains(input),
            input.pim,
            input.memory_level,
            mhfe.work_factor(),
        )?;
        run_negative(mhfe, input, container, Suite::SameLength)
    }
}

/// Recovers `container` for a negative case under the suite of its set and records the readings
/// recovery gives, or the error code of a verifier mismatch or of a length choice that does not
/// apply; any other error is returned. A case of `STATED_READING_ONLY` keeps the reading of the
/// stated length alone.
fn run_negative<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    input: &NegativeInput,
    container: &str,
    suite: Suite,
) -> Result<NegativeCase, MhfeError> {
    let work = mhfe.work_factor();
    let password = Password::new(input.password)?;
    let length = match input.words {
        0 => PhraseLength::Detect,
        words => PhraseLength::Words(WordCount::new(words)?),
    };
    let (mut recovery, error_code) =
        match mhfe.decrypt(container, &password, length, &mut |_, _| Ok(())) {
            Ok(Recovery::Phrase(phrase)) => (vec![phrase], None),
            Ok(Recovery::Ambiguous(candidates)) => (candidates, None),
            Err(crate::CipherError::Format(
                error @ (crate::FormatError::VerifierMismatch
                | crate::FormatError::LengthChoiceNotApplicable { .. }),
            )) => (Vec::new(), Some(error.code())),
            Err(other) => return Err(other.into()),
        };
    // The historical cases keep the reading of the stated length alone; every other case records
    // the recovery as the length rules give it.
    if let (PhraseLength::Words(words), true) = (length, STATED_READING_ONLY.contains(&input.name))
    {
        recovery.retain(|reading| reading.words() == words.get());
    }
    Ok(NegativeCase {
        schema: match suite {
            Suite::TwentyFourWords => NEGATIVE_SCHEMA,
            Suite::SameLength => SAME_LENGTH_NEGATIVE_SCHEMA,
        },
        suite_id: suite.id(),
        name: input.name.to_owned(),
        generator: GENERATOR,
        container: container.to_owned(),
        password: input.password.to_owned(),
        password_nfkd_utf8_hex: hex::encode(password.as_bytes()),
        pim: work.pim(),
        memory_level: work.memory_level(),
        words: input.words,
        recovery: recovery.iter().map(RecoveredCandidate::of).collect(),
        error_code,
    })
}

#[cfg(test)]
mod tests {
    use super::inputs::{input, ZERO_15};
    use super::*;

    /// The independent oracle exempts the same negative cases from the length rules as this
    /// generator: its copy of the list must name the same vectors (a copy that a second program
    /// cannot avoid, as the workspace rule on copies allows).
    #[test]
    fn the_oracle_exempts_the_same_cases() {
        let script = include_str!("../scripts/independent-suite3.py");
        let line = script
            .lines()
            .find(|line| line.starts_with("STATED_READING_ONLY = {"))
            .expect("the oracle defines STATED_READING_ONLY");
        let names: Vec<&str> = line
            .trim_start_matches("STATED_READING_ONLY = {")
            .trim_end_matches('}')
            .split(',')
            .map(|name| name.trim().trim_matches('"'))
            .filter(|name| !name.is_empty())
            .collect();
        assert_eq!(names, STATED_READING_ONLY);
    }
    use crate::suite::{DS_MASK, DS_SALT, SAME_LENGTH_DS_MASK, SAME_LENGTH_DS_SALT};
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    /// HMAC-SHA-256, as the round mask takes it, from an implementation of its own.
    fn hmac_sha256(key: &[u8], input: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(input);
        mac.finalize().into_bytes().to_vec()
    }

    impl PublicInput {
        /// The length of its phrase, once its phrase, password and settings are valid.
        fn checked_length(&self) -> usize {
            Password::new(self.password).unwrap();
            self.work().unwrap();
            crate::phrase::check_phrase(self.phrase).unwrap()
        }
    }

    #[test]
    fn the_public_inputs_are_valid_and_cover_the_required_cases() {
        let mut names = std::collections::HashSet::new();
        let mut lengths = std::collections::HashSet::new();
        for input in &PUBLIC_INPUTS {
            assert!(names.insert(input.name), "duplicate name {}", input.name);
            lengths.insert(input.checked_length());
        }
        assert_eq!(lengths.len(), 5, "every phrase length");
        assert!(PUBLIC_INPUTS
            .iter()
            .any(|input| input.pim > 0 && input.memory_level > 0));
        for negative in &NEGATIVE_INPUTS {
            assert!(names.contains(negative.container_of), "{}", negative.name);
        }
        let ambiguous = PUBLIC_INPUTS
            .iter()
            .find(|input| input.name == "ambiguous-12-21")
            .unwrap();
        let entropy = phrase::parse(ambiguous.phrase).unwrap().to_entropy();
        let state = packing::pack(&entropy).unwrap();
        assert_eq!(
            crate::detection::LengthDetection::of(mhfe::suite_3_state(&state).unwrap())
                .short_lengths(),
            [12, 21]
        );
    }

    #[test]
    fn a_reduced_vector_records_consistent_rounds() {
        let mut mhfe = crate::test_support::reduced();
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let reduced = input("reduced", phrase, "Caf\u{E9} \u{1F510}", 0, 0);
        // A private input at reduced cost, which the public entry point refuses.
        assert!(Vector::generate(&mut mhfe, &reduced).is_err());
        let vector = record(&mut mhfe, &reduced).unwrap();

        assert_eq!(
            vector.inputs.password_nfkd_utf8_hex,
            hex::encode("Cafe\u{301} \u{1F510}")
        );
        assert_eq!(vector.packing.words, 12);
        assert_eq!(vector.packing.verifier_hex.len(), 32);
        assert_eq!(vector.encryption.rounds.len(), 12);
        assert_eq!(vector.decryption.rounds[0].round, 11);
        assert_eq!(
            vector.encryption.output_state_hex,
            vector.decryption.input_state_hex
        );
        assert_eq!(vector.decryption.output_state_hex, vector.packing.state_hex);
        assert_eq!(vector.recovery.len(), 1);
        assert_eq!(vector.recovery[0].phrase, phrase);
        assert!(vector.recovery[0].verified);
        // Each forward round continues where the previous one ended.
        for pair in vector.encryption.rounds.windows(2) {
            assert_eq!(pair[0].left_after_hex, pair[1].left_before_hex);
            assert_eq!(pair[0].right_after_hex, pair[1].right_before_hex);
        }
        // The recorded inputs give the recorded salt and mask. A forward round hashes its right
        // half, an inverse round its left half, which is the right half of the round it undoes.
        for (rounds, uses_right) in [
            (&vector.encryption.rounds, true),
            (&vector.decryption.rounds, false),
        ] {
            for round in rounds.iter() {
                let half = if uses_right {
                    &round.right_before_hex
                } else {
                    &round.left_before_hex
                };
                assert!(round.salt_input_hex.ends_with(half.as_str()));
                assert!(round.mask_input_hex.ends_with(half.as_str()));
                let salt_input = hex::decode(&round.salt_input_hex).unwrap();
                assert!(salt_input.starts_with(DS_SALT));
                let digest = Blake2b::<U32>::digest(&salt_input);
                assert_eq!(hex::encode(&digest[..16]), round.salt_hex);
                let key = hex::decode(&round.argon2_key_hex).unwrap();
                let mask_input = hex::decode(&round.mask_input_hex).unwrap();
                assert!(mask_input.starts_with(DS_MASK));
                assert_eq!(
                    hex::encode(&hmac_sha256(&key, &mask_input)[..16]),
                    round.mask_hex
                );
            }
        }
    }

    #[test]
    fn the_same_length_inputs_cover_every_short_length() {
        let mut names = std::collections::HashSet::new();
        let mut lengths = std::collections::HashSet::new();
        for input in &SAME_LENGTH_INPUTS {
            assert!(names.insert(input.name), "duplicate name {}", input.name);
            assert!(!PUBLIC_INPUTS.iter().any(|other| other.name == input.name));
            lengths.insert(input.checked_length());
        }
        assert_eq!(lengths, [12, 15, 18, 21].into_iter().collect());
        for negative in &SAME_LENGTH_NEGATIVE_INPUTS {
            assert!(names.contains(negative.container_of), "{}", negative.name);
        }
    }

    #[test]
    fn a_reduced_same_length_vector_records_consistent_rounds() {
        let mut mhfe = crate::test_support::reduced();
        let reduced = input("reduced", ZERO_15, "Caf\u{E9} \u{1F510}", 0, 0);
        // A private input at reduced cost, which the public entry point refuses.
        assert!(SameLengthVector::generate(&mut mhfe, &reduced).is_err());
        let vector = record_same_length(&mut mhfe, &reduced).unwrap();
        assert_eq!(vector.suite_id, SAME_LENGTH_SUITE_ID);
        assert_eq!(
            (
                vector.state.words,
                vector.state.entropy_bits,
                vector.state.half_bytes
            ),
            (15, 160, 10)
        );
        assert_eq!(vector.container.split(' ').count(), 15);
        assert_eq!(
            vector.recovery.phrase,
            ZERO_15.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        assert!(!vector.recovery.verified);
        assert_eq!(vector.decryption.output_state_hex, vector.state.state_hex);
        let ent = hex::encode(160u32.to_be_bytes());
        for round in vector
            .encryption
            .rounds
            .iter()
            .chain(&vector.decryption.rounds)
        {
            let salt_input = hex::decode(&round.salt_input_hex).unwrap();
            assert!(salt_input.starts_with(SAME_LENGTH_DS_SALT));
            // DS || BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R, R of 10 bytes.
            let after_domain = hex::encode(&salt_input[SAME_LENGTH_DS_SALT.len()..]);
            assert_eq!(&after_domain[16..24], ent);
            assert_eq!(salt_input.len(), SAME_LENGTH_DS_SALT.len() + 16 + 10);
            let digest = Blake2b::<U32>::digest(&salt_input);
            assert_eq!(hex::encode(&digest[..16]), round.salt_hex);
            let mask_input = hex::decode(&round.mask_input_hex).unwrap();
            assert!(mask_input.starts_with(SAME_LENGTH_DS_MASK));
            let key = hex::decode(&round.argon2_key_hex).unwrap();
            assert_eq!(
                hex::encode(&hmac_sha256(&key, &mask_input)[..10]),
                round.mask_hex
            );
        }
        // A 24-word phrase has no same-length form.
        let refused = input("refused", ZERO_24, TEST_PASSWORD, 0, 0);
        assert_eq!(
            record_same_length(&mut mhfe, &refused).err(),
            Some(MhfeError::Format(
                crate::FormatError::SameLengthNeedsShortPhrase
            ))
        );
    }
}
