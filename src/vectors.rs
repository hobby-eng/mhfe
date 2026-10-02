//! Test vectors: every intermediate value of one encryption and of the matching recovery, for
//! suite 3 and for the same-length containers of suite 4.
//!
//! A vector contains the password and every round key by design. It must only ever be made from
//! public test inputs; the command-line tool therefore builds vectors only from the fixed
//! public inputs in its source code and never from anything a user types.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::engine::{Argon2Engine, KEY_BYTES, LANES};
use crate::feistel::{Geometry, RoundTrace};
use crate::mhfe::{self, Recovery};
use crate::packing;
use crate::{
    phrase, Mhfe, MhfeError, Password, PhraseLength, Suite, WordCount, WorkFactor,
    SAME_LENGTH_SUITE_ID, SUITE_ID,
};

/// Identifies this file layout; a changed layout gets a new name.
pub const SCHEMA: &str = "mhfe-suite-3-vector-v2";
/// The layout of a negative case.
pub const NEGATIVE_SCHEMA: &str = "mhfe-suite-3-negative-case-v2";
/// The layout of a suite 4 vector.
pub const SAME_LENGTH_SCHEMA: &str = "mhfe-suite-4-vector-v1";
/// The layout of a suite 4 negative case.
pub const SAME_LENGTH_NEGATIVE_SCHEMA: &str = "mhfe-suite-4-negative-case-v1";
const WARNING: &str = "Public test data only. This file contains the password and every round \
                       key by design; never use its phrase or password for real funds.";
/// Argon2 version 1.3, written as the number the specification and RFC 9106 use (0x13).
const ARGON2_VERSION: u32 = 0x13;

/// What wrote a vector. The exact source revision is the commit that adds the files; an
/// independent check records its own revision next to them (independent-verification.json).
#[derive(Serialize)]
pub struct Generator {
    pub program: &'static str,
    pub version: &'static str,
    pub argon2: &'static str,
}

const GENERATOR: Generator = Generator {
    program: "mhfe test-vectors",
    version: env!("CARGO_PKG_VERSION"),
    argon2: "reference C implementation, P-H-C/phc-winner-argon2 commit \
             f57e61e19229e23c4445b85494dbf7c07de721cb",
};

#[derive(Serialize)]
pub struct Vector {
    pub schema: &'static str,
    pub suite_id: &'static str,
    pub name: String,
    pub warning: &'static str,
    pub generator: Generator,
    pub inputs: Inputs,
    pub argon2: Argon2Parameters,
    pub packing: Packing,
    pub encryption: Pass,
    pub container: String,
    pub decryption: Pass,
    pub recovery: Vec<RecoveredCandidate>,
}

#[derive(Serialize)]
pub struct Inputs {
    pub phrase: String,
    /// The password as typed; `password_nfkd_utf8_hex` is `P_enc`, what Argon2 receives.
    pub password: String,
    pub password_utf8_hex: String,
    pub password_nfkd_utf8_hex: String,
    pub pim: u32,
    pub memory_level: u32,
}

#[derive(Serialize)]
pub struct Argon2Parameters {
    pub variant: &'static str,
    pub version: u32,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub output_bytes: usize,
}

#[derive(Serialize)]
pub struct Packing {
    pub words: usize,
    pub entropy_hex: String,
    /// `V_r`; empty for a 24-word phrase.
    pub verifier_hex: String,
    /// `X = E || V_r`.
    pub state_hex: String,
}

/// One direction of the permutation. Rounds appear in the order they run: 0 to 11 when
/// encrypting, 11 down to 0 when decrypting.
#[derive(Serialize)]
pub struct Pass {
    pub input_state_hex: String,
    pub rounds: Vec<Round>,
    pub output_state_hex: String,
}

#[derive(Serialize)]
pub struct Round {
    pub round: u32,
    pub left_before_hex: String,
    pub right_before_hex: String,
    /// The BLAKE2b-256 input `DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R`.
    pub salt_input_hex: String,
    pub salt_hex: String,
    pub argon2_key_hex: String,
    /// The HMAC-SHA-256 message `DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R`.
    pub mask_input_hex: String,
    pub mask_hex: String,
    pub left_after_hex: String,
    pub right_after_hex: String,
}

#[derive(Serialize)]
pub struct RecoveredCandidate {
    pub words: usize,
    pub verified: bool,
    pub phrase: String,
}

/// A suite 4 vector: the state is the entropy itself, without a verifier, and every round
/// message carries `BE32(ENT)`.
#[derive(Serialize)]
pub struct SameLengthVector {
    pub schema: &'static str,
    pub suite_id: &'static str,
    pub name: String,
    pub warning: &'static str,
    pub generator: Generator,
    pub inputs: Inputs,
    pub argon2: Argon2Parameters,
    pub state: SameLengthState,
    pub encryption: Pass,
    /// As many words as the phrase.
    pub container: String,
    pub decryption: Pass,
    /// The one reading of a same-length container: never verified, since it has no check.
    pub recovery: RecoveredCandidate,
}

#[derive(Serialize)]
pub struct SameLengthState {
    pub words: usize,
    /// `ENT`, which every salt and mask message carries as `BE32(ENT)`.
    pub entropy_bits: u32,
    /// `h / 8`, the size of each Feistel half.
    pub half_bytes: usize,
    /// `X = E`.
    pub state_hex: String,
}

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

/// Writes the transcript of one input; [`generate`] makes sure that it is a public one.
fn record<E: Argon2Engine>(mhfe: &mut Mhfe<E>, input: &PublicInput) -> Result<Vector, MhfeError> {
    let work = mhfe.work_factor();
    let password = Password::new(input.password)?;
    let source = phrase::parse(input.phrase).map_err(MhfeError::InvalidPhrase)?;
    let entropy = Zeroizing::new(source.to_entropy());
    let x = packing::pack(&entropy)?;

    let mut encryption_rounds = Vec::new();
    let y = mhfe.permutation(&password, Geometry::SUITE_3).forward(
        &x[..],
        &mut |_| Ok(()),
        Some(&mut encryption_rounds),
    )?;
    mhfe::reject_fixed_point(&x[..], &y)?;
    let container = mhfe::phrase_from_entropy(&y)?;

    let mut decryption_rounds = Vec::new();
    let recovered = mhfe.permutation(&password, Geometry::SUITE_3).inverse(
        &y,
        &mut |_| Ok(()),
        Some(&mut decryption_rounds),
    )?;
    let recovered_state = mhfe::suite_3_state(&recovered)?;
    if *recovered_state != *x {
        return Err(MhfeError::Internal(
            "the vector round trip did not return the original state".to_owned(),
        ));
    }
    let recovery = match mhfe::recover(&recovered_state, PhraseLength::Detect)? {
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
            words: source.word_count(),
            entropy_hex: hex::encode(&entropy[..]),
            verifier_hex: hex::encode(&x[entropy.len()..]),
            state_hex: hex::encode(&x[..]),
        },
        encryption: pass(Geometry::SUITE_3, &x[..], &encryption_rounds, &y),
        container: container.to_string(),
        decryption: pass(
            Geometry::SUITE_3,
            &y,
            &decryption_rounds,
            &recovered_state[..],
        ),
        recovery: recovery
            .into_iter()
            .map(|candidate| RecoveredCandidate {
                words: candidate.words,
                verified: candidate.verified,
                phrase: candidate.phrase.to_string(),
            })
            .collect(),
    })
}

/// Encrypts the phrase of a public suite 4 input into a container of its own length, recovers it
/// and records every value. Fails if the round trip does not return the original.
pub fn generate_same_length<E: Argon2Engine>(
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

/// Writes the transcript of one suite 4 input; [`generate_same_length`] makes sure it is public.
fn record_same_length<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    input: &PublicInput,
) -> Result<SameLengthVector, MhfeError> {
    let work = mhfe.work_factor();
    let password = Password::new(input.password)?;
    let source = phrase::parse(input.phrase).map_err(MhfeError::InvalidPhrase)?;
    let x = Zeroizing::new(source.to_entropy());
    if x.len() == packing::STATE_BYTES {
        return Err(MhfeError::SameLengthNeedsShortPhrase);
    }
    let geometry = Geometry::same_length(x.len())?;

    let mut encryption_rounds = Vec::new();
    let y = mhfe.permutation(&password, geometry).forward(
        &x,
        &mut |_| Ok(()),
        Some(&mut encryption_rounds),
    )?;
    mhfe::reject_fixed_point(&x, &y)?;
    let container = mhfe::phrase_from_entropy(&y)?;

    let mut decryption_rounds = Vec::new();
    let recovered = mhfe.permutation(&password, geometry).inverse(
        &y,
        &mut |_| Ok(()),
        Some(&mut decryption_rounds),
    )?;
    if *recovered != *x {
        return Err(MhfeError::Internal(
            "the vector round trip did not return the original state".to_owned(),
        ));
    }
    Ok(SameLengthVector {
        schema: SAME_LENGTH_SCHEMA,
        suite_id: SAME_LENGTH_SUITE_ID,
        name: input.name.to_owned(),
        warning: WARNING,
        generator: GENERATOR,
        inputs: inputs_of(input, &password, work),
        argon2: argon2_of(work),
        state: SameLengthState {
            words: source.word_count(),
            entropy_bits: 8 * x.len() as u32,
            half_bytes: geometry.half_bytes(),
            state_hex: hex::encode(&x[..]),
        },
        encryption: pass(geometry, &x, &encryption_rounds, &y),
        container: container.to_string(),
        decryption: pass(geometry, &y, &decryption_rounds, &recovered),
        recovery: RecoveredCandidate {
            words: source.word_count(),
            verified: false,
            phrase: mhfe::phrase_from_entropy(&recovered)?.to_string(),
        },
    })
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
        memory_kib: cost.memory_kib,
        passes: cost.passes,
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
                round: trace.round,
                left_before_hex: hex::encode(&trace.state_before[..half]),
                right_before_hex: hex::encode(&trace.state_before[half..]),
                salt_input_hex: hex::encode([geometry.ds_salt(), &trace.message[..]].concat()),
                salt_hex: hex::encode(trace.salt),
                argon2_key_hex: hex::encode(trace.key),
                mask_input_hex: hex::encode([geometry.ds_mask(), &trace.message[..]].concat()),
                mask_hex: hex::encode(&trace.mask),
                left_after_hex: hex::encode(&trace.state_after[..half]),
                right_after_hex: hex::encode(&trace.state_after[half..]),
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
        Err(MhfeError::Internal(
            "test vectors are made only from the fixed public inputs, at their own settings".into(),
        ))
    }
}

/// One public test case. The phrases are BIP39 test phrases and the passwords are public.
///
/// The fields are private and can only be read, so no code outside this crate can make or change
/// a `PublicInput`, and [`generate`] also refuses anything that is not in [`PUBLIC_INPUTS`]: the
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
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn phrase(&self) -> &'static str {
        self.phrase
    }

    pub const fn password(&self) -> &'static str {
        self.password
    }

    pub const fn pim(&self) -> u32 {
        self.pim
    }

    pub const fn memory_level(&self) -> u32 {
        self.memory_level
    }
}

const ZERO_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZERO_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art";
const ZERO_15: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon address";
const ZERO_18: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon agent";
const ZERO_21: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon admit";
const NONZERO_12: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NONZERO_21: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice \
                          cage absurd amount doctor acoustic avoid letter advice cage absurd apart";
/// NFKD changes all but the spaces and the emoji: e + U+0301, "fi", "P", "A" + U+030A, "1",
/// and U+0438 U+0306.
const UNICODE_PASSWORD: &str = "Caf\u{E9} \u{FB01} \u{FF30}\u{212B}\u{2460} \u{1F510} \u{439}";
const TEST_PASSWORD: &str = "public test password";
const OTHER_PASSWORD: &str = "audit probe password 2026";

const fn input(
    name: &'static str,
    phrase: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
) -> PublicInput {
    PublicInput {
        name,
        phrase,
        password,
        pim,
        memory_level,
    }
}

/// The suite 3 vector set: every phrase length with zero and non-zero entropy, a non-zero PIM, a
/// non-zero memory level and both together, a password that NFKD changes, a password with
/// leading, repeated and trailing spaces, and a phrase whose state passes two short checks.
pub const PUBLIC_INPUTS: [PublicInput; 17] = [
    input("zero-12", ZERO_12, TEST_PASSWORD, 0, 0),
    input("zero-15", ZERO_15, TEST_PASSWORD, 0, 0),
    input("zero-18", ZERO_18, TEST_PASSWORD, 0, 0),
    input("zero-21", ZERO_21, TEST_PASSWORD, 0, 0),
    input("zero-24", ZERO_24, TEST_PASSWORD, 0, 0),
    input("nonzero-12", NONZERO_12, OTHER_PASSWORD, 0, 0),
    input(
        "nonzero-15",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage \
         wise",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input(
        "nonzero-18",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount \
         doctor acoustic avoid letter always",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input("nonzero-21", NONZERO_21, OTHER_PASSWORD, 0, 0),
    input(
        "nonzero-24",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage \
         worth useful legal winner thank year wave sausage worth title",
        OTHER_PASSWORD,
        0,
        0,
    ),
    input("zero-12-pim-1", ZERO_12, TEST_PASSWORD, 1, 0),
    input("zero-12-memory-level-1", ZERO_12, TEST_PASSWORD, 0, 1),
    input("zero-12-pim-1-memory-level-1", ZERO_12, TEST_PASSWORD, 1, 1),
    input("zero-24-pim-1-memory-level-1", ZERO_24, TEST_PASSWORD, 1, 1),
    input("unicode-password", ZERO_12, UNICODE_PASSWORD, 0, 0),
    // Leading, repeated and trailing spaces are part of the password: nothing is trimmed.
    input(
        "spaces-password",
        ZERO_12,
        "  public   test password  ",
        0,
        0,
    ),
    // Its state passes both the 12- and the 21-word check, so recovery lists both and the
    // 24-word reading.
    input(
        "ambiguous-12-21",
        "essence drama mule dolphin bitter rain abandon abandon able human mule relax",
        TEST_PASSWORD,
        0,
        0,
    ),
];

/// A recovery that must not give the original: a wrong password or setting, or a wrongly chosen
/// length. `container_of` names the positive vector whose container is used.
///
/// Like [`PublicInput`], it can only be read outside this crate, and [`negative_case`] refuses
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
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The name of the positive vector whose container this case recovers.
    pub const fn container_of(&self) -> &'static str {
        self.container_of
    }

    pub const fn password(&self) -> &'static str {
        self.password
    }

    pub const fn pim(&self) -> u32 {
        self.pim
    }

    pub const fn memory_level(&self) -> u32 {
        self.memory_level
    }

    /// 0 for automatic detection, otherwise the chosen length.
    pub const fn words(&self) -> usize {
        self.words
    }
}

const fn negative(
    name: &'static str,
    container_of: &'static str,
    password: &'static str,
    pim: u32,
    memory_level: u32,
    words: usize,
) -> NegativeInput {
    NegativeInput {
        name,
        container_of,
        password,
        pim,
        memory_level,
        words,
    }
}

/// Wrong password, PIM and memory level for a 12-word container; a wrong password for a 24-word
/// container, which has no check and yields another valid phrase; and the right password with
/// 24 words selected for a 12-word container, which gives an unverified 24-word reading.
pub const NEGATIVE_INPUTS: [NegativeInput; 6] = [
    negative(
        "wrong-password-detect",
        "zero-12",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative(
        "wrong-password-12-words",
        "zero-12",
        "public test passworD",
        0,
        0,
        12,
    ),
    negative("wrong-pim", "zero-12", TEST_PASSWORD, 1, 0, 0),
    negative("wrong-memory-level", "zero-12", TEST_PASSWORD, 0, 1, 0),
    negative(
        "wrong-password-24-words",
        "zero-24",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative("selected-24-words", "zero-12", TEST_PASSWORD, 0, 0, 24),
];

/// The suite 4 vector set: every short length at the defaults, zero and non-zero entropy, a
/// non-zero PIM, memory level 1, both together, and a password that NFKD changes.
pub const SAME_LENGTH_INPUTS: [PublicInput; 10] = [
    input("same-length-zero-12", ZERO_12, TEST_PASSWORD, 0, 0),
    input("same-length-zero-15", ZERO_15, TEST_PASSWORD, 0, 0),
    input("same-length-zero-18", ZERO_18, TEST_PASSWORD, 0, 0),
    input("same-length-zero-21", ZERO_21, TEST_PASSWORD, 0, 0),
    input("same-length-nonzero-12", NONZERO_12, OTHER_PASSWORD, 0, 0),
    input("same-length-nonzero-21", NONZERO_21, OTHER_PASSWORD, 0, 0),
    input("same-length-zero-12-pim-1", ZERO_12, TEST_PASSWORD, 1, 0),
    input(
        "same-length-zero-12-memory-level-1",
        ZERO_12,
        TEST_PASSWORD,
        0,
        1,
    ),
    input(
        "same-length-zero-12-pim-1-memory-level-1",
        ZERO_12,
        TEST_PASSWORD,
        1,
        1,
    ),
    input(
        "same-length-unicode-password",
        ZERO_15,
        UNICODE_PASSWORD,
        0,
        0,
    ),
];

/// Suite 4 recoveries with a wrong password, PIM or memory level, which give another valid
/// phrase of the same length without any error, and with another length chosen, which is refused
/// before any Argon2 work.
pub const SAME_LENGTH_NEGATIVE_INPUTS: [NegativeInput; 4] = [
    negative(
        "same-length-wrong-password",
        "same-length-zero-12",
        "public test passworD",
        0,
        0,
        0,
    ),
    negative(
        "same-length-wrong-pim",
        "same-length-zero-12",
        TEST_PASSWORD,
        1,
        0,
        0,
    ),
    negative(
        "same-length-wrong-memory-level",
        "same-length-zero-12",
        TEST_PASSWORD,
        0,
        1,
        0,
    ),
    negative(
        "same-length-other-length-chosen",
        "same-length-zero-12",
        TEST_PASSWORD,
        0,
        0,
        15,
    ),
];

/// The recorded outcome of a negative case: the phrases recovery produced, or its error code.
#[derive(Serialize)]
pub struct NegativeCase {
    pub schema: &'static str,
    pub suite_id: &'static str,
    pub name: String,
    pub generator: Generator,
    pub container: String,
    pub password: String,
    pub password_nfkd_utf8_hex: String,
    pub pim: u32,
    pub memory_level: u32,
    /// 0 for automatic detection.
    pub words: usize,
    pub recovery: Vec<RecoveredCandidate>,
    pub error_code: Option<&'static str>,
}

/// Runs one suite 3 negative case at full size and records what recovery gives.
pub fn negative_case<E: Argon2Engine>(
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

/// Runs one suite 4 negative case at full size and records what recovery gives.
pub fn same_length_negative_case<E: Argon2Engine>(
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

/// A recovery of `container` that must not give its original, under the suite of its set.
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
    let (recovery, error_code) =
        match mhfe.decrypt(container, &password, length, &mut |_, _| Ok(())) {
            Ok(Recovery::Phrase(phrase)) => (vec![phrase], None),
            Ok(Recovery::Ambiguous(candidates)) => (candidates, None),
            Err(
                error @ (MhfeError::VerifierMismatch | MhfeError::LengthChoiceNotApplicable { .. }),
            ) => (Vec::new(), Some(error.code())),
            Err(other) => return Err(other),
        };
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
        recovery: recovery
            .into_iter()
            .map(|candidate| RecoveredCandidate {
                words: candidate.words,
                verified: candidate.verified,
                phrase: candidate.phrase.to_string(),
            })
            .collect(),
        error_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Argon2Cost, NativeEngine};
    use crate::suite::{DS_MASK, DS_SALT, SAME_LENGTH_DS_MASK, SAME_LENGTH_DS_SALT};
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    #[test]
    fn the_public_inputs_are_valid_and_cover_the_required_cases() {
        let mut names = std::collections::HashSet::new();
        let mut lengths = std::collections::HashSet::new();
        for input in &PUBLIC_INPUTS {
            assert!(names.insert(input.name), "duplicate name {}", input.name);
            lengths.insert(crate::check_phrase(input.phrase).unwrap());
            Password::new(input.password).unwrap();
            WorkFactor::new(input.pim, input.memory_level).unwrap();
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
        assert_eq!(
            packing::matching_short_lengths(&packing::pack(&entropy).unwrap()),
            vec![12, 21]
        );
    }

    #[test]
    fn a_reduced_vector_records_consistent_rounds() {
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        let engine = NativeEngine::reduced_for_tests(cost).unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), engine);
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let reduced = input("reduced", phrase, "Caf\u{E9} \u{1F510}", 0, 0);
        // A private input at reduced cost, which the public entry point refuses.
        assert!(generate(&mut mhfe, &reduced).is_err());
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
                let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
                mac.update(&mask_input);
                let tag = mac.finalize().into_bytes();
                assert_eq!(hex::encode(&tag[..16]), round.mask_hex);
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
            lengths.insert(crate::check_phrase(input.phrase).unwrap());
            Password::new(input.password).unwrap();
            WorkFactor::new(input.pim, input.memory_level).unwrap();
        }
        assert_eq!(lengths, [12, 15, 18, 21].into_iter().collect());
        for negative in &SAME_LENGTH_NEGATIVE_INPUTS {
            assert!(names.contains(negative.container_of), "{}", negative.name);
        }
    }

    #[test]
    fn a_reduced_same_length_vector_records_consistent_rounds() {
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        let engine = NativeEngine::reduced_for_tests(cost).unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), engine);
        let reduced = input("reduced", ZERO_15, "Caf\u{E9} \u{1F510}", 0, 0);
        // A private input at reduced cost, which the public entry point refuses.
        assert!(generate_same_length(&mut mhfe, &reduced).is_err());
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
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
            mac.update(&mask_input);
            let tag = mac.finalize().into_bytes();
            assert_eq!(hex::encode(&tag[..10]), round.mask_hex);
        }
        // A 24-word phrase has no same-length form.
        let refused = input("refused", ZERO_24, TEST_PASSWORD, 0, 0);
        assert_eq!(
            record_same_length(&mut mhfe, &refused).err(),
            Some(MhfeError::SameLengthNeedsShortPhrase)
        );
    }
}
