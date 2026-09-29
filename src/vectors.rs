//! Test vectors: every intermediate value of one encryption and of the matching recovery.
//!
//! A vector contains the password and every round key by design. It must only ever be made from
//! public test inputs; the command-line tool therefore builds vectors only from the fixed
//! public inputs in its source code and never from anything a user types.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::engine::{Argon2Engine, KEY_BYTES, LANES};
use crate::feistel::RoundTrace;
use crate::mhfe::{self, Recovery};
use crate::packing::{self, State};
use crate::suite::{DS_MASK, DS_SALT};
use crate::{phrase, Mhfe, MhfeError, Password, PhraseLength, SUITE_ID};

/// Identifies this file layout; a changed layout gets a new name.
pub const SCHEMA: &str = "mhfe-suite-3-vector-v2";
/// The layout of a negative case.
pub const NEGATIVE_SCHEMA: &str = "mhfe-suite-3-negative-case-v2";
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

/// Encrypts the phrase of a public input under its password, recovers it again with automatic
/// length detection and records every value. Fails if the round trip does not return the
/// original.
pub fn generate<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    input: &PublicInput,
) -> Result<Vector, MhfeError> {
    let (name, phrase_text, password_text) = (input.name, input.phrase, input.password);
    let work = mhfe.work_factor();
    let cost = work.argon2_cost();
    let password = Password::new(password_text)?;
    let source = phrase::parse(phrase_text).map_err(MhfeError::InvalidPhrase)?;
    let entropy = Zeroizing::new(source.to_entropy());
    let x = packing::pack(&entropy)?;

    let mut encryption_rounds = Vec::new();
    let y =
        mhfe.permutation(&password)
            .forward(&x, &mut |_| Ok(()), Some(&mut encryption_rounds))?;
    mhfe::reject_fixed_point(&x, &y)?;
    let container = mhfe::phrase_from_entropy(&y[..])?;

    let mut decryption_rounds = Vec::new();
    let recovered_state =
        mhfe.permutation(&password)
            .inverse(&y, &mut |_| Ok(()), Some(&mut decryption_rounds))?;
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
        name: name.to_owned(),
        warning: WARNING,
        generator: GENERATOR,
        inputs: Inputs {
            phrase: source.to_string(),
            password: password_text.to_owned(),
            password_utf8_hex: hex::encode(password_text.as_bytes()),
            password_nfkd_utf8_hex: hex::encode(password.as_bytes()),
            pim: work.pim(),
            memory_level: work.memory_level(),
        },
        argon2: Argon2Parameters {
            variant: "Argon2id",
            version: ARGON2_VERSION,
            memory_kib: cost.memory_kib,
            passes: cost.passes,
            lanes: LANES,
            output_bytes: KEY_BYTES,
        },
        packing: Packing {
            words: source.word_count(),
            entropy_hex: hex::encode(&entropy[..]),
            verifier_hex: hex::encode(&x[entropy.len()..]),
            state_hex: hex::encode(&x[..]),
        },
        encryption: pass(&x, &encryption_rounds, &y),
        container: container.to_string(),
        decryption: pass(&y, &decryption_rounds, &recovered_state),
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

fn pass(input: &State, rounds: &[RoundTrace], output: &State) -> Pass {
    let half = packing::STATE_BYTES / 2;
    Pass {
        input_state_hex: hex::encode(input),
        rounds: rounds
            .iter()
            .map(|trace| Round {
                round: trace.round,
                left_before_hex: hex::encode(&trace.state_before[..half]),
                right_before_hex: hex::encode(&trace.state_before[half..]),
                salt_input_hex: hex::encode([DS_SALT, &trace.message[..]].concat()),
                salt_hex: hex::encode(trace.salt),
                argon2_key_hex: hex::encode(trace.key),
                mask_input_hex: hex::encode([DS_MASK, &trace.message[..]].concat()),
                mask_hex: hex::encode(trace.mask),
                left_after_hex: hex::encode(&trace.state_after[..half]),
                right_after_hex: hex::encode(&trace.state_after[half..]),
            })
            .collect(),
        output_state_hex: hex::encode(output),
    }
}

/// One public test case. The phrases are BIP39 test phrases and the passwords are public.
///
/// The fields can be read anywhere, but `non_exhaustive` lets only this crate create a
/// `PublicInput`, so the round traces of [`generate`] exist only for the fixed public inputs in
/// [`PUBLIC_INPUTS`]. The specification forbids exporting intermediate states, salts, keys or
/// masks of anything else.
#[non_exhaustive]
pub struct PublicInput {
    pub name: &'static str,
    pub phrase: &'static str,
    pub password: &'static str,
    pub pim: u32,
    pub memory_level: u32,
}

const ZERO_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZERO_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art";
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
/// spaces and an embedded NUL, and a phrase whose state passes two short checks.
pub const PUBLIC_INPUTS: [PublicInput; 17] = [
    input("zero-12", ZERO_12, TEST_PASSWORD, 0, 0),
    input(
        "zero-15",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon address",
        TEST_PASSWORD,
        0,
        0,
    ),
    input(
        "zero-18",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon agent",
        TEST_PASSWORD,
        0,
        0,
    ),
    input(
        "zero-21",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
        TEST_PASSWORD,
        0,
        0,
    ),
    input("zero-24", ZERO_24, TEST_PASSWORD, 0, 0),
    input(
        "nonzero-12",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        OTHER_PASSWORD,
        0,
        0,
    ),
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
    input(
        "nonzero-21",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount \
         doctor acoustic avoid letter advice cage absurd apart",
        OTHER_PASSWORD,
        0,
        0,
    ),
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
    // NFKD changes all but the spaces and the emoji: e + U+0301, "fi", "P", "A" + U+030A, "1",
    // and U+0438 U+0306.
    input(
        "unicode-password",
        ZERO_12,
        "Caf\u{E9} \u{FB01} \u{FF30}\u{212B}\u{2460} \u{1F510} \u{439}",
        0,
        0,
    ),
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
pub struct NegativeInput {
    pub name: &'static str,
    pub container_of: &'static str,
    pub password: &'static str,
    pub pim: u32,
    pub memory_level: u32,
    /// 0 for automatic detection, otherwise the chosen length.
    pub words: usize,
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

/// Runs one negative case at full size and records what recovery gives.
pub fn negative_case<E: Argon2Engine>(
    mhfe: &mut Mhfe<E>,
    input: &NegativeInput,
    container: &str,
) -> Result<NegativeCase, MhfeError> {
    let work = mhfe.work_factor();
    let password = Password::new(input.password)?;
    let length = match input.words {
        0 => PhraseLength::Detect,
        words => PhraseLength::Words(words),
    };
    let (recovery, error_code) =
        match mhfe.decrypt(container, &password, length, &mut |_, _| Ok(())) {
            Ok(Recovery::Phrase(phrase)) => (vec![phrase], None),
            Ok(Recovery::Ambiguous(candidates)) => (candidates, None),
            Err(MhfeError::VerifierMismatch) => {
                (Vec::new(), Some(MhfeError::VerifierMismatch.code()))
            }
            Err(other) => return Err(other),
        };
    Ok(NegativeCase {
        schema: NEGATIVE_SCHEMA,
        suite_id: SUITE_ID,
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
    use crate::WorkFactor;
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    use hmac::{Hmac, Mac};
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
        let vector = generate(&mut mhfe, &reduced).unwrap();

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
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
                mac.update(&mask_input);
                let tag = mac.finalize().into_bytes();
                assert_eq!(hex::encode(&tag[..16]), round.mask_hex);
            }
        }
    }
}
