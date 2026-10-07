//! Runs the shared fast fixtures `tests/fixtures/validation-cases.json` (suite 3) and
//! `tests/fixtures/suite4-vectors/validation-cases.json` (suite 4) against the library. Their
//! expected values were computed independently (Python `hashlib`, `hmac` and `unicodedata`).

use serde_json::Value;

use crate::engine::Argon2Engine;
use crate::packing;
use crate::{Mhfe, MhfeError, Password, PhraseLength, WordCount, WorkFactor};

fn fixture() -> Value {
    serde_json::from_str(crate::validation_fixtures::SUITE_3).unwrap()
}

fn cases<'a>(fixture: &'a Value, section: &str) -> &'a Vec<Value> {
    fixture[section].as_array().unwrap()
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field].as_str().unwrap()
}

/// Fails the test if any case reaches Argon2: every rejection must come first.
struct NoArgon2Calls;

impl Argon2Engine for NoArgon2Calls {
    fn derive(&mut self, _: &[u8], _: &[u8; 16], _: &mut [u8; 32]) -> Result<(), MhfeError> {
        panic!("Argon2 was called for an input that should have been rejected");
    }
}

#[test]
fn passwords_encode_or_fail_as_the_fixture_says() {
    let fixture = fixture();
    for case in cases(&fixture, "passwords") {
        let id = text(case, "id");
        let input = match case.get("repeat_utf8_hex") {
            Some(unit) => hex::decode(unit.as_str().unwrap())
                .unwrap()
                .repeat(case["count"].as_u64().unwrap() as usize),
            None => hex::decode(text(case, "input_utf8_hex")).unwrap(),
        };
        let result = Password::from_utf8(&input);
        match case.get("expected_error") {
            Some(code) => {
                let error = result.err().unwrap_or_else(|| panic!("{id}: accepted"));
                assert_eq!(error.code(), code.as_str().unwrap(), "{id}");
                if let Some(bytes) = case.get("expected_nfkd_bytes") {
                    let length = bytes.as_u64().unwrap() as usize;
                    assert_eq!(error, MhfeError::PasswordTooLong(length), "{id}");
                }
            }
            None => {
                let password = result.unwrap_or_else(|error| panic!("{id}: {error}"));
                if let Some(expected) = case.get("expected_nfkd_utf8_hex") {
                    assert_eq!(
                        hex::encode(password.as_bytes()),
                        expected.as_str().unwrap(),
                        "{id}"
                    );
                }
                if let Some(bytes) = case.get("expected_nfkd_bytes") {
                    assert_eq!(
                        password.as_bytes().len() as u64,
                        bytes.as_u64().unwrap(),
                        "{id}"
                    );
                }
            }
        }
    }
}

#[test]
fn settings_are_checked_before_any_allocation() {
    let fixture = fixture();
    for case in cases(&fixture, "settings") {
        let id = text(case, "id");
        let result = WorkFactor::new(
            case["pim"].as_u64().unwrap() as u32,
            case["memory_level"].as_u64().unwrap() as u32,
        );
        match case.get("expected_error") {
            Some(code) => assert_eq!(result.unwrap_err().code(), code.as_str().unwrap(), "{id}"),
            None => {
                let work = result.unwrap();
                assert_eq!(
                    u64::from(work.memory_kib()),
                    case["expected_memory_kib"].as_u64().unwrap(),
                    "{id}"
                );
                assert_eq!(
                    u64::from(work.passes()),
                    case["expected_passes"].as_u64().unwrap(),
                    "{id}"
                );
            }
        }
    }
}

#[test]
fn bad_phrases_and_containers_fail_before_argon2() {
    let fixture = fixture();
    let password = Password::new("public test password").unwrap();
    let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
    for case in cases(&fixture, "phrases") {
        let id = text(case, "id");
        let error = match text(case, "operation") {
            "encrypt" => mhfe
                .encrypt(
                    text(case, "phrase"),
                    &password,
                    crate::suite::Suite::TwentyFourWords,
                    &mut |_, _| Ok(()),
                )
                .err(),
            "decrypt" => {
                // A wrong word count is refused when the length is made, before decrypt runs.
                let length = match case.get("words") {
                    Some(words) => {
                        WordCount::new(words.as_u64().unwrap() as usize).map(PhraseLength::Words)
                    }
                    None => Ok(PhraseLength::Detect),
                };
                length
                    .and_then(|length| {
                        // These are suite 3 cases: the suite is selected, not taken from the
                        // word count.
                        mhfe.decrypt_as(
                            text(case, "container"),
                            &password,
                            Some(crate::suite::Suite::TwentyFourWords),
                            length,
                            &mut |_, _| Ok(()),
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

#[test]
fn length_detection_matches_the_fixture() {
    let fixture = fixture();
    for case in cases(&fixture, "length_detection") {
        let id = text(case, "id");
        let state: packing::State = hex::decode(text(case, "state_hex"))
            .unwrap()
            .try_into()
            .unwrap();
        if let Some(entropy) = case.get("entropy_hex") {
            let packed = packing::pack(&hex::decode(entropy.as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(*packed, state, "{id}");
        }
        let expected: Vec<usize> = case["matching_short_lengths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|words| words.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(packing::matching_short_lengths(&state), expected, "{id}");
    }
}

#[test]
fn the_verifier_keeps_digest_byte_order() {
    let fixture = fixture();
    let case = &fixture["verifier_serialization"];
    let entropy = hex::decode(text(case, "entropy_hex")).unwrap();
    let state = packing::pack(&entropy).unwrap();
    assert_eq!(hex::encode(&state[..]), text(case, "state_hex"));
    assert_eq!(hex::encode(&state[28..]), text(case, "verifier_hex"));
}

fn suite_4_fixture() -> Value {
    serde_json::from_str(crate::validation_fixtures::SUITE_4).unwrap()
}

/// `BE32(ENT)` follows the settings in every suite 4 round message, so the same settings, round
/// and leading half bytes give a different salt and mask for each entropy size.
#[test]
fn suite_4_round_messages_carry_the_entropy_size() {
    use crate::feistel::{round_mask, round_message, round_salt, Geometry};
    let fixture = suite_4_fixture();
    assert_eq!(fixture["suite_id"], crate::SAME_LENGTH_SUITE_ID);
    for case in cases(&fixture, "ent_separation") {
        let id = text(case, "id");
        let bytes = case["entropy_bits"].as_u64().unwrap() as usize / 8;
        let geometry = Geometry::same_length(bytes).unwrap();
        let work = WorkFactor::new(
            case["pim"].as_u64().unwrap() as u32,
            case["memory_level"].as_u64().unwrap() as u32,
        )
        .unwrap();
        let half = hex::decode(text(case, "half_hex")).unwrap();
        let message = round_message(
            geometry,
            work,
            case["round"].as_u64().unwrap() as u32,
            &half,
        );
        let salt_input = [geometry.ds_salt(), &message].concat();
        assert_eq!(
            hex::encode(salt_input),
            text(case, "salt_input_hex"),
            "{id}"
        );
        assert_eq!(
            hex::encode(round_salt(geometry, &message)),
            text(case, "salt_hex"),
            "{id}"
        );
        let key: [u8; 32] = hex::decode(text(case, "key_hex"))
            .unwrap()
            .try_into()
            .unwrap();
        let mask_input = [geometry.ds_mask(), &message].concat();
        assert_eq!(
            hex::encode(mask_input),
            text(case, "mask_input_hex"),
            "{id}"
        );
        assert_eq!(
            hex::encode(round_mask(geometry, &key, &message)),
            text(case, "mask_hex"),
            "{id}"
        );
    }
}

#[test]
fn suite_4_refusals_come_before_argon2() {
    use crate::suite::Suite;
    let fixture = suite_4_fixture();
    let password = Password::new("public test password").unwrap();
    let mut mhfe = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
    for case in cases(&fixture, "refusals") {
        let id = text(case, "id");
        assert_eq!(text(case, "expected"), "rejected", "{id}");
        let result = match text(case, "operation") {
            "encrypt-same-length" => mhfe
                .encrypt(
                    text(case, "text"),
                    &password,
                    Suite::SameLength,
                    &mut |_, _| Ok(()),
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
                mhfe.decrypt_as(text(case, "text"), &password, suite, length, &mut |_, _| {
                    Ok(())
                })
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
