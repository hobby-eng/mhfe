//! Runs the passwords and settings of the shared fast fixture
//! `tests/fixtures/validation-cases.json` of suite 3 against the library's public interface. Its
//! expected values were computed independently (Python `hashlib`, `hmac` and `unicodedata`). The
//! fixture cases that need the library's own modules run with their unit tests: the refusals
//! before Argon2 of both suites, length detection and the verifier's byte order in src/mhfe.rs,
//! and the suite 4 round messages of `tests/fixtures/suite4-vectors/validation-cases.json` in
//! src/feistel.rs.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

use mhfe::{MhfeError, Password, WorkFactor};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/validation-cases.json")).unwrap()
}

fn cases<'a>(fixture: &'a Value, section: &str) -> &'a Vec<Value> {
    fixture[section].as_array().unwrap()
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field].as_str().unwrap()
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
