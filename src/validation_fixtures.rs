//! The shared validation fixtures, built into the program for its self-checks and read by the unit
//! tests too: `tests/fixtures/validation-cases.json` (suite 3) and
//! `tests/fixtures/suite4-vectors/validation-cases.json` (suite 4), the specification's
//! `vectors/suite3/validation-cases.json` and `vectors/suite4/validation-cases.json`. Their
//! expected values were computed independently with Python's hashlib, hmac and unicodedata.
//!
//! A self-check must fail, not stop the program, when a built-in table is damaged, so everything
//! here reads them without panicking.

// The passwords module of the browser package reads only the fixture's passwords.
#![cfg_attr(
    all(target_arch = "wasm32", not(feature = "browser-core")),
    allow(dead_code)
)]

use serde_json::Value;

/// Passwords, settings, phrases, length detection and the verifier's byte order of suite 3.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) const SUITE_3: &str = include_str!("../tests/fixtures/validation-cases.json");
/// The `passwords` section of the suite 3 fixture alone, as build.rs cuts it out: all that the
/// password encoding's check reads, so that the passwords module built alone carries no other case.
pub(crate) const SUITE_3_PASSWORDS: &str =
    include_str!(concat!(env!("OUT_DIR"), "/validation-passwords.json"));
/// The round messages of suite 4 for each entropy size, and its refusals before Argon2.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) const SUITE_4: &str =
    include_str!("../tests/fixtures/suite4-vectors/validation-cases.json");

use crate::self_check::damaged;

/// A fixture as read.
pub(crate) struct Fixture(Value);

impl Fixture {
    pub(crate) fn read(json: &str) -> Result<Self, crate::self_check::FailureDetail> {
        serde_json::from_str(json).map(Self).map_err(|_| damaged())
    }

    /// The cases of `section`.
    pub(crate) fn cases(
        &self,
        section: &str,
    ) -> Result<&[Value], crate::self_check::FailureDetail> {
        self.0[section]
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(damaged)
    }

    /// The single case of `section`, which is an object rather than a list.
    pub(crate) fn case(&self, section: &str) -> Result<&Value, crate::self_check::FailureDetail> {
        let case = &self.0[section];
        if case.is_object() {
            Ok(case)
        } else {
            Err(damaged())
        }
    }

    /// A text field of the fixture itself.
    pub(crate) fn text(&self, field: &str) -> Result<&str, crate::self_check::FailureDetail> {
        text(&self.0, field)
    }
}

pub(crate) fn text<'a>(
    case: &'a Value,
    field: &str,
) -> Result<&'a str, crate::self_check::FailureDetail> {
    case[field].as_str().ok_or_else(damaged)
}

pub(crate) fn number(case: &Value, field: &str) -> Result<u64, crate::self_check::FailureDetail> {
    case[field].as_u64().ok_or_else(damaged)
}

/// A number field that fits a `u32`, such as a PIM or a round.
pub(crate) fn number_u32(
    case: &Value,
    field: &str,
) -> Result<u32, crate::self_check::FailureDetail> {
    u32::try_from(number(case, field)?).map_err(|_| damaged())
}

/// The bytes of a hexadecimal field.
pub(crate) fn bytes(
    case: &Value,
    field: &str,
) -> Result<Vec<u8>, crate::self_check::FailureDetail> {
    hex::decode(text(case, field)?).map_err(|_| damaged())
}

/// A list of numbers, such as the matching lengths of a state.
pub(crate) fn numbers(
    case: &Value,
    field: &str,
) -> Result<Vec<usize>, crate::self_check::FailureDetail> {
    case[field]
        .as_array()
        .ok_or_else(damaged)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(damaged)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cut of build.rs is the fixture's passwords section, exactly, and nothing else.
    #[test]
    fn the_password_cases_are_the_fixtures() {
        let whole: Value = serde_json::from_str(SUITE_3).unwrap();
        let cut: Value = serde_json::from_str(SUITE_3_PASSWORDS).unwrap();
        assert_eq!(cut.as_object().unwrap().len(), 1);
        assert_eq!(cut["passwords"], whole["passwords"]);
    }
}
