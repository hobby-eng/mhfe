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
pub(crate) const SUITE_3: &str = include_str!("../tests/fixtures/validation-cases.json");
/// The round messages of suite 4 for each entropy size, and its refusals before Argon2.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) const SUITE_4: &str =
    include_str!("../tests/fixtures/suite4-vectors/validation-cases.json");

/// What a damaged built-in table gives as the detail of a failure.
const DAMAGED: &str = "the built-in cases are damaged";

/// A fixture as read.
pub(crate) struct Fixture(Value);

impl Fixture {
    pub(crate) fn read(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map(Self)
            .map_err(|_| DAMAGED.to_owned())
    }

    /// The cases of `section`.
    pub(crate) fn cases(&self, section: &str) -> Result<&[Value], String> {
        self.0[section]
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| DAMAGED.to_owned())
    }

    /// The single case of `section`, which is an object rather than a list.
    pub(crate) fn case(&self, section: &str) -> Result<&Value, String> {
        let case = &self.0[section];
        if case.is_object() {
            Ok(case)
        } else {
            Err(DAMAGED.to_owned())
        }
    }

    /// A text field of the fixture itself.
    pub(crate) fn text(&self, field: &str) -> Result<&str, String> {
        text(&self.0, field)
    }
}

pub(crate) fn text<'a>(case: &'a Value, field: &str) -> Result<&'a str, String> {
    case[field].as_str().ok_or_else(|| DAMAGED.to_owned())
}

pub(crate) fn number(case: &Value, field: &str) -> Result<u64, String> {
    case[field].as_u64().ok_or_else(|| DAMAGED.to_owned())
}

/// A number field that fits a `u32`, such as a PIM or a round.
pub(crate) fn number_u32(case: &Value, field: &str) -> Result<u32, String> {
    u32::try_from(number(case, field)?).map_err(|_| DAMAGED.to_owned())
}

/// The bytes of a hexadecimal field.
pub(crate) fn bytes(case: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(text(case, field)?).map_err(|_| DAMAGED.to_owned())
}

/// A list of numbers, such as the matching lengths of a state.
pub(crate) fn numbers(case: &Value, field: &str) -> Result<Vec<usize>, String> {
    case[field]
        .as_array()
        .ok_or_else(|| DAMAGED.to_owned())?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| DAMAGED.to_owned())
        })
        .collect()
}
