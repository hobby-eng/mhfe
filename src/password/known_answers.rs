//! Known answers of the password encoding: the self-check `password-unicode`.
//!
//! The NFKD and combining-class tables of unicode-normalization (Unicode 17.0.0), the test of
//! assigned characters, and the refusals of control characters, separators, lengths and invalid
//! UTF-8. The cases are the `passwords` of the shared validation fixture, which
//! `scripts/independent-suite3.py passwords` checks with Python's unicodedata2 17.0.0, and the
//! password of the published vector unicode-password. The full self-test adds two scans of every
//! Unicode scalar value: the number of refused characters, and that NFKD makes none of them.

use unicode_normalization::UnicodeNormalization;

use super::{is_forbidden_in_password, Password};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::validation_fixtures::{self as fixtures, Fixture};
use crate::MhfeError;

/// The password of the published vectors unicode-password and same-length-unicode-password: the
/// ANGSTROM SIGN U+212B among other characters NFKD changes. The bytes after NFKD are the vectors'
/// password_nfkd_utf8_hex.
const UNICODE_PASSWORD: &str = "Caf\u{e9} \u{fb01} \u{ff30}\u{212b}\u{2460} \u{1f510} \u{439}";
const UNICODE_PASSWORD_NFKD: &str = "43616665cc81206669205041cc8a3120f09f949020d0b8cc86";

/// The refused characters: the 65 of General_Category Cc in Unicode 17.0.0, U+2028 and U+2029.
const REFUSED_SCALARS: usize = 67;

/// The `password-unicode` check.
pub(crate) struct PasswordUnicodeCheck {
    fixture: &'static str,
    unicode_nfkd: &'static str,
}

impl PasswordUnicodeCheck {
    pub(crate) fn new() -> Self {
        Self {
            fixture: crate::validation_fixtures::SUITE_3,
            unicode_nfkd: UNICODE_PASSWORD_NFKD,
        }
    }

    /// One case of the fixture: the bytes after NFKD, or the refusal the fixture names.
    fn case(case: &serde_json::Value) -> Result<(), String> {
        let input = match case.get("repeat_utf8_hex") {
            Some(_) => {
                let count = usize::try_from(fixtures::number(case, "count")?)
                    .map_err(|_| "the built-in cases are damaged".to_owned())?;
                fixtures::bytes(case, "repeat_utf8_hex")?.repeat(count)
            }
            None => fixtures::bytes(case, "input_utf8_hex")?,
        };
        let result = Password::from_utf8(&input);
        if case.get("expected_error").is_some() {
            let code = fixtures::text(case, "expected_error")?;
            if case.get("expected_nfkd_bytes").is_some() {
                let length = usize::try_from(fixtures::number(case, "expected_nfkd_bytes")?)
                    .map_err(|_| "the built-in cases are damaged".to_owned())?;
                return expect(
                    matches!(&result, Err(MhfeError::PasswordTooLong(bytes)) if *bytes == length),
                    "gives another length",
                );
            }
            return expect_refusal(result, code);
        }
        let password = result.map_err(stopped)?;
        if case.get("expected_nfkd_utf8_hex").is_some() {
            expect(
                password.as_bytes() == fixtures::bytes(case, "expected_nfkd_utf8_hex")?,
                "gives other bytes",
            )?;
        }
        if case.get("expected_nfkd_bytes").is_some() {
            expect(
                password.as_bytes().len() as u64 == fixtures::number(case, "expected_nfkd_bytes")?,
                "gives another length",
            )?;
        }
        Ok(())
    }

    fn cases(&self, findings: &mut Findings) -> Result<(), String> {
        let fixture = Fixture::read(self.fixture)?;
        findings.each("case", fixture.cases("passwords")?, Self::case);
        Ok(())
    }
}

/// Every Unicode scalar value.
fn scalars() -> impl Iterator<Item = char> {
    (0..=char::MAX as u32).filter_map(char::from_u32)
}

impl ComponentCheck for PasswordUnicodeCheck {
    fn id(&self) -> &'static str {
        "password-unicode"
    }

    fn label(&self) -> &'static str {
        "Passwords (Unicode 17)"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.one(|| {
            expect(
                unicode_normalization::UNICODE_VERSION == (17, 0, 0),
                "the normalization tables are not Unicode 17.0.0",
            )
        });
        findings.one(|| {
            let password = Password::new(UNICODE_PASSWORD).map_err(stopped)?;
            expect(
                hex::encode(password.as_bytes()) == self.unicode_nfkd,
                "the published password gives other bytes",
            )
        });
        if let Err(damaged) = self.cases(&mut findings) {
            findings.one(|| Err(damaged));
        }
        if tier == Tier::Full {
            findings.one(|| {
                expect(
                    scalars()
                        .filter(|&character| is_forbidden_in_password(character))
                        .count()
                        == REFUSED_SCALARS,
                    "another number of characters is refused",
                )
            });
            // The refused characters are checked before NFKD, which is right only if NFKD never
            // makes one from another character.
            findings.one(|| {
                let creates_refused = scalars()
                    .filter(|&character| !is_forbidden_in_password(character))
                    .any(|character| {
                        std::iter::once(character)
                            .nfkd()
                            .any(is_forbidden_in_password)
                    });
                expect(!creates_refused, "NFKD makes a refused character")
            });
        }
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_encoding_passes() {
        assert_eq!(
            PasswordUnicodeCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    /// The full tier scans every scalar value twice, which takes seconds in a debug build.
    #[test]
    fn the_full_tier_passes() {
        assert_eq!(
            PasswordUnicodeCheck::new().run(Tier::Full),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn corrupted_bytes_or_a_wrong_refusal_fail() {
        let mut check = PasswordUnicodeCheck {
            unicode_nfkd: "43616665cc81206669205041c3853120f09f949020d0b8cc86",
            ..PasswordUnicodeCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("the published password gives other bytes".to_owned())
        );
        // The Hangul syllable decomposed otherwise.
        let changed = crate::validation_fixtures::SUITE_3
            .replacen("e18492e185a1e186ab", "ed959c", 1)
            .leak();
        let mut check = PasswordUnicodeCheck {
            fixture: changed,
            ..PasswordUnicodeCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("case 10 of 33 gives other bytes".to_owned())
        );
        // U+2028 expected to be refused as unassigned rather than as a separator.
        let separator = "\"input_utf8_hex\": \"61e280a862\",\n      \"expected_error\": ";
        let changed = crate::validation_fixtures::SUITE_3
            .replacen(
                &format!("{separator}\"CONTROL_CHARACTER_IN_PASSWORD\""),
                &format!("{separator}\"UNASSIGNED_CHARACTER\""),
                1,
            )
            .leak();
        assert_ne!(changed, crate::validation_fixtures::SUITE_3);
        let mut check = PasswordUnicodeCheck {
            fixture: changed,
            ..PasswordUnicodeCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "case 26 of 33 is refused with CONTROL_CHARACTER_IN_PASSWORD instead of \
                 UNASSIGNED_CHARACTER"
                    .to_owned()
            )
        );
    }
}
