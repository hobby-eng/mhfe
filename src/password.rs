//! The MHFE password, encoded as the specification requires ("Password encoding"):
//! `P_enc = UTF8(NFKD(P))`, using the Normalization Process for Stabilized Strings with the
//! Unicode 17.0.0 character database, 1 to 1024 bytes, and without control characters or the
//! line and paragraph separators.

use std::fmt;

use unicode_normalization::char::is_public_assigned;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::memory::LockedBytes;
use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
pub(crate) mod known_answers;

/// Longest accepted password after normalization, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A normalized password. It is kept out of swap, wiped from memory when dropped and never
/// printed.
pub struct Password {
    // Locked before the password is written into it, and wiped before its pages are unlocked,
    // also when it is refused.
    encoded: LockedBytes,
}

impl Password {
    /// Encodes `text` as NFKD in UTF-8. Fails, and never truncates, when `text` contains a
    /// control character, a line or paragraph separator, or a code point that Unicode 17.0.0 does
    /// not assign, or when the result is empty or over 1024 bytes. No case folding, trimming or
    /// other change is applied.
    pub fn new(text: &str) -> Result<Self, MhfeError> {
        // A password is ordinary single-line text: invisible characters such as NUL or TAB, and
        // line breaks, which Windows and other systems write differently, could not be typed or
        // pasted the same way everywhere. NFKD produces none of them from another character (a
        // test checks every code point), so checking the input is enough.
        if text.chars().any(is_forbidden_in_password) {
            return Err(MhfeError::ControlCharacterInPassword);
        }

        // The stabilization rule: a string with an unassigned code point is not normalized at
        // all, so that a later Unicode version cannot change what the password means.
        if !text.chars().all(is_assigned_in_unicode_17) {
            return Err(MhfeError::UnassignedCharacter);
        }

        // The buffer is allocated once at its largest allowed size and never grows, so no
        // reallocation can leave an unwiped copy of the password behind. It is locked before the
        // password is written into it; a password refused here is wiped while it is still locked.
        let encoded = LockedBytes::build(MAX_PASSWORD_BYTES, |encoded| {
            let mut encoded_length = 0usize;
            let mut character_bytes = [0u8; 4];
            for character in text.nfkd() {
                let bytes = character.encode_utf8(&mut character_bytes).as_bytes();
                encoded_length += bytes.len();
                if encoded_length <= MAX_PASSWORD_BYTES {
                    encoded.extend_from_slice(bytes);
                }
            }
            character_bytes.zeroize();
            match encoded_length {
                0 => Err(MhfeError::EmptyPassword),
                length if length > MAX_PASSWORD_BYTES => Err(MhfeError::PasswordTooLong(length)),
                _ => Ok(()),
            }
        })?;
        Ok(Self { encoded })
    }

    /// Same as [`Password::new`] for a password that arrives as UTF-8 bytes, as from a browser.
    pub fn from_utf8(bytes: &[u8]) -> Result<Self, MhfeError> {
        let text = std::str::from_utf8(bytes).map_err(|_| MhfeError::InvalidPasswordUtf8)?;
        Self::new(text)
    }

    /// The encoded password `P_enc`, as Argon2id receives it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(hidden)")
    }
}

/// Characters no password may contain: every control character (General_Category Cc, 65 code
/// points such as NUL, TAB, LF, CR and U+0085), U+2028 LINE SEPARATOR and U+2029 PARAGRAPH
/// SEPARATOR. `char::is_control` is exactly the Cc category.
fn is_forbidden_in_password(character: char) -> bool {
    character.is_control() || character == '\u{2028}' || character == '\u{2029}'
}

/// Whether Unicode 17.0.0 assigns `character`. `is_public_assigned` answers this except that it
/// also rejects Private Use characters, which are assigned and therefore allowed.
fn is_assigned_in_unicode_17(character: char) -> bool {
    is_public_assigned(character) || is_private_use(character)
}

/// The three Private Use areas: the one in the Basic Multilingual Plane and planes 15 and 16
/// without their last two code points, which are noncharacters.
fn is_private_use(character: char) -> bool {
    matches!(
        character,
        '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(text: &str) -> Vec<u8> {
        Password::new(text).unwrap().as_bytes().to_vec()
    }

    #[test]
    fn control_characters_and_separators_are_refused_anywhere() {
        for text in [
            "pass\nword",
            "pass\rword",
            "password\r\n",
            "\npassword",
            "a\tb",
            "a\u{0}b",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{9f}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            assert!(
                matches!(
                    Password::new(text),
                    Err(MhfeError::ControlCharacterInPassword)
                ),
                "{text:?}"
            );
        }
        // Visible separators and spaces stay part of the password.
        assert_eq!(encoded("  a b\u{a0}"), "  a b ".as_bytes());
    }

    /// The refused set is General_Category Cc, 65 code points in Unicode 17, plus U+2028 and
    /// U+2029: 67 in all.
    #[test]
    fn the_refused_set_has_67_code_points() {
        let refused = (0..=0x10FFFF)
            .filter_map(char::from_u32)
            .filter(|&character| is_forbidden_in_password(character))
            .count();
        assert_eq!(refused, 67);
    }

    /// The specification checks the refused characters before normalization and relies on NFKD
    /// never producing one from another character. This checks that claim for every Unicode 17
    /// scalar value.
    #[test]
    fn normalization_never_creates_a_refused_character() {
        use unicode_normalization::UnicodeNormalization;
        for character in (0..=0x10FFFF).filter_map(char::from_u32) {
            if is_forbidden_in_password(character) {
                continue;
            }
            let decomposed: String = std::iter::once(character).nfkd().collect();
            assert!(
                !decomposed.chars().any(is_forbidden_in_password),
                "U+{:04X} decomposes to a refused character",
                u32::from(character)
            );
        }
    }

    #[test]
    fn normalization_tables_are_unicode_17() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
    }

    #[test]
    fn ascii_passes_through_unchanged_with_case_and_spaces() {
        assert_eq!(encoded("public test password"), b"public test password");
        assert_eq!(encoded("  Case Matters "), b"  Case Matters ");
        assert_ne!(encoded("Password"), encoded("password"));
    }

    #[test]
    fn applies_compatibility_decomposition() {
        // Each pair: input and its NFKD form.
        let cases = [
            ("\u{FB01}", "fi"),                       // ligature fi
            ("\u{E9}", "e\u{301}"),                   // é becomes e + combining acute
            ("\u{212B}", "A\u{30A}"),                 // Angstrom sign
            ("\u{FF30}", "P"),                        // fullwidth P
            ("\u{2460}", "1"),                        // circled digit one
            ("\u{B2}", "2"),                          // superscript two
            ("\u{439}", "\u{438}\u{306}"),            // Cyrillic й
            ("\u{D55C}", "\u{1112}\u{1161}\u{11AB}"), // Hangul syllable han
            ("\u{1F510}", "\u{1F510}"),               // emoji, no decomposition
        ];
        for (input, expected) in cases {
            assert_eq!(encoded(input), expected.as_bytes(), "{input:?}");
        }
    }

    #[test]
    fn accepts_private_use_characters_unchanged() {
        for character in [
            '\u{E000}',
            '\u{F8FF}',
            '\u{F0000}',
            '\u{FFFFD}',
            '\u{100000}',
            '\u{10FFFD}',
        ] {
            let text = character.to_string();
            assert_eq!(encoded(&text), text.as_bytes(), "{character:?}");
        }
    }

    #[test]
    fn rejects_unassigned_code_points_and_noncharacters() {
        let unassigned = ['\u{378}', '\u{E0080}', '\u{50000}'];
        let noncharacters = [
            '\u{FDD0}',
            '\u{FDEF}',
            '\u{FFFE}',
            '\u{FFFF}',
            '\u{1FFFF}',
            '\u{10FFFF}',
        ];
        for character in unassigned.into_iter().chain(noncharacters) {
            let text = format!("valid{character}");
            assert!(
                matches!(Password::new(&text), Err(MhfeError::UnassignedCharacter)),
                "{character:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_and_invalid_utf8_passwords() {
        assert!(matches!(Password::new(""), Err(MhfeError::EmptyPassword)));
        for invalid in [
            &[0xff][..],
            &[0xc0, 0xaf],
            &[0xed, 0xa0, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
        ] {
            assert!(matches!(
                Password::from_utf8(invalid),
                Err(MhfeError::InvalidPasswordUtf8)
            ));
        }
    }

    #[test]
    fn length_limit_applies_after_normalization() {
        assert_eq!(encoded(&"a".repeat(1024)).len(), 1024);
        assert!(matches!(
            Password::new(&"a".repeat(1025)),
            Err(MhfeError::PasswordTooLong(1025))
        ));
        assert!(matches!(
            Password::new(&"\u{44F}".repeat(513)), // я, two bytes each
            Err(MhfeError::PasswordTooLong(1026))
        ));

        // U+FDFA expands to 18 characters, 33 UTF-8 bytes: 31 copies fit, 32 do not.
        let expanding = "\u{FDFA}";
        assert_eq!(encoded(expanding).len(), 33);
        assert_eq!(encoded(&expanding.repeat(31)).len(), 1023);
        assert!(matches!(
            Password::new(&expanding.repeat(32)),
            Err(MhfeError::PasswordTooLong(1056))
        ));

        // The ligature fi shrinks from three bytes to two: 1,536 input bytes are accepted.
        assert_eq!(encoded(&"\u{FB01}".repeat(512)).len(), 1024);
    }

    /// The encoded password lives in a buffer locked at the largest size, which it never outgrows;
    /// a refused one is wiped in that buffer while it is locked (LockedBytes::build).
    #[test]
    fn the_password_is_held_locked_at_its_largest_size() {
        let password = Password::new("public test password").unwrap();
        assert_eq!(password.encoded.is_locked(), cfg!(unix));
        let longest = Password::new(&"a".repeat(MAX_PASSWORD_BYTES)).unwrap();
        assert_eq!(longest.as_bytes().len(), MAX_PASSWORD_BYTES);
        assert_eq!(longest.encoded.is_locked(), cfg!(unix));
    }

    #[test]
    fn debug_output_hides_the_password() {
        let password = Password::new("public test password").unwrap();
        assert_eq!(format!("{password:?}"), "Password(hidden)");
    }
}
