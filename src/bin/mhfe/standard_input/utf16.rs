//! One Unicode scalar from a console, preserving a non-low unit after a malformed surrogate.

use std::io;

use mhfe::memory::LockedBytes;
use zeroize::Zeroizing;

/// FF cannot occur in valid UTF-8, so the line reader refuses malformed UTF-16 as input.
const INVALID_UTF8_BYTE: u8 = 0xff;

/// At most one console unit of look-ahead, locked and wiped like StandardInput's UTF-8 buffer.
pub(super) struct ScalarReader {
    pending: LockedBytes,
    available: bool,
}

impl ScalarReader {
    pub(super) fn new() -> Self {
        Self {
            pending: LockedBytes::copy_of(&[0; 2]),
            available: false,
        }
    }

    /// Malformed UTF-16 becomes one invalid UTF-8 byte, so the line reader refuses the whole
    /// answer without normalizing a secret to U+FFFD or losing its following newline/answer.
    pub(super) fn read(
        &mut self,
        mut next: impl FnMut(&mut u16) -> io::Result<usize>,
        into: &mut [u8],
    ) -> io::Result<usize> {
        let mut units = Zeroizing::new([0u16; 2]);
        if self.available {
            units[0] = u16::from_le_bytes([self.pending[0], self.pending[1]]);
            self.pending.fill(0);
            self.available = false;
        } else if next(&mut units[0])? == 0 {
            return Ok(0);
        }
        let length = if (0xd800..=0xdbff).contains(&units[0]) {
            if next(&mut units[1])? == 0 {
                into[0] = INVALID_UTF8_BYTE;
                return Ok(1);
            }
            if !(0xdc00..=0xdfff).contains(&units[1]) {
                self.pending.copy_from_slice(&units[1].to_le_bytes());
                self.available = true;
                into[0] = INVALID_UTF8_BYTE;
                return Ok(1);
            }
            2
        } else {
            1
        };
        match char::decode_utf16(units[..length].iter().copied()).next() {
            Some(Ok(scalar)) => Ok(scalar.encode_utf8(into).len()),
            _ => {
                into[0] = INVALID_UTF8_BYTE;
                Ok(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(units: &[u16], into: &mut [u8]) -> io::Result<(usize, usize)> {
        let mut taken = 0;
        let size = ScalarReader::new().read(
            |unit| match units.get(taken) {
                Some(next) => {
                    *unit = *next;
                    taken += 1;
                    Ok(1)
                }
                None => Ok(0),
            },
            into,
        )?;
        Ok((size, taken))
    }

    #[test]
    fn one_scalar_does_not_read_ahead_to_the_next() {
        let mut bytes = [0; 4];
        for (units, expected, read) in [
            (&[0x0061, 0x0062][..], "a", 1),
            (&[0x754c, 0x0062][..], "\u{754c}", 1),
            (&[0xd835, 0xdc00, 0x0062][..], "\u{1d400}", 2),
        ] {
            let (length, taken) = decode(units, &mut bytes).unwrap();
            assert_eq!(&bytes[..length], expected.as_bytes());
            assert_eq!(taken, read);
        }
        assert_eq!(decode(&[], &mut bytes).unwrap(), (0, 0));
    }

    #[test]
    fn malformed_units_preserve_line_endings_and_the_following_answer() {
        for (units, expected) in [
            (&[0xdc00, 10, 97, 10][..], &[0xff, 10, 97, 10][..]),
            (&[0xd835, 10, 97, 10][..], &[0xff, 10, 97, 10][..]),
            (&[0xd835, 98, 10, 97, 10][..], &[0xff, 98, 10, 97, 10][..]),
            (&[0xd835][..], &[0xff][..]),
            (
                &[0xd835, 0xd835, 0xdc00][..],
                &[0xff, 0xf0, 0x9d, 0x90, 0x80][..],
            ),
        ] {
            let mut reader = ScalarReader::new();
            let mut taken = 0;
            let mut output = Vec::new();
            loop {
                let mut bytes = [0; 4];
                let length = reader
                    .read(
                        |unit| {
                            if let Some(next) = units.get(taken) {
                                *unit = *next;
                                taken += 1;
                                Ok(1)
                            } else {
                                Ok(0)
                            }
                        },
                        &mut bytes,
                    )
                    .unwrap();
                if length == 0 {
                    break;
                }
                output.extend_from_slice(&bytes[..length]);
            }
            assert_eq!(output, expected);
            assert!(std::str::from_utf8(&output).is_err());
            assert!(!reader.available && reader.pending.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn an_error_reading_a_low_surrogate_is_preserved() {
        let mut calls = 0;
        let mut bytes = [0; 4];
        let error = ScalarReader::new()
            .read(
                |unit| {
                    calls += 1;
                    if calls == 1 {
                        *unit = 0xd835;
                        Ok(1)
                    } else {
                        Err(io::ErrorKind::PermissionDenied.into())
                    }
                },
                &mut bytes,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(bytes, [0; 4]);
    }
}
