//! One Unicode scalar from the console, including two separately delivered UTF-16 units.

use std::io;

use zeroize::Zeroizing;

/// Reads no further than the current scalar. Malformed or truncated UTF-16 is an input error.
pub(super) fn read_scalar(
    mut next: impl FnMut(&mut u16) -> io::Result<usize>,
    into: &mut [u8],
) -> io::Result<usize> {
    let mut units = Zeroizing::new([0u16; 2]);
    if next(&mut units[0])? == 0 {
        return Ok(0);
    }
    let length = if (0xd800..=0xdbff).contains(&units[0]) {
        if next(&mut units[1])? == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        2
    } else {
        1
    };
    let mut decoded = char::decode_utf16(units[..length].iter().copied());
    let Some(Ok(scalar)) = decoded.next() else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    Ok(scalar.encode_utf8(into).len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(units: &[u16], into: &mut [u8]) -> io::Result<(usize, usize)> {
        let mut taken = 0;
        let size = read_scalar(
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
    fn malformed_and_truncated_surrogates_are_refused() {
        for units in [&[0xdc00][..], &[0xd835][..], &[0xd835, 0x0061][..]] {
            let mut bytes = [0; 4];
            assert_eq!(
                decode(units, &mut bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(bytes, [0; 4]);
        }
    }

    #[test]
    fn an_error_reading_a_low_surrogate_is_preserved() {
        let mut calls = 0;
        let mut bytes = [0; 4];
        let error = read_scalar(
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
