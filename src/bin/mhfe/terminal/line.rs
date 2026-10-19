//! Bounded line input in one locked allocation, with explicit interactive refused-line draining.
use super::{note_unlocked, too_long_answer, ANSWER_BYTES, LINE_CAPACITY};
use crate::exit::Failure;
use mhfe::memory::{LockedBytes, LockedText};
use std::io::{self, BufRead, Read};

/// Reads an answer of at most ANSWER_BYTES bytes into the reserved, locked LINE_CAPACITY buffer,
/// without its line break. `None` means that the input had ended. A longer line is refused, and
/// what was read of it is wiped with the buffer, so the buffer never grows.
///
/// StandardInput owns and wipes its read-ahead buffer on Unix and Windows; Windows reads through
/// ReadFile or ReadConsoleW rather than the standard library's persistent input buffer. The
/// terminal driver and operating system may retain copies outside this owner's control.
pub(super) fn read_bounded_line(
    reader: &mut impl BufRead,
    drain_refused_line: bool,
) -> Result<Option<LockedText>, Failure> {
    let mut read = 0;
    let mut ended = false;
    // Byte input keeps invalid UTF-8 in the same locked, wiping allocation too.
    let bytes = LockedBytes::build(LINE_CAPACITY, |bytes| {
        read = reader
            .by_ref()
            .take(LINE_CAPACITY as u64)
            .read_until(b'\n', bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    invalid_text()
                } else {
                    error.into()
                }
            })?;
        ended = bytes.last() == Some(&b'\n');
        strip_line_ending(bytes);
        Ok::<(), Failure>(())
    })?;
    if read == LINE_CAPACITY && !ended {
        // Drain only this rejected line, without making another secret copy. Otherwise a
        // retry could accept its tail as the next answer. Real I/O failures still end input.
        if drain_refused_line {
            drain_line(reader)?;
        }
        return Err(too_long_answer());
    }
    if bytes.len() > ANSWER_BYTES {
        return Err(too_long_answer());
    }
    let line = bytes.into_text().map_err(|_| invalid_text())?;
    note_unlocked(line.is_locked());
    Ok((read > 0).then_some(line))
}

/// Discards the rest of one refused line through its delimiter or EOF, using the reader's owner.
fn drain_line(reader: &mut impl BufRead) -> Result<(), Failure> {
    loop {
        let available = reader.fill_buf()?;
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |at| at + 1);
        let done = available.is_empty() || available[consumed - 1] == b'\n';
        reader.consume(consumed);
        if done {
            return Ok(());
        }
    }
}

/// Removes only the line break. Spaces are part of a password and are never trimmed.
fn strip_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
}

/// The same input refusal for byte input and an encoding error from the reader.
fn invalid_text() -> Failure {
    Failure::invalid_input("The answer is not valid UTF-8 text.")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ErrorThenBytes {
        kind: Option<io::ErrorKind>,
        bytes: io::Cursor<&'static [u8]>,
    }

    impl Read for ErrorThenBytes {
        fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
            self.bytes.read(into)
        }
    }

    impl BufRead for ErrorThenBytes {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if let Some(kind) = self.kind.take() {
                return Err(kind.into());
            }
            self.bytes.fill_buf()
        }
        fn consume(&mut self, count: usize) {
            self.bytes.consume(count);
        }
    }

    #[test]
    fn reader_encoding_errors_are_refusals_and_real_io_failures_still_end_input() {
        for (kind, expected) in [
            (io::ErrorKind::InvalidData, crate::exit::INVALID_INPUT),
            (io::ErrorKind::PermissionDenied, crate::exit::INTERNAL_ERROR),
        ] {
            let mut reader = ErrorThenBytes {
                kind: Some(kind),
                bytes: io::Cursor::new(b"valid\n"),
            };
            let Err(error) = read_bounded_line(&mut reader, true) else {
                panic!("reader error accepted");
            };
            assert_eq!(error.exit_code(), expected);
            assert_eq!(
                &*read_bounded_line(&mut reader, true).unwrap().unwrap(),
                "valid"
            );
        }
        let mut reader = ErrorThenBytes {
            kind: Some(io::ErrorKind::Interrupted),
            bytes: io::Cursor::new(b"valid\n"),
        };
        assert_eq!(
            &*read_bounded_line(&mut reader, true).unwrap().unwrap(),
            "valid"
        );
    }
    #[test]
    fn only_the_line_break_is_removed() {
        let mut line = b"  pass word \r\n".to_vec();
        strip_line_ending(&mut line);
        assert_eq!(line, b"  pass word ");
    }

    #[test]
    fn lines_are_read_one_at_a_time_without_their_line_break() {
        let mut input = io::Cursor::new("first answer\r\n second \nlast without break");
        let mut next = || {
            read_bounded_line(&mut input, true)
                .unwrap()
                .map(|line| line.to_string())
        };
        assert_eq!(next().as_deref(), Some("first answer"));
        assert_eq!(next().as_deref(), Some(" second "));
        assert_eq!(next().as_deref(), Some("last without break"));
        assert_eq!(next(), None, "the end of the input is not an empty answer");
    }

    #[test]
    fn a_line_up_to_the_limit_keeps_its_buffer() {
        for ending in ["\n", "\r\n", ""] {
            let longest = format!("{}{ending}", "a".repeat(ANSWER_BYTES));
            let line = read_bounded_line(&mut io::Cursor::new(longest), false)
                .unwrap()
                .unwrap();
            assert_eq!(line.len(), ANSWER_BYTES);
            assert_eq!(
                line.capacity(),
                LINE_CAPACITY,
                "the buffer was never reallocated"
            );
        }
    }

    #[test]
    fn a_longer_line_is_refused() {
        let too_long = format!("{}\n", "a".repeat(ANSWER_BYTES + 1));
        let Err(failure) = read_bounded_line(&mut io::Cursor::new(too_long), false) else {
            panic!("a longer line was accepted");
        };
        assert_eq!(failure.message(), too_long_answer().message());
    }

    #[test]
    fn invalid_utf8_on_standard_input_is_an_input_refusal() {
        let Err(failure) = read_bounded_line(&mut io::Cursor::new(b"\xff\n"), false) else {
            panic!("invalid UTF-8 was accepted");
        };
        assert_eq!(failure.exit_code(), crate::exit::INVALID_INPUT);
        assert_eq!(failure.message(), "The answer is not valid UTF-8 text.");
    }

    #[test]
    fn an_excessive_line_is_drained_before_the_following_answer() {
        for suffix in ["\n", "\r\n"] {
            let data = format!("{}{suffix}valid\n", "a".repeat(LINE_CAPACITY * 2));
            let mut input = io::Cursor::new(data);
            let Err(refused) = read_bounded_line(&mut input, true) else {
                panic!("an excessive line was accepted");
            };
            assert_eq!(refused.exit_code(), crate::exit::INVALID_INPUT);
            assert_eq!(
                &*read_bounded_line(&mut input, true).unwrap().unwrap(),
                "valid"
            );
            assert!(read_bounded_line(&mut input, true).unwrap().is_none());
        }
    }

    #[test]
    fn a_script_refuses_an_excessive_line_without_draining_future_input() {
        let mut input = io::Cursor::new(vec![b'a'; LINE_CAPACITY * 2]);
        let Err(refused) = read_bounded_line(&mut input, false) else {
            panic!("an excessive scripted line was accepted");
        };
        assert_eq!(refused.exit_code(), crate::exit::INVALID_INPUT);
        assert_eq!(input.position(), LINE_CAPACITY as u64);
    }

    #[test]
    fn invalid_utf8_refuses_only_its_line() {
        let mut input = io::Cursor::new(b"public\xff\nvalid\n");
        let Err(refused) = read_bounded_line(&mut input, true) else {
            panic!("invalid UTF-8 was accepted");
        };
        assert_eq!(refused.exit_code(), crate::exit::INVALID_INPUT);
        assert_eq!(
            &*read_bounded_line(&mut input, true).unwrap().unwrap(),
            "valid"
        );
    }
}
