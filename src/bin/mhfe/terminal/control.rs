//! Raw terminal controls with bounded retries, including a non-blocking terminal's full queue.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::exit::Failure;

const CONTROL_TRIES: usize = 6000;
const CONTROL_WAIT: Duration = Duration::from_millis(10);
// A partial control followed by an error leaves the screen mode unknown. Subsequent private
// operations refuse it until a fresh process can switch and clear the terminal again.
static CONTROL_FAILED: AtomicBool = AtomicBool::new(false);

/// A private screen can be used only while every preceding screen control was written.
pub(super) fn require_healthy() -> Result<(), Failure> {
    if CONTROL_FAILED.load(Ordering::SeqCst) {
        return Err(Failure::internal(
            "The terminal could not change screens. Restart the command before showing secrets.",
        ));
    }
    Ok(())
}

/// Writes an unfiltered control, with at most a minute of waiting for a full terminal.
pub(crate) fn write_control(sequence: &str) -> Result<(), Failure> {
    let result = write_bytes(
        &mut io::stderr().lock(),
        sequence.as_bytes(),
        CONTROL_TRIES,
        || {
            std::thread::sleep(CONTROL_WAIT);
        },
    );
    if result.is_err() {
        CONTROL_FAILED.store(true, Ordering::SeqCst);
    }
    result.map_err(Into::into)
}

fn write_bytes(
    terminal: &mut impl Write,
    sequence: &[u8],
    attempts: usize,
    mut wait: impl FnMut(),
) -> io::Result<()> {
    let mut rest = sequence;
    for _ in 0..attempts {
        match terminal.write(rest) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => {
                rest = &rest[written..];
                if rest.is_empty() {
                    return terminal.flush();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => wait(),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from(io::ErrorKind::TimedOut))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Writer {
        bytes: Vec<u8>,
        calls: usize,
        block: usize,
        failure: Option<io::ErrorKind>,
    }

    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls <= self.block {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if let Some(error) = self.failure {
                return Err(io::Error::from(error));
            }
            let count = bytes.len().min(2);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_full_terminal_and_partial_writes_deliver_the_complete_control() {
        let mut writer = Writer {
            bytes: Vec::new(),
            calls: 0,
            block: 2,
            failure: None,
        };
        let mut waits = 0;
        write_bytes(&mut writer, b"public-control", 20, || waits += 1).unwrap();
        assert_eq!(writer.bytes, b"public-control");
        assert_eq!(waits, 2);
    }

    #[test]
    fn a_failed_or_permanently_full_terminal_returns_its_error() {
        for (block, failure, expected) in [
            (
                0,
                Some(io::ErrorKind::BrokenPipe),
                io::ErrorKind::BrokenPipe,
            ),
            (20, None, io::ErrorKind::TimedOut),
        ] {
            let mut writer = Writer {
                bytes: Vec::new(),
                calls: 0,
                block,
                failure,
            };
            assert_eq!(
                write_bytes(&mut writer, b"public-control", 3, || {})
                    .unwrap_err()
                    .kind(),
                expected
            );
        }
        let mut empty = io::sink();
        assert_eq!(
            write_bytes(&mut empty, b"x", 0, || {}).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
