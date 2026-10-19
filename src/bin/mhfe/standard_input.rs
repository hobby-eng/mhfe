//! The tool's sole standard-input reader. Unix descriptors and Windows pipes read one byte at a
//! time; the Windows console reads one Unicode scalar, including a split UTF-16 surrogate pair.
//! Pending UTF-8 bytes stay in an owned, locked buffer and are wiped as they are consumed. No
//! standard-library read-ahead buffer retains a typed or piped secret (AUD-024-SEC007).

use std::io::{self, BufRead, Read};

use mhfe::memory::LockedBytes;
use zeroize::Zeroize;

#[cfg(any(windows, test))]
mod utf16;
#[cfg(windows)]
mod windows;

/// Standard input, as [`StandardInput::new`] describes it.
pub(crate) struct StandardInput {
    /// At most one UTF-8 scalar; the allocation never moves and is wiped before it is unlocked.
    bytes: LockedBytes,
    pending: std::ops::Range<usize>,
    #[cfg(windows)]
    console: utf16::ScalarReader,
}

impl StandardInput {
    /// A reader of standard input. Bytes it read and that were not consumed are lost when it is
    /// dropped: at most one byte from a descriptor or one scalar and one pending UTF-16 unit
    /// from a Windows console. A malformed surrogate keeps its following unit for the next read.
    pub(crate) fn new() -> Self {
        Self {
            bytes: LockedBytes::copy_of(&[0; 4]),
            pending: 0..0,
            #[cfg(windows)]
            console: utf16::ScalarReader::new(),
        }
    }
}

impl Read for StandardInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let available = self.fill_buf()?;
        let taken = buffer.len().min(available.len());
        buffer[..taken].copy_from_slice(&available[..taken]);
        self.consume(taken);
        Ok(taken)
    }
}

impl BufRead for StandardInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pending.is_empty() {
            #[cfg(not(windows))]
            {
                self.pending = 0..read_input(&mut self.bytes)?;
            }
            #[cfg(windows)]
            {
                self.pending = 0..read_input(&mut self.bytes, &mut self.console)?;
            }
        }
        Ok(&self.bytes[self.pending.clone()])
    }

    fn consume(&mut self, amount: usize) {
        let end = self.pending.start + amount.min(self.pending.len());
        self.bytes[self.pending.start..end].zeroize();
        self.pending.start = end;
    }
}

/// Reads one byte of standard input into `into`: 1, or 0 at the end of the input. A read that a
/// signal interrupts is made again.
#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "read(2) of the descriptor is an operating-system call that Rust offers only through \
              an unsafe foreign function"
)]
fn read_input(into: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: reads at most one byte into `into`, which is valid for one byte's write.
        let read = unsafe { libc::read(libc::STDIN_FILENO, into.as_mut_ptr().cast(), 1) };
        if read >= 0 {
            return Ok(read.unsigned_abs());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(windows)]
fn read_input(into: &mut [u8], console: &mut utf16::ScalarReader) -> io::Result<usize> {
    windows::read(into, console)
}

#[cfg(not(any(unix, windows)))]
fn read_input(_: &mut [u8]) -> io::Result<usize> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const FIRST_LINE: &str = "public UTF-8 \u{1d400}\n";
    const SECOND_LINE: &str = "second public line\n";
    const PIPE_PROBE_PASSED: &str = "MHFE_PUBLIC_PIPE_READER_PASSED";
    // Bound a stalled public-input probe even on a busy native CI host.
    const PIPE_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
    const PIPE_PROBE_POLL: Duration = Duration::from_millis(10);

    struct PipeProbe(Option<Child>);

    impl Drop for PipeProbe {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn native_pipe_bytes_and_lines_leave_no_consumed_bytes_in_the_owner() {
        let mut probe = PipeProbe(Some(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "standard_input::tests::native_pipe_reader",
                    "--nocapture",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let child = probe.0.as_mut().unwrap();
        let deadline = Instant::now() + PIPE_PROBE_TIMEOUT;
        {
            let mut pipe = child.stdin.take().unwrap();
            pipe.write_all(FIRST_LINE.as_bytes()).unwrap();
            pipe.write_all(SECOND_LINE.as_bytes()).unwrap();
        }
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the public pipe probe timed out");
            std::thread::sleep(PIPE_PROBE_POLL);
        }
        let output = probe.0.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains(PIPE_PROBE_PASSED));
    }

    #[test]
    #[ignore = "invoked by the native pipe test with fixed public input"]
    fn native_pipe_reader() {
        // The parent supplies two public lines through a real pipe, exercising actual read(2)
        // or ReadFile rather than a constructed pending buffer. Inspect only live owned memory.
        let mut input = StandardInput::new();
        for expected in FIRST_LINE.as_bytes() {
            assert_eq!(input.fill_buf().unwrap(), &[*expected]);
            assert!(input.bytes[1..].iter().all(|byte| *byte == 0));
            let mut byte = [0; 1];
            assert_eq!(input.read(&mut byte).unwrap(), 1);
            assert_eq!(byte, [*expected]);
            assert!(input.bytes.iter().all(|byte| *byte == 0));
        }
        let mut line = zeroize::Zeroizing::new(String::new());
        assert_eq!(input.read_line(&mut line).unwrap(), SECOND_LINE.len());
        assert_eq!(line.as_str(), SECOND_LINE);
        assert!(input.pending.is_empty());
        assert!(input.bytes.iter().all(|byte| *byte == 0));
        line.zeroize();
        assert_eq!(input.read_line(&mut line).unwrap(), 0);
        assert!(line.is_empty());
        assert!(input.fill_buf().unwrap().is_empty());
        assert!(input.bytes.iter().all(|byte| *byte == 0));
        crate::style::out(PIPE_PROBE_PASSED).unwrap();
    }

    /// Every reader of the tool goes through [`StandardInput`]: no other code of the binary reads
    /// the standard library's standard input, whose buffer it cannot wipe (AUD-024-SEC007).
    #[test]
    fn no_other_code_reads_standard_input() {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/mhfe");
        let mut readers = Vec::new();
        for entry in walk(&folder) {
            let text = std::fs::read_to_string(&entry).unwrap();
            let production = text.split("\n#[cfg(test)]").next().unwrap();
            for (number, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                if code.contains("stdin().lock()")
                    || code.contains("stdin().read")
                    || code.contains("stdin().lines()")
                {
                    readers.push(format!("{}:{}", entry.display(), number + 1));
                }
            }
        }
        assert!(readers.is_empty(), "{readers:?}");
    }

    /// The Rust files under `folder`, at any depth.
    fn walk(folder: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(folder).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk(&path));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
        files
    }

    /// A consumed byte is wiped from the reader, and an empty buffer reads nothing.
    #[test]
    fn a_consumed_byte_is_wiped() {
        let mut input = StandardInput::new();
        input.bytes.copy_from_slice(b"x\0\0\0");
        input.pending = 0..1;
        assert_eq!(input.read(&mut []).unwrap(), 0);
        let mut taken = [0u8; 4];
        assert_eq!(input.read(&mut taken).unwrap(), 1);
        assert_eq!(taken[0], b'x');
        assert_eq!(&*input.bytes, [0; 4]);
        assert!(input.pending.is_empty());
    }

    #[test]
    fn a_partly_consumed_scalar_keeps_only_its_unread_bytes() {
        let mut input = StandardInput::new();
        input.bytes.copy_from_slice("\u{1d400}".as_bytes());
        input.pending = 0..4;
        let mut bytes = [0; 2];
        assert_eq!(input.read(&mut bytes).unwrap(), 2);
        assert_eq!(bytes, [0xf0, 0x9d]);
        assert_eq!(&*input.bytes, [0, 0, 0x90, 0x80]);
        assert_eq!(input.fill_buf().unwrap(), [0x90, 0x80]);
        input.consume(2);
        assert_eq!(&*input.bytes, [0; 4]);
    }
}
