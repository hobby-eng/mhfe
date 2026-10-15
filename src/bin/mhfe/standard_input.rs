//! Standard input, the one reader of the tool. On Unix it reads its descriptor one byte at a
//! time, so that no read-ahead of a typed or piped secret stays in a buffer the program cannot
//! wipe, as the standard library's buffer of standard input keeps one (AUD-024-SEC007). Taking
//! nothing beyond what it is asked for also lets each reader start where the last one stopped,
//! with no buffer to share between them. On Windows the standard library's reader still turns the
//! console's UTF-16 characters into UTF-8 bytes, and keeps its buffer.

use std::io::{self, BufRead, Read};

#[cfg(unix)]
use zeroize::{Zeroize, Zeroizing};

/// Standard input, as [`StandardInput::new`] describes it.
pub(crate) struct StandardInput {
    /// The byte [`BufRead::fill_buf`] read and nothing has consumed yet; wiped once it is.
    #[cfg(unix)]
    byte: Zeroizing<[u8; 1]>,
    #[cfg(unix)]
    filled: bool,
    #[cfg(not(unix))]
    lock: io::StdinLock<'static>,
}

impl StandardInput {
    /// A reader of standard input. Bytes it read and that were not consumed are lost when it is
    /// dropped: at most one on Unix.
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(unix)]
            byte: Zeroizing::new([0]),
            #[cfg(unix)]
            filled: false,
            #[cfg(not(unix))]
            lock: io::stdin().lock(),
        }
    }
}

impl Read for StandardInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            let Some(first) = buffer.first_mut() else {
                return Ok(0);
            };
            if self.filled {
                *first = self.byte[0];
                self.consume(1);
                return Ok(1);
            }
            read_byte(first)
        }
        #[cfg(not(unix))]
        {
            self.lock.read(buffer)
        }
    }
}

impl BufRead for StandardInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        #[cfg(unix)]
        {
            if !self.filled {
                self.filled = read_byte(&mut self.byte[0])? == 1;
            }
            Ok(&self.byte[..usize::from(self.filled)])
        }
        #[cfg(not(unix))]
        {
            self.lock.fill_buf()
        }
    }

    fn consume(&mut self, amount: usize) {
        #[cfg(unix)]
        if amount > 0 && self.filled {
            self.byte.zeroize();
            self.filled = false;
        }
        #[cfg(not(unix))]
        self.lock.consume(amount);
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
fn read_byte(into: &mut u8) -> io::Result<usize> {
    loop {
        // SAFETY: reads at most one byte into `into`, which is valid for one byte's write.
        let read = unsafe { libc::read(libc::STDIN_FILENO, std::ptr::from_mut(into).cast(), 1) };
        if read >= 0 {
            return Ok(read.unsigned_abs());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    /// Every reader of the tool goes through [`StandardInput`]: no other code of the binary reads
    /// the standard library's standard input, whose buffer it cannot wipe (AUD-024-SEC007).
    #[test]
    fn no_other_code_reads_standard_input() {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/mhfe");
        let mut readers = Vec::new();
        for entry in walk(&folder) {
            let text = std::fs::read_to_string(&entry).unwrap();
            for (number, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                if code.contains("stdin().lock()")
                    || code.contains("stdin().read")
                    || code.contains("stdin().lines()")
                {
                    readers.push(format!("{}:{}", entry.display(), number + 1));
                }
            }
        }
        let this = folder.join("standard_input.rs");
        readers.retain(|reader| !reader.starts_with(&this.display().to_string()));
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
    #[cfg(unix)]
    #[test]
    fn a_consumed_byte_is_wiped() {
        let mut input = StandardInput {
            byte: Zeroizing::new(*b"x"),
            filled: true,
        };
        assert_eq!(input.read(&mut []).unwrap(), 0);
        let mut taken = [0u8; 4];
        assert_eq!(input.read(&mut taken).unwrap(), 1);
        assert_eq!(taken[0], b'x');
        assert_eq!((input.byte[0], input.filled), (0, false));
    }
}
