//! Standard input and standard output, read and written with the operating system's own calls.
//!
//! The standard library puts a buffer of its own in front of both: `io::stdin()` reads up to 8 KiB
//! ahead into one, and `io::stdout()` keeps what it last wrote in another. Both are statics, never
//! freed, wiped or locked, so they would keep a typed password, a pasted phrase, the next answer of
//! a script or a phrase shown for as long as the tool runs (RUST-13). Here every byte goes straight
//! between the descriptor and the caller's buffer, which is locked and wiped where it holds a
//! secret (mhfe::memory): a read through this module, a write through the core's `write_secret`.
//! clippy.toml refuses `io::stdin` and `io::stdout` everywhere else.
//!
//! On Windows a console is read and written in UTF-16, as the standard library does, through
//! buffers that are wiped when dropped; any other handle, such as a pipe, as it is.

#![allow(
    unsafe_code,
    reason = "reading a descriptor needs the operating system's calls, which Rust offers only \
              through unsafe foreign functions"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "this module owns standard input and output; it asks the standard library only \
              whether they are terminals and which colours standard output takes"
)]

use std::fmt;
use std::io::{self, IsTerminal, Write};

use mhfe_core::protect::write_secret;

/// Whether standard input is a terminal.
pub fn input_is_terminal() -> bool {
    io::stdin().is_terminal()
}

/// Whether standard output is a terminal.
pub fn output_is_terminal() -> bool {
    io::stdout().is_terminal()
}

/// Standard input without a buffer: a read takes at most the bytes asked for, so nothing after an
/// answer is read ahead.
#[derive(Default)]
pub struct Stdin(platform::Reader);

impl io::Read for Stdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

/// Standard output without a buffer.
struct Stdout;

impl Write for Stdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // `write_line` formats text, and anstream cuts text only between characters.
        let text = std::str::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
        write_secret(text)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `arguments` and a line break to standard output, with or without colours as
/// `anstream::println!` writes them. A failure, a closed pipe included, is returned, so that a
/// result that cannot be written does not end the tool as a success.
pub fn write_line(arguments: fmt::Arguments) -> io::Result<()> {
    let choice = anstream::stdout().current_choice();
    let mut raw = Stdout;
    let mut output = anstream::AutoStream::new(&mut raw as &mut dyn Write, choice);
    writeln!(output, "{arguments}")
}

/// `println!` to standard output past the standard library's buffer, which returns the error of a
/// failed write; imported in place of `anstream::println`.
macro_rules! println {
    ($($argument:tt)*) => {
        $crate::raw_io::write_line(format_args!($($argument)*))
    };
}
pub(crate) use println;

#[cfg(unix)]
mod platform {
    use std::io;

    /// read(2) on descriptor 0 needs nothing kept between reads.
    #[derive(Default)]
    pub struct Reader;

    impl Reader {
        pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            // SAFETY: `buffer` is valid for writes of its length.
            let read =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            usize::try_from(read).map_err(|_| io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::File;
    use std::io::{self, Read};
    use std::mem::ManuallyDrop;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        GetLastError, SetLastError, ERROR_OPERATION_ABORTED, HANDLE,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, CONSOLE_MODE, STD_INPUT_HANDLE,
    };
    use zeroize::Zeroizing;

    /// A console is read one UTF-16 character at a time and handed on as UTF-8. The bytes of a
    /// character that did not fit a read wait here.
    #[derive(Default)]
    pub struct Reader {
        pending: Zeroizing<[u8; 4]>,
        start: usize,
        end: usize,
    }

    impl Reader {
        pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            // SAFETY: a plain console call.
            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            if !is_console(handle) {
                return standard_file(handle).read(buffer);
            }
            if self.start == self.end {
                self.start = 0;
                self.end = read_character(handle, &mut self.pending)?;
            }
            let count = buffer.len().min(self.end - self.start);
            buffer[..count].copy_from_slice(&self.pending[self.start..self.start + count]);
            self.start += count;
            Ok(count)
        }
    }

    /// Reads one character into `buffer` as UTF-8 and returns its length, 0 at the end of the
    /// input. A character outside the Basic Multilingual Plane comes as two UTF-16 units; half of
    /// one is refused, as by the standard library.
    fn read_character(handle: HANDLE, buffer: &mut [u8; 4]) -> io::Result<usize> {
        let mut units = Zeroizing::new([0u16; 2]);
        let mut count = read_units(handle, &mut units[..1])?;
        if count > 0 && (0xD800..=0xDBFF).contains(&units[0]) {
            count += read_units(handle, &mut units[1..])?;
        }
        let mut written = 0;
        for character in char::decode_utf16(units[..count].iter().copied()) {
            let character = character.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the console sent half of a UTF-16 character",
                )
            })?;
            written += character.encode_utf8(&mut buffer[written..]).len();
        }
        Ok(written)
    }

    /// Reads UTF-16 units into `units`, at least one unless the input has ended. Every key is
    /// data: no Ctrl+Z ends a read here, as it does for the standard library.
    fn read_units(handle: HANDLE, units: &mut [u16]) -> io::Result<usize> {
        loop {
            let mut read = 0u32;
            // SAFETY: room for the units asked for; the input control is optional. The last error
            // is cleared first, so that an error read below is this call's.
            let done = unsafe {
                SetLastError(0);
                ReadConsoleW(
                    handle,
                    units.as_mut_ptr().cast(),
                    units.len() as u32,
                    &mut read,
                    ptr::null(),
                )
            };
            if done == 0 {
                return Err(io::Error::last_os_error());
            }
            // Ctrl+C makes the console return nothing with this error, and the Ctrl+C handler ends
            // the tool; it is not the end of the input.
            // SAFETY: a plain call that reads the thread's last error.
            if read == 0 && unsafe { GetLastError() } == ERROR_OPERATION_ABORTED {
                continue;
            }
            return Ok(read as usize);
        }
    }

    fn is_console(handle: HANDLE) -> bool {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: a plain console call on a standard handle.
        unsafe { GetConsoleMode(handle, &mut mode) != 0 }
    }

    /// A standard handle that is no console, such as a pipe or a file, as a file, which has no
    /// buffer; it stays open.
    fn standard_file(handle: HANDLE) -> ManuallyDrop<File> {
        // SAFETY: a standard handle of this process, which ManuallyDrop never closes.
        ManuallyDrop::new(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};

    /// Set in the child that [`a_failed_write_is_returned`] starts.
    const CHILD: &str = "MHFE_TEST_WRITE_A_LINE";

    /// A line that cannot be written is an error for the caller, so that the tool does not end as
    /// a success, and no panic, also at a closed pipe. Standard output changes only in a child of
    /// its own, since the test harness writes its reports there. /dev/full is Linux's.
    #[test]
    fn a_failed_write_is_returned() {
        if std::env::var_os(CHILD).is_some() {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap();
            let failed = write_a_line_to(full.as_raw_fd()).unwrap_err();
            assert_eq!(failed.kind(), io::ErrorKind::StorageFull);
            let (reader, closed) = io::pipe().unwrap();
            drop(reader);
            let failed = write_a_line_to(closed.as_raw_fd()).unwrap_err();
            assert_eq!(failed.kind(), io::ErrorKind::BrokenPipe);
            return;
        }
        let name = "raw_io::tests::a_failed_write_is_returned";
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&child.stdout);
        assert!(child.status.success(), "{report}");
        assert!(report.contains("1 passed"), "{report}");
    }

    /// [`write_line`] with standard output on `target` for one line.
    fn write_a_line_to(target: RawFd) -> io::Result<()> {
        // SAFETY: a plain call on standard output, which stays open.
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0);
        // SAFETY: both descriptors are open.
        assert!(unsafe { libc::dup2(target, libc::STDOUT_FILENO) } >= 0);
        let written = write_line(format_args!("a line"));
        // SAFETY: `saved` is open and closed only after it is standard output again.
        unsafe {
            libc::dup2(saved, libc::STDOUT_FILENO);
            libc::close(saved);
        }
        written
    }
}
