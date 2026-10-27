//! Standard input and standard output, read and written with the operating system's own calls.
//!
//! The standard library puts a buffer of its own in front of both: `io::stdin()` reads up to 8 KiB
//! ahead into one, and `io::stdout()` keeps what it last wrote in another. Both are statics, never
//! freed, wiped or locked, so they would keep a typed password, a pasted phrase, the next answer of
//! a script or a phrase shown for as long as the tool runs (RUST-13). Here every byte goes straight
//! between the descriptor and the caller's buffer, which is locked and wiped where it holds a
//! secret (mhfe::memory). clippy.toml refuses `io::stdin` and `io::stdout` everywhere else.
//!
//! On Windows a console is read and written in UTF-16, as the standard library does, through
//! buffers that are wiped when dropped; any other handle, such as a pipe, as it is.

#![allow(
    unsafe_code,
    reason = "reading and writing a descriptor needs the operating system's calls, which Rust \
              offers only through unsafe foreign functions"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "this module owns standard input and output; it asks the standard library only \
              whether they are terminals and which colours standard output takes"
)]

use std::fmt;
use std::io::{self, IsTerminal, Write};

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
        platform::write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `arguments` and a line break to standard output, with or without colours as
/// `anstream::println!` writes them. A closed pipe is ignored, as with `anstream::println!`, which
/// [`println`] replaces; any other failure is returned, so that a result that cannot be written
/// does not end the tool as a success.
pub fn write_line(arguments: fmt::Arguments) -> io::Result<()> {
    let choice = anstream::stdout().current_choice();
    let mut raw = Stdout;
    let mut output = anstream::AutoStream::new(&mut raw as &mut dyn Write, choice);
    match writeln!(output, "{arguments}") {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        written => written,
    }
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

    pub fn write(bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: `bytes` is valid for reads of its length.
        let written =
            unsafe { libc::write(libc::STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        usize::try_from(written).map_err(|_| io::Error::last_os_error())
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::ManuallyDrop;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        GetLastError, SetLastError, ERROR_OPERATION_ABORTED, HANDLE,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, WriteConsoleW, CONSOLE_MODE, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    use zeroize::Zeroizing;

    /// A console is read in UTF-16 and handed on as UTF-8. A read into a buffer too small for any
    /// character takes one, and the bytes that did not fit wait here.
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
                if buffer.len() >= self.pending.len() {
                    return read_characters(handle, buffer);
                }
                self.start = 0;
                self.end = read_characters(handle, &mut self.pending[..])?;
            }
            let count = buffer.len().min(self.end - self.start);
            buffer[..count].copy_from_slice(&self.pending[self.start..self.start + count]);
            self.start += count;
            Ok(count)
        }
    }

    /// Reads what the console has, up to what fits `buffer` of at least four bytes, into it as
    /// UTF-8, as the standard library does; 0 at the end of the input. A key's escape sequence thus
    /// comes whole. A character outside the Basic Multilingual Plane comes as two UTF-16 units;
    /// half of one is refused, as by the standard library.
    fn read_characters(handle: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
        // A unit takes at most three bytes in UTF-8 and a pair of them four, so the pair of a
        // last unit read still fits.
        let mut units = Zeroizing::new(vec![0u16; (buffer.len() - 1) / 3 + 1]);
        let last = units.len() - 1;
        let mut count = read_units(handle, &mut units[..last])?;
        if count > 0 && (0xD800..=0xDBFF).contains(&units[count - 1]) {
            count += read_units(handle, &mut units[count..=count])?;
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

    pub fn write(bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: a plain console call.
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        if !is_console(handle) {
            return standard_file(handle).write(bytes);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a console takes only UTF-8 text",
            )
        })?;
        // Reserved at its largest size, so that it never grows and leaves no unwiped copy.
        let mut units = Zeroizing::new(Vec::with_capacity(text.len()));
        units.extend(text.encode_utf16());
        let mut rest = &units[..];
        while !rest.is_empty() {
            let mut written = 0u32;
            // SAFETY: `rest` is valid for reads of its length in UTF-16 units.
            let done = unsafe {
                WriteConsoleW(
                    handle,
                    rest.as_ptr(),
                    rest.len() as u32,
                    &mut written,
                    ptr::null(),
                )
            };
            if done == 0 {
                return Err(io::Error::last_os_error());
            }
            rest = &rest[written as usize..];
        }
        Ok(bytes.len())
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
    /// a success, and no panic; a closed pipe is none. Standard output changes only in a child of
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
            write_a_line_to(closed.as_raw_fd()).unwrap();
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
