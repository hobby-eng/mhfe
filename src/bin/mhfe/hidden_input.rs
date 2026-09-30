//! Reads one line from the terminal without showing it and without changing it.
//!
//! The specification requires a password with a control character, such as TAB, NUL or U+0085,
//! to be refused, never cleaned. A reader that swallowed such characters would encrypt with a
//! different password from the one that was typed or pasted. So every character is kept as
//! data, except these keys, which keep their usual meaning:
//!
//! - Backspace deletes the last character and Ctrl+U the whole line;
//! - Enter ends the line, and Ctrl+D on an empty line ends the input;
//! - Ctrl+C cancels the tool.
//!
//! On Unix and on Windows the terminal's own line editing is switched off and this module edits
//! the line itself, so both behave the same. A terminal's line mode would otherwise act on further
//! keys (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O, Ctrl+\, Ctrl+Z) and, on Linux, cut a line
//! after 4095 bytes, although a valid password can take 4096 bytes before normalization (1024
//! characters that NFKD turns into one byte each). scripts/verify-hidden-input.py checks this in a
//! Unix pseudo-terminal and scripts/verify-hidden-input-windows.py in a Windows pseudo-console.

// Changing the terminal settings needs the operating system's terminal calls, which Rust offers
// only through unsafe foreign functions.
#![allow(unsafe_code)]

use std::io;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::exit::Failure;

/// The terminal settings to restore while a hidden prompt has changed them. Whoever changes or
/// restores the terminal holds this lock, so the Ctrl+C handler and a prompt never interleave.
static SAVED: Mutex<Option<platform::Settings>> = Mutex::new(None);

/// Switches the terminal to hidden input, runs `prompt`, reads one line as described above and
/// restores the terminal, also when reading fails. `None` means that the input was closed. The
/// terminal is switched before the prompt appears, so that a key typed or text pasted as soon as
/// the prompt shows is already read as data.
pub fn read_line(
    prompt: impl FnOnce() -> Result<(), Failure>,
) -> Result<Option<Zeroizing<String>>, Failure> {
    let original = platform::current()?;
    {
        let mut saved = lock_saved();
        *saved = Some(original);
        if let Err(error) = platform::hide(&original) {
            saved.take();
            platform::restore(&original);
            return Err(error);
        }
    }
    let result = prompt().and_then(|()| platform::read_line());
    if let Some(original) = lock_saved().take() {
        platform::restore(&original);
    }
    // The terminal did not show the Enter key either.
    anstream::eprintln!();
    result
}

/// For the Ctrl+C handler: restores the terminal if a hidden prompt changed it, and keeps the lock
/// until `exit` has ended the tool, so that no new prompt can change the terminal in between.
pub fn restore_and_exit(exit: fn() -> !) -> ! {
    let mut saved = lock_saved();
    if let Some(original) = saved.take() {
        platform::restore(&original);
    }
    exit()
}

fn lock_saved() -> std::sync::MutexGuard<'static, Option<platform::Settings>> {
    // A panic while the lock was held cannot leave the saved settings half-written.
    SAVED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn terminal_error(action: &str) -> Failure {
    let error = io::Error::last_os_error();
    Failure::from(io::Error::new(
        error.kind(),
        format!("could not {action} the terminal: {error}"),
    ))
}

/// The keys that edit a hidden line; every other byte is kept.
mod keys {
    pub const BACKSPACE: u8 = 0x08;
    pub const DELETE: u8 = 0x7f;
    pub const CTRL_U: u8 = 0x15;
    pub const CTRL_D: u8 = 0x04;
}

/// Edits a line from raw terminal bytes: Backspace or Delete removes the last character, Ctrl+U
/// the whole line, Enter (CR or LF) ends it, and Ctrl+D on an empty line or the end of the input
/// gives `None`. Every other byte is kept. The buffer is reserved at its largest size and never
/// grows, so it leaves no unwiped copy; a longer line is refused.
fn edit_line(reader: &mut impl io::Read) -> Result<Option<Zeroizing<String>>, Failure> {
    use crate::terminal::LINE_CAPACITY;
    use keys::{BACKSPACE, CTRL_D, CTRL_U, DELETE};

    let mut line = Zeroizing::new(Vec::with_capacity(LINE_CAPACITY));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(&mut byte[..]) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        match byte[0] {
            b'\r' | b'\n' => break,
            BACKSPACE | DELETE => remove_last_character(&mut line),
            CTRL_U => line.clear(),
            CTRL_D if line.is_empty() => return Ok(None),
            _ if line.len() == LINE_CAPACITY => {
                return Err(Failure::invalid_input(format!(
                    "An answer is longer than {LINE_CAPACITY} bytes; no valid answer is that long."
                )))
            }
            other => line.push(other),
        }
    }
    let bytes = std::mem::take(&mut *line);
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(error) => {
            // The error holds the bytes; they are wiped before it is dropped.
            drop(Zeroizing::new(error.into_bytes()));
            Err(Failure::invalid_input(
                "The answer is not valid UTF-8 text.",
            ))
        }
    }
}

/// Removes the last UTF-8 character: its continuation bytes, then its first byte.
fn remove_last_character(line: &mut Vec<u8>) {
    const CONTINUATION_MASK: u8 = 0b1100_0000;
    const CONTINUATION: u8 = 0b1000_0000;
    while line
        .last()
        .is_some_and(|byte| byte & CONTINUATION_MASK == CONTINUATION)
    {
        line.pop();
    }
    line.pop();
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::mem::MaybeUninit;

    use zeroize::Zeroizing;

    use super::{edit_line, terminal_error};
    use crate::exit::Failure;

    pub type Settings = libc::termios;

    pub fn current() -> Result<Settings, Failure> {
        let mut settings = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the whole structure when it returns 0.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, settings.as_mut_ptr()) } != 0 {
            return Err(terminal_error("read the settings of"));
        }
        // SAFETY: initialised by the successful tcgetattr above.
        Ok(unsafe { settings.assume_init() })
    }

    pub fn hide(original: &Settings) -> Result<(), Failure> {
        let mut hidden = *original;
        // No echo and no line mode: this module edits the line. ISIG keeps Ctrl+C as the
        // interrupt key; quit and suspend become ordinary characters.
        hidden.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN);
        hidden.c_lflag |= libc::ISIG;
        hidden.c_cc[libc::VQUIT] = libc::_POSIX_VDISABLE;
        hidden.c_cc[libc::VSUSP] = libc::_POSIX_VDISABLE;
        // A read returns as soon as one byte is there.
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        // No flow control (Ctrl+S, Ctrl+Q) and no changes to the bytes.
        hidden.c_iflag &= !(libc::IXON | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL);
        // SAFETY: a valid termios for the terminal on standard input.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err(terminal_error("hide the input on"));
        }
        Ok(())
    }

    pub fn read_line() -> Result<Option<Zeroizing<String>>, Failure> {
        edit_line(&mut io::stdin().lock())
    }

    pub fn restore(original: &Settings) {
        // SAFETY: the settings read from this terminal before. A failure cannot be reported
        // usefully here; the shell restores the terminal when the tool ends in any case.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original) };
    }
}

#[cfg(windows)]
mod platform {
    use std::io;

    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
    };
    use zeroize::Zeroizing;

    use super::{edit_line, terminal_error};
    use crate::exit::Failure;

    pub type Settings = CONSOLE_MODE;

    pub fn current() -> Result<Settings, Failure> {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: a plain console call on the standard input handle.
        if unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) } == 0 {
            return Err(terminal_error("read the settings of"));
        }
        Ok(mode)
    }

    pub fn hide(original: &Settings) -> Result<(), Failure> {
        // No echo and no line mode: this module edits the line. Processed input keeps Ctrl+C as
        // the cancel key; without line input the console acts on no other key.
        let hidden = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
        // SAFETY: a plain console call on the standard input handle.
        if unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), hidden) } == 0 {
            return Err(terminal_error("hide the input on"));
        }
        Ok(())
    }

    /// The standard library turns the console's UTF-16 characters into UTF-8 bytes.
    pub fn read_line() -> Result<Option<Zeroizing<String>>, Failure> {
        edit_line(&mut io::stdin().lock())
    }

    pub fn restore(original: &Settings) {
        // SAFETY: the mode read from this console before.
        unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), *original) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edited(bytes: &[u8]) -> Option<String> {
        edit_line(&mut io::Cursor::new(bytes.to_vec()))
            .unwrap()
            .map(|line| line.to_string())
    }

    #[test]
    fn control_characters_other_than_the_editing_keys_are_kept() {
        for key in [b'\t', 0x00, 0x11, 0x13, 0x16, 0x17, 0x1a, 0x1c, 0x1b] {
            assert_eq!(
                edited(&[b'a', key, b'b', b'\r']).unwrap().as_bytes(),
                [b'a', key, b'b']
            );
        }
        // Ctrl+D inside a line is kept too; the password check refuses it.
        assert_eq!(edited(b"a\x04b\n").unwrap(), "a\u{4}b");
    }

    #[test]
    fn backspace_and_ctrl_u_edit_the_line() {
        assert_eq!(edited(b"abx\x7f\r").unwrap(), "ab");
        assert_eq!(edited(b"abx\x08\r").unwrap(), "ab");
        assert_eq!(edited("a\u{1D400}\x7f\r".as_bytes()).unwrap(), "a");
        assert_eq!(edited(b"wrong\x15right\r").unwrap(), "right");
        assert_eq!(edited(b"\x7f\x7fa\r").unwrap(), "a");
    }

    #[test]
    fn ctrl_d_on_an_empty_line_or_the_end_of_input_closes_it() {
        assert_eq!(edited(b"\x04"), None);
        assert_eq!(edited(b""), None);
        assert_eq!(edited(b"abc").unwrap(), "abc");
    }

    /// 1024 characters U+1D400 take 4096 bytes and normalize to 1024 bytes: a valid password.
    #[test]
    fn the_longest_valid_password_fits() {
        let text = "\u{1D400}".repeat(1024);
        assert_eq!(edited(format!("{text}\r").as_bytes()).unwrap(), text);
        assert!(mhfe::Password::new(&text).is_ok());
    }

    #[test]
    fn a_line_over_the_capacity_or_invalid_utf8_is_refused() {
        use crate::terminal::LINE_CAPACITY;
        let longest = "a".repeat(LINE_CAPACITY);
        assert_eq!(edited(format!("{longest}\r").as_bytes()).unwrap(), longest);
        let too_long = format!("{longest}a\r");
        assert!(edit_line(&mut io::Cursor::new(too_long)).is_err());
        assert!(edit_line(&mut io::Cursor::new(b"\xff\r".to_vec())).is_err());
    }
}
