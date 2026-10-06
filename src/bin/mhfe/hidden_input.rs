//! Reads one line from the terminal without changing it: hidden, or, on the private screen,
//! shown as it is typed.
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
//! A line that is shown is shown as the person types it, except its control characters: they are
//! kept for the password check to refuse, but never written to the terminal, which would act on
//! them.
//!
//! On Unix and on Windows the terminal's own line editing is switched off and this module edits
//! the line itself, so both behave the same. A terminal's line mode would otherwise act on further
//! keys (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O, Ctrl+\, Ctrl+Z) and, on Linux, cut a line
//! after 4095 bytes, although a valid password can take 4096 bytes before normalization (1024
//! characters that NFKD turns into one byte each). scripts/verify-hidden-input.py checks this in a
//! Unix pseudo-terminal and scripts/verify-hidden-input-windows.py in a Windows pseudo-console.
//!
//! The menu that `mhfe` shows when it starts without arguments reads single keys in the same
//! terminal mode: [`with_keys`].

// Changing the terminal settings needs the operating system's terminal calls, which Rust offers
// only through unsafe foreign functions.
#![allow(unsafe_code)]

use std::io::{self, BufRead};
use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::exit::Failure;
use crate::locked_text::LockedText;

/// The terminal settings to restore while a hidden prompt has changed them. Whoever changes or
/// restores the terminal holds this lock, so the Ctrl+C handler and a prompt never interleave.
static SAVED: Mutex<Option<platform::Settings>> = Mutex::new(None);

/// Switches the terminal to reading single bytes without its own echo, runs `prompt`, reads one
/// line as described above, shown as it is typed when `shown` is true, and restores the terminal,
/// also when reading fails. `None` means that the input was closed. The terminal is switched
/// before the prompt appears, so that a key typed or text pasted as soon as the prompt shows is
/// already read as data. On Windows the standard library turns the console's UTF-16 characters
/// into UTF-8 bytes.
pub fn read_line(
    prompt: impl FnOnce() -> Result<(), Failure>,
    shown: bool,
) -> Result<Option<LockedText>, Failure> {
    let result = with_terminal_switched(platform::hide, || {
        prompt()?;
        let mut screen = io::stderr();
        let echo = shown.then_some(&mut screen as &mut dyn io::Write);
        edit_line(&mut io::stdin().lock(), echo)
    });
    // The terminal did not show the Enter key either.
    anstream::eprintln!();
    result
}

/// A key that the menu acts on.
#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    /// A digit key from 1 to 9.
    Digit(u8),
    /// ?, which asks for an explanation.
    Help,
    /// Escape alone, q, Ctrl+D or the end of the input. q is an alias: a keyboard layout may have
    /// no q key, where that key types another letter.
    Quit,
    /// Any other key, which the menu ignores.
    Other,
}

/// Switches the terminal to single keys without echo, as for a hidden line, runs `choose` with a
/// function that reads the next key, and restores the terminal, also when `choose` fails.
pub fn with_keys<T>(
    choose: impl FnOnce(&mut dyn FnMut() -> Result<Key, Failure>) -> Result<T, Failure>,
) -> Result<T, Failure> {
    with_terminal_switched(platform::single_keys, || {
        let mut keys = TerminalKeys::new(io::stdin().lock());
        choose(&mut || read_key(&mut keys))
    })
}

/// Switches the terminal with `switch`, runs `body` and restores the terminal, also when `body`
/// fails. The original settings are saved before the switch, so that Ctrl+C can restore them.
fn with_terminal_switched<T>(
    switch: fn(&platform::Settings) -> Result<(), Failure>,
    body: impl FnOnce() -> Result<T, Failure>,
) -> Result<T, Failure> {
    let original = platform::current()?;
    {
        let mut saved = lock_saved();
        *saved = Some(original);
        if let Err(error) = switch(&original) {
            saved.take();
            platform::restore(&original);
            return Err(error);
        }
    }
    let result = body();
    if let Some(original) = lock_saved().take() {
        platform::restore(&original);
    }
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
    /// Normally the terminal turns Ctrl+C into a signal; should the byte arrive, it quits too.
    pub const CTRL_C: u8 = 0x03;
    pub const ESCAPE: u8 = 0x1b;
}

/// The width of the terminal on standard error, in columns, or `None` when it cannot be read.
pub fn columns() -> Option<usize> {
    platform::columns()
}

/// Whether the terminal on standard error carries out control sequences such as the switch to the
/// alternate screen; on Windows the console is asked to do so first.
pub fn control_sequences() -> bool {
    platform::control_sequences()
}

/// How long a lone Escape waits for the rest of an escape sequence. A terminal sends an arrow
/// key's sequence at once, so an Escape that nothing follows within this time is the Escape key;
/// MnemoCode waits as long (ESCAPE_DELAY_MS in its src/cli/terminal-input.ts).
const ESCAPE_DELAY: Duration = Duration::from_millis(100);

/// Where keys come from: their bytes, and whether more bytes follow at once, which tells the
/// Escape key from the start of an escape sequence.
trait KeySource {
    /// One byte, or `None` at the end of the input.
    fn next_byte(&mut self) -> Result<Option<u8>, Failure>;
    /// Whether another byte is there or arrives within `delay`.
    fn more_within(&mut self, delay: Duration) -> Result<bool, Failure>;
}

/// The keys typed at the terminal. Whatever the standard library has read from the terminal is
/// taken over at once, so that its buffer stays empty and only the operating system needs to be
/// asked whether more is coming. Bytes still here when a choice ends are dropped with this
/// reader: a key pressed once too often must not end up in the next answer, such as a password.
struct TerminalKeys<'a> {
    input: io::StdinLock<'a>,
    /// Bytes taken over and not yet read; wiped when dropped, as they could be typed-ahead text.
    pending: Zeroizing<Vec<u8>>,
    next: usize,
}

impl<'a> TerminalKeys<'a> {
    fn new(input: io::StdinLock<'a>) -> Self {
        Self {
            input,
            // Reserved at the size of the standard library's buffer, whose contents it takes
            // whole, so that it is never reallocated and leaves no unwiped copy.
            pending: Zeroizing::new(Vec::with_capacity(crate::terminal::LINE_CAPACITY)),
            next: 0,
        }
    }
}

impl KeySource for TerminalKeys<'_> {
    fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
        if self.next == self.pending.len() {
            self.pending.clear();
            self.next = 0;
            let available = loop {
                match self.input.fill_buf() {
                    Ok(bytes) => break bytes,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let taken = available.len();
            self.pending.extend_from_slice(available);
            self.input.consume(taken);
        }
        let byte = self.pending.get(self.next).copied();
        self.next += usize::from(byte.is_some());
        Ok(byte)
    }

    fn more_within(&mut self, delay: Duration) -> Result<bool, Failure> {
        Ok(self.next < self.pending.len() || platform::input_within(delay)?)
    }
}

/// Reads one key from raw terminal bytes. The arrow keys send the VT escape sequences ESC [ A and
/// ESC [ B, or ESC O A and ESC O B in a terminal's application mode. Every other escape sequence is
/// read to its end and ignored, so that no byte of it, such as the 5 of Ctrl+Up (ESC [ 1 ; 5 A),
/// is taken for a key of its own. An ESC that nothing follows at once is the Escape key.
fn read_key(keys: &mut impl KeySource) -> Result<Key, Failure> {
    use keys::{CTRL_C, CTRL_D, ESCAPE};

    let Some(byte) = keys.next_byte()? else {
        return Ok(Key::Quit);
    };
    let key = match byte {
        b'\r' | b'\n' => Key::Enter,
        b'1'..=b'9' => Key::Digit(byte - b'0'),
        b'?' => Key::Help,
        b'q' | b'Q' | CTRL_D | CTRL_C => Key::Quit,
        ESCAPE if !keys.more_within(ESCAPE_DELAY)? => Key::Quit,
        ESCAPE => match keys.next_byte()? {
            Some(b'[') => read_control_sequence(keys)?,
            Some(b'O') => arrow(keys.next_byte()?),
            _ => Key::Other,
        },
        _ => Key::Other,
    };
    Ok(key)
}

/// The rest of a control sequence after ESC [: parameter and intermediate bytes, then one final
/// byte from @ to ~ (ECMA-48). Only an arrow key without parameters counts.
fn read_control_sequence(keys: &mut impl KeySource) -> Result<Key, Failure> {
    const FINAL_BYTES: std::ops::RangeInclusive<u8> = 0x40..=0x7e;
    let mut has_parameters = false;
    loop {
        match keys.next_byte()? {
            None => return Ok(Key::Quit),
            Some(byte) if FINAL_BYTES.contains(&byte) => {
                return Ok(if has_parameters {
                    Key::Other
                } else {
                    arrow(Some(byte))
                })
            }
            Some(_) => has_parameters = true,
        }
    }
}

fn arrow(final_byte: Option<u8>) -> Key {
    match final_byte {
        Some(b'A') => Key::Up,
        Some(b'B') => Key::Down,
        _ => Key::Other,
    }
}

/// Edits a line from raw terminal bytes: Backspace or Delete removes the last character, Ctrl+U
/// the whole line, Enter (CR or LF) ends it, and Ctrl+D on an empty line or the end of the input
/// gives `None`. Every other byte is kept. The buffer is reserved at its largest size and never
/// grows, so it leaves no unwiped copy; a longer line is refused. With `echo`, every complete
/// character that is not a control character is written to it as it arrives, and the editing keys
/// erase what they remove from it. The line keeps the lock of its buffer.
fn edit_line(
    reader: &mut impl io::Read,
    mut echo: Option<&mut dyn io::Write>,
) -> Result<Option<LockedText>, Failure> {
    use crate::terminal::LINE_CAPACITY;
    use keys::{BACKSPACE, CTRL_D, CTRL_U, DELETE};

    let mut line = Zeroizing::new(Vec::with_capacity(LINE_CAPACITY));
    // Locked before anything is typed into it: the line may be a password or a phrase.
    let line_locked = mhfe::memory::LockedPages::of_vec(&line);
    // For every character of the line, whether it was written to `echo`; only those are erased.
    let mut written: Vec<bool> = Vec::with_capacity(LINE_CAPACITY);
    // Where the character still arriving begins: a UTF-8 character comes one byte at a time.
    let mut complete = 0;
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
            // The first bytes of a character that has not arrived whole go without a trace.
            BACKSPACE | DELETE if complete < line.len() => line.truncate(complete),
            BACKSPACE | DELETE => {
                remove_last_character(&mut line);
                complete = line.len();
                let erased = usize::from(written.pop() == Some(true));
                erase(&mut echo, erased)?;
            }
            CTRL_U => {
                line.clear();
                complete = 0;
                let erased = written.iter().filter(|shown| **shown).count();
                written.clear();
                erase(&mut echo, erased)?;
            }
            CTRL_D if line.is_empty() => return Ok(None),
            _ if line.len() == LINE_CAPACITY => {
                return Err(Failure::invalid_input(format!(
                    "An answer is longer than {LINE_CAPACITY} bytes; no valid answer is that long."
                )))
            }
            other => {
                line.push(other);
                match std::str::from_utf8(&line[complete..]) {
                    Ok(character) => {
                        let shown = !character.chars().any(char::is_control);
                        if let (true, Some(screen)) = (shown, echo.as_mut()) {
                            screen.write_all(character.as_bytes())?;
                            screen.flush()?;
                        }
                        written.push(shown);
                        complete = line.len();
                    }
                    // The rest of the character is still to come.
                    Err(error) if error.error_len().is_none() => {}
                    // Not UTF-8: kept, so that the whole answer is refused below, and not shown.
                    Err(_) => {
                        written.push(false);
                        complete = line.len();
                    }
                }
            }
        }
    }
    let bytes = std::mem::take(&mut *line);
    // from_utf8 keeps the same buffer, so the lock goes with it.
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(LockedText::from_locked(
            Zeroizing::new(text),
            line_locked,
        ))),
        Err(error) => {
            // The error holds the bytes; they are wiped before it is dropped.
            drop(Zeroizing::new(error.into_bytes()));
            Err(Failure::invalid_input(
                "The answer is not valid UTF-8 text.",
            ))
        }
    }
}

/// Erases the last `characters` characters written to `echo`: back, a space over each, back again.
fn erase(echo: &mut Option<&mut dyn io::Write>, characters: usize) -> Result<(), Failure> {
    if let Some(screen) = echo.as_mut() {
        if characters > 0 {
            screen.write_all("\x08 \x08".repeat(characters).as_bytes())?;
            screen.flush()?;
        }
    }
    Ok(())
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
    use std::ptr;
    use std::time::Duration;

    use super::terminal_error;
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

    /// The menu's keys need the same settings as a hidden line: every byte at once, no echo.
    pub fn single_keys(original: &Settings) -> Result<(), Failure> {
        hide(original)
    }

    /// A Unix terminal carries out control sequences as they come.
    pub fn control_sequences() -> bool {
        true
    }

    pub fn columns() -> Option<usize> {
        let mut size = MaybeUninit::<libc::winsize>::zeroed();
        // SAFETY: TIOCGWINSZ fills the winsize when it returns 0; it was zeroed before.
        let read = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) };
        // SAFETY: all zero bytes are a valid winsize, and a successful call filled it.
        let columns = unsafe { size.assume_init() }.ws_col;
        (read == 0 && columns > 0).then_some(usize::from(columns))
    }

    /// Whether a byte arrives on standard input within `delay`. select, not poll: macOS's poll
    /// does not support terminals.
    pub fn input_within(delay: Duration) -> Result<bool, Failure> {
        loop {
            // SAFETY: an fd_set and a timeval on the stack that select may change, for standard
            // input only; all zero bytes are a valid fd_set.
            let ready = unsafe {
                let mut readable = MaybeUninit::<libc::fd_set>::zeroed().assume_init();
                libc::FD_ZERO(&mut readable);
                libc::FD_SET(libc::STDIN_FILENO, &mut readable);
                let mut timeout = libc::timeval {
                    tv_sec: delay.as_secs() as libc::time_t,
                    tv_usec: delay.subsec_micros() as libc::suseconds_t,
                };
                libc::select(
                    libc::STDIN_FILENO + 1,
                    &mut readable,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut timeout,
                )
            };
            match ready {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                -1 => return Err(terminal_error("wait for a key from")),
                count => return Ok(count > 0),
            }
        }
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
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, PeekConsoleInputW,
        SetConsoleMode, CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, INPUT_RECORD, KEY_EVENT, STD_ERROR_HANDLE,
        STD_INPUT_HANDLE,
    };

    use super::terminal_error;
    use crate::exit::Failure;
    use crate::locked_text::LockedText;

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

    /// As for a hidden line, and the console sends the arrow keys as VT escape sequences, as a
    /// Unix terminal does (Windows 10 and later). The menu redraws itself with VT cursor
    /// sequences on standard error, so the console is also asked to carry those out there; that
    /// output mode stays on, as for any program that writes colours.
    pub fn single_keys(original: &Settings) -> Result<(), Failure> {
        let keys = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT))
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: plain console calls on the standard handles.
        unsafe {
            if SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), keys) == 0 {
                return Err(terminal_error("read single keys from"));
            }
            let output = GetStdHandle(STD_ERROR_HANDLE);
            let mut mode: CONSOLE_MODE = 0;
            if GetConsoleMode(output, &mut mode) == 0
                || SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0
            {
                return Err(terminal_error("draw the menu on"));
            }
        }
        Ok(())
    }

    /// Asks the console to carry out the VT control sequences written to standard error, such as
    /// switching to the alternate screen; whether it agreed. The mode stays on, as in single_keys.
    pub fn control_sequences() -> bool {
        // SAFETY: plain console calls on the standard error handle.
        unsafe {
            let output = GetStdHandle(STD_ERROR_HANDLE);
            let mut mode: CONSOLE_MODE = 0;
            GetConsoleMode(output, &mut mode) != 0
                && SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }

    /// The width of the console window that standard error writes to.
    pub fn columns() -> Option<usize> {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: a plain console call that fills `info`.
        let read = unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &mut info) };
        let width = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        (read != 0 && width > 0).then_some(width as usize)
    }

    /// Whether a typed character arrives within `delay`. The console has no wait for that alone:
    /// its queue also holds events that give no character, such as the release of the Escape key
    /// itself, so the queue is looked at every few milliseconds until the time is up.
    pub fn input_within(delay: Duration) -> Result<bool, Failure> {
        const LOOK_EVERY: Duration = Duration::from_millis(5);
        let end = Instant::now() + delay;
        loop {
            if character_waiting()? {
                return Ok(true);
            }
            if Instant::now() >= end {
                return Ok(false);
            }
            std::thread::sleep(LOOK_EVERY);
        }
    }

    /// Whether the console's queue holds a key press with a character. With VT input, the rest of
    /// an arrow key's sequence arrives as such presses.
    fn character_waiting() -> Result<bool, Failure> {
        // More than the events of one key's sequence, with their releases.
        const EVENTS: usize = 32;
        let mut events = [INPUT_RECORD::default(); EVENTS];
        let mut count = 0u32;
        // SAFETY: room for EVENTS records; peeking leaves the events in the queue.
        let peeked = unsafe {
            PeekConsoleInputW(
                GetStdHandle(STD_INPUT_HANDLE),
                events.as_mut_ptr(),
                EVENTS as u32,
                &mut count,
            )
        };
        if peeked == 0 {
            return Err(terminal_error("look at the keys of"));
        }
        let typed = events[..count as usize].iter().any(|event| {
            // SAFETY: the union holds a key event when EventType says so, and its character is
            // read as the UTF-16 unit that the W function fills in.
            event.EventType == KEY_EVENT as u16
                && unsafe {
                    event.Event.KeyEvent.bKeyDown != 0
                        && event.Event.KeyEvent.uChar.UnicodeChar != 0
                }
        });
        Ok(typed)
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
        edit_line(&mut io::Cursor::new(bytes.to_vec()), None)
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

    /// The line read and what the screen showed of it.
    fn echoed(bytes: &[u8]) -> (String, Vec<u8>) {
        let mut screen = Vec::new();
        let line = edit_line(
            &mut io::Cursor::new(bytes.to_vec()),
            Some(&mut screen as &mut dyn io::Write),
        )
        .unwrap()
        .unwrap();
        (line.to_string(), screen)
    }

    #[test]
    fn a_shown_line_shows_what_is_typed_but_no_control_character() {
        assert_eq!(echoed(b"ab\r"), ("ab".into(), b"ab".to_vec()));
        // Backspace erases on the screen too, a whole character at a time.
        let (line, screen) = echoed("a\u{448}\x7fb\r".as_bytes());
        assert_eq!(line, "ab");
        assert_eq!(screen, "a\u{448}\x08 \x08b".as_bytes());
        // A TAB and U+0085 stay in the line, for the password check to refuse, but are not shown,
        // and Backspace over one of them erases nothing on the screen.
        let (line, screen) = echoed("a\tb\u{85}\x7f\r".as_bytes());
        assert_eq!(line, "a\tb");
        assert_eq!(screen, b"ab");
        // Ctrl+U erases every character that was shown.
        let (line, screen) = echoed(b"ab\tc\x15d\r");
        assert_eq!(line, "d");
        assert_eq!(screen, b"abc\x08 \x08\x08 \x08\x08 \x08d");
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

    /// The keys in `bytes` up to the first Quit, which the end of the input gives too.
    /// Test input that arrives all at once: more follows exactly while bytes are left.
    impl KeySource for io::Cursor<Vec<u8>> {
        fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
            let mut byte = [0u8; 1];
            Ok((io::Read::read(self, &mut byte)? == 1).then_some(byte[0]))
        }

        fn more_within(&mut self, _delay: Duration) -> Result<bool, Failure> {
            Ok((self.position() as usize) < self.get_ref().len())
        }
    }

    fn keys_in(bytes: &[u8]) -> Vec<Key> {
        let mut reader = io::Cursor::new(bytes.to_vec());
        let mut keys = Vec::new();
        loop {
            let key = read_key(&mut reader).unwrap();
            let quit = key == Key::Quit;
            keys.push(key);
            if quit {
                return keys;
            }
        }
    }

    #[test]
    fn arrow_keys_digits_and_enter_are_read() {
        use Key::*;
        assert_eq!(
            keys_in(b"\x1b[A\x1b[B\x1bOA\x1bOB\r\n"),
            [Up, Down, Up, Down, Enter, Enter, Quit]
        );
        assert_eq!(keys_in(b"19q"), [Digit(1), Digit(9), Quit]);
        assert_eq!(keys_in(b"?q"), [Help, Quit]);
        assert_eq!(keys_in(b"0x\x04"), [Other, Other, Quit]);
        assert_eq!(keys_in(b"\x03"), [Quit]);
    }

    #[test]
    fn other_escape_sequences_are_read_to_their_end() {
        use Key::*;
        // Ctrl+Up, Delete and F5: none of their digits may count as a digit key.
        assert_eq!(
            keys_in(b"\x1b[1;5A\x1b[3~\x1b[15~\r"),
            [Other, Other, Other, Enter, Quit]
        );
        // Right and left arrows are ignored.
        assert_eq!(keys_in(b"\x1b[C\x1b[D2"), [Other, Other, Digit(2), Quit]);
    }

    #[test]
    fn the_end_of_the_input_quits() {
        assert_eq!(keys_in(b""), [Key::Quit]);
        assert_eq!(keys_in(b"\x1b["), [Key::Quit]);
    }

    #[test]
    fn escape_alone_quits() {
        use Key::*;
        assert_eq!(keys_in(b"\x1b[B2\x1b"), [Down, Digit(2), Quit]);
        // Escape followed at once by another key, as Alt+x sends it, is no Escape.
        assert_eq!(keys_in(b"\x1bx\r\x1b"), [Other, Enter, Quit]);
    }

    #[test]
    fn a_line_over_the_capacity_or_invalid_utf8_is_refused() {
        use crate::terminal::LINE_CAPACITY;
        let longest = "a".repeat(LINE_CAPACITY);
        assert_eq!(edited(format!("{longest}\r").as_bytes()).unwrap(), longest);
        let too_long = format!("{longest}a\r");
        assert!(edit_line(&mut io::Cursor::new(too_long), None).is_err());
        assert!(edit_line(&mut io::Cursor::new(b"\xff\r".to_vec()), None).is_err());
    }

    /// The lock of the buffer goes with the line to the caller (AUD-007-SEC003).
    #[test]
    fn a_line_stays_locked_after_it_is_returned() {
        let line = edit_line(&mut io::Cursor::new(b"pass word\r".to_vec()), None)
            .unwrap()
            .unwrap();
        assert_eq!(&*line, "pass word");
        assert_eq!(line.is_locked(), cfg!(unix));
    }
}
