//! The terminal calls of Unix: termios for the settings, `select` for keys typed ahead, and the
//! window size of standard error.

#![allow(
    unsafe_code,
    reason = "the terminal settings are changed through the system's unsafe foreign functions"
)]

use std::io;
use std::mem::MaybeUninit;
use std::ptr;
use std::time::Duration;

use super::terminal_error;
use crate::exit::Failure;

pub type Settings = libc::termios;

pub fn current() -> Result<Settings, Failure> {
    current_on(libc::STDIN_FILENO)
}

/// The settings of the terminal on `descriptor`.
pub fn current_on(descriptor: libc::c_int) -> Result<Settings, Failure> {
    let mut settings = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr fills the whole structure when it returns 0.
    if unsafe { libc::tcgetattr(descriptor, settings.as_mut_ptr()) } != 0 {
        return Err(terminal_error("read the settings of"));
    }
    // SAFETY: initialised by the successful tcgetattr above.
    Ok(unsafe { settings.assume_init() })
}

pub fn hide(original: &Settings) -> Result<(), Failure> {
    hide_on(libc::STDIN_FILENO, original)
}

/// The modes of the terminal's own echo and line editing, which a hidden prompt switches off.
const ECHO_AND_EDITING: libc::tcflag_t = libc::ECHO | libc::ICANON | libc::IEXTEN;

/// [`hide`] for the terminal on `descriptor`.
pub fn hide_on(descriptor: libc::c_int, original: &Settings) -> Result<(), Failure> {
    let mut hidden = *original;
    // No echo and no line mode: this module edits the line. ISIG keeps Ctrl+C as the
    // interrupt key; quit and suspend become ordinary characters.
    hidden.c_lflag &= !ECHO_AND_EDITING;
    hidden.c_lflag |= libc::ISIG;
    hidden.c_cc[libc::VQUIT] = libc::_POSIX_VDISABLE;
    hidden.c_cc[libc::VSUSP] = libc::_POSIX_VDISABLE;
    // A read returns as soon as one byte is there.
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    // No flow control (Ctrl+S, Ctrl+Q) and no changes to the bytes.
    hidden.c_iflag &= !(libc::IXON | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL);
    // SAFETY: a valid termios for the terminal on `descriptor`.
    if unsafe { libc::tcsetattr(descriptor, libc::TCSANOW, &hidden) } != 0 {
        return Err(terminal_error("hide the input on"));
    }
    // tcsetattr succeeds when any one of the changes was made (POSIX), so the terminal is
    // asked what it does now before anything is read.
    if !echo_off(&current_on(descriptor)?) {
        return Err(super::echo_stays_on());
    }
    Ok(())
}

/// Whether `settings` have neither the terminal's echo nor its own line editing.
pub fn echo_off(settings: &Settings) -> bool {
    settings.c_lflag & ECHO_AND_EDITING == 0
}

/// The menu's keys need the same settings as a hidden line: every byte at once, no echo.
pub fn single_keys(original: &Settings) -> Result<(), Failure> {
    hide(original)
}

/// A Unix terminal carries out control sequences as they come.
pub fn control_sequences() -> bool {
    true
}

pub fn output_on_error_terminal() -> bool {
    same_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO)
}

/// Whether two descriptors are the same terminal: character devices with the same device
/// number. Two terminals of one system, such as two pseudo-terminals, have different numbers.
pub fn same_terminal(first: libc::c_int, second: libc::c_int) -> bool {
    let device = |descriptor| {
        let mut status = MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: fstat fills the stat when it returns 0; it was zeroed before.
        let read = unsafe { libc::fstat(descriptor, status.as_mut_ptr()) };
        // SAFETY: all zero bytes are a valid stat, and a successful call filled it.
        let status = unsafe { status.assume_init() };
        (read == 0 && status.st_mode & libc::S_IFMT == libc::S_IFCHR).then_some(status.st_rdev)
    };
    matches!((device(first), device(second)), (Some(first), Some(second)) if first == second)
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
