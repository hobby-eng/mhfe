//! The console calls of Windows: the console mode for the settings, the input queue for keys
//! typed ahead, and the window of standard error.

#![allow(
    unsafe_code,
    reason = "the console settings are changed through the system's unsafe foreign functions"
)]

use std::time::{Duration, Instant};

use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, PeekConsoleInputW, SetConsoleMode,
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    INPUT_RECORD, KEY_EVENT, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

use super::terminal_error;
use crate::exit::Failure;

pub(crate) type Settings = CONSOLE_MODE;

pub(crate) fn current() -> Result<Settings, Failure> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: a plain console call on the standard input handle.
    if unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) } == 0 {
        return Err(terminal_error("read the settings of"));
    }
    Ok(mode)
}

pub(crate) fn hide(original: &Settings) -> Result<(), Failure> {
    // No echo and no line mode: this module edits the line. Processed input keeps Ctrl+C as
    // the cancel key; without line input the console acts on no other key.
    let hidden = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
    // SAFETY: a plain console call on the standard input handle.
    if unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), hidden) } == 0 {
        return Err(terminal_error("hide the input on"));
    }
    read_back_echo_off()
}

/// Asks the console what it does now, before anything is read: neither echo nor its own line
/// editing may be left on.
fn read_back_echo_off() -> Result<(), Failure> {
    if current()? & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) != 0 {
        return Err(super::echo_stays_on());
    }
    Ok(())
}

/// As for a hidden line, and the console sends the arrow keys as VT escape sequences, as a
/// Unix terminal does (Windows 10 and later). The menu redraws itself with VT cursor
/// sequences on standard error, so the console is also asked to carry those out there; that
/// output mode stays on, as for any program that writes colours.
pub(crate) fn single_keys(original: &Settings) -> Result<(), Failure> {
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
    read_back_echo_off()
}

/// Asks the console to carry out the VT control sequences written to standard error, such as
/// switching to the alternate screen; whether it agreed. The mode stays on, as in single_keys.
pub(crate) fn control_sequences() -> bool {
    // SAFETY: plain console calls on the standard error handle.
    unsafe {
        let output = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode: CONSOLE_MODE = 0;
        GetConsoleMode(output, &mut mode) != 0
            && SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// A process has one console: standard output and standard error, when both are consoles,
/// are that one.
pub(crate) fn output_on_error_terminal() -> bool {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: plain console calls on the standard output and error handles.
    unsafe {
        GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut mode) != 0
            && GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mut mode) != 0
    }
}

/// The width of the console window that standard error writes to.
pub(crate) fn columns() -> Option<usize> {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: a plain console call that fills `info`.
    let read = unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &mut info) };
    let width = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    (read != 0 && width > 0).then_some(width as usize)
}

/// Whether a typed character arrives within `delay`. The console has no wait for that alone:
/// its queue also holds events that give no character, such as the release of the Escape key
/// itself, so the queue is looked at every few milliseconds until the time is up.
pub(crate) fn input_within(delay: Duration) -> Result<bool, Failure> {
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
                event.Event.KeyEvent.bKeyDown != 0 && event.Event.KeyEvent.uChar.UnicodeChar != 0
            }
    });
    Ok(typed)
}

pub(crate) fn restore(original: &Settings) {
    // SAFETY: the mode read from this console before.
    unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), *original) };
}
