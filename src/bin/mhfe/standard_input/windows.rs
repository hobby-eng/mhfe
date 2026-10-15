//! Raw Windows input without the standard library's persistent read-ahead buffer.

#![allow(
    unsafe_code,
    reason = "ReadConsoleW and ReadFile fill owned buffers through Windows foreign functions"
)]

use std::io;

use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_OPERATION_ABORTED,
    HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, ReadConsoleW, STD_INPUT_HANDLE,
};

/// A console uses UTF-16; a redirected stream carries bytes without a code-page conversion.
pub(super) fn read(into: &mut [u8]) -> io::Result<usize> {
    let mut mode = 0;
    // SAFETY: GetStdHandle returns a borrowed handle; GetConsoleMode fills a live u32.
    let (input, console) = unsafe {
        let input = GetStdHandle(STD_INPUT_HANDLE);
        (input, GetConsoleMode(input, &mut mode) != 0)
    };
    if console {
        super::utf16::read_scalar(|unit| read_unit(input, unit), into)
    } else {
        read_byte(input, into)
    }
}

fn read_unit(input: HANDLE, unit: &mut u16) -> io::Result<usize> {
    loop {
        let mut count = 0;
        // SAFETY: the borrowed input handle is used synchronously; `unit` holds the single UTF-16
        // unit requested, and `count` lives until ReadConsoleW has completed. Clear last-error
        // because a successful read may leave an old error untouched.
        let read = unsafe {
            SetLastError(0);
            ReadConsoleW(
                input,
                std::ptr::from_mut(unit).cast(),
                1,
                &mut count,
                std::ptr::null(),
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        // ReadConsoleW can report Ctrl+C/Break as a successful empty read with this error.
        // Retry until the installed interrupt handler exits, rather than treating it as EOF.
        // SAFETY: captures this thread's error before any other Windows call.
        if count != 0 || unsafe { GetLastError() } != ERROR_OPERATION_ABORTED {
            return Ok(count as usize);
        }
    }
}

fn read_byte(input: HANDLE, into: &mut [u8]) -> io::Result<usize> {
    let mut count = 0;
    // SAFETY: one byte is read synchronously into a nonempty owned buffer; no OVERLAPPED work
    // survives the call and the borrowed standard handle is never closed here.
    let read = unsafe {
        ReadFile(
            input,
            into.as_mut_ptr(),
            1,
            &mut count,
            std::ptr::null_mut(),
        )
    };
    if read != 0 {
        return Ok(count as usize);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF) => Ok(0),
        _ => Err(error),
    }
}
