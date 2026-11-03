//! A Windows pseudo-console (ConPTY) with the tool running in it: the one place of xtask on
//! Windows that needs `unsafe`, for the console's system calls (RUST-07).
#![expect(
    unsafe_code,
    reason = "a pseudo-console and its process are made by system calls"
)]

use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE};
use windows_sys::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute,
};

use crate::Failure;

/// A process in a pseudo-console of 200 columns and 40 rows: what it writes arrives as chunks
/// of the console's output on `output`.
pub(crate) struct Console {
    console: HPCON,
    process: OwnedHandle,
    input: File,
    pub(crate) output: Receiver<Vec<u8>>,
}

fn failed(what: &str) -> Failure {
    Failure(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// A pipe's read and write ends.
fn pipe() -> Result<(OwnedHandle, OwnedHandle), Failure> {
    let (mut read, mut write): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: both pointers are to local handles that the call fills; no attributes are passed.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(failed("CreatePipe"));
    }
    // SAFETY: the call succeeded, so both handles are open and owned by nothing else.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

/// `text` as a NUL-ended wide string.
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

/// The command line of `program` with `arguments`, each quoted as the C runtime reads it back.
fn command_line(program: &Path, arguments: &[&str]) -> Vec<u16> {
    let mut line = OsString::new();
    for (index, part) in std::iter::once(program.as_os_str())
        .chain(arguments.iter().map(OsStr::new))
        .enumerate()
    {
        if index > 0 {
            line.push(" ");
        }
        line.push("\"");
        line.push(part);
        line.push("\"");
    }
    wide(&line)
}

/// This process's environment with NO_COLOR set, as a block of NUL-ended `name=value` strings,
/// sorted by name as CreateProcess expects, ended by one more NUL.
fn environment() -> Vec<u16> {
    let mut variables: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("NO_COLOR"))
        .chain([("NO_COLOR".into(), "1".into())])
        .collect();
    variables.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in variables {
        let mut entry = name;
        entry.push("=");
        entry.push(value);
        block.extend(wide(&entry));
    }
    block.push(0);
    block
}

impl Console {
    pub(crate) fn spawn(program: &Path, arguments: &[&str]) -> Result<Self, Failure> {
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let mut console: HPCON = 0;
        let size = COORD { X: 200, Y: 40 };
        // SAFETY: the two handles are open pipe ends; the console keeps its own copies.
        let result = unsafe {
            CreatePseudoConsole(
                size,
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut console,
            )
        };
        if result < 0 {
            return Err(Failure(format!("CreatePseudoConsole: error {result:#x}")));
        }
        // The console holds the other ends; ours are closed so that the output ends with it.
        drop((input_read, output_write));
        let process = match start(console, program, arguments) {
            Ok(process) => process,
            Err(failure) => {
                // SAFETY: the console was made above and is closed once.
                unsafe { ClosePseudoConsole(console) };
                return Err(failure);
            }
        };
        let (sender, output) = mpsc::channel();
        let mut reader = File::from(output_read);
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(count) = reader.read(&mut buffer) {
                if count == 0 || sender.send(buffer[..count].to_vec()).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            console,
            process,
            input: File::from(input_write),
            output,
        })
    }

    pub(crate) fn write(&mut self, text: &str) -> Result<(), Failure> {
        self.input
            .write_all(text.as_bytes())
            .map_err(|error| Failure(format!("writing to the console: {error}")))
    }

    /// The exit code, or `None` while the process runs.
    pub(crate) fn exit_code(&self) -> Option<u32> {
        let mut code = 0;
        // SAFETY: the handle is the process's own, open for as long as `self`.
        let read = unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) };
        (read != 0 && code != STILL_ACTIVE as u32).then_some(code)
    }

    pub(crate) fn terminate(&self) {
        // SAFETY: the handle is the process's own; a process already ended refuses, which is fine.
        unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if self.exit_code().is_none() {
            self.terminate();
        }
        // SAFETY: the console was made by spawn and is closed once, here.
        unsafe { ClosePseudoConsole(self.console) };
    }
}

/// Starts `program` with `arguments` attached to `console`; its process handle.
fn start(console: HPCON, program: &Path, arguments: &[&str]) -> Result<OwnedHandle, Failure> {
    let mut size = 0;
    // SAFETY: a first call with no list only reports the size the list needs, as documented.
    unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
    // usize alignment suits the list, whose layout the system keeps opaque.
    let mut list = vec![0_usize; size.div_ceil(size_of::<usize>())];
    let attributes = list.as_mut_ptr().cast::<c_void>();
    // SAFETY: `attributes` points to `size` writable bytes, as the first call asked.
    if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) } == 0 {
        return Err(failed("InitializeProcThreadAttributeList"));
    }
    // SAFETY: the list was initialized above; the console's handle is passed as the value, as
    // the pseudo-console attribute takes it, and outlives the process's start.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            console as *const c_void,
            size_of::<HPCON>(),
            null_mut(),
            null(),
        )
    };
    let mut info = STARTUPINFOEXW::default();
    info.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    info.lpAttributeList = attributes;
    // Standard handles stated as none, so that the tool takes the console's own and not this
    // program's, which CI redirects to pipes.
    info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    info.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    info.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    info.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    let mut line = command_line(program, arguments);
    let environment = environment();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a live local: the command line, writable as the call may change
    // it; the environment block, ended as documented; the start-up information with its list;
    // and the process information that the call fills.
    let started = updated != 0
        && unsafe {
            CreateProcessW(
                null(),
                line.as_mut_ptr(),
                null(),
                null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                null(),
                &info.StartupInfo,
                &mut process,
            )
        } != 0;
    let failure = (!started).then(|| failed("CreateProcessW"));
    // SAFETY: the list was initialized above and is deleted once, after its last use.
    unsafe { DeleteProcThreadAttributeList(attributes) };
    if let Some(failure) = failure {
        return Err(failure);
    }
    // SAFETY: the call succeeded, so both handles are open and owned by nothing else; the
    // thread's is not needed.
    unsafe {
        drop(OwnedHandle::from_raw_handle(process.hThread));
        Ok(OwnedHandle::from_raw_handle(process.hProcess))
    }
}
