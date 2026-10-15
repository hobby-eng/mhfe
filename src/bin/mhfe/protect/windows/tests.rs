//! Native enforcement probes run in disposable test processes, before any private input exists.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

use super::super::test_process::{require_success, run, TARGET_PID};
use super::*;

#[test]
fn windows_process_protections_are_enforced() {
    require_success(run("protect::windows::tests::hardened_process", None));
}

#[test]
#[ignore = "invoked only by the enforcement test in its own process"]
fn hardened_process() {
    assert_ne!(
        memory_access(),
        ReadBack::Set,
        "the control process is initially unrestricted"
    );
    harden();
    assert_eq!(crash_reporting(), ReadBack::Set);
    assert_eq!(memory_access(), ReadBack::Set);
    require_success(run(
        "protect::windows::tests::another_process_cannot_read_memory",
        Some(std::process::id()),
    ));
}

#[test]
#[ignore = "invoked only as the other process of the enforcement probe"]
fn another_process_cannot_read_memory() {
    let pid: u32 = std::env::var(TARGET_PID).unwrap().parse().unwrap();
    // WRITE_DAC (0x00040000) would let an owner grant VM_READ back to itself.
    const WRITE_DAC: u32 = 0x0004_0000;
    for rights in [PROCESS_VM_READ, WRITE_DAC] {
        // SAFETY: this asks for a fresh handle to the public probe PID. No memory is accessed.
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        // SAFETY: captures this thread's error immediately after the failed call.
        let error = unsafe { GetLastError() };
        if !handle.is_null() {
            // SAFETY: close the one handle returned by OpenProcess, once.
            unsafe { CloseHandle(handle) };
        }
        assert!(
            handle.is_null(),
            "a same-user process obtained access {rights:#x}"
        );
        assert_eq!(error, ERROR_ACCESS_DENIED);
    }
}
