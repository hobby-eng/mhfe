//! Check actual PT_DENY_ATTACH enforcement in separate, public-data-only processes.

use std::os::unix::process::ExitStatusExt;

use super::super::test_process::{require_success, run, TARGET_PID};
use super::*;

#[test]
fn macos_debugger_attachment_is_refused() {
    require_success(run("protect::macos::tests::hardened_process", None));
}

#[test]
#[ignore = "invoked by the enforcement test in its own process"]
fn hardened_process() {
    harden();
    assert!(DENIED_ATTACH.load(Ordering::Relaxed));
    assert_ne!(memory_access(), ReadBack::Differs);
    let output = run(
        "protect::macos::tests::attempt_attachment",
        Some(std::process::id()),
    );
    // XNU sends SIGSEGV to a requester that attempts PT_ATTACH after PT_DENY_ATTACH; an ordinary
    // permission refusal alone does not prove that the target's flag was set.
    assert_eq!(output.status.signal(), Some(libc::SIGSEGV), "{output:?}");
}

#[test]
#[ignore = "the requestor process is expected to be killed by the target's policy"]
fn attempt_attachment() {
    let pid: libc::pid_t = std::env::var(TARGET_PID).unwrap().parse().unwrap();
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the limit structure lives for the call. The deliberately crashing public probe
    // must not produce a core file on the runner.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) }, 0);
    // SAFETY: PT_ATTACH takes the public PID of the isolated test target and no data pointer.
    let result = unsafe { libc::ptrace(libc::PT_ATTACH, pid, std::ptr::null_mut(), 0) };
    panic!("PT_DENY_ATTACH did not terminate the requestor: {result}");
}
