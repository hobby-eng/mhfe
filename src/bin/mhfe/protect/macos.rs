//! Refuse debugger attachment and inspect the running binary's hardened-runtime policy.

#![allow(
    unsafe_code,
    reason = "ptrace and csops are macOS process-policy foreign functions"
)]

use std::sync::atomic::{AtomicBool, Ordering};

use super::ReadBack;

static DENIED_ATTACH: AtomicBool = AtomicBool::new(false);

// sys/codesign.h and kern/cs_blobs.h of Apple's XNU headers. libc does not expose csops.
const CS_OPS_STATUS: u32 = 0;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
const CS_DEBUGGED: u32 = 0x1000_0000;

unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        operation: u32,
        address: *mut libc::c_void,
        size: usize,
    ) -> libc::c_int;
}

pub(super) fn harden() {
    // SAFETY: PT_DENY_ATTACH acts on the current process and dereferences no pointer. macOS
    // ends an already-traced process rather than allowing it to proceed to secret input.
    let denied = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0;
    DENIED_ATTACH.store(denied, Ordering::Relaxed);
}

pub(super) fn memory_access() -> ReadBack {
    let mut flags = 0u32;
    // SAFETY: csops writes exactly one u32 for CS_OPS_STATUS of this process; flags lives until
    // the synchronous call returns. A failure is kept distinct from a read-back of policy.
    let read = unsafe {
        csops(
            libc::getpid(),
            CS_OPS_STATUS,
            std::ptr::from_mut(&mut flags).cast(),
            std::mem::size_of_val(&flags),
        )
    };
    if read == 0 && flags & CS_RUNTIME != 0 && flags & (CS_GET_TASK_ALLOW | CS_DEBUGGED) == 0 {
        return ReadBack::Set;
    }
    if !DENIED_ATTACH.load(Ordering::Relaxed) {
        return ReadBack::Differs;
    }
    // PT_DENY_ATTACH has no public read-back. A local unsigned/dev build must not claim that
    // its successful request proves the policy; release binaries carry the inspectable runtime.
    ReadBack::Unknown(
        "debugger-attachment refusal was requested; the hardened runtime is not verified",
    )
}

#[cfg(test)]
mod tests;
