//! Paired, public-data-only PT_ATTACH probes. A denied control never proves target hardening.

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::super::test_process::run;
use super::*;

const PROTECTED: &str = "MHFE_PUBLIC_PROBE_HARDENED";
const READY: &str = "MHFE_PUBLIC_TARGET_READY";
const ATTACHED: &str = "MHFE_PUBLIC_ATTACHED_AND_DETACHED";
// Public probes poll promptly while giving a busy host time to deliver a process stop.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TRACE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
// Bound an orphan's lifetime even if reparenting does not become observable on the host.
const TARGET_LIFETIME: Duration = Duration::from_secs(30);
// The exact-test runner emits a short preamble before the one ready line.
const MAX_READY_LINES: usize = 16;

#[test]
fn macos_debugger_attachment_is_refused() {
    let control = run("protect::macos::tests::unrestricted_process", None);
    assert!(control.status.success(),
        "UNAVAILABLE: PT_ATTACH control could not run; target protection remains unverified: {control:?}");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains(ATTACHED),
        "{control:?}"
    );
    let protected = run("protect::macos::tests::hardened_process", None);
    // Apple's ptrace manual describes SIGSEGV in the tracing parent. Only an attachable,
    // otherwise equivalent control lets that signal demonstrate the target's policy.
    assert_eq!(
        protected.status.signal(),
        Some(libc::SIGSEGV),
        "{protected:?}"
    );
}

#[test]
#[ignore = "invoked by the paired enforcement test in a public probe process"]
fn unrestricted_process() {
    attempt_attachment(false);
}

#[test]
#[ignore = "the public tracing parent is expected to be killed by its protected child"]
fn hardened_process() {
    attempt_attachment(true);
}

/// Owns the test child on every ordinary error path; it holds no private input.
struct Target(Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn attempt_attachment(protected: bool) {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the structure lives for the call; the intentionally signalled public probe must
    // not leave a core file behind.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) }, 0);
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "protect::macos::tests::attachment_target",
            "--nocapture",
        ])
        .env(PROTECTED, if protected { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut target = Target(child);
    let mut output = BufReader::new(target.0.stdout.take().unwrap());
    let mut ready = false;
    for _ in 0..MAX_READY_LINES {
        let mut line = String::new();
        if output.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.contains(READY) {
            ready = true;
            break;
        }
    }
    assert!(ready, "the public target did not reach its ready state");
    let pid = libc::pid_t::try_from(target.0.id()).unwrap();
    // SAFETY: this PID belongs to our public child. PT_ATTACH dereferences no pointer. Unlike
    // a child-to-parent probe, this follows the parent relationship of PT_DENY_ATTACH's contract.
    let result = unsafe { libc::ptrace(libc::PT_ATTACH, pid, std::ptr::null_mut(), 0) };
    let error = (result == -1).then(|| std::io::Error::last_os_error().raw_os_error());
    crate::style::out(format!("PT_ATTACH result={result}, errno={error:?}")).unwrap();
    assert_eq!(result, 0, "PT_ATTACH unavailable: errno={error:?}");
    let deadline = Instant::now() + TRACE_STOP_TIMEOUT;
    loop {
        let mut status = 0;
        // SAFETY: the PID is our attached child; status is writable for the synchronous call.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        if waited == pid {
            assert!(libc::WIFSTOPPED(status), "target did not stop: {status}");
            break;
        }
        assert_eq!(waited, 0, "waitpid: {}", std::io::Error::last_os_error());
        assert!(
            Instant::now() < deadline,
            "attached target did not stop within five seconds"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
    // SAFETY: the same child is stopped under our trace; PT_DETACH continues it and reads no
    // pointer. The guard kills/reaps it after this observation, including on a failed detach.
    let detached = unsafe { libc::ptrace(libc::PT_DETACH, pid, std::ptr::null_mut(), 0) };
    assert_eq!(
        detached,
        0,
        "PT_DETACH: {}",
        std::io::Error::last_os_error()
    );
    crate::style::out(ATTACHED).unwrap();
}

#[test]
#[ignore = "public child of the paired attachment probes; no operation or secret input"]
fn attachment_target() {
    // SAFETY: getppid reads process identity and has no pointer arguments.
    let parent = unsafe { libc::getppid() };
    if std::env::var(PROTECTED).as_deref() == Ok("1") {
        harden();
        assert!(DENIED_ATTACH.load(Ordering::Relaxed));
        assert_ne!(memory_access(), ReadBack::Differs);
    }
    crate::style::out(READY).unwrap();
    // The target takes no standard input. A signalled tracer is reaped by the outer test,
    // reparenting this child; the deadline also bounds cleanup if the host behaves otherwise.
    let deadline = Instant::now() + TARGET_LIFETIME;
    // SAFETY: as above, this only reads the current process's parent identity.
    while unsafe { libc::getppid() } == parent && Instant::now() < deadline {
        std::thread::sleep(POLL_INTERVAL);
    }
}
