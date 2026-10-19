//! Public synthetic-signal control for Rust's Unix stack-overflow handler.
//! This reproduces handler behavior, not macOS ptrace enforcement.

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

// Linux ABI constants for this standalone, dependency-free control.
const SIGSEGV: i32 = 11;
const RLIMIT_CORE: i32 = 4;
const SIG_DFL: usize = 0;
const SIG_ERR: usize = usize::MAX;

#[repr(C)]
struct Rlimit {
    current: u64,
    maximum: u64,
}

unsafe extern "C" {
    fn signal(number: i32, handler: usize) -> usize;
    fn raise(number: i32) -> i32;
    fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
}

fn main() {
    assert!(cfg!(all(target_os = "linux", target_pointer_width = "64")));
    if let Some(mode) = std::env::args().nth(1) {
        assert_eq!(
            // SAFETY: this public child changes only its core limit, with a live ABI struct.
            unsafe {
                setrlimit(
                    RLIMIT_CORE,
                    &Rlimit {
                        current: 0,
                        maximum: 0,
                    },
                )
            },
            0
        );
        if mode == "default" {
            // SAFETY: SIG_DFL is a valid disposition. Only this disposable child is changed.
            assert_ne!(unsafe { signal(SIGSEGV, SIG_DFL) }, SIG_ERR);
        } else {
            assert_eq!(mode, "rust-handler");
        }
        // SAFETY: sends one synthetic signal to this public child; no memory fault is created.
        assert_eq!(unsafe { raise(SIGSEGV) }, 0);
        assert_eq!(
            mode, "rust-handler",
            "default SIGSEGV unexpectedly returned"
        );
        // SAFETY: replace and inspect only this child's current signal disposition.
        assert_eq!(unsafe { signal(SIGSEGV, SIG_DFL) }, SIG_DFL);
        println!("RUST_HANDLER_CONSUMED_SYNTHETIC_SIGSEGV");
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let baseline = Command::new(&executable)
        .arg("rust-handler")
        .output()
        .unwrap();
    assert!(baseline.status.success(), "{baseline:?}");
    assert!(
        String::from_utf8_lossy(&baseline.stdout)
            .contains("RUST_HANDLER_CONSUMED_SYNTHETIC_SIGSEGV")
    );
    let default = Command::new(executable).arg("default").output().unwrap();
    assert_eq!(default.status.signal(), Some(SIGSEGV), "{default:?}");
    println!("PASS: baseline consumed one synthetic signal; default disposition was fatal");
}
