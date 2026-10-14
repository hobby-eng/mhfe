//! AUD-024 secrets-native probe. Compiles mhfe's own isolation modules at commit b6fca69
//! (src/bin/mhfe/protect/landlock.rs and seccomp.rs, unchanged, through #[path]) and applies them
//! as protect::isolate_thread does for a command that needs neither the network nor writes:
//! PR_SET_NO_NEW_PRIVS, Landlock with TCP, then seccomp. Case 1 is a command started directly: a
//! child of a single thread that first enters a user and network namespace of its own. Case 2 is a
//! command of the start menu: a thread of its own, without a namespace. Each tries what the tool's
//! own probe tries (opening /dev/null for writing) and the file-system writes that need no opening
//! for writing: an extended attribute, a mode change, a timestamp change and a truncate by path.
//! The main thread, which is not isolated, then reads back what reached the disk. Public data only:
//! the attribute holds the BIP39 test phrase. Exits 1 when any of these writes gets through
//! in either case (the defect of AUD-024), 0 when every one is refused.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Writes that got through in this process (the forked child reports through its exit code).
static ALLOWED: AtomicUsize = AtomicUsize::new(0);

#[path = "../../../../../../src/bin/mhfe/protect/landlock.rs"]
mod landlock;
#[path = "../../../../../../src/bin/mhfe/protect/seccomp.rs"]
mod seccomp;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn report(case: &str, what: &str, result: libc::c_int) {
    if result == 0 {
        if !what.starts_with("open") {
            ALLOWED.fetch_add(1, Ordering::SeqCst);
        }
        println!("{case}: {what}: ALLOWED");
    } else {
        println!("{case}: {what}: refused, errno {}", errno());
    }
}

/// Applies the isolation as protect::isolate_thread does (PR_SET_NO_NEW_PRIVS, Landlock with
/// TCP, seccomp; the namespace, where `namespace` says so, was entered just before) and tries the
/// writes. Each write that succeeds is undone by the next case's fresh file content only.
fn attempt(case: &str, path: &CString, namespace: bool) {
    // SAFETY: integers only, as in protect::isolate_thread.
    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
    let no_writes = landlock::forbid_writes(true);
    let no_network = seccomp::forbid_sockets();
    println!("{case}: namespace {namespace}, no_new_privs {no_new_privs}, no_writes {no_writes}, no_network {no_network}");
    let name = format!("user.mhfe-probe-{}", if namespace { "direct" } else { "menu" });
    let name = CString::new(name).unwrap();
    // SAFETY: NUL-terminated paths and plain values, for the duration of each call.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        report(case, "open /dev/null for writing (the tool's own probe)", if devnull >= 0 { libc::close(devnull); 0 } else { -1 });
        let opened = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        report(case, "open the file for writing", if opened >= 0 { libc::close(opened); 0 } else { -1 });
        report(
            case,
            "setxattr (the test phrase)",
            libc::setxattr(path.as_ptr(), name.as_ptr(), PHRASE.as_ptr().cast(), PHRASE.len(), 0),
        );
        report(case, "chmod 0644", libc::chmod(path.as_ptr(), 0o644));
        let times = [
            libc::timespec { tv_sec: 1_000_000_000, tv_nsec: 0 },
            libc::timespec { tv_sec: 1_000_000_000, tv_nsec: 0 },
        ];
        report(case, "utimensat to 2001-09-09", libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0));
        report(case, "truncate to 0 bytes", libc::truncate(path.as_ptr(), 0));
    }
}

fn main() {
    // A folder for the one scratch file: the first argument, or the system's temporary folder. It
    // must be on a file system with user extended attributes (ext4, btrfs, xfs, tmpfs from 6.6).
    let base = std::env::args_os().nth(1).map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let folder = base.join(format!("aud024-isolation-writes-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let file = folder.join("victim.txt");
    std::fs::write(&file, "public test content\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = CString::new(file.to_str().unwrap()).unwrap();
    // SAFETY: the version query with a null attribute only returns a number.
    let abi = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32)
    };
    println!("Landlock ABI of this kernel: {abi}");
    // Case 1, a command started directly: a child of a single thread follows
    // protect::isolate_thread with Needs::NOTHING, the user and network namespace included.
    // SAFETY: the process has a single thread here; the child makes system calls and _exits.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let namespace = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0;
        attempt("direct command", &path, namespace);
        let code = i32::from(ALLOWED.load(Ordering::SeqCst) > 0);
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    let direct_allowed = !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    // Case 2, a command of the start menu: a thread of its own, without a namespace.
    let path_for_thread = path.clone();
    std::thread::spawn(move || attempt("menu thread", &path_for_thread, false))
        .join()
        .unwrap();
    // Back in the main thread, which is not isolated: what reached the file system.
    for which in ["direct", "menu"] {
        let name = CString::new(format!("user.mhfe-probe-{which}")).unwrap();
        let mut value = vec![0u8; 256];
        // SAFETY: a buffer of 256 bytes that lives for the call.
        let length = unsafe {
            libc::getxattr(path.as_ptr(), name.as_ptr(), value.as_mut_ptr().cast(), value.len())
        };
        let stored = if length >= 0 {
            String::from_utf8_lossy(&value[..length as usize]).into_owned()
        } else {
            format!("<none, errno {}>", errno())
        };
        println!("on disk afterwards: xattr user.mhfe-probe-{which} = {stored:?}");
    }
    let metadata = std::fs::metadata(&file).unwrap();
    println!(
        "on disk afterwards: mode {:o}, length {}, mtime {}",
        metadata.permissions().mode() & 0o777,
        metadata.len(),
        std::os::unix::fs::MetadataExt::mtime(&metadata)
    );
    let _ = std::fs::remove_dir_all(&folder);
    let failed = direct_allowed || ALLOWED.load(Ordering::SeqCst) > 0;
    println!(
        "{}",
        if failed {
            "FAIL: a write to the file system got through the isolation of a secret command"
        } else {
            "PASS: every write tried was refused"
        }
    );
    std::process::exit(i32::from(failed));
}
