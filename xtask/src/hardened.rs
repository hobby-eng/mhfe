//! `cargo xtask hardened <program>`, on a Mac: checks the signature that `cargo xtask
//! macos-binary` gives a program (macho.rs) as macOS reads it. `codesign` must verify it strictly
//! and show the flags ad hoc and runtime. Then, where System Integrity Protection is on, the
//! program, running `mhfe decrypt --stdin` and waiting for its input, must keep its task port,
//! through which another process reads and writes its memory, from a process of root, while a
//! copy signed ad hoc without the hardened runtime gives that port. Should the copy not give it
//! either, the check would prove nothing, and it fails. Where System Integrity Protection is off,
//! as on GitHub's hosted Macs, root takes any task port, so the check says so and stops after the
//! signature.
//!
//! `cargo xtask task-port <pid>` is the part that runs as root, through `sudo -n`: exit code 0 when
//! this process gets the task port of `pid`, 3 when macOS refuses it.

#![allow(
    unsafe_code,
    reason = "task_for_pid and the task port of this process are foreign items of macOS"
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::{Failure, at, ensure};

/// The flags `codesign --display` shows for an ad-hoc signature with the hardened runtime.
const HARDENED: &str = "flags=0x10002(adhoc,runtime)";
/// The exit code of `task-port` when macOS refuses the port.
const REFUSED: i32 = 3;
/// How long the program gets for its checks at start before it waits for its input.
const START: Duration = Duration::from_secs(5);

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    let [program] = arguments else {
        return Err(Failure("usage: cargo xtask hardened <program>".to_owned()));
    };
    ensure(cfg!(target_os = "macos"), || {
        "cargo xtask hardened runs on macOS".to_owned()
    })?;
    let program = Path::new(program);
    codesign(&["--verify", "--strict", "--verbose=2"], program)?;
    let shown = codesign(&["--display", "--verbose=2"], program)?;
    ensure(shown.contains(HARDENED), || {
        format!(
            "{}: no hardened runtime in its signature:\n{shown}",
            program.display()
        )
    })?;
    let status = Command::new("csrutil")
        .arg("status")
        .output()
        .map_err(|error| Failure(format!("csrutil status: {error}")))?;
    let status = String::from_utf8_lossy(&status.stdout);
    println!("{}", status.trim());
    if !status.contains("enabled") {
        println!(
            "{}: signed ad hoc with the hardened runtime; System Integrity Protection is not on \
             here, so root may take any task port and the refusal cannot be shown on this Mac",
            program.display()
        );
        return Ok(());
    }
    let folder = root.join("target/xtask-hardened");
    let _ = fs::remove_dir_all(&folder);
    fs::create_dir_all(&folder).map_err(|error| at(&folder, error))?;
    let control = folder.join("mhfe");
    fs::copy(program, &control).map_err(|error| at(&control, error))?;
    codesign(&["--force", "--sign", "-"], &control)?;
    let shown = codesign(&["--display", "--verbose=2"], &control)?;
    ensure(!shown.contains("runtime"), || {
        format!("the copy signed without the hardened runtime still shows it:\n{shown}")
    })?;
    match (task_port_given(&control)?, task_port_given(program)?) {
        (true, false) => {
            println!(
                "{}: signed ad hoc with the hardened runtime; root gets no task port of it, \
                 and does of a copy without the hardened runtime",
                program.display()
            );
            Ok(())
        }
        (false, _) => Err(Failure(
            "root gets no task port even of a copy without the hardened runtime: on this Mac the \
             check proves nothing"
                .to_owned(),
        )),
        (true, true) => Err(Failure(format!(
            "root gets the task port of {}, and with it its memory",
            program.display()
        ))),
    }
}

/// The output of `codesign` with `arguments` for `program`, which must succeed.
fn codesign(arguments: &[&str], program: &Path) -> Result<String, Failure> {
    let output = Command::new("codesign")
        .args(arguments)
        .arg(program)
        .output()
        .map_err(|error| Failure(format!("codesign: {error}")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure(output.status.success(), || {
        format!(
            "codesign {} {}: {text}",
            arguments.join(" "),
            program.display()
        )
    })?;
    Ok(text)
}

/// Whether a process of root gets the task port of `program` while it waits for its input in
/// `mhfe decrypt --stdin`.
fn task_port_given(program: &Path) -> Result<bool, Failure> {
    let mut running = Command::new(program)
        .args(["decrypt", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| at(program, error))?;
    std::thread::sleep(START);
    let waiting = running.try_wait().is_ok_and(|ended| ended.is_none());
    let probe = waiting.then(|| {
        std::env::current_exe().and_then(|this| {
            Command::new("sudo")
                .arg("-n")
                .arg(this)
                .args(["task-port", &running.id().to_string()])
                .status()
        })
    });
    let _ = running.kill();
    let _ = running.wait();
    let status = probe
        .ok_or_else(|| {
            Failure(format!(
                "{} ended before the check: it should wait for its input",
                program.display()
            ))
        })?
        .map_err(|error| Failure(format!("sudo -n xtask task-port: {error}")))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(REFUSED) => Ok(false),
        other => Err(Failure(format!(
            "sudo -n xtask task-port ended with {other:?}"
        ))),
    }
}

/// `cargo xtask task-port <pid>`: ends with exit code 0 when this process gets the task port of
/// `pid`, and with [`REFUSED`] when macOS refuses it.
pub(crate) fn task_port(arguments: &[String]) -> Result<(), Failure> {
    let [pid] = arguments else {
        return Err(Failure("usage: cargo xtask task-port <pid>".to_owned()));
    };
    let pid: i32 = pid
        .parse()
        .map_err(|_| Failure(format!("not a process number: {pid}")))?;
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            /// This process's own task port, which `mach_task_self()` of the C headers reads.
            static mach_task_self_: libc::mach_port_t;
        }
        let mut task: libc::mach_port_t = 0;
        // SAFETY: mach_task_self_ is set by the system before main and never changed; task_for_pid
        // writes the port it gives into `task`, which lives for the call.
        let answer = unsafe { libc::task_for_pid(mach_task_self_, pid, &mut task) };
        if answer != libc::KERN_SUCCESS {
            std::process::exit(REFUSED);
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Err(Failure("cargo xtask task-port runs on macOS".to_owned()))
    }
}
