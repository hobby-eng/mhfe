//! Runs the unmodified MHFE executable in a pseudo-terminal with public dice input.

#[allow(
    unsafe_code,
    reason = "a pseudo-terminal and SIGINT need Unix descriptor and signal calls"
)]
mod terminal;

use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const WORD: &[u8] = b"abacus";
const LEAVE: &[u8] = b"\x1b[?1049l";
const READY: &[u8] = b"AUD045_READY";
const LEFT: &[u8] = b"AUD045_LEAVE_WRITTEN";
const DEADLINE: Duration = Duration::from_secs(30);

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            // A probe error must not leave the command waiting for input. Cleanup errors cannot
            // replace the original error; the bounded parent run retains its own failure.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("usage: aud045-probe <mhfe executable> <interposer .so>".into());
    }
    let (mut master, slave) = terminal::open()?;
    let mut child = ChildGuard(
        Command::new(&arguments[0])
            .args(["password", "--dice", "--words", "1"])
            .env("LD_PRELOAD", &arguments[1])
            .env("TERM", "xterm-256color")
            .env("COLUMNS", "120")
            .env("LINES", "40")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave))
            .spawn()?,
    );
    let start = Instant::now();
    let mut output = Vec::new();
    let (mut typed, mut signalled) = (false, false);
    let mut buffer = [0; 8192];
    while start.elapsed() < DEADLINE {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => return Err(error.into()),
        }
        if !typed && contains(&output, b"Word 1:") {
            master.write_all(b"11111\n")?;
            typed = true;
        }
        if !signalled && contains(&output, READY) {
            terminal::interrupt(child.0.id())?;
            signalled = true;
        }
        if child.0.try_wait()?.is_some() {
            // Drain what the terminal already holds before deciding the ordering.
            continue;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let status = match child.0.try_wait()? {
        Some(status) => status,
        None => {
            child.0.kill()?;
            child.0.wait()?;
            return Err("the probe timed out before the command exited".into());
        }
    };
    let after_leave = output
        .windows(LEAVE.len())
        .rposition(|part| part == LEAVE)
        .is_some_and(|at| contains(&output[at + LEAVE.len()..], WORD));
    let handler_wrote_leave = contains(&output, LEFT);
    println!(
        "typed_public_dice={typed}; signalled_at_write={signalled}; handler_wrote_leave={handler_wrote_leave}; exit={status}; word_after_leave={after_leave}"
    );
    if !typed || !signalled || status.code() != Some(130) {
        return Err("the probe did not reach its required schedule".into());
    }
    if after_leave {
        return Err(
            "the public password word was written after the private screen was left".into(),
        );
    }
    if !handler_wrote_leave {
        return Err(
            "the tested interleaving was not reached; this is not a passing privacy check".into(),
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AUD-045: {error}");
            ExitCode::FAILURE
        }
    }
}
