//! A run of the tool in a pseudo-terminal, as a person at a terminal drives it, and a run without
//! one, as a script does.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill};
use nix::sys::termios::Termios;
use nix::unistd::{Pid, read, write};

use super::pty::{self, Pty};
use super::{CTRL_C, container, ensure};
use crate::Failure;

/// The variables that turn colour on or off (src/bin/mhfe/style.rs); a run that is about colour
/// sets the one it checks and passes none of the others on.
const COLOUR_VARIABLES: [&str; 3] = ["NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE"];
/// An address space of 1 GiB, too small for the 2 GiB that memory level 0 reserves for Argon2: a
/// command that goes on to the long work is refused there, before Argon2 runs. Only Linux
/// enforces this limit (RLIMIT_AS).
const ADDRESS_SPACE_CAP: u64 = 1 << 30;
/// How often the terminal is looked at while waiting.
const TICK: u16 = 100;

/// Whether this system enforces the address space limit, so that a capped run stops at the
/// memory reservation.
pub(crate) fn capped_here() -> bool {
    cfg!(target_os = "linux")
}

/// The environment of the tool: NO_COLOR unless `colour`, and nothing else that turns colour on
/// or off. A capable terminal unless `term` names another: the shell that runs the checks may
/// itself be a dumb one, as some editors' consoles are.
fn environment(command: &mut Command, colour: bool, term: &str) {
    for name in COLOUR_VARIABLES {
        command.env_remove(name);
    }
    command.env("TERM", term);
    if !colour {
        command.env("NO_COLOR", "1");
    }
}

/// How a session starts: the tool's arguments; a replacement of the terminal as standard
/// output, such as a pipe; TERM; whether the address space is capped; whether colour stays on;
/// and another copy of the tool to run.
pub(crate) struct Start<'a> {
    pub(crate) arguments: &'a [&'a str],
    pub(crate) stdout: Option<Stdio>,
    pub(crate) term: &'a str,
    pub(crate) capped: bool,
    pub(crate) colour: bool,
    pub(crate) program: Option<&'a Path>,
}

impl<'a> Start<'a> {
    /// Standard output to a pipe; its read end, which holds what the tool wrote once it ended.
    pub(crate) fn piped(&mut self) -> Result<std::fs::File, Failure> {
        let (reader, writer) =
            nix::unistd::pipe().map_err(|error| Failure(format!("pipe: {error}")))?;
        self.stdout = Some(Stdio::from(writer));
        Ok(std::fs::File::from(reader))
    }

    pub(crate) fn of(arguments: &'a [&'a str]) -> Self {
        Self {
            arguments,
            stdout: None,
            term: "xterm-256color",
            capped: false,
            colour: false,
            program: None,
        }
    }
}

pub(crate) struct Session {
    pty: Pty,
    child: Child,
    /// Everything the tool wrote to the terminal so far.
    pub(crate) output: Vec<u8>,
    /// The terminal's settings before the tool started.
    pub(crate) original: Termios,
}

impl Session {
    /// `mhfe check --fingerprint --pim 0`, which reads the container and then its password and
    /// never reaches Argon2.
    pub(crate) fn check() -> Result<Self, Failure> {
        Self::start(Start::of(&["check", "--fingerprint", "--pim", "0"]))
    }

    pub(crate) fn of(arguments: &[&str]) -> Result<Self, Failure> {
        Self::start(Start::of(arguments))
    }

    /// A session whose address space is capped where this system enforces the cap.
    pub(crate) fn capped(arguments: &[&str]) -> Result<Self, Failure> {
        Self::start(Start {
            capped: capped_here(),
            ..Start::of(arguments)
        })
    }

    pub(crate) fn start(start: Start<'_>) -> Result<Self, Failure> {
        let pty = Pty::open()?;
        let original = pty.settings()?;
        let program = start.program.unwrap_or_else(|| super::program());
        let mut command = Command::new(program);
        command.args(start.arguments);
        environment(&mut command, start.colour, start.term);
        let slave = |pty: &Pty| -> Result<Stdio, Failure> {
            let copy = pty
                .slave
                .try_clone()
                .map_err(|error| Failure(error.to_string()))?;
            Ok(Stdio::from(copy))
        };
        command.stdin(slave(&pty)?).stderr(slave(&pty)?);
        command.stdout(match start.stdout {
            Some(stdout) => stdout,
            None => slave(&pty)?,
        });
        pty::attach(&mut command, start.capped.then_some(ADDRESS_SPACE_CAP));
        let child = command
            .spawn()
            .map_err(|error| Failure(format!("{} did not start: {error}", program.display())))?;
        Ok(Self {
            pty,
            child,
            output: Vec::new(),
            original,
        })
    }

    pub(crate) fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.child.id()).unwrap_or(i32::MAX))
    }

    pub(crate) fn signal(&self, signal: Signal) -> Result<(), Failure> {
        kill(self.pid(), signal).map_err(|error| Failure(format!("kill: {error}")))
    }

    /// Reads what the tool wrote, waiting up to TICK milliseconds for something; whether the
    /// terminal can still be read.
    fn read_some(&mut self) -> bool {
        let master = self.pty.master();
        let mut fds = [PollFd::new(master, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(TICK)) {
            Ok(0) | Err(Errno::EINTR) => return true,
            Err(_) => return false,
            Ok(_) => {}
        }
        let mut buffer = [0_u8; 4096];
        match read(master, &mut buffer) {
            Ok(0) => false,
            Ok(count) => {
                self.output.extend_from_slice(&buffer[..count]);
                true
            }
            Err(Errno::EAGAIN | Errno::EINTR) => true,
            // EIO once the tool's side has closed.
            Err(_) => false,
        }
    }

    /// Reads until one of `needles` appears after the text already seen, or after `since` in it;
    /// returns it.
    pub(crate) fn wait_for<'n>(
        &mut self,
        needles: &[&'n [u8]],
        limit: u64,
        since: Option<usize>,
    ) -> Result<&'n [u8], Failure> {
        let start = since.unwrap_or(self.output.len());
        let end = Instant::now() + Duration::from_secs(limit);
        loop {
            if let Some(found) = needles
                .iter()
                .find(|needle| contains(&self.output[start..], needle))
            {
                return Ok(found);
            }
            if Instant::now() > end || !self.read_some() {
                return Err(Failure(format!(
                    "none of {:?} in {:?}",
                    needles
                        .iter()
                        .map(|needle| shown(needle))
                        .collect::<Vec<_>>(),
                    shown(&self.output[start..])
                )));
            }
        }
    }

    /// Waits up to ten seconds for `needle` after the text already seen.
    pub(crate) fn wait(&mut self, needle: &[u8]) -> Result<(), Failure> {
        self.wait_for(&[needle], 10, None).map(|_| ())
    }

    /// Types `keys` and reads until every one of `expected` has appeared after them. A list and
    /// its question arrive together, so each is looked for in all that followed the keys.
    pub(crate) fn answer(&mut self, keys: &[u8], expected: &[&[u8]]) -> Result<(), Failure> {
        self.answer_within(keys, expected, 10)
    }

    pub(crate) fn answer_within(
        &mut self,
        keys: &[u8],
        expected: &[&[u8]],
        limit: u64,
    ) -> Result<(), Failure> {
        let start = self.output.len();
        self.type_keys(keys)?;
        let end = Instant::now() + Duration::from_secs(limit);
        while !expected
            .iter()
            .all(|needle| contains(&self.output[start..], needle))
        {
            if Instant::now() > end {
                return Err(Failure(format!(
                    "not all of {:?} in {:?}",
                    expected
                        .iter()
                        .map(|needle| shown(needle))
                        .collect::<Vec<_>>(),
                    shown(&self.output[start..])
                )));
            }
            if !self.read_some() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }

    /// Types `keys` and returns all that the tool wrote in the `seconds` after them.
    pub(crate) fn idle(&mut self, keys: &[u8], seconds: f64) -> Result<Vec<u8>, Failure> {
        let start = self.output.len();
        self.type_keys(keys)?;
        let end = Instant::now() + Duration::from_secs_f64(seconds);
        while Instant::now() < end {
            if !self.read_some() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(self.output[start..].to_vec())
    }

    /// Writes `data` as pasted text; the line only ends at the carriage return.
    ///
    /// A pseudo-terminal holds little input (about 1 KiB on macOS), so a long paste is written
    /// in parts as the tool reads them. The tool's output is read meanwhile, so that neither side
    /// waits for the other, and a tool that stops reading fails the check instead of blocking it
    /// for ever.
    pub(crate) fn type_keys(&mut self, data: &[u8]) -> Result<(), Failure> {
        let end = Instant::now() + Duration::from_secs(10);
        let mut rest = data;
        while !rest.is_empty() {
            if Instant::now() > end {
                return Err(Failure(format!(
                    "the tool stopped reading; {} bytes left to type",
                    rest.len()
                )));
            }
            let master = self.pty.master();
            let mut fds = [PollFd::new(master, PollFlags::POLLIN | PollFlags::POLLOUT)];
            let _ = poll(&mut fds, PollTimeout::from(TICK));
            let events = fds[0].revents().unwrap_or(PollFlags::empty());
            if events.contains(PollFlags::POLLIN) {
                self.read_some();
            }
            if events.contains(PollFlags::POLLOUT) {
                match write(self.pty.master(), rest) {
                    Ok(count) => rest = &rest[count..],
                    Err(Errno::EAGAIN | Errno::EINTR) => {}
                    Err(error) => return Err(Failure(format!("write: {error}"))),
                }
            }
        }
        Ok(())
    }

    /// Waits up to `limit` seconds for the tool to end, reading its output meanwhile.
    ///
    /// On macOS a process that ends waits until the terminal has delivered its last output, which
    /// happens only when this side reads it; without reading, the tool never finishes exiting.
    pub(crate) fn drain_until_exit(&mut self, limit: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(limit);
        while matches!(self.child.try_wait(), Ok(None)) {
            if Instant::now() > end {
                return false;
            }
            if !self.read_some() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // What the tool wrote last.
        while self.read_some_now() {}
        true
    }

    /// Reads what is there without waiting; whether anything was.
    fn read_some_now(&mut self) -> bool {
        let mut buffer = [0_u8; 4096];
        match read(self.pty.master(), &mut buffer) {
            Ok(count) if count > 0 => {
                self.output.extend_from_slice(&buffer[..count]);
                true
            }
            _ => false,
        }
    }

    /// Ends the tool as a person would, with Ctrl+C, so that it can restore the terminal; its exit
    /// code and the terminal's settings afterwards.
    pub(crate) fn close(&mut self) -> Result<(i32, Termios), Failure> {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.type_keys(CTRL_C)?;
            if !self.drain_until_exit(5) {
                // SIGKILL leaves the terminal as it is; the settings check then fails.
                let _ = self.child.kill();
            }
        }
        ensure(self.drain_until_exit(10), || {
            "the tool did not end".to_owned()
        })?;
        let status = self
            .child
            .wait()
            .map_err(|error| Failure(error.to_string()))?;
        let code = status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0));
        Ok((code, self.pty.settings()?))
    }

    /// close(), and a failure unless the exit code is `code` and the terminal is as it was.
    pub(crate) fn ends_with(&mut self, code: i32, label: &str) -> Result<(), Failure> {
        let (got, settings) = self.close()?;
        ensure(got == code, || {
            format!("{label}: exit code {got}, not {code}")
        })?;
        ensure(settings == self.original, || {
            format!("{label}: the terminal settings were not restored")
        })
    }

    /// Up to the container password of `mhfe check`: the container is read on its own private
    /// screen and taken at once.
    pub(crate) fn at_password_prompt(&mut self) -> Result<(), Failure> {
        self.wait(b"original seed phrase: ")?;
        let container = format!("{}\r", container());
        self.answer(container.as_bytes(), &[b"Container password: "])
    }

    /// What the main screen got after the private screen was last left.
    pub(crate) fn summary(&self) -> &[u8] {
        let at = rfind(&self.output, super::LEAVE_PRIVATE).unwrap_or(0);
        &self.output[at..]
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs the tool with `data` on standard input and both outputs in pipes, without a terminal;
/// `colour` forces colour on, and `capped` limits the address space as for a session.
pub(crate) fn run_plainly(
    arguments: &[&str],
    data: &[u8],
    colour: bool,
    capped: bool,
) -> Result<Output, Failure> {
    run_without_terminal(super::program(), arguments, data, colour, capped)
}

pub(crate) fn run_without_terminal(
    program: &Path,
    arguments: &[&str],
    data: &[u8],
    colour: bool,
    capped: bool,
) -> Result<Output, Failure> {
    let mut command = Command::new(program);
    command.args(arguments);
    environment(&mut command, colour, "xterm-256color");
    if colour {
        command.env("CLICOLOR_FORCE", "1");
    }
    if capped {
        pty::limit(&mut command, ADDRESS_SPACE_CAP);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure(format!("{} did not start: {error}", program.display())))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A tool that ends early closes its side: what it did not read does not matter.
        let _ = stdin.write_all(data);
    }
    child
        .wait_with_output()
        .map_err(|error| Failure(error.to_string()))
}

/// The exit code of a run without a terminal.
pub(crate) fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .unwrap_or_else(|| -output.status.signal().unwrap_or(0))
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle, 0).is_some()
}

pub(crate) fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(haystack.len()));
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
}

pub(crate) fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&at| &haystack[at..at + needle.len()] == needle)
}

pub(crate) fn count(haystack: &[u8], needle: &[u8]) -> usize {
    let mut found = 0;
    let mut at = 0;
    while let Some(next) = find(haystack, needle, at) {
        found += 1;
        at = next + needle.len().max(1);
    }
    found
}

/// Bytes as a message shows them.
pub(crate) fn shown(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}
