//! The pseudo-terminal of a session on Linux and macOS: the one place of xtask that needs
//! `unsafe`, to make the terminal the controlling terminal of the tool between fork and exec,
//! which std offers only through `pre_exec` (RUST-07).
#![expect(
    unsafe_code,
    reason = "a child's controlling terminal and address space are set between fork and exec"
)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::openpty;
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::termios::{Termios, tcgetattr};
use nix::unistd::setsid;

use crate::Failure;

/// The two ends of a pseudo-terminal: the side this program reads and writes, and the side the
/// tool runs on.
pub(crate) struct Pty {
    pub(crate) master: OwnedFd,
    pub(crate) slave: OwnedFd,
}

impl Pty {
    pub(crate) fn open() -> Result<Self, Failure> {
        let ends = openpty(None, None).map_err(|error| Failure(format!("openpty: {error}")))?;
        let flags = fcntl(&ends.master, FcntlArg::F_GETFL)
            .map_err(|error| Failure(format!("fcntl: {error}")))?;
        let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(&ends.master, FcntlArg::F_SETFL(flags))
            .map_err(|error| Failure(format!("fcntl: {error}")))?;
        Ok(Self {
            master: ends.master,
            slave: ends.slave,
        })
    }

    /// The terminal's settings, read through the master side: on macOS the slave side stops
    /// answering once the tool, the leader of its session, has ended, because the system revokes
    /// the terminal of an ended session.
    pub(crate) fn settings(&self) -> Result<Termios, Failure> {
        tcgetattr(&self.master).map_err(|error| Failure(format!("tcgetattr: {error}")))
    }

    pub(crate) fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }
}

/// Makes the child of `command` the leader of a session of its own whose controlling terminal is
/// its standard input, so that Ctrl+C typed there sends it SIGINT; with `address_space`, its
/// address space is limited to that many bytes, so that the memory for Argon2 is refused.
pub(crate) fn attach(command: &mut Command, address_space: Option<u64>) {
    let hook = move || -> std::io::Result<()> {
        setsid()?;
        // SAFETY: TIOCSCTTY takes no pointer, only the descriptor 0 of this child, which is the
        // pseudo-terminal's slave side; the call is async-signal-safe, as pre_exec requires.
        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(bytes) = address_space {
            setrlimit(Resource::RLIMIT_AS, bytes, bytes)?;
        }
        Ok(())
    };
    // SAFETY: the hook calls only setsid, ioctl and setrlimit, which allocate nothing and are
    // async-signal-safe, as code between fork and exec must be.
    unsafe {
        command.pre_exec(hook);
    }
}

/// Limits the address space of the child of `command` to `bytes`, without a terminal.
pub(crate) fn limit(command: &mut Command, bytes: u64) {
    // SAFETY: setrlimit allocates nothing and is async-signal-safe, as code between fork and exec
    // must be.
    unsafe {
        command.pre_exec(move || Ok(setrlimit(Resource::RLIMIT_AS, bytes, bytes)?));
    }
}
