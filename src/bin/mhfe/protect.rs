//! What the tool does to keep secrets inside its own memory and itself offline:
//!
//! - no core dumps, and no reading of its memory by other programs of the same user;
//! - Ctrl+\ and Ctrl+Z end the tool as Ctrl+C does, so that no key leaves a secret on the screen;
//! - a warning when swap could write memory to a disk without encryption. Argon2's work area is far
//!   too large to keep out of swap (src/memory.rs), and from its blocks a password guess can be
//!   tested cheaply, so unencrypted swap matters;
//! - on Linux, seccomp refuses new sockets and io_uring, and Landlock restricts opening files for
//!   writing. Both cover the calling thread and workers it starts, including Argon2's, and cannot
//!   be undone. Already-open descriptors remain usable, so a trusted offline host is required;
//! - a command started directly also enters its own network namespace, where permitted, with only
//!   inactive loopback and no external routes. Previously opened sockets keep their original
//!   namespace. The localhost browser server stays outside these secret-command restrictions.
//!
//! Each protection is read back before it is relied on: [`CoreDumpCheck`] and [`IsolationCheck`]
//! are parts of the checks at start (startup.rs) and of `mhfe self-test`.

#![allow(
    unsafe_code,
    reason = "prctl, setrlimit, sigaction and the Landlock calls are operating-system calls that \
              Rust offers only through unsafe foreign functions"
)]

use std::cell::Cell;

use mhfe::self_check::{process, ComponentCheck, ComponentOutcome, Tier};

/// Forbids core dumps of this process and, on Linux, makes it non-dumpable, which also keeps
/// other processes of the same user from attaching to it (ptrace) or reading /proc/PID/mem. A
/// crash then writes nothing to disk, wherever systemd-coredump or apport would put it. Called
/// first in `main`; a refusal, which no usual system gives, changes nothing else.
pub fn harden_process() {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the struct, which lives for the call.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes an integer and touches no memory of this process.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    }
}

/// Ctrl+\ (SIGQUIT) and Ctrl+Z (SIGTSTP) interrupt the tool as Ctrl+C does, so that its handler
/// (terminal::stop_on_ctrl_c) restores the terminal and leaves a private screen: by default the
/// first would end the tool and the second stop it with a secret still on the screen
/// (AUD-015-SEC004). A handler, unlike an ignored signal, is reset for a program the tool starts,
/// such as the browser of `mhfe serve`. Returns whether both handlers read back as set, as every
/// protection is read back before it is relied on.
pub fn interrupt_on_quit_and_suspend() -> bool {
    #[cfg(not(unix))]
    {
        true
    }
    #[cfg(unix)]
    {
        extern "C" fn interrupt(_signal: libc::c_int) {
            // SAFETY: raise is async-signal-safe (POSIX.1-2008, 2.4.3); the handler of SIGINT
            // (ctrlc) only writes to the pipe its thread waits on.
            unsafe { libc::raise(libc::SIGINT) };
        }
        let handler = interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let mut set = true;
        for signal in [libc::SIGQUIT, libc::SIGTSTP] {
            // SAFETY: a zeroed sigaction is a valid empty one; every field set below is a plain
            // value, and sigaction reads the first structure and writes the second only during
            // the call.
            let in_force = unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = handler;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                let mut current: libc::sigaction = std::mem::zeroed();
                libc::sigaction(signal, &action, std::ptr::null_mut()) == 0
                    && libc::sigaction(signal, std::ptr::null(), &mut current) == 0
                    && current.sa_sigaction == handler
            };
            set &= in_force;
        }
        set
    }
}

/// The identifier of [`CoreDumpCheck`] in a self-check report.
pub const CORE_DUMPS_ID: &str = process::CORE_DUMPS.id;

/// How one protection reads back from the kernel.
// Windows reads nothing back: there, only the tests construct every variant.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadBack {
    /// As [`harden_process`] set it.
    Set,
    /// Otherwise: the protection is not in force.
    Differs,
    /// The kernel would not say, for the reason given.
    Unknown(&'static str),
}

/// What the kernel reports about core dumps of this process; `None` where a system has no such
/// setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoreDumps {
    /// RLIMIT_CORE, on Unix: both limits must be 0.
    limit: Option<ReadBack>,
    /// PR_GET_DUMPABLE, on Linux: it must be 0. A pipe in core_pattern, as systemd-coredump and
    /// apport use, ignores RLIMIT_CORE, so on Linux only this keeps a crash off the disk.
    dumpable: Option<ReadBack>,
}

impl CoreDumps {
    /// Reads both settings back now.
    fn read() -> Self {
        Self {
            limit: core_limit(),
            dumpable: dumpable(),
        }
    }

    /// Failed when a setting reads back otherwise: a crash could then write memory, secrets
    /// included, to a disk. A setting the kernel does not report is not a failure.
    fn outcome(self) -> ComponentOutcome {
        let readings = [self.limit, self.dumpable];
        if readings.contains(&Some(ReadBack::Differs)) {
            return ComponentOutcome::Failed("the kernel still allows them".to_owned());
        }
        let unknown = readings.iter().find_map(|reading| match reading {
            Some(ReadBack::Unknown(reason)) => Some(*reason),
            _ => None,
        });
        if let Some(reason) = unknown {
            return ComponentOutcome::NotAvailable(reason.to_owned());
        }
        if readings.iter().all(Option::is_none) {
            return ComponentOutcome::NotAvailable(NO_CORE_DUMP_SETTING.to_owned());
        }
        ComponentOutcome::Passed
    }
}

/// Why a system without RLIMIT_CORE gives no reading.
const NO_CORE_DUMP_SETTING: &str = if cfg!(windows) {
    "Windows Error Reporting decides whether a crash is saved"
} else {
    "this system has no core-dump limit"
};

#[cfg(unix)]
fn core_limit() -> Option<ReadBack> {
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } != 0 {
        return Some(ReadBack::Unknown("the core-dump limit cannot be read"));
    }
    Some(if (limit.rlim_cur, limit.rlim_max) == (0, 0) {
        ReadBack::Set
    } else {
        ReadBack::Differs
    })
}

#[cfg(not(unix))]
fn core_limit() -> Option<ReadBack> {
    None
}

#[cfg(target_os = "linux")]
fn dumpable() -> Option<ReadBack> {
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag, or -1 with errno (EINVAL in a
    // kernel that does not know it).
    Some(
        match unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } {
            0 => ReadBack::Set,
            -1 => ReadBack::Unknown("the kernel does not say whether the process can be dumped"),
            _ => ReadBack::Differs,
        },
    )
}

#[cfg(not(target_os = "linux"))]
fn dumpable() -> Option<ReadBack> {
    None
}

/// The `core-dumps` check: no core dumps and, on Linux, no reading of this process's memory by
/// other programs, as [`harden_process`] set it.
pub struct CoreDumpCheck;

impl ComponentCheck for CoreDumpCheck {
    fn id(&self) -> &'static str {
        CORE_DUMPS_ID
    }

    fn label(&self) -> &'static str {
        process::CORE_DUMPS.label
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        CoreDumps::read().outcome()
    }
}

/// What a command needs that isolation would forbid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Needs {
    pub network: bool,
    pub writes: bool,
}

impl Needs {
    /// A command that handles secrets needs neither.
    pub const NOTHING: Self = Self {
        network: false,
        writes: false,
    };
}

/// What the kernel enforces for the thread that runs a command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Isolation {
    pub no_network: bool,
    pub no_writes: bool,
    /// The process runs in its own network namespace, with only an inactive loopback interface.
    pub empty_network: bool,
}

impl Isolation {
    const NONE: Self = Self {
        no_network: false,
        no_writes: false,
        empty_network: false,
    };

    /// Whether nothing is enforced.
    pub fn is_empty(self) -> bool {
        self == Self::NONE
    }

    /// The boundaries, as a summary names them.
    pub fn names(self) -> Vec<&'static str> {
        [
            (self.empty_network, "the isolated network"),
            (self.no_network, "no new sockets"),
            (self.no_writes, "no new file writes"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect()
    }
}

thread_local! {
    /// What [`isolate`] reported for the thread it isolated.
    static CLAIMED: Cell<Isolation> = const { Cell::new(Isolation::NONE) };
    /// What [`verify_isolation`] found of that report, once it has run in the thread.
    static PROBED: Cell<Option<IsolationProbe>> = const { Cell::new(None) };
}

/// Forbids the calling thread, and every thread it starts afterwards, what `needs` does not
/// include, as far as the kernel allows: sockets through seccomp, writes to files through
/// Landlock (Linux 5.13 and later). Descriptors already open, including sockets, files and
/// terminals, stay usable. Returns what the kernel reports as now enforced; elsewhere than on
/// Linux nothing is. [`verify_isolation`] then checks the report from the inside.
pub fn isolate(needs: Needs) -> Isolation {
    let isolation = isolate_thread(needs);
    CLAIMED.with(|claimed| claimed.set(isolation));
    PROBED.with(|probed| probed.set(None));
    isolation
}

/// What is enforced for the calling thread, as the summary of a command states it: what the probes
/// confirmed once [`verify_isolation`] has run, else what [`isolate`] reported.
pub fn isolation() -> Isolation {
    match PROBED.with(Cell::get) {
        Some(probe) => probe.confirmed,
        None => CLAIMED.with(Cell::get),
    }
}

/// What [`isolate`] reported for the calling thread and a probe found does not hold.
pub fn isolation_refuted() -> Isolation {
    PROBED
        .with(Cell::get)
        .map_or(Isolation::NONE, |probe| probe.refuted)
}

/// What the probes found of each boundary [`isolate`] reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IsolationProbe {
    /// The boundaries that hold: what the summary of a command states from now on.
    pub confirmed: Isolation,
    /// The boundaries the kernel reported but a probe got through.
    pub refuted: Isolation,
    /// The boundaries no probe could confirm or refute, as without a /dev/null to open.
    pub unverified: Isolation,
}

/// Probes, in the calling thread, every boundary [`isolate`] reported for it, and keeps only what
/// holds for the summary of the command. Each probe tries what the boundary forbids and closes at
/// once whatever opens: no packet is sent and no file is written. Run in each thread a command
/// runs in, after [`isolate`]; running it again probes the same report again.
pub fn verify_isolation() -> IsolationProbe {
    verify_isolation_with(&platform_probes::Kernel)
}

fn verify_isolation_with(probes: &dyn Probes) -> IsolationProbe {
    let claimed = CLAIMED.with(Cell::get);
    let probe = probe_claims(claimed, probes);
    PROBED.with(|probed| probed.set(Some(probe)));
    probe
}

/// The calls the probes make: the kernel's, or a test's own answers.
trait Probes {
    /// Opens a UDP socket over IPv4 and closes it at once: `Ok` when it opened, else the error
    /// number of the refusal.
    fn socket(&self) -> Result<(), i32>;
    /// Sets up an io_uring of one entry and closes it at once, as [`Probes::socket`].
    fn io_uring(&self) -> Result<(), i32>;
    /// Opens /dev/null for writing and closes it at once, as [`Probes::socket`].
    fn open_for_writing(&self) -> Result<(), i32>;
    /// The text of /proc/self/net/`name`, or `None` when it cannot be read.
    fn net_file(&self, name: &str) -> Option<String>;
}

/// What a probe of one boundary found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    Holds,
    Broken,
    Unknown,
}

/// The error number the seccomp filter and Landlock give a refused call: EACCES, 13 on Linux
/// (asm-generic/errno-base.h). The filter runs before the system call itself, so a refusal with
/// any other number did not come from it.
const REFUSED: i32 = 13;

fn probe_claims(claimed: Isolation, probes: &dyn Probes) -> IsolationProbe {
    let mut probe = IsolationProbe::default();
    let mut sort = |claimed: bool, found: &dyn Fn() -> Found, set: fn(&mut Isolation)| {
        if !claimed {
            return;
        }
        match found() {
            Found::Holds => set(&mut probe.confirmed),
            Found::Broken => set(&mut probe.refuted),
            Found::Unknown => set(&mut probe.unverified),
        }
    };
    sort(
        claimed.no_network,
        &|| sockets_refused(probes),
        |isolation| isolation.no_network = true,
    );
    sort(claimed.no_writes, &|| writes_refused(probes), |isolation| {
        isolation.no_writes = true
    });
    sort(
        claimed.empty_network,
        &|| network_empty(probes),
        |isolation| isolation.empty_network = true,
    );
    probe
}

/// Both a socket and an io_uring, which could open a socket without the socket call
/// (AUD-008-SEC001), must be refused by the filter.
fn sockets_refused(probes: &dyn Probes) -> Found {
    if probes.socket() == Err(REFUSED) && probes.io_uring() == Err(REFUSED) {
        Found::Holds
    } else {
        Found::Broken
    }
}

/// Opening /dev/null for writing must be refused by Landlock. A system without /dev/null, or one
/// that refuses for another reason, cannot tell.
fn writes_refused(probes: &dyn Probes) -> Found {
    match probes.open_for_writing() {
        Err(REFUSED) => Found::Holds,
        Ok(()) => Found::Broken,
        Err(_) => Found::Unknown,
    }
}

/// The network namespace must hold only the loopback interface and no IPv4 route. The kernel
/// lists the interfaces after two heading lines, each as "name: counters", and the routes after a
/// heading that starts with "Iface"; an empty table may lack that heading.
fn network_empty(probes: &dyn Probes) -> Found {
    /// Heading lines of /proc/net/dev.
    const DEVICE_HEADINGS: usize = 2;
    let (Some(devices), Some(routes)) = (probes.net_file("dev"), probes.net_file("route")) else {
        return Found::Unknown;
    };
    let only_loopback = devices
        .lines()
        .skip(DEVICE_HEADINGS)
        .filter_map(|line| line.split(':').next())
        .all(|name| name.trim() == "lo");
    let no_route = routes
        .lines()
        .all(|line| line.trim().is_empty() || line.starts_with("Iface"));
    if only_loopback && no_route {
        Found::Holds
    } else {
        Found::Broken
    }
}

#[cfg(target_os = "linux")]
mod platform_probes {
    use std::io;

    /// The probes against the kernel, in the calling thread.
    pub(super) struct Kernel;

    /// `Ok` and closed when `descriptor` opened, else the error number of the refusal.
    fn opened(descriptor: i64) -> Result<(), i32> {
        if descriptor >= 0 {
            // SAFETY: closes the descriptor the probe just opened, once.
            unsafe { libc::close(descriptor as libc::c_int) };
            Ok(())
        } else {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    impl super::Probes for Kernel {
        fn socket(&self) -> Result<(), i32> {
            // SAFETY: socket takes integers and touches no memory of this process.
            let socket =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            opened(i64::from(socket))
        }

        fn io_uring(&self) -> Result<(), i32> {
            // `struct io_uring_params` of linux/io_uring.h is 120 bytes; zero asks for the defaults.
            let mut params = [0u8; 120];
            // SAFETY: the kernel reads and fills the 120 bytes of `params`, which live for the
            // call.
            let ring =
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
            opened(ring)
        }

        fn open_for_writing(&self) -> Result<(), i32> {
            // SAFETY: the path is a NUL-terminated literal; open touches nothing else.
            let file =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            opened(i64::from(file))
        }

        fn net_file(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(format!("/proc/self/net/{name}")).ok()
        }
    }
}

/// Elsewhere [`isolate`] reports nothing, so nothing is probed.
#[cfg(not(target_os = "linux"))]
mod platform_probes {
    pub(super) struct Kernel;

    /// No error number: nothing is tried where nothing is isolated.
    const NOT_TRIED: i32 = 0;

    impl super::Probes for Kernel {
        fn socket(&self) -> Result<(), i32> {
            Err(NOT_TRIED)
        }

        fn io_uring(&self) -> Result<(), i32> {
            Err(NOT_TRIED)
        }

        fn open_for_writing(&self) -> Result<(), i32> {
            Err(NOT_TRIED)
        }

        fn net_file(&self, _: &str) -> Option<String> {
            None
        }
    }
}

/// The identifier of [`IsolationCheck`] in a self-check report.
pub const ISOLATION_ID: &str = process::ISOLATION.id;

/// The `isolation` check: whether what [`isolate`] reported for the calling thread holds. It is not
/// a failure when it does not: the summary of the command then states only what holds, with a
/// warning, and the command goes on, as it would on a system without these boundaries.
pub struct IsolationCheck;

impl IsolationCheck {
    fn outcome(probe: IsolationProbe) -> ComponentOutcome {
        if !probe.refuted.is_empty() {
            return ComponentOutcome::Warning(format!(
                "weaker than the kernel reported: {}",
                probe.refuted.names().join(", ")
            ));
        }
        if !probe.unverified.is_empty() {
            return ComponentOutcome::NotAvailable(format!(
                "could not be verified: {}",
                probe.unverified.names().join(", ")
            ));
        }
        if probe.confirmed.is_empty() {
            let reason = if cfg!(target_os = "linux") {
                "the kernel enforces none for this run"
            } else {
                "this system offers none to a program"
            };
            return ComponentOutcome::NotAvailable(reason.to_owned());
        }
        ComponentOutcome::Passed
    }
}

impl ComponentCheck for IsolationCheck {
    fn id(&self) -> &'static str {
        ISOLATION_ID
    }

    fn label(&self) -> &'static str {
        process::ISOLATION.label
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        Self::outcome(verify_isolation())
    }
}

/// The most memory this process may lock (RLIMIT_MEMLOCK), in bytes; `None` where it cannot be
/// read, has no limit, or this is not Unix.
pub fn lock_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct, which lives for the call.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0
            || limit.rlim_cur == libc::RLIM_INFINITY
        {
            return None;
        }
        #[allow(
            clippy::useless_conversion,
            reason = "rlim_t is u64 on Linux and macOS, but not on every Unix"
        )]
        let bytes = u64::from(limit.rlim_cur);
        Some(bytes)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn isolate_thread(needs: Needs) -> Isolation {
    if needs.network && needs.writes {
        return Isolation::default();
    }
    // Both seccomp and Landlock require no_new_privs for an unprivileged process: no program it
    // starts can gain privileges, as a set-user-ID program would.
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integers and touches no memory of this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Isolation::default();
    }
    // Only a command that needs neither: in a user namespace of its own the process could not
    // create a file, as no owner of a new file maps to the system's users.
    let empty_network = needs == Needs::NOTHING && namespace::enter_empty_network();
    Isolation {
        no_writes: !needs.writes && landlock::forbid_writes(!needs.network),
        no_network: !needs.network && seccomp::forbid_sockets(),
        empty_network,
    }
}

/// A network namespace of its own for the process, with only a loopback interface that stays
/// down and no external routes. Previously opened sockets remain in their original namespace;
/// this supplements the socket-creation filter rather than revoking inherited descriptors.
/// An unprivileged process may create one only together with a user namespace of its
/// own, which the kernel allows only while the process has a single thread, as a command started
/// directly has at this point, and only where the system allows user namespaces. A command of the
/// start menu, which runs in a thread of the menu, does not get one.
#[cfg(target_os = "linux")]
mod namespace {
    /// Whether the process now runs in the empty network; a refusal changes nothing.
    pub(super) fn enter_empty_network() -> bool {
        // SAFETY: unshare takes flags only and touches no memory of this process.
        unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0 }
    }
}

#[cfg(not(target_os = "linux"))]
fn isolate_thread(_needs: Needs) -> Isolation {
    Isolation::default()
}

#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
mod landlock;

mod swap;

pub use swap::unprotected_swap;

/// A swap area through which memory could reach a disk unencrypted.
#[derive(Debug, PartialEq, Eq)]
pub struct SwapArea {
    /// The device or file, as /proc/swaps names it.
    pub name: String,
    /// False when it is surely unencrypted, true when MHFE cannot tell, as for a swap file on a
    /// file system whose device it cannot see.
    pub unknown: bool,
}

/// An inspected swap inventory, or an unavailable Linux inventory that must still warn.
#[derive(Debug, PartialEq, Eq)]
pub enum SwapInventory {
    Available(Vec<SwapArea>),
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// In a thread of its own, so that the other tests stay free: a socket cannot be opened and a
    /// file cannot be written, where the kernel offers each, while the test's own thread can.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_isolated_thread_cannot_open_a_socket_or_write_a_file() {
        let folder = std::env::temp_dir().join(format!("mhfe-isolation-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let target = folder.join("written");
        let (isolation, socket, write) = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let isolation = isolate(Needs::NOTHING);
                    assert_eq!(super::isolation(), isolation);
                    let socket = std::net::TcpListener::bind("127.0.0.1:0").is_ok();
                    let write = fs::write(&target, "x").is_ok();
                    // io_uring could create a socket without the socket call (AUD-008-SEC001).
                    assert_eq!(io_uring_setup(), Some(libc::EACCES), "io_uring was set up");
                    (isolation, socket, write)
                })
                .join()
                .unwrap()
        });
        // seccomp is in every kernel this tool supports.
        assert!(isolation.no_network);
        assert!(!socket, "a socket was opened");
        assert_eq!(write, !isolation.no_writes, "Landlock: {isolation:?}");
        // The rest of the process is not isolated.
        assert_eq!(super::isolation(), Isolation::default());
        assert!(std::net::TcpListener::bind("127.0.0.1:0").is_ok());
        fs::write(&target, "x").unwrap();
        let _ = fs::remove_dir_all(&folder);
    }

    /// A process with a single thread enters the empty network, where nothing is in reach: a
    /// datagram even to the loopback address finds no route. The check runs in a child forked off
    /// the test, which has the single thread a new user namespace needs; on a system that allows
    /// no user namespace there is nothing to check.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_with_one_thread_gets_an_empty_network() {
        /// Exit codes of the child: the datagram found no route, it was sent, no namespace.
        const UNREACHABLE: i32 = 0;
        const SENT: i32 = 1;
        const NO_NAMESPACE: i32 = 2;
        // SAFETY: the child makes only system calls and ends with _exit, as the child of a process
        // with several threads must.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let code = if namespace::enter_empty_network() {
                let address = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    // The discard port: nothing would answer even with a network.
                    sin_port: 9u16.to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: a datagram of one byte to the address above, both of which live for the
                // calls.
                let sent = unsafe {
                    let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                    libc::sendto(
                        socket,
                        b"x".as_ptr().cast(),
                        1,
                        0,
                        (&address as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                let error = std::io::Error::last_os_error().raw_os_error();
                if sent < 0 && error == Some(libc::ENETUNREACH) {
                    UNREACHABLE
                } else {
                    SENT
                }
            } else {
                NO_NAMESPACE
            };
            // SAFETY: ends the child at once, without running anything of the test's process.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "the child did not end: {status}");
        match libc::WEXITSTATUS(status) {
            UNREACHABLE => {}
            NO_NAMESPACE => eprintln!("This system allows no user namespace: nothing to check."),
            code => panic!("a datagram left the empty network ({code})"),
        }
    }

    /// Sets up an io_uring of one entry and closes it again; the error number when that is refused.
    #[cfg(target_os = "linux")]
    fn io_uring_setup() -> Option<i32> {
        // `struct io_uring_params` of linux/io_uring.h is 120 bytes; zero asks for the defaults.
        let mut params = [0u8; 120];
        // SAFETY: the kernel reads and fills the 120 bytes of `params`, which live for the call.
        let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
        if ring < 0 {
            return Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        // SAFETY: closes the descriptor that io_uring_setup returned.
        unsafe { libc::close(ring as i32) };
        None
    }

    #[test]
    fn a_command_that_needs_everything_is_not_isolated() {
        let needs = Needs {
            network: true,
            writes: true,
        };
        let isolation = std::thread::scope(|scope| scope.spawn(|| isolate(needs)).join().unwrap());
        assert_eq!(isolation, Isolation::default());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_process_forbids_core_dumps() {
        harden_process();
        // SAFETY: PR_GET_DUMPABLE takes no pointer.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes the struct, which lives for the call.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
        // And the check reads them back as off.
        assert_eq!(CoreDumpCheck.run(Tier::Startup), ComponentOutcome::Passed);
    }

    #[cfg(unix)]
    #[test]
    fn the_refusal_number_is_eacces() {
        assert_eq!(REFUSED, libc::EACCES);
    }

    /// A read-back that differs fails the check; a setting the kernel does not report, as a
    /// PR_GET_DUMPABLE refused with EINVAL, is not available; a system without the settings has
    /// nothing to read.
    #[test]
    fn core_dumps_fail_only_when_a_setting_reads_back_otherwise() {
        use ReadBack::{Differs, Set, Unknown};
        let read = |limit, dumpable| CoreDumps { limit, dumpable }.outcome();
        assert_eq!(read(Some(Set), Some(Set)), ComponentOutcome::Passed);
        // macOS reads back the limit only.
        assert_eq!(read(Some(Set), None), ComponentOutcome::Passed);
        for (limit, dumpable) in [
            (Some(Differs), Some(Set)),
            (Some(Set), Some(Differs)),
            (Some(Differs), Some(Unknown("x"))),
        ] {
            assert!(read(limit, dumpable).is_failure(), "{limit:?} {dumpable:?}");
        }
        assert_eq!(
            read(Some(Set), Some(Unknown("no answer"))),
            ComponentOutcome::NotAvailable("no answer".to_owned())
        );
        assert_eq!(
            read(None, None),
            ComponentOutcome::NotAvailable(NO_CORE_DUMP_SETTING.to_owned())
        );
    }

    /// The probes' answers, as a test gives them.
    #[derive(Clone)]
    struct FakeKernel {
        socket: Result<(), i32>,
        io_uring: Result<(), i32>,
        write: Result<(), i32>,
        devices: Option<&'static str>,
        routes: Option<&'static str>,
    }

    /// /proc/self/net/dev of an empty network namespace.
    const LOOPBACK_ONLY: &str =
        "Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n    lo: 0 0 0\n";

    impl FakeKernel {
        /// A kernel that enforces everything.
        fn enforcing() -> Self {
            Self {
                socket: Err(REFUSED),
                io_uring: Err(REFUSED),
                write: Err(REFUSED),
                devices: Some(LOOPBACK_ONLY),
                // An empty route table may lack its heading line.
                routes: Some(""),
            }
        }
    }

    impl Probes for FakeKernel {
        fn socket(&self) -> Result<(), i32> {
            self.socket
        }

        fn io_uring(&self) -> Result<(), i32> {
            self.io_uring
        }

        fn open_for_writing(&self) -> Result<(), i32> {
            self.write
        }

        fn net_file(&self, name: &str) -> Option<String> {
            match name {
                "dev" => self.devices.map(str::to_owned),
                "route" => self.routes.map(str::to_owned),
                other => panic!("no probe reads {other}"),
            }
        }
    }

    const EVERYTHING: Isolation = Isolation {
        no_network: true,
        no_writes: true,
        empty_network: true,
    };

    #[test]
    fn the_probes_confirm_what_holds() {
        let probe = probe_claims(EVERYTHING, &FakeKernel::enforcing());
        assert_eq!(probe.confirmed, EVERYTHING);
        assert!(probe.refuted.is_empty() && probe.unverified.is_empty());
        assert_eq!(IsolationCheck::outcome(probe), ComponentOutcome::Passed);
        // A heading line in the route table is no route.
        let with_heading = FakeKernel {
            routes: Some("Iface\tDestination\tGateway\n"),
            ..FakeKernel::enforcing()
        };
        assert_eq!(
            probe_claims(EVERYTHING, &with_heading).confirmed,
            EVERYTHING
        );
        // What was not reported is not probed, and nothing reported is not available.
        let nothing = probe_claims(Isolation::NONE, &FakeKernel::enforcing());
        assert_eq!(nothing, IsolationProbe::default());
        assert_eq!(IsolationCheck::outcome(nothing).name(), "notAvailable");
    }

    #[test]
    fn isolation_probe_downgrades_a_false_claim() {
        let cases: [(&str, FakeKernel, Isolation); 6] = [
            (
                "a socket opens",
                FakeKernel {
                    socket: Ok(()),
                    ..FakeKernel::enforcing()
                },
                Isolation {
                    no_network: true,
                    ..Isolation::NONE
                },
            ),
            (
                "io_uring is refused by something else than the filter",
                FakeKernel {
                    io_uring: Err(38),
                    ..FakeKernel::enforcing()
                },
                Isolation {
                    no_network: true,
                    ..Isolation::NONE
                },
            ),
            (
                "/dev/null opens for writing",
                FakeKernel {
                    write: Ok(()),
                    ..FakeKernel::enforcing()
                },
                Isolation {
                    no_writes: true,
                    ..Isolation::NONE
                },
            ),
            (
                "another interface",
                FakeKernel {
                    devices: Some("h1\nh2\n    lo: 0\n  eth0: 0\n"),
                    ..FakeKernel::enforcing()
                },
                Isolation {
                    empty_network: true,
                    ..Isolation::NONE
                },
            ),
            (
                "a route",
                FakeKernel {
                    routes: Some("Iface\tDestination\neth0\t00000000\n"),
                    ..FakeKernel::enforcing()
                },
                Isolation {
                    empty_network: true,
                    ..Isolation::NONE
                },
            ),
            (
                "everything gets through",
                FakeKernel {
                    socket: Ok(()),
                    write: Ok(()),
                    devices: Some("h1\nh2\n  eth0: 0\n"),
                    ..FakeKernel::enforcing()
                },
                EVERYTHING,
            ),
        ];
        for (case, kernel, refuted) in cases {
            let probe = probe_claims(EVERYTHING, &kernel);
            assert_eq!(probe.refuted, refuted, "{case}");
            assert!(probe.unverified.is_empty(), "{case}");
            assert_eq!(
                probe.confirmed,
                Isolation {
                    no_network: !refuted.no_network,
                    no_writes: !refuted.no_writes,
                    empty_network: !refuted.empty_network,
                },
                "{case}"
            );
            assert_eq!(
                IsolationCheck::outcome(probe),
                ComponentOutcome::Warning(format!(
                    "weaker than the kernel reported: {}",
                    refuted.names().join(", ")
                )),
                "{case}"
            );
        }
    }

    /// Without /dev/null, or without /proc, a probe cannot tell: unverified, not refuted.
    #[test]
    fn a_probe_that_cannot_tell_leaves_the_claim_unverified() {
        /// ENOENT on Linux (asm-generic/errno-base.h).
        const NO_SUCH_FILE: i32 = 2;
        let no_dev_null = FakeKernel {
            write: Err(NO_SUCH_FILE),
            ..FakeKernel::enforcing()
        };
        let probe = probe_claims(EVERYTHING, &no_dev_null);
        assert_eq!(
            probe.unverified,
            Isolation {
                no_writes: true,
                ..Isolation::NONE
            }
        );
        assert!(probe.refuted.is_empty());
        assert!(!probe.confirmed.no_writes && probe.confirmed.no_network);
        assert_eq!(
            IsolationCheck::outcome(probe),
            ComponentOutcome::NotAvailable("could not be verified: no new file writes".to_owned())
        );
        let no_proc = FakeKernel {
            routes: None,
            ..FakeKernel::enforcing()
        };
        assert!(probe_claims(EVERYTHING, &no_proc).unverified.empty_network);
    }

    /// After a probe, the summary of the command states only what holds, and names what does not.
    #[test]
    fn the_summary_states_only_what_the_probes_confirmed() {
        std::thread::spawn(|| {
            CLAIMED.with(|claimed| claimed.set(EVERYTHING));
            assert_eq!(isolation(), EVERYTHING, "before the probe, the report");
            assert!(isolation_refuted().is_empty());
            let open = FakeKernel {
                socket: Ok(()),
                ..FakeKernel::enforcing()
            };
            verify_isolation_with(&open);
            assert!(!isolation().no_network && isolation().no_writes);
            assert_eq!(isolation_refuted().names(), ["no new sockets"]);
            // Probing again probes the same report, and a new isolate() starts afresh.
            verify_isolation_with(&FakeKernel::enforcing());
            assert_eq!(isolation(), EVERYTHING);
            isolate(Needs {
                network: true,
                writes: true,
            });
            assert!(isolation().is_empty() && isolation_refuted().is_empty());
        })
        .join()
        .unwrap();
    }

    /// Landlock refuses to open /dev/null for writing, the probe of `no_writes`, and the probes of
    /// a real isolated thread confirm everything isolate() reported for it.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_refuses_opening_dev_null_for_writing() {
        std::thread::spawn(|| {
            let claimed = isolate(Needs::NOTHING);
            if claimed.no_writes {
                assert_eq!(
                    super::Probes::open_for_writing(&platform_probes::Kernel),
                    Err(libc::EACCES)
                );
            }
            let probe = verify_isolation();
            assert_eq!(probe.confirmed, claimed);
            assert!(probe.refuted.is_empty() && probe.unverified.is_empty());
            assert_eq!(IsolationCheck.run(Tier::Startup), ComponentOutcome::Passed);
        })
        .join()
        .unwrap();
        // The test's own thread may still open it.
        assert_eq!(
            super::Probes::open_for_writing(&platform_probes::Kernel),
            Ok(())
        );
    }

    /// Exit codes of the process that [`g10_isolated_command`] forks, which its test process passes
    /// on as its own. They are not 0 or 101, the codes of a test process that ran no such child.
    #[cfg(target_os = "linux")]
    mod g10 {
        pub const ISOLATED: i32 = 40;
        pub const NO_NAMESPACE: i32 = 41;
        pub const CHECKS_FAILED: i32 = 42;
        pub const NOT_EMPTY: i32 = 43;
        pub const NO_CHILD: i32 = 44;
        /// Set for the test process that runs [`super::g10_isolated_command`].
        pub const VARIABLE: &str = "MHFE_TEST_G10_CHILD";
    }

    /// G10: a command started directly enters its empty network before the checks at start, whose
    /// Argon2 check runs four threads; a process with more than one thread could not enter it. The
    /// order of main is followed for `mhfe encrypt` in a process of a single thread, as a command
    /// has at that point: forked off a test process of its own that runs nothing else, so that no
    /// other test holds a lock or a descriptor the fork would copy. On a system that allows no
    /// user namespace only the checks are verified.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_empty_network_is_entered_before_the_startup_checks_start_threads() {
        /// Longest wait: the checks at start take about a second in a debug build.
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(120);
        let mut process = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "protect::tests::g10_isolated_command",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env(g10::VARIABLE, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > LIMIT {
                let _ = process.kill();
                panic!("the isolated command did not end within {LIMIT:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        match status.code() {
            Some(g10::ISOLATED) => {}
            Some(g10::NO_NAMESPACE) => {
                eprintln!("This system allows no user namespace: checks only.")
            }
            Some(g10::CHECKS_FAILED) => panic!("the checks at start failed after isolation"),
            Some(g10::NOT_EMPTY) => panic!("the network of the isolated command is not empty"),
            other => panic!("the test process ran no isolated command: {other:?}"),
        }
    }

    /// Run only by the test above, in a test process of its own: forks a child of a single thread
    /// that follows main for `mhfe encrypt` up to its first question, and ends with the child's
    /// exit code.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by the_empty_network_is_entered_before_the_startup_checks_start_threads"]
    fn g10_isolated_command() {
        use clap::Parser;
        if std::env::var_os(g10::VARIABLE).is_none() {
            return;
        }
        let command = crate::Cli::try_parse_from(["mhfe", "encrypt"])
            .unwrap()
            .command;
        harden_process();
        // SAFETY: this test process runs no other test, so the child copies no lock that another
        // thread holds; it ends with _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let code = if crate::prepare(&command).is_err() {
                g10::CHECKS_FAILED
            } else if !isolation().empty_network {
                g10::NO_NAMESPACE
            } else {
                let devices = fs::read_to_string("/proc/self/net/dev").unwrap_or_default();
                let interfaces: Vec<&str> = devices
                    .lines()
                    .skip(2)
                    .filter_map(|line| line.split(':').next())
                    .map(str::trim)
                    .collect();
                if interfaces == ["lo"] {
                    g10::ISOLATED
                } else {
                    g10::NOT_EMPTY
                }
            };
            // SAFETY: ends the child at once, without running anything of the test's process.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        let waited = child > 0 && unsafe { libc::waitpid(child, &mut status, 0) } == child;
        let code = if waited && libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            g10::NO_CHILD
        };
        std::process::exit(code);
    }
}
