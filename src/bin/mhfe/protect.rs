//! What the tool does around mhfe-core's isolation, which keeps secrets inside this process and the
//! process offline:
//!
//! - [`enter`] applies that isolation and keeps what it read back, which [`CoreDumpCheck`] and
//!   [`IsolationCheck`] report as parts of the checks at start (startup.rs) and of `mhfe self-test`;
//! - on Unix, Ctrl+C, SIGTERM and a closed terminal (SIGHUP) run the tool's stop handler on a
//!   thread of its own, and Ctrl+\ and Ctrl+Z end the tool as Ctrl+C does, so that no key leaves a
//!   secret on the screen;
//! - a warning when swap could write memory to a disk without encryption. Argon2's work area is
//!   kept out of swap only where the limit on locked memory holds all of it (src/memory.rs), and
//!   from its blocks a password guess can be tested cheaply, so unencrypted swap matters.

#![allow(
    unsafe_code,
    reason = "sigaction, raise, kill, waitid, pipe, read, write, close, close_range, fcntl and \
              getrlimit are operating-system calls that Rust offers only through unsafe foreign \
              functions"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use mhfe::self_check::{ComponentCheck, ComponentOutcome, Tier};
use mhfe_core::protect::Isolation;
use secret_protection_core::Options;

use crate::exit::Failure;

/// What [`enter`] read back; unset in a process that did not call it, such as the start menu.
static REPORT: OnceLock<Isolation> = OnceLock::new();
/// Whether [`enter`] closed every descriptor that the program starting this one left open.
static INHERITED_CLOSED: AtomicBool = AtomicBool::new(false);

/// The protections a command adds to those every isolation applies, none of which it needs: on
/// Linux no file locks, no `sendmsg` and signals only to itself; on Windows no new executable code
/// and only DLLs that Microsoft signed. Each system ignores the others' options.
const OPTIONS: Options = Options::new()
    .refuse_file_locks()
    .refuse_sendmsg()
    .signals_to_self_only()
    .refuse_dynamic_code()
    .microsoft_signed_only();

/// Applies what this system offers against a secret leaving the process, for good, and keeps what
/// reads back as holding. All of it takes a process of one thread (main.rs). Isolation leaves
/// open descriptors usable, so those the process was started with are closed first.
pub(crate) fn enter() {
    REPORT.get_or_init(|| {
        close_inherited();
        let report = Isolation::enter_with(OPTIONS);
        INHERITED_CLOSED.store(only_standard_streams(), Ordering::Relaxed);
        report
    });
}

/// Whether secret-protection-core's census of the process finds no descriptor open beyond standard
/// input, output and error and no shared memory it can write: the check to make after isolation,
/// as no new channel can open then. Windows offers no census.
fn only_standard_streams() -> bool {
    secret_protection_core::open_channels().is_ok_and(|channels| channels.only(&[0, 1, 2]).is_ok())
}

/// Closes every descriptor above standard input, output and error: one the starting program left
/// open, such as a socket, a pipe or a file open for writing, would stay a way out of isolation.
/// The tool holds none of its own at this point. [`only_standard_streams`] then checks what is
/// left. Windows hands a program only the handles its parent marked for it, and it is not told
/// which.
fn close_inherited() {
    #[cfg(target_os = "linux")]
    // SAFETY: close_range takes integers and closes descriptors only, none of which this process
    // uses: it has one thread and holds no file at this point.
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
        return;
    }
    #[cfg(unix)]
    {
        // Where close_range is missing, every number up to the limit on open descriptors.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct, which lives for the call.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            let top = libc::c_int::try_from(limit.rlim_cur.min(1 << 20)).unwrap_or(0);
            for descriptor in 3..top {
                // SAFETY: close takes an integer; the same holds as for close_range above.
                unsafe { libc::close(descriptor) };
            }
        }
    }
}

/// What holds against a secret leaving the process, as [`enter`] read it back; before it, nothing.
pub(crate) fn report() -> Isolation {
    REPORT.get().copied().unwrap_or_default()
}

/// Stands in for [`enter`] in a test, where the real one would limit every other test of the
/// process for good: it reports what the checks ask for, so that a whole set of them can pass.
#[cfg(test)]
pub(crate) fn inject_report() {
    let mut report = Isolation::default();
    report.no_core_dumps = true;
    report.no_memory_reading = true;
    report.no_new_sockets = true;
    report.whole_process = true;
    report.file_locks_refused = true;
    report.sendmsg_refused = true;
    report.signals_to_self_only = true;
    report.dynamic_code_refused = true;
    report.microsoft_signed_only = true;
    INHERITED_CLOSED.store(true, Ordering::Relaxed);
    REPORT.get_or_init(|| report);
}

/// Ctrl+\ (SIGQUIT) and Ctrl+Z (SIGTSTP) interrupt the tool as Ctrl+C does, so that its handler
/// (terminal::stop_on_ctrl_c) restores the terminal and leaves a private screen: by default the
/// first would end the tool and the second stop it with a secret still on the screen
/// (AUD-015-SEC004). A handler, unlike an ignored signal, is reset for a program the tool starts,
/// such as the browser of `mhfe serve`. Returns whether both handlers read back as set, as every
/// protection is read back before it is relied on.
pub(crate) fn interrupt_on_quit_and_suspend() -> bool {
    #[cfg(not(unix))]
    {
        true
    }
    #[cfg(unix)]
    {
        extern "C" fn interrupt(_signal: libc::c_int) {
            // SAFETY: raise is async-signal-safe (POSIX.1-2008, 2.4.3); the handler of SIGINT
            // (on_stop_signals) only writes to the pipe its thread waits on.
            unsafe { libc::raise(libc::SIGINT) };
        }
        handle(&[libc::SIGQUIT, libc::SIGTSTP], interrupt)
    }
}

/// The write end of the pipe of [`on_stop_signals`], -1 before it is made.
#[cfg(unix)]
static STOP_PIPE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Runs `stop` on a thread of its own each time SIGINT (Ctrl+C), SIGTERM or SIGHUP (a closed
/// terminal) arrives, also inside an Argon2 round. The signal handler only writes one byte to a
/// pipe, which is async-signal-safe (POSIX.1-2008, 2.4.3); the thread that reads it may do what
/// `stop` needs, such as restoring the terminal and ending the tool. The thread is started after
/// [`enter`], so it inherits the isolation. Returns whether the pipe, the thread and every handler
/// are in place.
#[cfg(unix)]
pub(crate) fn on_stop_signals(stop: impl Fn() + Send + 'static) -> bool {
    use std::sync::atomic::Ordering;
    extern "C" fn write_byte(_signal: libc::c_int) {
        let byte = 0u8;
        // SAFETY: write is async-signal-safe and reads one byte of this frame; a full pipe or a
        // closed one refuses it without blocking, and a stop is then on its way already.
        unsafe {
            libc::write(
                STOP_PIPE.load(Ordering::Relaxed),
                (&raw const byte).cast(),
                1,
            )
        };
    }
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: pipe writes two descriptors into the array, which lives for the call.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return false;
    }
    let [read_end, write_end] = ends;
    // SAFETY: fcntl takes integers, and both descriptors are this process's own. A program the
    // tool starts, such as the browser of `mhfe serve`, gets neither, and a write never blocks.
    let flags_set = unsafe {
        libc::fcntl(read_end, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::fcntl(write_end, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::fcntl(write_end, libc::F_SETFL, libc::O_NONBLOCK) == 0
    };
    STOP_PIPE.store(write_end, Ordering::Relaxed);
    let reader = std::thread::Builder::new()
        .name("stop".to_owned())
        .spawn(move || {
            let mut byte = 0u8;
            loop {
                // SAFETY: read writes at most one byte into `byte`, which lives for the call.
                match unsafe { libc::read(read_end, (&raw mut byte).cast(), 1) } {
                    1 => stop(),
                    -1 if std::io::Error::last_os_error().kind()
                        == std::io::ErrorKind::Interrupted => {}
                    _ => return,
                }
            }
        });
    flags_set && reader.is_ok() && handle(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], write_byte)
}

/// Sets `handler` for each of `signals`, restarting the calls it interrupts, and returns whether
/// every one reads back as set, as every protection is read back before it is relied on.
#[cfg(unix)]
fn handle(signals: &[libc::c_int], handler: extern "C" fn(libc::c_int)) -> bool {
    let handler = handler as libc::sighandler_t;
    let mut set = true;
    for &signal in signals {
        // SAFETY: a zeroed sigaction is a valid empty one; every field set below is a plain value,
        // and sigaction reads the first structure and writes the second only during the call.
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

/// Waits until `process`, a child of this one, has ended, and leaves it to be reaped by
/// [`std::process::Child::wait`]: until then its number stays its own, so that
/// [`pass_on_termination`] cannot reach another process that took that number. Windows passes
/// nothing on.
pub(crate) fn wait_unreaped(process: u32) {
    #[cfg(unix)]
    loop {
        // SAFETY: a zeroed siginfo_t is a valid one to write into; waitid takes integers and writes
        // that struct, which lives for the call. WNOWAIT leaves the child to be reaped.
        let waited = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                libc::id_t::from(process),
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if waited == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            break;
        }
    }
    #[cfg(not(unix))]
    let _ = process;
}

/// Passes on to `process`, a command of the start menu, a request to end that reached the menu
/// alone, as SIGTERM does. A console's events reach every process on it, so Windows needs nothing.
pub(crate) fn pass_on_termination(process: u32) {
    #[cfg(unix)]
    // SAFETY: kill takes integers and touches no memory of this process.
    unsafe {
        libc::kill(process as libc::pid_t, libc::SIGTERM);
        // A command that Ctrl+Z stopped before it set its handlers takes the signal only once it
        // runs, and the menu would wait for it for ever: a wait does not see a stop.
        libc::kill(process as libc::pid_t, libc::SIGCONT);
    }
    #[cfg(not(unix))]
    let _ = process;
}

/// The identifier of [`CoreDumpCheck`] in a self-check report.
pub(crate) const CORE_DUMPS_ID: &str = "core-dumps";

/// The `core-dumps` check: a crash writes no core dump of this process, as [`enter`] read it back.
pub(crate) struct CoreDumpCheck;

impl CoreDumpCheck {
    /// Failed when a crash could write memory, secrets included, to a disk. Windows has no such
    /// setting: its error reports hold the threads' stacks and registers in any case, and isolation
    /// asks them to leave out the heap, which Windows does not let it read back, so the check says
    /// so and never stops a command there.
    fn outcome(no_core_dumps: bool) -> ComponentOutcome {
        match (cfg!(windows), no_core_dumps) {
            (true, _) => ComponentOutcome::NotAvailable(
                "error reports hold the stacks, and the heap unless Windows leaves it out"
                    .to_owned(),
            ),
            (false, true) => ComponentOutcome::Passed,
            (false, false) => ComponentOutcome::Failed("the kernel still allows them".to_owned()),
        }
    }
}

impl ComponentCheck for CoreDumpCheck {
    fn id(&self) -> &'static str {
        CORE_DUMPS_ID
    }

    fn label(&self) -> &'static str {
        "Core dumps"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        Self::outcome(report().no_core_dumps)
    }
}

/// The identifier of [`IsolationCheck`] in a self-check report.
pub(crate) const ISOLATION_ID: &str = "isolation";

/// The `isolation` check: whether [`enter`] kept other programs out of the memory of this process,
/// closed the network, refused file writes, covered every thread, on Unix closed the descriptors
/// the process was started with, and refused what [`OPTIONS`] asks for on this system. Memory that
/// other programs could read fails it, and
/// the command stops before it reads a secret: every secret would be theirs. The rest is not a
/// failure: the summary of a command warns of what stays open, and the command goes on, as it must
/// on Windows, whose network only an administrator can close for a program.
pub(crate) struct IsolationCheck;

/// The detail of an [`IsolationCheck`] that failed.
pub(crate) const MEMORY_OPEN: &str = "other programs could read the memory";

impl IsolationCheck {
    fn outcome(isolation: Isolation, inherited_closed: bool) -> ComponentOutcome {
        if !isolation.no_memory_reading {
            return ComponentOutcome::Failed(MEMORY_OPEN.to_owned());
        }
        let gaps: Vec<&str> = [
            (
                isolation.no_new_sockets || isolation.empty_network,
                "the network stays open",
            ),
            (isolation.no_file_changes, "file writes stay open"),
            (
                isolation.whole_process,
                "threads started before it are left out",
            ),
            (
                !cfg!(unix) || inherited_closed,
                "files and connections it was started with stay open",
            ),
            // What OPTIONS asks for on this system and did not get.
            (
                !cfg!(target_os = "linux") || isolation.file_locks_refused,
                "file locks stay open",
            ),
            (
                !cfg!(target_os = "linux") || isolation.sendmsg_refused,
                "sendmsg stays open",
            ),
            (
                !cfg!(target_os = "linux") || isolation.signals_to_self_only,
                "signals to other programs stay open",
            ),
            (
                !cfg!(windows) || isolation.dynamic_code_refused,
                "new executable code stays allowed",
            ),
            (
                !cfg!(windows) || isolation.microsoft_signed_only,
                "DLLs that Microsoft did not sign may still load",
            ),
        ]
        .into_iter()
        .filter_map(|(holds, gap)| (!holds).then_some(gap))
        .collect();
        if gaps.is_empty() {
            ComponentOutcome::Passed
        } else {
            ComponentOutcome::Warning(format!("weaker than needed: {}", gaps.join(", ")))
        }
    }
}

impl ComponentCheck for IsolationCheck {
    fn id(&self) -> &'static str {
        ISOLATION_ID
    }

    fn label(&self) -> &'static str {
        "Isolation"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        Self::outcome(report(), INHERITED_CLOSED.load(Ordering::Relaxed))
    }
}

/// The most memory this process may lock (RLIMIT_MEMLOCK), in bytes; `None` where it cannot be
/// read, has no limit, or this is not Unix.
pub(crate) fn lock_limit() -> Option<u64> {
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

/// A swap area through which memory could reach a disk unencrypted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SwapArea {
    /// The device or file, as /proc/swaps names it.
    pub name: String,
    /// False when it is surely unencrypted, true when MHFE cannot tell, as for a swap file on a
    /// file system whose device it cannot see.
    pub unknown: bool,
}

/// How a secret command stands towards swap on a disk, as its summary says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Swap {
    /// There is none.
    NotOnDisk,
    /// This process may use none, whatever swap the computer has.
    Forbidden,
    /// It could not be forbidden, but what reaches the disk is encrypted.
    Encrypted,
    /// The person chose to go on with swap that is not encrypted, or that nothing can tell of.
    Allowed,
}

static SWAP: OnceLock<Swap> = OnceLock::new();

/// [`keep_off_swap`]'s result; `None` where swap cannot be told, as outside Linux.
pub(crate) fn swap() -> Option<Swap> {
    SWAP.get().copied()
}

/// The program that asks the user's systemd for a scope.
#[cfg(unix)]
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
/// Its options for a scope whose processes may use no swap.
#[cfg(unix)]
const NO_SWAP_SCOPE: [&str; 6] = [
    "--user",
    "--scope",
    "--quiet",
    "-p",
    "MemorySwapMax=0",
    "--",
];
/// Set for the program started in that scope, so that a limit that did not hold does not start it
/// again and again.
#[cfg(unix)]
const IN_SCOPE: &str = "MHFE_IN_NO_SWAP_SCOPE";

/// Keeps a secret command's memory off the disk, on Linux, before it reads anything. Locking cannot
/// do it: the limit on locked memory is far below Argon2's work area, and a stack or a heap is not
/// locked. Where swap lies on a disk the program starts itself again in a scope without swap, as a
/// page written before such a limit could still leave. Where that cannot be done, encrypted swap
/// is accepted and any other is for the person to decide, which [`ask_about_swap`] asks after the
/// checks at start.
pub(crate) fn keep_off_swap() -> Result<(), Failure> {
    if cfg!(target_os = "linux") {
        let root = Path::new("/");
        let swap = if !swap_on_disk_under(root) {
            Swap::NotOnDisk
        } else if mhfe::engine::swap_forbidden() {
            Swap::Forbidden
        } else {
            restart_without_swap();
            let areas = unprotected_swap_under(root);
            if areas.is_empty() {
                Swap::Encrypted
            } else {
                // Asked after the checks at start, which may stop the command anyway.
                let _ = SWAP_TO_ASK.set(areas);
                return Ok(());
            }
        };
        // Set once: a process prepares one command.
        let _ = SWAP.set(swap);
    }
    Ok(())
}

/// Swap on a disk without encryption that [`keep_off_swap`] could not keep this process out of,
/// which [`ask_about_swap`] asks about.
static SWAP_TO_ASK: OnceLock<Vec<SwapArea>> = OnceLock::new();

/// Asks whether to go on with swap that could write memory to a disk without encryption, after
/// the checks at start have passed; nothing where [`keep_off_swap`] found none.
pub(crate) fn ask_about_swap() -> Result<(), Failure> {
    if let Some(areas) = SWAP_TO_ASK.get() {
        crate::settings::ask_about_swap(areas)?;
        let _ = SWAP.set(Swap::Allowed);
    }
    Ok(())
}

/// Starts this program again, with the same arguments and terminal, in a scope without swap.
/// Returns where that cannot be done: a first scope tries it, as the program is gone once
/// systemd-run has taken its place.
fn restart_without_swap() {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let scope = || {
            let mut command = Command::new(SYSTEMD_RUN);
            command.args(NO_SWAP_SCOPE);
            command
        };
        let works = std::env::var_os(IN_SCOPE).is_none()
            && scope()
                .arg("/bin/true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
        if let (true, Ok(program)) = (works, std::env::current_exe()) {
            // Comes back only if the start failed.
            let _ = scope()
                .arg(program)
                .args(std::env::args_os().skip(1))
                .env(IN_SCOPE, "1")
                .exec();
        }
    }
}

/// The areas of /proc/swaps under `root`, each with its kind; `None` when it cannot be read.
fn swap_lines(root: &Path) -> Option<Vec<(String, String)>> {
    let swaps = fs::read_to_string(root.join("proc/swaps")).ok()?;
    // "Filename Type Size Used Priority", one line per area after the heading; spaces in a name
    // are written as \040.
    Some(
        swaps
            .lines()
            .skip(1)
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                Some((
                    fields.next()?.replace("\\040", " "),
                    fields.next()?.to_owned(),
                ))
            })
            .collect(),
    )
}

/// Whether any swap can reach a disk, encrypted or not; an inventory that cannot be read counts.
fn swap_on_disk_under(root: &Path) -> bool {
    swap_lines(root).is_none_or(|areas| {
        areas.iter().any(|(name, _)| {
            let device = name.rsplit('/').next().unwrap_or_default();
            !stays_in_memory(root, device)
        })
    })
}

/// The swap areas under `root` that are not encrypted by dm-crypt, or whose encryption cannot be
/// told. An area in memory (zram) is safe.
fn unprotected_swap_under(root: &Path) -> Vec<SwapArea> {
    let Some(areas) = swap_lines(root) else {
        return vec![SwapArea {
            name: "/proc/swaps".to_owned(),
            unknown: true,
        }];
    };
    areas
        .into_iter()
        .filter_map(|(name, kind)| {
            let device = match kind.as_str() {
                "partition" => device_of_node(root, &name),
                _ => device_of_file(root, &name),
            };
            match device {
                Some(device) if encrypted(root, &device, 0) => None,
                Some(_) => Some(SwapArea {
                    name,
                    unknown: false,
                }),
                None => Some(SwapArea {
                    name,
                    unknown: true,
                }),
            }
        })
        .collect()
}

/// Whether `device` is a zram device that writes back to no disk.
fn stays_in_memory(root: &Path, device: &str) -> bool {
    let folder = root.join("sys/block").join(device);
    device.starts_with("zram")
        && folder.is_dir()
        && fs::read_to_string(folder.join("backing_dev"))
            .map_or(true, |backing| backing.trim() == "none")
}

/// The kernel's name of the block device at a path such as /dev/sda2 or /dev/mapper/swap.
fn device_of_node(root: &Path, node: &str) -> Option<String> {
    let path = root.join(node.trim_start_matches('/'));
    let resolved = fs::canonicalize(path).ok()?;
    Some(resolved.file_name()?.to_string_lossy().into_owned())
}

/// The kernel's name of the block device that holds a swap file. /sys/dev/block is Linux's, and
/// so is the type of the device number that libc::major and libc::minor take.
fn device_of_file(root: &Path, file: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let device = fs::metadata(root.join(file.trim_start_matches('/')))
            .ok()?
            .dev();
        let (major, minor) = (libc::major(device), libc::minor(device));
        let link = root.join(format!("sys/dev/block/{major}:{minor}"));
        let resolved = fs::canonicalize(link).ok()?;
        Some(resolved.file_name()?.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, file);
        None
    }
}

/// Deepest stack of devices followed: LUKS under LVM under RAID is three.
const MAX_DEVICE_DEPTH: usize = 8;

/// Whether a block device is encrypted with dm-crypt, directly or through the devices it is
/// built on (LVM on LUKS), or lies in memory (zram).
fn encrypted(root: &Path, device: &str, depth: usize) -> bool {
    if stays_in_memory(root, device) {
        return true;
    }
    let sysfs = root.join("sys/class/block").join(device);
    // dm-crypt gives its devices a UUID starting with CRYPT-; dm-integrity uses it too, and
    // encrypts nothing.
    if let Ok(uuid) = fs::read_to_string(sysfs.join("dm/uuid")) {
        if uuid.starts_with("CRYPT-") && !uuid.starts_with("CRYPT-INTEGRITY-") {
            return true;
        }
    }
    if depth >= MAX_DEVICE_DEPTH {
        return false;
    }
    let below: Vec<PathBuf> = fs::read_dir(sysfs.join("slaves"))
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    // A device built on others is encrypted only if all of them are.
    !below.is_empty()
        && below.iter().all(|path| {
            path.file_name()
                .is_some_and(|name| encrypted(root, &name.to_string_lossy(), depth + 1))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A made-up /proc and /sys in a fresh temporary folder.
    struct FakeSystem(PathBuf);

    impl FakeSystem {
        fn new(swaps: &str) -> Self {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "mhfe-swap-test-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::SeqCst)
            ));
            // A new folder: one that another program made in its place is refused.
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(root.join("proc")).unwrap();
            fs::create_dir_all(root.join("dev/mapper")).unwrap();
            fs::write(
                root.join("proc/swaps"),
                format!("Filename\tType\tSize\tUsed\tPriority\n{swaps}"),
            )
            .unwrap();
            Self(root)
        }

        /// A zram device, with what it writes back to, where it says.
        fn memory_device(&self, name: &str, backing: Option<&str>) {
            self.device(name, None, &[]);
            let folder = self.0.join("sys/block").join(name);
            fs::create_dir_all(&folder).unwrap();
            if let Some(backing) = backing {
                fs::write(folder.join("backing_dev"), backing).unwrap();
            }
        }

        /// A block device, with a dm UUID and the devices it is built on.
        fn device(&self, name: &str, uuid: Option<&str>, below: &[&str]) {
            let sysfs = self.0.join("sys/class/block").join(name);
            fs::create_dir_all(sysfs.join("slaves")).unwrap();
            if let Some(uuid) = uuid {
                fs::create_dir_all(sysfs.join("dm")).unwrap();
                fs::write(sysfs.join("dm/uuid"), uuid).unwrap();
            }
            for lower in below {
                fs::create_dir_all(sysfs.join("slaves").join(lower)).unwrap();
            }
            fs::write(self.0.join("dev").join(name), "").unwrap();
        }

        fn unprotected(&self) -> Vec<SwapArea> {
            unprotected_swap_under(&self.0)
        }
    }

    impl Drop for FakeSystem {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_plain_partition_is_unprotected() {
        let system = FakeSystem::new("/dev/sda2 partition 1024 0 -2\n");
        system.device("sda2", None, &[]);
        assert_eq!(
            system.unprotected(),
            [SwapArea {
                name: "/dev/sda2".into(),
                unknown: false
            }]
        );
    }

    #[test]
    fn dm_crypt_and_zram_are_protected() {
        let system = FakeSystem::new(
            "/dev/dm-0 partition 1024 0 -2\n/dev/dm-2 partition 1024 0 -3\n/dev/zram0 partition 1024 0 100\n",
        );
        system.device("dm-0", Some("CRYPT-PLAIN-swap"), &["sda3"]);
        // LVM on LUKS: the logical volume is built on the encrypted device.
        system.device("dm-1", Some("CRYPT-LUKS2-abc-root"), &["nvme0n1p2"]);
        system.device("dm-2", Some("LVM-xyz"), &["dm-1"]);
        system.memory_device("zram0", None);
        assert_eq!(system.unprotected(), []);
    }

    #[test]
    fn swap_in_memory_is_not_on_a_disk() {
        let system = FakeSystem::new("/dev/zram0 partition 1024 0 -2\n");
        system.memory_device("zram0", Some("none\n"));
        assert!(!swap_on_disk_under(&system.0));
        assert_eq!(system.unprotected(), []);
        // Encrypted swap is on a disk all the same, and an empty list means no swap.
        let system = FakeSystem::new("/dev/dm-0 partition 1024 0 -2\n");
        system.device("dm-0", Some("CRYPT-PLAIN-swap"), &["sda3"]);
        assert!(swap_on_disk_under(&system.0));
        assert!(!swap_on_disk_under(&FakeSystem::new("").0));
    }

    #[test]
    fn zram_that_writes_back_to_a_disk_is_unprotected() {
        let system = FakeSystem::new("/dev/zram0 partition 1024 0 -2\n");
        system.memory_device("zram0", Some("/dev/sda3\n"));
        assert!(swap_on_disk_under(&system.0));
        assert_eq!(system.unprotected().len(), 1);
    }

    #[test]
    fn dm_integrity_encrypts_nothing() {
        let system = FakeSystem::new("/dev/dm-0 partition 1024 0 -2\n");
        system.device("dm-0", Some("CRYPT-INTEGRITY-swap"), &["sda3"]);
        system.device("sda3", None, &[]);
        assert_eq!(system.unprotected().len(), 1);
    }

    #[test]
    fn an_unreadable_inventory_counts_as_swap_nothing_can_tell_of() {
        let system = FakeSystem::new("");
        fs::remove_file(system.0.join("proc/swaps")).unwrap();
        assert!(swap_on_disk_under(&system.0));
        assert_eq!(
            system.unprotected(),
            [SwapArea {
                name: "/proc/swaps".to_owned(),
                unknown: true,
            }]
        );
    }

    #[test]
    fn lvm_without_encryption_is_unprotected() {
        let system = FakeSystem::new("/dev/dm-3 partition 1024 0 -2\n");
        system.device("dm-3", Some("LVM-xyz"), &["sdb1"]);
        system.device("sdb1", None, &[]);
        assert_eq!(system.unprotected().len(), 1);
    }

    #[test]
    fn a_file_whose_device_cannot_be_seen_is_unknown() {
        let system = FakeSystem::new("/swap\\040file file 1024 0 -2\n");
        assert_eq!(
            system.unprotected(),
            [SwapArea {
                name: "/swap file".into(),
                unknown: true
            }]
        );
    }

    #[test]
    fn no_swap_needs_no_warning() {
        assert_eq!(FakeSystem::new("").unprotected(), []);
    }

    /// Where core dumps can be turned off, a setting that reads back otherwise stops a command;
    /// Windows only says what its error reports hold.
    #[test]
    fn core_dumps_stop_a_command_only_where_they_can_be_turned_off() {
        let (off, on) = (CoreDumpCheck::outcome(true), CoreDumpCheck::outcome(false));
        if cfg!(windows) {
            assert_eq!(off.name(), "notAvailable");
            assert_eq!(on.name(), "notAvailable");
        } else {
            assert_eq!(off, ComponentOutcome::Passed);
            assert!(on.is_failure());
        }
    }

    /// A command of the menu that has ended keeps its number until it is reaped, so a stop passed
    /// on meanwhile cannot reach another process that took the number.
    #[cfg(unix)]
    #[test]
    fn an_ended_command_keeps_its_number_until_it_is_reaped() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        wait_unreaped(child.id());
        // SAFETY: as in wait_unreaped; WNOHANG returns at once, and si_pid reads the struct
        // waitid wrote, 0 for a child that has not ended.
        let ended_unreaped = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                libc::id_t::from(child.id()),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == 0
                && info.si_pid() == child.id() as libc::pid_t
        };
        assert!(ended_unreaped, "the command has ended and is not reaped");
        assert_eq!(child.wait().unwrap().code(), Some(7));
    }

    /// What the system refused is named in a warning, and the command goes on.
    #[test]
    fn the_isolation_check_warns_of_what_stays_open() {
        let warning = |gaps: &str| ComponentOutcome::Warning(format!("weaker than needed: {gaps}"));
        let outcome = |isolation| IsolationCheck::outcome(isolation, true);
        let mut isolation = Isolation::default();
        isolation.no_file_changes = true;
        isolation.whole_process = true;
        isolation.file_locks_refused = true;
        isolation.sendmsg_refused = true;
        isolation.signals_to_self_only = true;
        isolation.dynamic_code_refused = true;
        isolation.microsoft_signed_only = true;
        // Memory that other programs could read stops the command, whatever else holds.
        assert_eq!(
            outcome(isolation),
            ComponentOutcome::Failed(MEMORY_OPEN.to_owned())
        );
        isolation.no_memory_reading = true;
        assert_eq!(outcome(isolation), warning("the network stays open"));
        isolation.no_new_sockets = true;
        assert_eq!(outcome(isolation), ComponentOutcome::Passed);
        isolation.no_new_sockets = false;
        isolation.empty_network = true;
        assert_eq!(outcome(isolation), ComponentOutcome::Passed);
        isolation.no_file_changes = false;
        assert_eq!(outcome(isolation), warning("file writes stay open"));
        isolation.no_file_changes = true;
        // Protections of the calling thread alone leave out the threads that ran before it.
        isolation.whole_process = false;
        assert_eq!(
            outcome(isolation),
            warning("threads started before it are left out")
        );
        isolation.whole_process = true;
        assert_eq!(
            IsolationCheck::outcome(isolation, false),
            if cfg!(unix) {
                warning("files and connections it was started with stay open")
            } else {
                ComponentOutcome::Passed
            }
        );
        // An option asked for on this system that did not take effect is named.
        isolation.file_locks_refused = false;
        isolation.dynamic_code_refused = false;
        let expected = if cfg!(target_os = "linux") {
            warning("file locks stay open")
        } else if cfg!(windows) {
            warning("new executable code stays allowed")
        } else {
            ComponentOutcome::Passed
        };
        assert_eq!(outcome(isolation), expected);
        isolation.no_memory_reading = false;
        assert_eq!(
            IsolationCheck::outcome(isolation, false),
            ComponentOutcome::Failed(MEMORY_OPEN.to_owned())
        );
    }

    /// Exit codes of the process that [`isolated_command`] ends, which the test passes on as the
    /// outcome. They are not 0 or 101, the codes of a test process that ran no isolated command.
    #[cfg(target_os = "linux")]
    mod isolated_child {
        pub(super) const ISOLATED: i32 = 40;
        pub(super) const NO_NAMESPACE: i32 = 41;
        pub(super) const CHECKS_FAILED: i32 = 42;
        pub(super) const LATE: i32 = 43;
        pub(super) const INHERITED_OPEN: i32 = 45;
        pub(super) const MEMORY_OPEN: i32 = 46;
        /// Set for the test process in which [`super::isolated_command`] runs.
        pub(super) const VARIABLE: &str = "MHFE_TEST_ISOLATED_CHILD";
    }

    /// A command started directly enters its empty network before the checks at start, whose
    /// Argon2 check runs four threads; a process with more than one thread could not enter it. The
    /// order of main is followed for `mhfe encrypt` in a process of a single thread, as a command
    /// has at that point: a new test process, in which [`isolated_command`] runs before the test
    /// harness has started a thread, so that nothing of another thread is copied (AUD-051-ARC002).
    /// A file the process holds open is closed before isolation. On a system that allows no user
    /// namespace only the order and the checks are verified.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_empty_network_is_entered_before_the_startup_checks_start_threads() {
        /// Longest wait: the checks at start take about a second in a debug build.
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(120);
        // A test name that none has: should isolated_command not end the process, it runs no test
        // and ends with 0.
        let mut process = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "protect::tests::no_test_has_this_name"])
            .env(isolated_child::VARIABLE, "1")
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
            Some(isolated_child::ISOLATED) => {}
            Some(isolated_child::NO_NAMESPACE) => {
                eprintln!("This system allows no user namespace: order and checks only.")
            }
            // In a container, as the reproducible build runs its tests, secret-protection-core
            // cannot confirm that other programs are kept out of the memory: the command stopped
            // before its first question, as it must, its inherited descriptor closed and its
            // isolation entered with one thread, as the process checks first.
            Some(isolated_child::MEMORY_OPEN) => {
                eprintln!(
                    "Other programs may read the memory here: the command stopped, as it must."
                )
            }
            Some(isolated_child::CHECKS_FAILED) => {
                panic!("the checks at start failed after isolation")
            }
            Some(isolated_child::LATE) => {
                panic!("the command entered isolation with more than one thread")
            }
            Some(isolated_child::INHERITED_OPEN) => {
                panic!("a descriptor the command was started with stayed open")
            }
            other => panic!("the test process ran no isolated command: {other:?}"),
        }
    }

    /// Runs [`isolated_command`] in every test process, before main: before the test harness has
    /// started a thread.
    #[cfg(target_os = "linux")]
    #[used]
    #[link_section = ".init_array"]
    static ISOLATED_COMMAND: extern "C" fn() = isolated_command;

    /// Only in the test process that [`the_empty_network_is_entered_before_the_startup_checks_start_threads`]
    /// starts: follows main for `mhfe encrypt` up to its first question, in a process of a single
    /// thread, and ends the process with an exit code of [`isolated_child`]. Every other test
    /// process goes on at once.
    #[cfg(target_os = "linux")]
    extern "C" fn isolated_command() {
        use clap::Parser;
        use std::os::fd::IntoRawFd;
        if std::env::var_os(isolated_child::VARIABLE).is_none() {
            return;
        }
        let command = crate::Cli::try_parse_from(["mhfe", "encrypt"])
            .unwrap()
            .command;
        // Open as a descriptor from the starting program would be: a file nothing else opens, so
        // that a descriptor that later takes the same number is told apart. Only its number is
        // kept, owned by nothing, as the start closes it (AUD-051-ARC002).
        let inherited = fs::File::open(std::env::current_exe().unwrap())
            .unwrap()
            .into_raw_fd();
        let identity = |descriptor: libc::c_int| {
            // SAFETY: fstat writes into the zeroed stat it is given, which lives for the call.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat takes an integer and that stat.
            (unsafe { libc::fstat(descriptor, &mut stat) } == 0)
                .then_some((stat.st_dev, stat.st_ino))
        };
        let opened = identity(inherited);
        let prepared = crate::prepare(&command);
        let left_open = identity(inherited) == opened || !INHERITED_CLOSED.load(Ordering::Relaxed);
        // Isolation came before the checks at start, so the descriptors and the single thread
        // are checked whatever those decided, open memory included (AUD-050-ARC002).
        let code = if left_open {
            isolated_child::INHERITED_OPEN
        } else if !report().whole_process {
            isolated_child::LATE
        } else if prepared.is_err() && !report().no_memory_reading {
            isolated_child::MEMORY_OPEN
        } else if prepared.is_err() {
            isolated_child::CHECKS_FAILED
        } else if report().empty_network {
            isolated_child::ISOLATED
        } else {
            isolated_child::NO_NAMESPACE
        };
        // SAFETY: ends the process at once, before the test harness has run anything.
        unsafe { libc::_exit(code) };
    }
}
