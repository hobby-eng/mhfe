//! What the tool does around mhfe-core's isolation, which keeps secrets inside this process and the
//! process offline:
//!
//! - [`enter`] applies that isolation and keeps what it read back, which [`CoreDumpCheck`] and
//!   [`IsolationCheck`] report as parts of the checks at start (startup.rs) and of `mhfe self-test`;
//! - Ctrl+\ and Ctrl+Z end the tool as Ctrl+C does, so that no key leaves a secret on the screen;
//! - a warning when swap could write memory to a disk without encryption. Argon2's work area is
//!   kept out of swap only where the limit on locked memory holds all of it (src/memory.rs), and
//!   from its blocks a password guess can be tested cheaply, so unencrypted swap matters.

#![allow(
    unsafe_code,
    reason = "sigaction, raise, kill and getrlimit are operating-system calls that Rust offers only \
              through unsafe foreign functions"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use mhfe::self_check::{ComponentCheck, ComponentOutcome, Tier};
use mhfe_core::protect::Isolation;

use crate::exit::Failure;

/// What [`enter`] read back; unset in a process that did not call it, such as the start menu.
static REPORT: OnceLock<Isolation> = OnceLock::new();

/// Applies what this system offers against a secret leaving the process, for good, and keeps what
/// reads back as holding. All of it takes a process of one thread (main.rs).
pub(crate) fn enter() {
    REPORT.get_or_init(Isolation::enter);
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
    /// setting: its error reports hold the threads' stacks and registers in any case and leave out
    /// the heap at best, so the check says which and never stops a command there.
    fn outcome(no_core_dumps: bool) -> ComponentOutcome {
        match (cfg!(windows), no_core_dumps) {
            (false, true) => ComponentOutcome::Passed,
            (false, false) => ComponentOutcome::Failed("the kernel still allows them".to_owned()),
            (true, true) => ComponentOutcome::NotAvailable(
                "error reports leave out the heap, not the stacks".to_owned(),
            ),
            (true, false) => ComponentOutcome::Warning("error reports hold the heap".to_owned()),
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

/// The `isolation` check: whether [`enter`] closed the network and kept other programs out of the
/// memory of this process. It is not a failure when it did not: the summary of a command warns of
/// what stays open, and the command goes on, as it must on Windows, whose network only an
/// administrator can close for a program.
pub(crate) struct IsolationCheck;

impl IsolationCheck {
    fn outcome(isolation: Isolation) -> ComponentOutcome {
        let gaps: Vec<&str> = [
            (
                isolation.no_new_sockets || isolation.empty_network,
                "the network stays open",
            ),
            (
                isolation.no_memory_reading,
                "other programs can read the memory",
            ),
            (
                !cfg!(target_os = "linux") || isolation.no_file_changes,
                "file writes stay open",
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
        Self::outcome(report())
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
/// is accepted and any other is for the person to decide.
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
                crate::settings::ask_about_swap(&areas)?;
                Swap::Allowed
            }
        };
        // Set once: a process prepares one command.
        let _ = SWAP.set(swap);
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
            assert_eq!(on.name(), "warning");
        } else {
            assert_eq!(off, ComponentOutcome::Passed);
            assert!(on.is_failure());
        }
    }

    /// What the system refused is named in a warning, and the command goes on.
    #[test]
    fn the_isolation_check_warns_of_what_stays_open() {
        let warning = |gaps: &str| ComponentOutcome::Warning(format!("weaker than needed: {gaps}"));
        let mut isolation = Isolation::default();
        isolation.no_file_changes = true;
        assert_eq!(
            IsolationCheck::outcome(isolation),
            warning("the network stays open, other programs can read the memory")
        );
        isolation.no_memory_reading = true;
        assert_eq!(
            IsolationCheck::outcome(isolation),
            warning("the network stays open")
        );
        isolation.no_new_sockets = true;
        assert_eq!(IsolationCheck::outcome(isolation), ComponentOutcome::Passed);
        isolation.no_new_sockets = false;
        isolation.empty_network = true;
        assert_eq!(IsolationCheck::outcome(isolation), ComponentOutcome::Passed);
        #[cfg(target_os = "linux")]
        {
            isolation.no_file_changes = false;
            assert_eq!(
                IsolationCheck::outcome(isolation),
                warning("file writes stay open")
            );
            isolation.no_file_changes = true;
        }
        isolation.no_memory_reading = false;
        assert_eq!(
            IsolationCheck::outcome(isolation),
            warning("other programs can read the memory")
        );
    }

    /// Exit codes of the process that [`isolated_command_runs_in_its_empty_network`] forks, which its test process passes
    /// on as its own. They are not 0 or 101, the codes of a test process that ran no such child.
    #[cfg(target_os = "linux")]
    mod isolated_child {
        pub(super) const ISOLATED: i32 = 40;
        pub(super) const NO_NAMESPACE: i32 = 41;
        pub(super) const CHECKS_FAILED: i32 = 42;
        pub(super) const LATE: i32 = 43;
        pub(super) const NO_CHILD: i32 = 44;
        /// Set for the test process that runs [`super::isolated_command_runs_in_its_empty_network`].
        pub(super) const VARIABLE: &str = "MHFE_TEST_ISOLATED_CHILD";
    }

    /// A command started directly enters its empty network before the checks at start, whose
    /// Argon2 check runs four threads; a process with more than one thread could not enter it. The
    /// order of main is followed for `mhfe encrypt` in a process of a single thread, as a command
    /// has at that point: forked off a test process of its own that runs nothing else, so that no
    /// other test holds a lock or a descriptor the fork would copy. On a system that allows no
    /// user namespace only the order and the checks are verified.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_empty_network_is_entered_before_the_startup_checks_start_threads() {
        /// Longest wait: the checks at start take about a second in a debug build.
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(120);
        let mut process = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "protect::tests::isolated_command_runs_in_its_empty_network",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
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
            Some(isolated_child::CHECKS_FAILED) => {
                panic!("the checks at start failed after isolation")
            }
            Some(isolated_child::LATE) => {
                panic!("the command entered isolation with more than one thread")
            }
            other => panic!("the test process ran no isolated command: {other:?}"),
        }
    }

    /// Run only by the test above, in a test process of its own: forks a child of a single thread
    /// that follows main for `mhfe encrypt` up to its first question, and ends with the child's
    /// exit code.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by the_empty_network_is_entered_before_the_startup_checks_start_threads"]
    fn isolated_command_runs_in_its_empty_network() {
        use clap::Parser;
        if std::env::var_os(isolated_child::VARIABLE).is_none() {
            return;
        }
        let command = crate::Cli::try_parse_from(["mhfe", "encrypt"])
            .unwrap()
            .command;
        // SAFETY: this test process runs no other test, so the child copies no lock that another
        // thread holds; it ends with _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let code = if crate::prepare(&command).is_err() {
                isolated_child::CHECKS_FAILED
            } else if !report().whole_process {
                isolated_child::LATE
            } else if report().empty_network {
                isolated_child::ISOLATED
            } else {
                isolated_child::NO_NAMESPACE
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
            isolated_child::NO_CHILD
        };
        std::process::exit(code);
    }
}
