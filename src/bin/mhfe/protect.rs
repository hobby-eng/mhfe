//! What the tool does to keep secrets inside its own memory and itself offline:
//!
//! - no core dumps, and no reading of its memory by other programs of the same user;
//! - a warning when swap could write memory to a disk without encryption. Argon2's work area is far
//!   too large to keep out of swap (src/memory.rs), and from its blocks a password guess can be
//!   tested cheaply, so unencrypted swap matters;
//! - on Linux, a command that handles secrets cannot open a network socket (seccomp) or write to
//!   any file (Landlock): the kernel enforces that it stays offline, so not even a fault or a
//!   tampered dependency could send a secret away or leave it in a file. Both apply to the thread
//!   that runs the command and every thread it starts, such as Argon2's, and cannot be undone;
//! - on Linux, a command started directly also moves into a network namespace of its own, where no
//!   network interface exists: whatever way a socket were made, it would reach nothing. Where the
//!   system does not allow that, the command runs on with the two above.

// prctl, setrlimit and the Landlock calls are operating-system calls that Rust offers only through
// unsafe foreign functions.
#![allow(unsafe_code)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

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

thread_local! {
    /// Set by [`isolate`] for the thread it isolated, read by the summary of the command.
    static ISOLATION: Cell<Isolation> = const {
        Cell::new(Isolation { no_network: false, no_writes: false, empty_network: false })
    };
}

/// Forbids the calling thread, and every thread it starts afterwards, what `needs` does not
/// include, as far as the kernel allows: sockets through seccomp, writes to files through
/// Landlock (Linux 5.13 and later). Descriptors already open, including sockets, files and
/// terminals, stay usable. Returns
/// what is now enforced; elsewhere than on Linux nothing is.
pub fn isolate(needs: Needs) -> Isolation {
    let isolation = isolate_thread(needs);
    ISOLATION.with(|current| current.set(isolation));
    isolation
}

/// What [`isolate`] enforced for the calling thread.
pub fn isolation() -> Isolation {
    ISOLATION.with(Cell::get)
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

/// A seccomp filter that refuses the creation of any socket with EACCES. Previously opened sockets
/// remain usable; Unix socket creation is refused too, which the tool does not use. It
/// refuses io_uring altogether as well: its operations, a socket among them since Linux 5.19
/// (IORING_OP_SOCKET), run inside the kernel without a system call of their own, so the filter
/// would never see them (AUD-008-SEC001). Nothing in the tool uses io_uring.
#[cfg(target_os = "linux")]
mod seccomp {
    /// The architecture of the system calls the filter expects (AUDIT_ARCH_* in
    /// linux/audit.h); calls of any other ABI, such as 32-bit ones, are refused as well.
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7;
    /// x32 system calls on x86-64 carry this bit in their number (__X32_SYSCALL_BIT); refused.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    /// Offsets in `struct seccomp_data` (linux/seccomp.h): `int nr`, then `__u32 arch`.
    const NUMBER_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    fn load(offset: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    fn jump(condition: u32, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | condition | libc::BPF_K) as u16,
            jt,
            jf,
            k: value,
        }
    }

    fn ret(value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(super) fn forbid_sockets() -> bool {
        let refuse = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // Each test jumps forward to the final instruction, which refuses; `to_refusal` counts the
        // instructions between a test and it.
        let mut tests = vec![
            (libc::BPF_JEQ, libc::SYS_socket as u32),
            (libc::BPF_JEQ, libc::SYS_socketpair as u32),
            (libc::BPF_JEQ, libc::SYS_io_uring_setup as u32),
            (libc::BPF_JEQ, libc::SYS_io_uring_enter as u32),
            (libc::BPF_JEQ, libc::SYS_io_uring_register as u32),
        ];
        #[cfg(target_arch = "x86_64")]
        tests.insert(0, (libc::BPF_JGE, X32_SYSCALL_BIT));
        let mut program = vec![load(ARCH_OFFSET)];
        // Instructions after the architecture test: load, the tests, allow; then the refusal.
        let after_arch = 1 + tests.len() + 1;
        program.push(jump(libc::BPF_JEQ, ARCH, 0, after_arch as u8));
        program.push(load(NUMBER_OFFSET));
        for (position, &(condition, value)) in tests.iter().enumerate() {
            let to_refusal = (tests.len() - position) as u8;
            program.push(jump(condition, value, to_refusal, 0));
        }
        program.push(ret(libc::SECCOMP_RET_ALLOW));
        program.push(ret(refuse));
        let filter = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: the filter points to `len` instructions that live for the call; the kernel copies
        // them. It affects only the calling thread and the threads it starts afterwards.
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &filter as *const libc::sock_fprog,
                0,
                0,
            ) == 0
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub(super) fn forbid_sockets() -> bool {
        false
    }
}

/// A Landlock ruleset that handles every right to change the file system and grants none, so that
/// files cannot be opened for writing, created, renamed or removed; descriptors already open for
/// writing stay usable, and reading stays unrestricted. On Linux 6.7
/// and later it also refuses TCP bind and connect, besides seccomp.
#[cfg(target_os = "linux")]
mod landlock {
    use std::mem::size_of;
    use std::ptr;

    /// `struct landlock_ruleset_attr` of linux/landlock.h; ABI 1 to 3 know only its first field.
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    /// LANDLOCK_CREATE_RULESET_VERSION: asks for the ABI version instead of creating a ruleset.
    const CREATE_RULESET_VERSION: u32 = 1;
    /// The rights of linux/landlock.h that change the file system, by the ABI that added them.
    const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13; // ABI 2
    const TRUNCATE: u64 = 1 << 14; // ABI 3
    const BIND_TCP: u64 = 1 << 0; // ABI 4, network rights
    const CONNECT_TCP: u64 = 1 << 1;

    pub(super) fn forbid_writes(also_tcp: bool) -> bool {
        // SAFETY: with a null attribute and the version flag the call only returns a number.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        if abi < 1 {
            // No Landlock in this kernel, or it is switched off.
            return false;
        }
        let mut handled_fs = WRITE_FILE
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        if abi >= 2 {
            handled_fs |= REFER;
        }
        if abi >= 3 {
            handled_fs |= TRUNCATE;
        }
        let with_network = abi >= 4;
        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: if with_network && also_tcp {
                BIND_TCP | CONNECT_TCP
            } else {
                0
            },
        };
        let size = if with_network {
            size_of::<RulesetAttr>()
        } else {
            size_of::<u64>()
        };
        // SAFETY: the attribute lives for the call and `size` covers only the fields this ABI
        // knows; the kernel returns a new file descriptor or an error.
        let ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size,
                0u32,
            )
        };
        if ruleset < 0 {
            return false;
        }
        let ruleset = ruleset as libc::c_int;
        // No rule grants any of the handled rights: they are refused everywhere.
        // SAFETY: the descriptor came from the call above and is closed once.
        unsafe {
            let restricted = libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) == 0;
            libc::close(ruleset);
            restricted
        }
    }
}

/// A swap area through which memory could reach a disk unencrypted.
#[derive(Debug, PartialEq, Eq)]
pub struct SwapArea {
    /// The device or file, as /proc/swaps names it.
    pub name: String,
    /// False when it is surely unencrypted, true when MHFE cannot tell, as for a swap file on a
    /// file system whose device it cannot see.
    pub unknown: bool,
}

/// The swap areas that are not encrypted by dm-crypt, or whose encryption cannot be told. An
/// area in memory (zram) is safe. Empty when there is no swap or this is not Linux.
pub fn unprotected_swap() -> Vec<SwapArea> {
    if cfg!(target_os = "linux") {
        unprotected_swap_under(Path::new("/"))
    } else {
        // macOS encrypts its swap; Windows keeps its page file without telling.
        Vec::new()
    }
}

/// [`unprotected_swap`] with /proc and /sys under `root`, so that a test can supply its own.
fn unprotected_swap_under(root: &Path) -> Vec<SwapArea> {
    let Ok(swaps) = fs::read_to_string(root.join("proc/swaps")) else {
        return Vec::new();
    };
    // "Filename Type Size Used Priority", one line per area after the heading; spaces in a name
    // are written as \040.
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
    if device.starts_with("zram") {
        return true;
    }
    let sysfs = root.join("sys/class/block").join(device);
    // dm-crypt gives its devices a UUID starting with CRYPT-.
    if let Ok(uuid) = fs::read_to_string(sysfs.join("dm/uuid")) {
        if uuid.starts_with("CRYPT-") {
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
        system.device("zram0", None, &[]);
        assert_eq!(system.unprotected(), []);
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
    }
}
