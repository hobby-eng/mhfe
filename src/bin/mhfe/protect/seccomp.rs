//! Two seccomp filters, each refusing its calls with EACCES. The socket filter refuses the creation
//! of any socket; previously opened sockets remain usable, and Unix socket creation is refused too,
//! which the tool does not use. It refuses io_uring altogether as well: its operations, a socket
//! among them since Linux 5.19 (IORING_OP_SOCKET), run inside the kernel without a system call of
//! their own, so the filter would never see them (AUD-008-SEC001). Nothing in the tool uses
//! io_uring. The file filter refuses the changes Landlock leaves to a file it cannot open for
//! writing: its mode, owner, extended attributes and times, and its truncation by path, which
//! Landlock refuses only from Linux 6.2 (AUD-024-SEC001). Descriptors already open for writing
//! stay usable, as with Landlock.

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

/// fchmodat2, setxattrat and removexattrat (Linux 6.6 and 6.13), which libc does not name for
/// every architecture; their numbers are the same on x86-64 and AArch64 (asm-generic/unistd.h and
/// arch/x86/entry/syscalls/syscall_64.tbl).
const SYS_FCHMODAT2: u32 = 452;
const SYS_SETXATTRAT: u32 = 463;
const SYS_REMOVEXATTRAT: u32 = 466;

/// The calls the socket filter refuses.
const SOCKET_CALLS: [libc::c_long; 5] = [
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// The calls the file filter refuses: they change a file's mode, owner, extended attributes or
/// times, or truncate it by path. x86-64 has the older calls besides the *at ones.
#[cfg(target_arch = "x86_64")]
const FILE_CHANGE_CALLS: [libc::c_long; 18] = [
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_lchown,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_utime,
    libc::SYS_utimes,
    libc::SYS_futimesat,
    libc::SYS_utimensat,
    libc::SYS_truncate,
];
#[cfg(target_arch = "aarch64")]
const FILE_CHANGE_CALLS: [libc::c_long; 12] = [
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_utimensat,
    libc::SYS_truncate,
];

/// Refuses socket creation and io_uring in the calling thread and the threads it starts afterwards.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn forbid_sockets() -> bool {
    install(&SOCKET_CALLS.map(|call| call as u32))
}

/// Refuses changes of a file's mode, owner, extended attributes and times, and truncation by path,
/// in the calling thread and the threads it starts afterwards.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn forbid_file_changes() -> bool {
    let named = FILE_CHANGE_CALLS.map(|call| call as u32);
    let calls: Vec<u32> = named
        .iter()
        .copied()
        .chain([SYS_FCHMODAT2, SYS_SETXATTRAT, SYS_REMOVEXATTRAT])
        .collect();
    install(&calls)
}

/// Installs a filter that refuses `calls` with EACCES, and every call of another ABI.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn install(calls: &[u32]) -> bool {
    let refuse = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;
    // Each test jumps forward to the final instruction, which refuses; `to_refusal` counts the
    // instructions between a test and it.
    let mut tests: Vec<(u32, u32)> = Vec::with_capacity(calls.len() + 1);
    #[cfg(target_arch = "x86_64")]
    tests.push((libc::BPF_JGE, X32_SYSCALL_BIT));
    tests.extend(calls.iter().map(|&call| (libc::BPF_JEQ, call)));
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn forbid_file_changes() -> bool {
    false
}
