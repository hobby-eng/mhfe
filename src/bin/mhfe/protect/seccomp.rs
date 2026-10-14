//! A seccomp filter that refuses the creation of any socket with EACCES. Previously opened sockets
//! remain usable; Unix socket creation is refused too, which the tool does not use. It
//! refuses io_uring altogether as well: its operations, a socket among them since Linux 5.19
//! (IORING_OP_SOCKET), run inside the kernel without a system call of their own, so the filter
//! would never see them (AUD-008-SEC001). Nothing in the tool uses io_uring.

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
    let tests = [
        #[cfg(target_arch = "x86_64")]
        (libc::BPF_JGE, X32_SYSCALL_BIT),
        (libc::BPF_JEQ, libc::SYS_socket as u32),
        (libc::BPF_JEQ, libc::SYS_socketpair as u32),
        (libc::BPF_JEQ, libc::SYS_io_uring_setup as u32),
        (libc::BPF_JEQ, libc::SYS_io_uring_enter as u32),
        (libc::BPF_JEQ, libc::SYS_io_uring_register as u32),
    ];
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
