//! A Landlock ruleset that handles every right to change the file system and grants none, so that
//! files cannot be opened for writing, created, renamed or removed; descriptors already open for
//! writing stay usable, and reading stays unrestricted. On Linux 6.7
//! and later it also refuses TCP bind and connect, besides seccomp.

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
