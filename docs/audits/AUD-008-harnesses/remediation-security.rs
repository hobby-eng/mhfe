//! Focused AUD-008 remediation checks; every password and entropy value is public synthetic data.
//! The runner inserts the current same-terminal predicate and includes production protect.rs.
use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "../../../src/bin/mhfe/protect.rs"]
mod protect;

const MARKER: &[u8] = b"legal winner";
const MAX_ENGLISH_WORD_BYTES: usize = 8;
static WATCHING: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);

struct WatchingAllocator;

unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::SeqCst) {
            // The allocation is still live here; inspect it before returning it to the allocator.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            if bytes.windows(MARKER.len()).any(|part| part == MARKER) {
                UNWIPED.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // A real allocator is allowed to move; force that case to expose released prefixes.
        let moved =
            unsafe { System.alloc(Layout::from_size_align_unchecked(size, layout.align())) };
        if !moved.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(pointer, moved, layout.size().min(size));
                self.dealloc(pointer, layout);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

fn watch(action: impl FnOnce()) -> usize {
    UNWIPED.store(0, Ordering::SeqCst);
    WATCHING.store(true, Ordering::SeqCst);
    action();
    WATCHING.store(false, Ordering::SeqCst);
    UNWIPED.load(Ordering::SeqCst)
}

fn formatter() {
    let mnemonic = bip39::Mnemonic::from_entropy(&[0x7f; 32]).unwrap();
    let historical_control = watch(|| {
        let text = zeroize::Zeroizing::new(mnemonic.to_string());
        assert!(text.starts_with("legal winner"));
    });
    assert!(
        historical_control > 0,
        "the allocator control did not detect released prefixes"
    );
    let current = watch(|| {
        let text = mhfe::phrase_from_entropy(&[0x7f; 32]).unwrap();
        assert!(text.starts_with("legal winner"));
        assert_eq!(text.capacity(), 24 * (MAX_ENGLISH_WORD_BYTES + 1));
    });
    assert_eq!(
        current, 0,
        "the current formatter released mnemonic prefixes without wiping"
    );
    println!("SEC002 historical_control_unwiped={historical_control} current_unwiped={current}");
}

fn page_locked(address: usize) -> bool {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut inside = false;
    for line in smaps.lines() {
        let range = line.split_once(' ').map_or(line, |(range, _)| range);
        if let Some((start, end)) = range.split_once('-') {
            if let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) {
                inside = (start..end).contains(&address);
                continue;
            }
        }
        if let (true, Some(flags)) = (inside, line.strip_prefix("VmFlags:")) {
            return flags.split_whitespace().any(|flag| flag == "lo");
        }
    }
    false
}

fn retention() {
    const COUNT: usize = 16;
    let public_password = "P".repeat(mhfe::MAX_PASSWORD_BYTES);
    let mut used: Vec<mhfe::Password> = Vec::new();
    for _ in 0..COUNT {
        let password = mhfe::Password::new(&public_password).unwrap();
        let address = password.as_bytes().as_ptr() as usize;
        if !page_locked(address) {
            println!("BLOCKED: the operating system refused the Password memory lock");
            std::process::exit(77);
        }
        used.push(password);
        assert_eq!(used.last().unwrap().as_bytes().as_ptr() as usize, address);
    }
    let locked = used
        .iter()
        .filter(|password| page_locked(password.as_bytes().as_ptr() as usize))
        .count();
    assert_eq!(locked, COUNT, "retained passwords lost their memory locks");
    assert!(used
        .iter()
        .all(|password| password.as_bytes() == public_password.as_bytes()));
    println!("SEC003 retained_password_pages_locked={locked}/{COUNT}; owned_buffers_moved_without_copy=true");
}

// SOURCE_SAME_TERMINAL

fn terminals() {
    let open = || {
        let (mut master, mut slave) = (0, 0);
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "could not open a synthetic pseudo-terminal");
        (master, slave)
    };
    let (first_master, first) = open();
    let (second_master, second) = open();
    let duplicate = unsafe { libc::dup(first) };
    assert!(duplicate >= 0);
    let null = std::fs::File::open("/dev/null").unwrap();
    assert!(same_terminal(first, duplicate));
    assert!(!same_terminal(first, second));
    assert!(!same_terminal(first, null.as_raw_fd()));
    assert!(!same_terminal(first, -1));
    for descriptor in [first_master, first, second_master, second, duplicate] {
        unsafe { libc::close(descriptor) };
    }
    println!("SEC004 exact_current_predicate: same_pty=true, different_pty=false, nonterminal=false, invalid_fd=false");
}

fn syscall_errors() -> [Option<i32>; 5] {
    let result = |call: &dyn Fn() -> libc::c_long| {
        let descriptor = call();
        if descriptor < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            unsafe { libc::close(descriptor as libc::c_int) };
            None
        }
    };
    let mut parameters = [0u8; 120]; // Linux struct io_uring_params is 120 bytes.
    let parameters = parameters.as_mut_ptr();
    let mut descriptors = [-1i32; 2];
    let descriptor_pointer = descriptors.as_mut_ptr();
    let socket =
        result(&|| unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) });
    let pair = unsafe {
        libc::syscall(
            libc::SYS_socketpair,
            libc::AF_UNIX,
            libc::SOCK_STREAM,
            0,
            descriptor_pointer,
        )
    };
    let pair_error = if pair < 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        for descriptor in descriptors {
            unsafe { libc::close(descriptor) };
        }
        None
    };
    [
        socket,
        pair_error,
        result(&|| unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, parameters) }),
        result(&|| unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                -1i32,
                0u32,
                0u32,
                0u32,
                std::ptr::null::<u8>(),
                0usize,
            )
        }),
        result(&|| unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                -1i32,
                0u32,
                std::ptr::null::<u8>(),
                0u32,
            )
        }),
    ]
}

fn isolation() {
    let namespace_before = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    let before = syscall_errors();
    println!("SEC001 before_isolation_errno={before:?}");
    if before.contains(&Some(libc::EACCES)) {
        println!(
            "BLOCKED: an enclosing filter already returns EACCES; cannot attribute denials to MHFE"
        );
        std::process::exit(77);
    }
    let applied = protect::isolate(protect::Needs::NOTHING);
    assert!(
        applied.no_network,
        "the production socket filter was not applied"
    );
    let namespace_after = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    assert_eq!(namespace_before != namespace_after, applied.empty_network);
    let after = syscall_errors();
    assert_eq!(after, [Some(libc::EACCES); 5]);
    const WORKERS: usize = 4;
    let together = std::sync::Barrier::new(WORKERS);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                scope.spawn(|| {
                    together.wait();
                    let namespace = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
                    assert_eq!(
                        namespace, namespace_after,
                        "a worker lost its network namespace"
                    );
                    assert_eq!(
                        syscall_errors(),
                        after,
                        "a worker did not inherit the filter"
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    println!("SEC001 production_isolation={applied:?}; after_errno={after:?}; workers_started_and_joined={WORKERS}; namespace_inheritance=true");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("formatter") => formatter(),
        Some("retention") => retention(),
        Some("terminals") => terminals(),
        Some("isolation") => isolation(),
        _ => panic!("choose formatter, retention, terminals or isolation"),
    }
}
