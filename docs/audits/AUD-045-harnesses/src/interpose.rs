use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

// 11111 is the first EFF word, a public fixture, never a wallet secret.
const WORD: &[u8] = b"abacus";
const LEAVE: &[u8] = b"\x1b[?1049l";
const READY: &[u8] = b"AUD045_READY\n";
const LEFT: &[u8] = b"AUD045_LEAVE_WRITTEN\n";
const WAIT: Duration = Duration::from_secs(3);
static PHASE: AtomicU8 = AtomicU8::new(0);

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

fn wait_for(phase: u8) {
    let start = Instant::now();
    while PHASE.load(Ordering::SeqCst) < phase && start.elapsed() < WAIT {
        std::thread::sleep(Duration::from_millis(1));
    }
}

// This fixture is for x86-64 Linux, whose libc exposes SYS_write. Bypassing the interposed
// symbol avoids recursion; the same original descriptor, bytes and count reach the kernel.
unsafe fn real_write(fd: i32, bytes: *const u8, count: usize) -> isize {
    // SAFETY: the caller passes the original valid write buffer or READY's static bytes.
    unsafe { libc::syscall(libc::SYS_write, fd, bytes, count) as isize }
}

/// Schedules the main thread before its public fixture and the handler after leaving the screen.
///
/// # Safety
/// This targeted probe accepts the valid readable buffers the unmodified MHFE program writes.
#[unsafe(no_mangle)]
unsafe extern "C" fn write(fd: i32, bytes: *const libc::c_void, count: usize) -> isize {
    let bytes = bytes.cast::<u8>();
    if count == 0 || bytes.is_null() {
        // SAFETY: the syscall, rather than a Rust slice, handles an empty or null buffer.
        return unsafe { real_write(fd, bytes, count) };
    }
    // SAFETY: the program's write caller supplies a readable buffer for exactly count bytes.
    let text = unsafe { std::slice::from_raw_parts(bytes, count) };
    if fd == 1
        && contains(text, WORD)
        && PHASE
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        // SAFETY: READY is a live static byte slice. It contains no secret or terminal escape.
        unsafe { real_write(2, READY.as_ptr(), READY.len()) };
        wait_for(2);
        // SAFETY: this is the unchanged write that entered the interposer.
        let result = unsafe { real_write(fd, bytes, count) };
        PHASE.store(3, Ordering::SeqCst);
        return result;
    }
    if fd == 2 && contains(text, LEAVE) && PHASE.load(Ordering::SeqCst) == 1 {
        // SAFETY: this is the unchanged handler write that entered the interposer.
        let result = unsafe { real_write(fd, bytes, count) };
        // SAFETY: LEFT is a live static public marker; LEAVE above already reached the kernel.
        unsafe { real_write(2, LEFT.as_ptr(), LEFT.len()) };
        PHASE.store(2, Ordering::SeqCst);
        wait_for(3);
        return result;
    }
    // SAFETY: all other writes are forwarded unchanged.
    unsafe { real_write(fd, bytes, count) }
}
