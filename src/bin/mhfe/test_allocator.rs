//! The test binary's allocator, which counts the blocks freed on a watching thread that still
//! hold [`WATCHED`]: a copy of a secret word that was not wiped (AUD-023-SEC001, AUD-024-SEC008).
//! The tests of hint rows and of list lines share it; it exists only in the test binary.

#![allow(
    unsafe_code,
    reason = "a global allocator is unsafe code by nature; it exists only in the test binary"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// An EFF word a hint row or a check-word answer shows, which no other test of this binary frees.
pub(crate) const WATCHED: &str = "zookeeper";

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    /// The blocks counted on this thread.
    static UNWIPED: Cell<usize> = const { Cell::new(0) };
}

/// The blocks that `work` freed on the calling thread and that still held [`WATCHED`]. Other
/// threads' blocks are not counted, so tests may run at once.
pub(crate) fn unwiped_blocks(work: impl FnOnce()) -> usize {
    UNWIPED.with(|unwiped| unwiped.set(0));
    WATCHING.with(|watching| watching.set(true));
    work();
    WATCHING.with(|watching| watching.set(false));
    UNWIPED.with(Cell::get)
}

struct Inspecting;

// SAFETY: every call is passed on to the system allocator unchanged; dealloc only reads the block
// it is given before it is freed.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout goes to the system allocator unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // try_with: a thread's last blocks may be freed after its thread-local values.
        if WATCHING.try_with(Cell::get).unwrap_or(false) {
            // SAFETY: the block is `layout.size()` bytes, allocated and not yet freed.
            let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
            let watched = WATCHED.as_bytes();
            if bytes.windows(watched.len()).any(|window| window == watched) {
                let _ = UNWIPED.try_with(|unwiped| unwiped.set(unwiped.get() + 1));
            }
        }
        // SAFETY: the block came from System.alloc with this layout and is freed once.
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;
