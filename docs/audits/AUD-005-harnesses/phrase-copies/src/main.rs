//! AUD-005 probe for the phrase text that MHFE builds for its callers.
//!
//! A global allocator wraps the system allocator and, whenever a heap block is freed or moved by
//! a reallocation, looks for the beginning of a public BIP39 test phrase in the old bytes. A block
//! found there was released without being wiped, so a copy of the phrase stays in freed memory.
//! Only the public BIP39 test phrase "legal winner thank year ..." is used.
//!
//! Exit code 0: no unwiped copy left by `mhfe::read_phrase`; 1: at least one copy found.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The public 24-word test phrase of the BIP39 reference vectors, typed with short forms and in
/// upper case, as a person may type it.
const TYPED: &str = "LEGAL WINN THAN YEAR WAVE SAUS WORT USEF LEGAL WINN THAN YEAR \
                     WAVE SAUS WORT USEF LEGAL WINN THAN YEAR WAVE SAUS WORT TITL";
/// The beginning of the phrase as MHFE writes it out. Twelve bytes, so that a block holding only
/// a single typed word never matches.
const MARKER: &[u8] = b"legal winner";

static WATCHING: AtomicBool = AtomicBool::new(false);
static UNWIPED_COPIES: AtomicUsize = AtomicUsize::new(0);

struct Watching;

fn holds_marker(block: *const u8, size: usize) -> bool {
    // SAFETY: called only with a block the allocator handed out and that is still allocated.
    let bytes = unsafe { std::slice::from_raw_parts(block, size) };
    bytes.windows(MARKER.len()).any(|window| window == MARKER)
}

fn inspect(block: *const u8, size: usize) {
    if WATCHING.load(Ordering::SeqCst) && holds_marker(block, size) {
        UNWIPED_COPIES.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        inspect(block, layout.size());
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Always move, as an allocator may: the old block is then freed with its bytes.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let moved = unsafe { System.alloc(new_layout) };
        if !moved.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(block, moved, layout.size().min(new_size));
                self.dealloc(block, layout);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// Runs `action` and returns how many freed blocks still held the phrase.
fn copies_left_by(action: impl FnOnce()) -> usize {
    UNWIPED_COPIES.store(0, Ordering::SeqCst);
    WATCHING.store(true, Ordering::SeqCst);
    action();
    WATCHING.store(false, Ordering::SeqCst);
    UNWIPED_COPIES.load(Ordering::SeqCst)
}

fn main() {
    let read = copies_left_by(|| {
        let phrase = mhfe::read_phrase(TYPED).expect("the public test phrase is valid");
        assert!(phrase.starts_with("legal winner thank year"));
    });
    println!("mhfe::read_phrase: {read} freed heap blocks still held the phrase");

    // For information only: wallet derivation goes through the bip39 and pbkdf2 crates, whose
    // working buffers SECURITY.md already names as outside the crate's control.
    let phrase = mhfe::read_phrase(TYPED).expect("the public test phrase is valid");
    let wallet = copies_left_by(|| {
        mhfe::wallet::master_fingerprint(&phrase, "").expect("a public test wallet");
    });
    println!("mhfe::wallet::master_fingerprint (information only): {wallet}");

    if read > 0 {
        println!("FAIL: read_phrase left unwiped copies of the phrase in freed memory");
        std::process::exit(1);
    }
    println!("PASS: read_phrase left no unwiped copy of the phrase");
}
