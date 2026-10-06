//! AUD-008 allocation probe; uses public BIP39 reference entropy only.
//! The runner inserts exact formatter source bytes from the authoritative checkout.
use bip39::{Language, Mnemonic};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use zeroize::Zeroizing;

const MARKER: &[u8] = b"legal winner";
static WATCHING: AtomicBool = AtomicBool::new(false);
static COPIES: AtomicUsize = AtomicUsize::new(0);
struct Watching;
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::SeqCst) {
            // This reads an allocated block immediately before its allocator releases it.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.windows(MARKER.len()).any(|part| part == MARKER) {
                COPIES.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Moving is permitted behavior for a real allocator and exposes released old buffers.
        let moved =
            unsafe { System.alloc(Layout::from_size_align_unchecked(new_size, layout.align())) };
        if !moved.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, moved, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        moved
    }
}
#[global_allocator]
static ALLOCATOR: Watching = Watching;

fn unsafe_formatter(mnemonic: &Mnemonic) -> Zeroizing<String> {
    // SOURCE_EXPRESSION
}
const LONGEST_WORD: usize = 8;
// SOURCE_SAFE_FORMATTER
fn count(action: impl FnOnce()) -> usize {
    COPIES.store(0, Ordering::SeqCst);
    WATCHING.store(true, Ordering::SeqCst);
    action();
    WATCHING.store(false, Ordering::SeqCst);
    COPIES.load(Ordering::SeqCst)
}
fn main() {
    // BIP39 reference vector: 256 bits of 0x7f, beginning "legal winner".
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &[0x7f; 32]).unwrap();
    let current = count(|| {
        let phrase = unsafe_formatter(&mnemonic);
        assert!(phrase.starts_with("legal winner"));
    });
    let reserved = count(|| {
        let phrase = phrase_text(&mnemonic);
        assert!(phrase.starts_with("legal winner"));
    });
    println!("current_new_wallet_formatter_unwiped_freed_blocks={current}");
    println!("production_reserved_formatter_unwiped_freed_blocks={reserved}");
    if current > 0 || reserved != 0 {
        std::process::exit(1);
    }
}
