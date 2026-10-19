//! The test binary's allocator, which counts the blocks freed on a watching thread that still
//! hold [`WATCHED`]: a copy of a secret word that was not wiped (AUD-023-SEC001, AUD-024-SEC008).
//! The tests of hint rows and of list lines share it; it exists only in the test binary. The
//! operating system copies allocation storage into initialized scratch bytes before inspection;
//! Rust never interprets uninitialized padding or spare capacity as a byte slice.

#![allow(
    unsafe_code,
    reason = "a global allocator is unsafe code by nature; it exists only in the test binary"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, OnceCell};
use std::mem::size_of;

mod memory_reader;
use memory_reader::MemoryReader;

/// An EFF word a hint row or a check-word answer shows, which no other test of this binary frees.
pub(crate) const WATCHED: &str = "zookeeper";

/// Native byte encoding of public test indices, without unsafe views of typed storage.
pub(crate) const fn index_bytes<const BYTES: usize>(words: &[u16]) -> [u8; BYTES] {
    assert!(BYTES == std::mem::size_of_val(words));
    let mut bytes = [0; BYTES];
    let mut index = 0;
    while index < words.len() {
        let value = words[index].to_ne_bytes();
        bytes[index * size_of::<u16>()] = value[0];
        bytes[index * size_of::<u16>() + 1] = value[1];
        index += 1;
    }
    bytes
}

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static NEEDLE: Cell<&'static [u8]> = const { Cell::new(WATCHED.as_bytes()) };
    /// The blocks counted on this thread.
    static UNWIPED: Cell<usize> = const { Cell::new(0) };
    static UNREADABLE: Cell<usize> = const { Cell::new(0) };
    // Open before watching: initialization and resource cleanup never run in dealloc.
    static READER: OnceCell<MemoryReader> = const { OnceCell::new() };
}

struct Watching;

impl Drop for Watching {
    fn drop(&mut self) {
        WATCHING.with(|watching| watching.set(false));
    }
}

/// The blocks that `work` freed on the calling thread and that still held [`WATCHED`]. Other
/// threads' blocks are not counted, so tests may run at once.
pub(crate) fn unwiped_blocks(work: impl FnOnce()) -> usize {
    unwiped_matching(WATCHED.as_bytes(), work)
}

/// The same observer for a public, static word/index witness, without retaining caller secrets.
pub(crate) fn unwiped_matching(needle: &'static [u8], work: impl FnOnce()) -> usize {
    assert!(
        !WATCHING.with(Cell::get),
        "a probe cannot nest another probe"
    );
    READER.with(|reader| {
        reader.get_or_init(|| MemoryReader::open().expect("open the test memory reader"));
    });
    assert!(!needle.is_empty());
    NEEDLE.with(|selected| selected.set(needle));
    UNWIPED.with(|unwiped| unwiped.set(0));
    UNREADABLE.with(|unreadable| unreadable.set(0));
    WATCHING.with(|watching| watching.set(true));
    let watching = Watching;
    work();
    drop(watching);
    assert_eq!(UNREADABLE.with(Cell::get), 0, "a test memory read failed");
    UNWIPED.with(Cell::get)
}

struct Inspecting;

// SAFETY: every call is passed on to the system allocator unchanged. The OS copies each live
// block into initialized scratch bytes before System.dealloc; no Rust load reads its padding.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout goes to the system allocator unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // try_with: a thread's last blocks may be freed after its thread-local values.
        if WATCHING.try_with(Cell::get).unwrap_or(false) {
            let result = READER
                .try_with(|reader| {
                    let needle = NEEDLE.try_with(Cell::get).map_err(|_| ())?;
                    reader
                        .get()
                        .ok_or(())?
                        .contains(block as usize, layout.size(), needle)
                })
                .unwrap_or(Err(()));
            match result {
                Ok(true) => {
                    let _ =
                        UNWIPED.try_with(|unwiped| unwiped.set(unwiped.get().saturating_add(1)));
                }
                Ok(false) => {}
                Err(()) => {
                    let _ = UNREADABLE
                        .try_with(|unreadable| unreadable.set(unreadable.get().saturating_add(1)));
                }
            }
        }
        // SAFETY: the block came from System.alloc with this layout and is freed once.
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_probe_disables_the_watcher() {
        let result = std::panic::catch_unwind(|| {
            unwiped_blocks(|| panic!("synthetic probe failure"));
        });
        assert!(result.is_err());
        assert!(!WATCHING.with(Cell::get));
    }

    #[test]
    fn the_probe_finds_an_unwiped_word_and_accepts_a_wiped_word() {
        use zeroize::Zeroizing;
        assert_eq!(unwiped_blocks(|| drop(WATCHED.to_owned())), 1);
        assert_eq!(
            unwiped_blocks(|| drop(Zeroizing::new(WATCHED.to_owned()))),
            0
        );
    }

    #[test]
    fn the_probe_detects_and_wipes_a_binary_selection_witness() {
        const WORD_NUMBERS: &[u8] = &[8, 3, 19, 2, 91, 5, 117, 6, 20, 3, 11, 1];
        assert_eq!(
            unwiped_matching(WORD_NUMBERS, || drop(WORD_NUMBERS.to_vec())),
            1
        );
        assert_eq!(
            unwiped_matching(WORD_NUMBERS, || drop(zeroize::Zeroizing::new(
                WORD_NUMBERS.to_vec()
            ))),
            0
        );
        // The legacy entry point resets its witness after a differently configured probe.
        assert_eq!(unwiped_blocks(|| drop(WATCHED.to_owned())), 1);
    }

    #[test]
    fn the_probe_handles_spare_capacity_and_typed_padding() {
        #[repr(C)]
        struct Padded {
            tag: u8,
            word: [u8; WATCHED.len()],
            aligned: u64,
        }
        assert_eq!(
            unwiped_blocks(|| {
                let mut text = String::with_capacity(16_384);
                text.push_str(WATCHED);
                drop(text);
                drop(Box::new(Padded {
                    tag: 1,
                    word: *b"zookeeper",
                    aligned: 2,
                }));
            }),
            2
        );
    }

    #[test]
    fn a_full_unwiped_counter_does_not_panic_or_wrap() {
        READER.with(|reader| {
            reader.get_or_init(|| MemoryReader::open().unwrap());
        });
        let block = WATCHED.to_owned();
        UNWIPED.with(|count| count.set(usize::MAX));
        WATCHING.with(|watching| watching.set(true));
        let watching = Watching;
        drop(block);
        drop(watching);
        assert_eq!(UNWIPED.with(Cell::get), usize::MAX);
    }
}
