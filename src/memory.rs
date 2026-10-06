//! Keeps the memory of a secret out of swap while it lives. An operating system may write any page
//! of a program to its swap space on disk, where it can outlast the program by years; a locked
//! page stays in memory (mlock on Unix). Locking is best effort: a refusal, such as a low
//! RLIMIT_MEMLOCK, leaves the secret as it was, and the browser and Windows builds lock nothing.
//! Argon2's work area is far too large to lock; the program warns instead when swap is not
//! encrypted.

/// The locked pages under a buffer, unlocked when this is dropped. The buffer must stay where it
/// is while this lives: lock only a buffer reserved at its final size, which never grows.
#[derive(Debug)]
pub struct LockedPages {
    /// The address of the buffer, kept as a number: it is only handed back to the kernel.
    start: usize,
    bytes: usize,
    locked: bool,
}

impl LockedPages {
    /// Locks the whole capacity of `buffer`, so that what is written into it later is covered too.
    pub fn of_vec(buffer: &Vec<u8>) -> Self {
        Self::lock(buffer.as_ptr(), buffer.capacity())
    }

    /// Locks the whole capacity of `text`.
    pub fn of_string(text: &String) -> Self {
        Self::lock(text.as_ptr(), text.capacity())
    }

    /// Whether the operating system keeps the pages in memory. They stay locked for as long as
    /// this lives, also when a guard of another buffer on the same page is dropped first.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    fn lock(start: *const u8, bytes: usize) -> Self {
        let start = start as usize;
        let locked = bytes > 0 && pages::hold(start, bytes);
        Self {
            start,
            bytes,
            locked,
        }
    }
}

impl Drop for LockedPages {
    fn drop(&mut self) {
        if self.locked {
            pages::release(self.start, self.bytes);
        }
    }
}

/// mlock and munlock act on whole pages and do not count: one munlock unlocks a page for every
/// buffer on it. Two small secrets often share a page, so a page is unlocked only once the last
/// guard that holds it is dropped.
#[cfg(not(target_arch = "wasm32"))]
mod pages {
    use std::collections::BTreeMap;
    use std::ops::RangeInclusive;
    use std::sync::{Mutex, PoisonError};

    use crate::engine::{lock_pages, page_size, unlock_pages};

    /// How many live guards hold each page, by page number (its address divided by the page
    /// size). Every mlock and munlock happens under this lock too, so that another thread never
    /// unlocks a page between an mlock and the count that records it.
    static HOLDERS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

    /// Locks the pages under `bytes` bytes at `start` and counts this guard as one of their
    /// holders. Returns whether the operating system agreed.
    pub(super) fn hold(start: usize, bytes: usize) -> bool {
        let Some(size) = page_size() else {
            return false;
        };
        // Nothing panics while the lock is held, so it is never poisoned; this only avoids an unwrap.
        let mut holders = HOLDERS.lock().unwrap_or_else(PoisonError::into_inner);
        if !lock_pages(start as *const u8, bytes) {
            // A refusal may still have locked some of the pages; those that no guard holds are
            // unlocked again, so that they are not kept in memory without an owner.
            for page in numbers(start, bytes, size) {
                if !holders.contains_key(&page) {
                    unlock_page(page, size);
                }
            }
            return false;
        }
        for page in numbers(start, bytes, size) {
            *holders.entry(page).or_insert(0) += 1;
        }
        true
    }

    /// Undoes [`hold`]: a page is unlocked when no other guard holds it any more.
    pub(super) fn release(start: usize, bytes: usize) {
        let Some(size) = page_size() else {
            return;
        };
        let mut holders = HOLDERS.lock().unwrap_or_else(PoisonError::into_inner);
        for page in numbers(start, bytes, size) {
            let Some(count) = holders.get_mut(&page) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                holders.remove(&page);
                unlock_page(page, size);
            }
        }
    }

    /// The numbers of the pages under `bytes` bytes at `start`; `bytes` is not zero.
    fn numbers(start: usize, bytes: usize, size: usize) -> RangeInclusive<usize> {
        start / size..=(start + bytes - 1) / size
    }

    fn unlock_page(page: usize, size: usize) {
        unlock_pages((page * size) as *const u8, size);
    }

    /// How many guards hold the page at `address`.
    #[cfg(test)]
    pub(super) fn holders_of(address: usize) -> usize {
        let size = page_size().expect("a Unix system reports its page size");
        let holders = HOLDERS.lock().unwrap_or_else(PoisonError::into_inner);
        holders.get(&(address / size)).copied().unwrap_or(0)
    }
}

/// The browser build has no mlock.
#[cfg(target_arch = "wasm32")]
mod pages {
    pub(super) fn hold(_start: usize, _bytes: usize) -> bool {
        false
    }

    pub(super) fn release(_start: usize, _bytes: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small buffer fits any usual RLIMIT_MEMLOCK (64 KiB or more) on Unix.
    #[test]
    fn a_small_buffer_is_locked_on_unix() {
        let buffer: Vec<u8> = Vec::with_capacity(1024);
        let pages = LockedPages::of_vec(&buffer);
        assert_eq!(pages.is_locked(), cfg!(unix));
        drop(pages);
        // An empty capacity locks nothing and unlocks nothing.
        assert!(!LockedPages::of_vec(&Vec::new()).is_locked());
    }

    /// Two secrets on one page, as the allocator often places small buffers: dropping the guard
    /// of one, in either order, must not unlock the other (AUD-007-SEC002). The page lies inside
    /// a buffer of this test alone, so no other test's guard can hold it too.
    #[cfg(unix)]
    #[test]
    fn a_shared_page_stays_locked_until_its_last_guard_is_dropped() {
        let size = crate::engine::page_size().expect("a Unix system reports its page size");
        let area: Vec<u8> = Vec::with_capacity(3 * size);
        let page = (area.as_ptr() as usize).next_multiple_of(size);
        let (first, second) = (page, page + size / 2);
        for first_dropped_first in [true, false] {
            let a = LockedPages::lock(first as *const u8, 64);
            let b = LockedPages::lock(second as *const u8, 64);
            if !(a.is_locked() && b.is_locked()) {
                // mlock refused here, such as with RLIMIT_MEMLOCK 0: nothing to count.
                return;
            }
            assert_eq!(pages::holders_of(page), 2);
            let remaining = if first_dropped_first {
                drop(a);
                b
            } else {
                drop(b);
                a
            };
            assert_eq!(pages::holders_of(page), 1);
            assert!(remaining.is_locked());
            #[cfg(target_os = "linux")]
            assert!(
                kernel_keeps_locked(page),
                "the page was unlocked under a live guard"
            );
            drop(remaining);
            assert_eq!(pages::holders_of(page), 0);
            #[cfg(target_os = "linux")]
            assert!(
                !kernel_keeps_locked(page),
                "the page stayed locked without a guard"
            );
        }
        drop(area);
    }

    /// A refused mlock, here of a page that is not mapped, holds nothing and leaves no count.
    /// Linux only: it refuses that page, while macOS accepts it, as the first pages lie in the
    /// range it reserves as __PAGEZERO, so there the lock would succeed and hold the page.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_lock_holds_nothing() {
        let size = crate::engine::page_size().expect("a Unix system reports its page size");
        // The first page above address zero, which no process maps.
        let unmapped = size;
        let refused = LockedPages::lock(unmapped as *const u8, 64);
        assert!(!refused.is_locked());
        assert_eq!(pages::holders_of(unmapped), 0);
        drop(refused);
        assert_eq!(pages::holders_of(unmapped), 0);
    }

    /// Guards on one page taken and dropped from several threads at once leave the counts exact:
    /// the page is held while any guard lives and unlocked once the last is gone.
    #[cfg(unix)]
    #[test]
    fn guards_on_one_page_from_several_threads_keep_exact_counts() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 500;
        let size = crate::engine::page_size().expect("a Unix system reports its page size");
        let area: Vec<u8> = Vec::with_capacity(3 * size);
        let page = (area.as_ptr() as usize).next_multiple_of(size);
        // Kept by this thread throughout, so the page must stay locked whatever the others do.
        let kept = LockedPages::lock(page as *const u8, 16);
        if !kept.is_locked() {
            // mlock refused here, such as with RLIMIT_MEMLOCK 0: nothing to count.
            return;
        }
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                scope.spawn(move || {
                    let offset = 64 * (thread + 1);
                    for _ in 0..ROUNDS {
                        let guard = LockedPages::lock((page + offset) as *const u8, 32);
                        assert!(guard.is_locked());
                    }
                });
            }
        });
        assert_eq!(pages::holders_of(page), 1);
        #[cfg(target_os = "linux")]
        assert!(
            kernel_keeps_locked(page),
            "the page was unlocked under a live guard"
        );
        drop(kept);
        assert_eq!(pages::holders_of(page), 0);
        #[cfg(target_os = "linux")]
        assert!(
            !kernel_keeps_locked(page),
            "the page stayed locked without a guard"
        );
        drop(area);
    }

    /// Whether the kernel marks the mapping that contains `address` as locked: mlock gives a
    /// locked range a mapping of its own, whose VmFlags in /proc/self/smaps include "lo".
    #[cfg(target_os = "linux")]
    fn kernel_keeps_locked(address: usize) -> bool {
        let smaps = std::fs::read_to_string("/proc/self/smaps").expect("/proc/self/smaps");
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
}
