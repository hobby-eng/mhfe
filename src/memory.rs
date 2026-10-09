//! Keeps the memory of a secret out of swap while it lives. An operating system may write any page
//! of a program to its swap space on disk, where it can outlast the program by years; a locked
//! page stays in memory (mlock on Unix). Locking is best effort: a refusal, such as a low
//! RLIMIT_MEMLOCK, leaves the secret as it was, and the browser and Windows builds lock nothing.
//! Argon2's work area is far too large to lock; the program warns instead when swap is not
//! encrypted.

use std::convert::Infallible;
use std::fmt;
use std::ops::{Deref, DerefMut};

use zeroize::Zeroizing;

/// Text that is secret, or may be: a password, a phrase, a passphrase, or an answer read the same
/// way as they are. Its buffer is locked before the text is written into it and stays locked
/// until the text is wiped, also after it is handed to the code that asked for it
/// (AUD-007-SEC003).
pub struct LockedText {
    text: Zeroizing<String>,
    // Declared after `text`, so that the pages are unlocked only once they are wiped.
    locked: LockedPages,
}

impl LockedText {
    /// Takes over `text` together with the guard that locked its buffer before it was filled.
    /// `locked` must cover the buffer of `text` itself, not of a copy, and `text` must not grow.
    pub fn from_locked(text: Zeroizing<String>, locked: LockedPages) -> Self {
        Self { text, locked }
    }

    /// A text that `fill` writes into a buffer reserved at `capacity` bytes and locked first. The
    /// text is held here from the start, so that a `fill` that fails leaves it wiped while its
    /// pages are still locked. `fill` must not write more than `capacity` bytes: the buffer must
    /// never move.
    pub fn build<E>(
        capacity: usize,
        fill: impl FnOnce(&mut String) -> Result<(), E>,
    ) -> Result<Self, E> {
        let text = Zeroizing::new(String::with_capacity(capacity));
        let locked = LockedPages::of_string(&text);
        let reserved = text.capacity();
        let mut built = Self { text, locked };
        fill(&mut built.text)?;
        assert_eq!(
            built.text.capacity(),
            reserved,
            "a locked text outgrew its buffer"
        );
        Ok(built)
    }

    /// A copy of `text` in a buffer reserved at its final size and locked before the copy is
    /// written into it, so that the copy never moves and never leaves part of itself behind.
    pub fn copy_of(text: &str) -> Self {
        let Ok(copy) = Self::build::<Infallible>(text.len(), |copy| {
            copy.push_str(text);
            Ok(())
        });
        copy
    }

    /// Whether the operating system keeps the text out of swap.
    pub fn is_locked(&self) -> bool {
        self.locked.is_locked()
    }

    /// The size of the buffer, which never changes once the text is in it.
    pub fn capacity(&self) -> usize {
        self.text.capacity()
    }
}

impl Deref for LockedText {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

/// Bytes that are secret, or may be: the byte form of [`LockedText`], for a password as it is
/// encoded, the entropy of a phrase, a state of the cipher or a line as it is typed. Its buffer is
/// locked before the bytes are written into it and stays locked until they are wiped, also when
/// they are refused while they are written. The bytes may change in place but never grow.
pub struct LockedBytes {
    bytes: Zeroizing<Vec<u8>>,
    // Declared after `bytes`, so that the pages are unlocked only once they are wiped.
    locked: LockedPages,
}

impl LockedBytes {
    /// Bytes that `fill` writes into a buffer reserved at `capacity` bytes and locked first. They
    /// are held here from the start, so that a `fill` that fails, such as on a password that is
    /// too long, leaves them wiped while their pages are still locked. `fill` must not write more
    /// than `capacity` bytes: the buffer must never move.
    pub fn build<E>(
        capacity: usize,
        fill: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
    ) -> Result<Self, E> {
        let bytes = Zeroizing::new(Vec::with_capacity(capacity));
        let locked = LockedPages::of_vec(&bytes);
        let reserved = bytes.capacity();
        let mut built = Self { bytes, locked };
        fill(&mut built.bytes)?;
        assert_eq!(
            built.bytes.capacity(),
            reserved,
            "locked bytes outgrew their buffer"
        );
        Ok(built)
    }

    /// A copy of `bytes` in a buffer reserved at its final size and locked before the copy is
    /// written into it.
    pub fn copy_of(bytes: &[u8]) -> Self {
        let Ok(copy) = Self::build::<Infallible>(bytes.len(), |copy| {
            copy.extend_from_slice(bytes);
            Ok(())
        });
        copy
    }

    /// Whether the operating system keeps the bytes out of swap.
    pub fn is_locked(&self) -> bool {
        self.locked.is_locked()
    }

    /// The bytes as text, in the same buffer and under the same lock. Bytes that are not UTF-8
    /// come back as they are, still locked, to be wiped when they are dropped.
    pub fn into_text(self) -> Result<LockedText, Self> {
        let Self { mut bytes, locked } = self;
        // Taken without a copy: from_utf8 keeps the buffer, and gives it back on an error.
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(text) => Ok(LockedText::from_locked(Zeroizing::new(text), locked)),
            Err(error) => {
                *bytes = error.into_bytes();
                Err(Self { bytes, locked })
            }
        }
    }
}

impl fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LockedBytes(hidden)")
    }
}

impl Deref for LockedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl DerefMut for LockedBytes {
    /// The bytes to change in place; as a slice, they cannot grow out of their locked buffer.
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// The buffer a front end reads one typed line into, a secret possibly, reserved and locked at
/// this size so that it never moves: 8 KiB. Every valid answer is far shorter: a password has at
/// most 1024 bytes after NFKD normalization and at most 4096 as typed, since NFKD never shortens a
/// character count and a character takes at most four bytes.
pub const TYPED_LINE_BYTES: usize = 8192;

/// The self-check `memory-locking`: whether this process can keep a secret out of swap, tried on
/// a buffer of the size a front end locks for each typed line ([`TYPED_LINE_BYTES`]), so that a
/// pass says that buffer is locked, not only a smaller one (AUD-016-SEC002). It only warns: a
/// refusal, such as a low RLIMIT_MEMLOCK, leaves secrets working but able to reach swap. Where
/// nothing is locked at all, it says why. Each buffer is locked as it is made, and
/// [`LockedText::is_locked`] tells whether that one was.
pub struct LockProbe {
    bytes: usize,
}

impl LockProbe {
    /// The probe of a buffer of `bytes` bytes.
    pub const fn of(bytes: usize) -> Self {
        Self { bytes }
    }
}

impl Default for LockProbe {
    /// The probe of one typed line's buffer.
    fn default() -> Self {
        Self::of(TYPED_LINE_BYTES)
    }
}

impl crate::self_check::ComponentCheck for LockProbe {
    fn id(&self) -> &'static str {
        "memory-locking"
    }

    fn label(&self) -> &'static str {
        "Locked memory"
    }

    fn run(&mut self, _: crate::self_check::Tier) -> crate::self_check::ComponentOutcome {
        use crate::self_check::ComponentOutcome;
        if cfg!(target_arch = "wasm32") {
            return ComponentOutcome::NotAvailable(
                "a web page cannot keep its memory out of swap".to_owned(),
            );
        }
        if !cfg!(unix) {
            return ComponentOutcome::NotAvailable(
                "this build locks no memory on this system".to_owned(),
            );
        }
        // Nothing is written into it: only its pages matter.
        let Ok(probe) = LockedBytes::build::<Infallible>(self.bytes, |_| Ok(()));
        if probe.is_locked() {
            ComponentOutcome::Passed
        } else {
            ComponentOutcome::Warning(format!(
                "the system refused to lock {} bytes of memory, so typed secrets may reach swap",
                self.bytes
            ))
        }
    }
}

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

    /// How many guards hold the page at `address`; only the Unix tests ask.
    #[cfg(all(test, unix))]
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

    #[test]
    fn the_lock_probe_tells_whether_memory_is_locked() {
        use crate::self_check::{ComponentCheck, Tier};
        let outcome = LockProbe::default().run(Tier::Startup);
        let Ok(buffer) = LockedBytes::build::<Infallible>(TYPED_LINE_BYTES, |_| Ok(()));
        let locked = buffer.is_locked();
        let expected = match (cfg!(unix), locked) {
            (true, true) => "passed",
            (true, false) => "warning",
            (false, _) => "notAvailable",
        };
        assert_eq!(outcome.name(), expected);
        assert!(!LockProbe::default().run(Tier::Full).is_failure());
    }

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

    /// A copy is made at its final size and locked, like the text that is read in place.
    #[test]
    fn a_copy_is_locked_at_its_final_size() {
        let text = "public test password";
        let copy = LockedText::copy_of(text);
        assert_eq!(&*copy, text);
        assert_eq!(copy.capacity(), text.len(), "the buffer never grew");
        assert_eq!(copy.is_locked(), cfg!(unix));
        // Empty text has no buffer: nothing to lock.
        let empty = LockedText::copy_of("");
        assert_eq!(&*empty, "");
        assert!(!empty.is_locked());
    }

    /// Bytes are locked at their final size, may change in place, and become text in the same
    /// buffer under the same lock; bytes that are not UTF-8 come back as they were.
    #[test]
    fn locked_bytes_keep_their_buffer_and_lock() {
        let mut bytes = LockedBytes::copy_of(b"public test bytes");
        assert_eq!(&*bytes, b"public test bytes");
        assert_eq!(bytes.is_locked(), cfg!(unix));
        bytes[0] = b'P';
        let address = bytes.as_ptr();
        let text = bytes.into_text().ok().unwrap();
        assert_eq!(&*text, "Public test bytes");
        assert_eq!(text.as_ptr(), address, "the text kept the buffer");
        assert_eq!(text.is_locked(), cfg!(unix));
        let not_utf8 = LockedBytes::copy_of(&[0xff, 0xfe]);
        let back = not_utf8.into_text().err().unwrap();
        assert_eq!(&*back, [0xff, 0xfe]);
        assert_eq!(back.is_locked(), cfg!(unix));
    }

    /// A `fill` that fails, as on a password that is too long or a line that is too long, gets a
    /// buffer that is locked while it writes, and the error comes back once the bytes are wiped
    /// and their pages released. The wipe comes first by the order of the fields, which Rust
    /// drops in their declared order; reading freed memory to see it would need unsafe code.
    /// The buffer spans whole pages of its own, so that no other test's guard can hold them.
    #[cfg(unix)]
    #[test]
    fn a_failed_fill_releases_its_pages() {
        let size = crate::engine::page_size().expect("a Unix system reports its page size");
        let mut page = 0;
        let mut was_locked = false;
        let refused = LockedBytes::build(3 * size, |bytes| {
            page = (bytes.as_ptr() as usize).next_multiple_of(size);
            was_locked = pages::holders_of(page) == 1;
            bytes.extend_from_slice(b"public bytes of a refused answer");
            Err("refused")
        });
        assert!(matches!(refused, Err("refused")));
        if !was_locked {
            // mlock refused here, such as with RLIMIT_MEMLOCK 0: nothing to release.
            return;
        }
        assert_eq!(pages::holders_of(page), 0, "the pages were not released");
    }

    /// A whole page inside a buffer of the calling test alone, so that no other test's guard can
    /// hold it: the buffer, which must outlive the page's use, the page's address and its size.
    #[cfg(unix)]
    fn page_of_this_test() -> (Vec<u8>, usize, usize) {
        let size = crate::engine::page_size().expect("a Unix system reports its page size");
        let area: Vec<u8> = Vec::with_capacity(3 * size);
        let page = (area.as_ptr() as usize).next_multiple_of(size);
        (area, page, size)
    }

    /// Two secrets on one page, as the allocator often places small buffers: dropping the guard
    /// of one, in either order, must not unlock the other (AUD-007-SEC002). The page lies inside
    /// a buffer of this test alone, so no other test's guard can hold it too.
    #[cfg(unix)]
    #[test]
    fn a_shared_page_stays_locked_until_its_last_guard_is_dropped() {
        let (area, page, size) = page_of_this_test();
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
        let (area, page, _) = page_of_this_test();
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
