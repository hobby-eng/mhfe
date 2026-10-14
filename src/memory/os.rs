//! Operating-system page locking, owned by the secret-buffer module. These calls change page
//! policy without reading or writing a buffer; the safe owners keep the allocation and guard
//! together and count overlapping page locks.
#![allow(
    unsafe_code,
    reason = "page-size, mlock and munlock use operating-system foreign functions (RUST-07)"
)]

/// The size of a memory page, a power of two, or `None` when the system does not say.
#[cfg(unix)]
pub(crate) fn page_size() -> Option<usize> {
    // SAFETY: sysconf only reads a system value.
    match usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) {
        Ok(page) if page.is_power_of_two() => Some(page),
        _ => None,
    }
}

/// Nothing is locked where there is no mlock, so no page size is needed.
#[cfg(not(unix))]
pub(crate) fn page_size() -> Option<usize> {
    None
}

/// Asks the operating system to keep the pages under `bytes` bytes at `start` in memory, never in
/// swap (mlock). Returns whether it agreed: a low RLIMIT_MEMLOCK, for example, refuses.
#[cfg(unix)]
pub(super) fn lock_pages(start: *const u8, bytes: usize) -> bool {
    // SAFETY: mlock only changes how the kernel treats the pages of this process that contain
    // the range; it reads and writes no memory, and a range that is not mapped is refused.
    unsafe { libc::mlock(start.cast(), bytes) == 0 }
}

/// Undoes [`lock_pages`] for the same range.
#[cfg(unix)]
pub(super) fn unlock_pages(start: *const u8, bytes: usize) {
    // SAFETY: as for mlock; munlock of pages that are no longer locked or mapped is refused
    // without effect.
    unsafe { libc::munlock(start.cast(), bytes) };
}

#[cfg(not(unix))]
pub(super) fn lock_pages(_start: *const u8, _bytes: usize) -> bool {
    false
}

#[cfg(not(unix))]
pub(super) fn unlock_pages(_start: *const u8, _bytes: usize) {}
