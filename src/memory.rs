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

    /// Whether the operating system keeps the pages in memory.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    fn lock(start: *const u8, bytes: usize) -> Self {
        let locked = bytes > 0 && lock(start, bytes);
        Self {
            start: start as usize,
            bytes,
            locked,
        }
    }
}

impl Drop for LockedPages {
    fn drop(&mut self) {
        if self.locked {
            unlock(self.start as *const u8, self.bytes);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
use crate::engine::{lock_pages as lock, unlock_pages as unlock};

#[cfg(target_arch = "wasm32")]
fn lock(_start: *const u8, _bytes: usize) -> bool {
    false
}

#[cfg(target_arch = "wasm32")]
fn unlock(_start: *const u8, _bytes: usize) {}

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
}
