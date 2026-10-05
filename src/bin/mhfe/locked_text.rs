//! Text read from the person, kept in locked memory for its whole life.

use std::ops::Deref;

use mhfe::memory::LockedPages;
use zeroize::Zeroizing;

/// An answer as it was read: a password, a phrase, a passphrase or a public answer, all read the
/// same way. Its buffer is locked before anything is read into it and stays locked until the text
/// is wiped, also after it is handed to the code that asked for it (AUD-007-SEC003).
pub struct LockedText {
    text: Zeroizing<String>,
    // Declared after `text`, so that the pages are unlocked only once they are wiped.
    _locked: LockedPages,
}

impl LockedText {
    /// Takes over `text` together with the guard that locked its buffer before it was filled.
    /// `locked` must cover the buffer of `text` itself, not of a copy.
    pub fn from_locked(text: Zeroizing<String>, locked: LockedPages) -> Self {
        Self {
            text,
            _locked: locked,
        }
    }

    /// Whether the operating system keeps the text out of swap.
    #[cfg(test)]
    pub fn is_locked(&self) -> bool {
        self._locked.is_locked()
    }

    /// The size of the buffer, which reading never changes.
    #[cfg(test)]
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
