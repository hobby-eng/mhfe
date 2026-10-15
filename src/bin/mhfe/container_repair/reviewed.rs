//! A reviewed container and the secret owners a repair/search passes to its command.

use mhfe::memory::LockedText;
use mhfe::Password;

/// A container phrase as typed, repaired with its card, found by a search or as it was, ready
/// to be read.
pub(crate) struct Reviewed {
    words: LockedText,
    /// What was repaired, for the summary, without the words: "word 3 of the container phrase".
    repaired: Option<String>,
    /// The container password, when a search asked for it already.
    password: Option<Password>,
    /// What a search for missing words matched, such as "the container's own wallet: master key
    /// fingerprint e0f73b78", for a check to list among its matches.
    found_by: Option<String>,
}

impl Reviewed {
    pub(crate) fn new(
        words: LockedText,
        repaired: Option<String>,
        password: Option<Password>,
        found_by: Option<String>,
    ) -> Self {
        Self {
            words,
            repaired,
            password,
            found_by,
        }
    }
    pub(crate) fn words(&self) -> &str {
        &self.words
    }
    pub(crate) fn repaired(&self) -> Option<&str> {
        self.repaired.as_deref()
    }
    /// Transfer each secret owner without cloning its buffer.
    pub(crate) fn into_parts(
        self,
    ) -> (LockedText, Option<String>, Option<Password>, Option<String>) {
        (self.words, self.repaired, self.password, self.found_by)
    }

    pub(super) fn as_typed(words: LockedText) -> Self {
        Self {
            words,
            repaired: None,
            password: None,
            found_by: None,
        }
    }
}
