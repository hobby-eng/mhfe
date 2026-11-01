//! Keeps the memory of a secret out of swap while it lives. An operating system may write any page
//! of a program to its swap space on disk, where it can outlast the program by years; a locked
//! page stays in memory. The buffer of a secret is the core's [`Secret`], whose pages hold nothing
//! else. Locking is best effort: a refusal leaves the secret as it was, and the browser build locks
//! nothing. A low RLIMIT_MEMLOCK is the exception on a Linux kernel with commit 97d34aa65c29: it
//! gives secret memory and refuses only the first write, so mhfe-core 0.1.0 cannot fall back and
//! the process ends with SIGBUS. Argon2's work area is locked only where the limit on locked
//! memory holds all of it; the program warns when swap is not encrypted.

use std::fmt;
use std::ops::Deref;

use mhfe_core::protect::Secret;
use zeroize::Zeroizing;

/// Text that is secret, or may be: a password, a phrase, a passphrase, or an answer read the same
/// way as they are. Its buffer is locked before the text is written into it and stays locked
/// until the text is wiped, also after it is handed to the code that asked for it
/// (AUD-007-SEC003).
pub struct LockedText {
    text: Secret,
}

impl LockedText {
    /// A text that `fill` writes, with [`LockedText::push`] and [`LockedText::push_str`], into a
    /// buffer of `capacity` bytes that is locked first. A `fill` that fails leaves it wiped.
    pub fn build<E>(
        capacity: usize,
        fill: impl FnOnce(&mut Self) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut built = Self {
            text: Secret::with_capacity(capacity),
        };
        fill(&mut built)?;
        Ok(built)
    }

    /// A copy of `text` in a buffer of its size, locked before the copy is written into it.
    pub fn copy_of(text: &str) -> Self {
        let mut copy = Self {
            text: Secret::with_capacity(text.len()),
        };
        copy.push_str(text);
        copy
    }

    /// The text in `line`, which a front end read into it byte by byte, in the same buffer and
    /// under the same lock; `None`, with the line wiped, when it is not UTF-8.
    pub fn from_secret(line: Secret) -> Option<Self> {
        line.as_str().is_some().then_some(Self { text: line })
    }

    /// Adds `text` at the end. It must fit: the buffer never grows, so it leaves no copy behind.
    pub fn push_str(&mut self, text: &str) {
        let pushed = self.text.push(text.as_bytes());
        assert!(pushed.is_ok(), "a locked text outgrew its buffer");
    }

    /// Adds `character` at the end, as [`LockedText::push_str`] does.
    pub fn push(&mut self, character: char) {
        let mut encoded = Zeroizing::new([0u8; 4]);
        self.push_str(character.encode_utf8(&mut encoded[..]));
    }

    /// Whether the operating system keeps the text out of swap.
    pub fn is_locked(&self) -> bool {
        self.text.is_locked()
    }

    /// The size of the buffer, which never changes.
    pub fn capacity(&self) -> usize {
        self.text.capacity()
    }
}

/// Lets `write!` format into the text, where `format!` would leave a copy behind. What it writes
/// must fit, as for [`LockedText::push_str`].
impl fmt::Write for LockedText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

impl Deref for LockedText {
    type Target = str;

    #[expect(
        clippy::expect_used,
        reason = "from_secret checked the text, and only text is pushed after it"
    )]
    fn deref(&self) -> &str {
        self.text.as_str().expect("a locked text is UTF-8")
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
/// refusal leaves secrets working but able to reach swap. Under the low RLIMIT_MEMLOCK above, it
/// cannot warn: the wipe of its buffer on drop is a first write, which ends the process. Where
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
        if Secret::with_capacity(self.bytes).is_locked() {
            ComponentOutcome::Passed
        } else {
            ComponentOutcome::Warning(format!(
                "the system refused to lock {} bytes of memory, so typed secrets may reach swap",
                self.bytes
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[test]
    fn the_lock_probe_tells_whether_memory_is_locked() {
        use crate::self_check::{ComponentCheck, Tier};
        let outcome = LockProbe::default().run(Tier::Startup);
        let expected = if Secret::with_capacity(TYPED_LINE_BYTES).is_locked() {
            "passed"
        } else {
            "warning"
        };
        assert_eq!(outcome.name(), expected);
        assert!(!LockProbe::default().run(Tier::Full).is_failure());
    }

    /// A copy is made at its final size and locked, like the text that is read in place.
    #[test]
    fn a_copy_is_locked_at_its_final_size() {
        let text = "public test password";
        let copy = LockedText::copy_of(text);
        assert_eq!(&*copy, text);
        assert_eq!(copy.capacity(), text.len(), "the buffer never grew");
        assert_eq!(copy.is_locked(), cfg!(any(unix, windows)));
        assert_eq!(&*LockedText::copy_of(""), "");
    }

    /// A line becomes text in the same buffer under the same lock; bytes that are not UTF-8 are
    /// refused.
    #[test]
    fn a_line_becomes_text_in_its_own_buffer() {
        let mut line = Secret::with_capacity(32);
        line.push(b"public test bytes").unwrap();
        let address = line.as_bytes().as_ptr();
        let text = LockedText::from_secret(line).unwrap();
        assert_eq!(&*text, "public test bytes");
        assert_eq!(text.as_ptr(), address, "the text kept the buffer");
        assert_eq!(text.is_locked(), cfg!(any(unix, windows)));
        let mut not_utf8 = Secret::with_capacity(2);
        not_utf8.push(&[0xff, 0xfe]).unwrap();
        assert!(LockedText::from_secret(not_utf8).is_none());
    }

    /// A text is written in place, characters of every length too, and a `fill` that fails hands
    /// back its error.
    #[test]
    fn a_fill_writes_in_place_or_fails() {
        let Ok(text) = LockedText::build::<Infallible>(7, |text| {
            text.push_str("ab");
            text.push('\u{1D400}');
            text.push('c');
            Ok(())
        });
        assert_eq!(&*text, "ab\u{1D400}c");
        let refused = LockedText::build(8, |text| {
            text.push_str("public");
            Err("refused")
        });
        assert!(matches!(refused, Err("refused")));
    }

    #[test]
    #[should_panic(expected = "a locked text outgrew its buffer")]
    fn a_text_never_outgrows_its_buffer() {
        LockedText::copy_of("four").push('!');
    }
}
