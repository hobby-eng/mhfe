//! What mhfe adds to the core's [`Suite`] and [`WorkFactor`] (specification: "Suite parameters",
//! "Suite 4" and "Work factor"), as free functions, since only the core can add to its types.
//! `Suite` is non_exhaustive, so a match on it needs a wildcard arm: throughout this crate that arm
//! is suite 4, the only other suite of the one core version it pins.

use mhfe_core::{Suite, WorkFactor};

use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};
use crate::MhfeError;

/// The lengths of an original whose built-in check a recovery of a container of `suite` can be
/// compared with: 12 to 21 words in suite 3, none in suite 4, which has no check.
pub(crate) fn built_in_check_lengths(suite: Suite) -> &'static [usize] {
    match suite {
        Suite::TwentyFourWords => &SHORT_WORD_COUNTS,
        _ => &[],
    }
}

/// Refuses an original of `words` words that `suite` has no container for: suite 4 has none for a
/// 24-word phrase, which fills the whole state and leaves nothing to keep its length
/// (`SAME_LENGTH_NEEDS_SHORT_PHRASE`).
pub fn require_original(suite: Suite, words: usize) -> Result<(), MhfeError> {
    if suite == Suite::SameLength && words == STATE_WORDS {
        return Err(MhfeError::SameLengthNeedsShortPhrase);
    }
    Ok(())
}

/// Whether a container of `suite` holds a whole 256-bit state, as a phrase drawn with the wallet
/// check and a hidden wallet need: suite 3 only.
pub(crate) fn holds_full_state(suite: Suite) -> bool {
    suite == Suite::TwentyFourWords
}

/// Number of Feistel rounds, each with one Argon2id call. A deliberate copy of `ROUNDS` in the
/// core's src/suite.rs, which keeps it private, for the progress the front ends show: a change goes
/// to both.
pub const ROUNDS: u32 = 12;
/// One operation at the defaults takes about one to two minutes natively: twelve Argon2id calls
/// of 5 to 10 seconds each on current laptops (see docs/measurements/).
const DEFAULT_SECONDS_LOW: u64 = 60;
const DEFAULT_SECONDS_HIGH: u64 = 120;

/// A memory size as every front end writes it: whole tebibytes from 1 TiB on, as the highest
/// levels are, else gibibytes with one decimal unless whole: "2 GiB", "1.5 GiB", "3 TiB". Integers
/// only.
pub fn memory_text(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;
    if bytes >= TIB && bytes.is_multiple_of(TIB) {
        return format!("{} TiB", bytes / TIB);
    }
    if bytes.is_multiple_of(GIB) {
        return format!("{} GiB", bytes / GIB);
    }
    let tenths = bytes / (GIB / 10);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

/// The memory of every Argon2 call of `work`, in bytes.
pub fn memory_bytes(work: WorkFactor) -> u64 {
    u64::from(work.memory_kib()) * 1024
}

/// Refuses a memory level above `highest`, the most a build or host provides, such as a browser's
/// (`MEMORY_LEVEL_NOT_SUPPORTED_HERE`), before any memory is used.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) fn require_level(work: WorkFactor, highest: u32) -> Result<(), MhfeError> {
    if work.memory_level() > highest {
        return Err(MhfeError::MemoryLevelNotSupportedHere {
            level: work.memory_level(),
            highest_supported: highest,
        });
    }
    Ok(())
}

/// Expected native time of one operation, in seconds, as a range: about one to two minutes at the
/// defaults on a current computer, growing with the passes and the memory. At PIM 1023 this gives
/// roughly 17 to 34 hours.
pub fn estimated_seconds(work: WorkFactor) -> (u64, u64) {
    let scale = u64::from(work.pim() + 1) * u64::from(work.memory_kib());
    let default_memory_kib = u64::from(WorkFactor::default().memory_kib());
    (
        DEFAULT_SECONDS_LOW * scale / default_memory_kib,
        DEFAULT_SECONDS_HIGH * scale / default_memory_kib,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_written_in_gibibytes_or_whole_tebibytes() {
        const GIB: u64 = 1 << 30;
        let text_of = |work| memory_text(memory_bytes(work));
        assert_eq!(memory_text(3 * GIB), "3 GiB");
        assert_eq!(memory_text(GIB + GIB / 2), "1.5 GiB");
        assert_eq!(memory_text(GIB / 10 - 1), "0.0 GiB");
        assert_eq!(text_of(WorkFactor::default()), "2 GiB");
        assert_eq!(text_of(WorkFactor::new(0, 19).unwrap()), "1536 GiB");
        assert_eq!(
            text_of(WorkFactor::new(0, WorkFactor::MAX_MEMORY_LEVEL).unwrap()),
            "3 TiB"
        );
    }

    #[test]
    fn time_estimates_scale_with_both_settings() {
        assert_eq!(estimated_seconds(WorkFactor::default()), (60, 120));
        assert_eq!(
            estimated_seconds(WorkFactor::new(1, 1).unwrap()),
            (180, 360)
        );
        let (low, high) = estimated_seconds(WorkFactor::new(WorkFactor::MAX_PIM, 0).unwrap());
        assert_eq!((low / 3600, high / 3600), (17, 34));
    }
}
