//! The two suites and their two settings (specification: "Suite parameters", "Suite 4" and
//! "Work factor").

use std::fmt;

use crate::engine::Argon2Cost;
use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};
use crate::MhfeError;

/// Suite identifier; the round domain strings are built from it.
pub const SUITE_ID: &str = "MHFE-BIP39-256-EXPERIMENTAL-3";
/// Domain string for the round salt: `SUITE_ID || "/ROUND-SALT"`, no terminating NUL.
pub const DS_SALT: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-SALT";
/// Domain string for the round mask: `SUITE_ID || "/ROUND-MASK"`, no terminating NUL.
pub const DS_MASK: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-MASK";

/// Suite 4, which keeps the length of a 12- to 21-word original.
pub const SAME_LENGTH_SUITE_ID: &str = "MHFE-BIP39-LP-EXPERIMENTAL-4";
/// Suite 4's salt domain: `SAME_LENGTH_SUITE_ID || "/ROUND-SALT"`.
pub const SAME_LENGTH_DS_SALT: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-SALT";
/// Suite 4's mask domain: `SAME_LENGTH_SUITE_ID || "/ROUND-MASK"`.
pub const SAME_LENGTH_DS_MASK: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-MASK";

/// The suite of a container. Suite 3 is the default for every original; suite 4 is used only
/// when the user chooses it ("Choosing the suite").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Suite {
    /// Suite 3: every original becomes a 24-word container. A 12- to 21-word original carries
    /// a check value, so a wrong password is detected, and every container looks the same.
    #[default]
    TwentyFourWords,
    /// Suite 4: a 12-, 15-, 18- or 21-word original becomes a container of the same length.
    /// Nothing detects a wrong password, the container shows the original's length, and a word
    /// copied wrongly passes the shorter checksum more often.
    SameLength,
}

impl Suite {
    /// The identifier an application shows after creating a container.
    pub fn id(self) -> &'static str {
        match self {
            Self::TwentyFourWords => SUITE_ID,
            Self::SameLength => SAME_LENGTH_SUITE_ID,
        }
    }

    /// The suite of a container with `words` words, as recovery selects it: 24 words are suite 3
    /// and 12 to 21 words suite 4. The word count does not show that a phrase is a container.
    pub fn of_container(words: usize) -> Result<Self, MhfeError> {
        match words {
            STATE_WORDS => Ok(Self::TwentyFourWords),
            words if SHORT_WORD_COUNTS.contains(&words) => Ok(Self::SameLength),
            other => Err(MhfeError::InvalidWordCount(other)),
        }
    }

    /// The suite the specification numbers `number`, as its fixtures name it: 3 or 4.
    #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
    pub(crate) fn of_number(number: u64) -> Option<Self> {
        match number {
            3 => Some(Self::TwentyFourWords),
            4 => Some(Self::SameLength),
            _ => None,
        }
    }

    /// Whether `error` is one of the refusals the length rules give a suite 4 phrase or container
    /// before any Argon2 work: a 24-word original, a length choice that does not apply to the
    /// suite, or a container whose length the suite does not have. The last has the code of any
    /// unreadable container, so the caller reads the container first. Suite 4's validation fixture
    /// names these cases "rejected" without an error code.
    #[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
    pub(crate) fn is_length_refusal(error: &MhfeError) -> bool {
        matches!(
            error,
            MhfeError::SameLengthNeedsShortPhrase
                | MhfeError::LengthChoiceNotApplicable { .. }
                | MhfeError::InvalidContainer(_)
        )
    }

    /// The lengths of an original whose built-in check a recovery of a container of this suite
    /// can be compared with: 12 to 21 words in suite 3, none in suite 4, which has no check.
    pub fn built_in_check_lengths(self) -> &'static [usize] {
        match self {
            Self::TwentyFourWords => &SHORT_WORD_COUNTS,
            Self::SameLength => &[],
        }
    }

    /// Refuses an original of `words` words that this suite has no container for: suite 4 has
    /// none for a 24-word phrase, which fills the whole state and leaves nothing to keep its
    /// length (`SAME_LENGTH_NEEDS_SHORT_PHRASE`).
    pub fn require_original(self, words: usize) -> Result<(), MhfeError> {
        if self == Self::SameLength && words == STATE_WORDS {
            return Err(MhfeError::SameLengthNeedsShortPhrase);
        }
        Ok(())
    }

    /// Whether a container of this suite holds a whole 256-bit state, as a phrase drawn with the
    /// wallet check and a hidden wallet need: suite 3 only.
    pub fn holds_full_state(self) -> bool {
        self == Self::TwentyFourWords
    }
}

/// Number of Feistel rounds, each with one Argon2id call.
pub const ROUNDS: u32 = 12;
/// Highest PIM. A factor of 1,024 already adds only ten bits while every recovery takes about
/// a day and a half.
pub const MAX_PIM: u32 = 1023;
/// Highest memory level. Level 22 would need 2^32 KiB, one more than Argon2 accepts.
pub const MAX_MEMORY_LEVEL: u32 = 21;
/// Argon2 passes at PIM 0.
const BASE_PASSES: u32 = 12;
/// One operation at the defaults takes about one to two minutes natively: twelve Argon2id calls
/// of 5 to 10 seconds each on current laptops (see docs/measurements/).
const DEFAULT_SECONDS_LOW: u64 = 60;
const DEFAULT_SECONDS_HIGH: u64 = 120;

/// The two settings a user may choose. PIM multiplies the Argon2 passes and the memory level
/// sets the Argon2 memory. Both default to 0: 12 passes and 2 GiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkFactor {
    pim: u32,
    memory_level: u32,
}

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

/// Which settings a PIM or a memory level belongs to: those of the operation, or the new ones of a
/// rekey, which a refusal names as such so that they are not taken for the old container's. Its
/// [`fmt::Display`] gives the words that name the settings in a message: "the" or "the new".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settings {
    /// The settings of an encryption, a recovery or any other operation on one container.
    Current,
    /// The new settings of a rekey.
    New,
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Current => "the",
            Self::New => "the new",
        })
    }
}

impl WorkFactor {
    /// Accepts PIM `0..=1023` and memory level `0..=21`, before any memory is allocated.
    pub fn new(pim: u32, memory_level: u32) -> Result<Self, MhfeError> {
        Self::of(Settings::Current, pim, memory_level)
    }

    /// [`WorkFactor::new`] for the new settings of a rekey: a refusal names them as the new PIM or
    /// the new memory level, so that it is not taken for one of the old container's.
    pub fn new_settings(pim: u32, memory_level: u32) -> Result<Self, MhfeError> {
        Self::of(Settings::New, pim, memory_level)
    }

    /// [`WorkFactor::new`] for the settings `settings`, which a refusal names.
    pub(crate) fn of(settings: Settings, pim: u32, memory_level: u32) -> Result<Self, MhfeError> {
        if pim > MAX_PIM {
            return Err(MhfeError::InvalidPim { pim, settings });
        }
        if memory_level > MAX_MEMORY_LEVEL {
            return Err(MhfeError::InvalidMemoryLevel {
                level: memory_level,
                settings,
            });
        }
        Ok(Self { pim, memory_level })
    }

    /// The PIM, 0 to [`MAX_PIM`].
    pub fn pim(self) -> u32 {
        self.pim
    }

    /// The memory level, 0 to [`MAX_MEMORY_LEVEL`].
    pub fn memory_level(self) -> u32 {
        self.memory_level
    }

    /// `t(PIM) = 12 * (PIM + 1)`.
    pub fn passes(self) -> u32 {
        BASE_PASSES * (self.pim + 1)
    }

    /// `m(MEM) = (2 + MEM mod 2) * 2^(20 + floor(MEM / 2))` KiB: 2, 3, 4, 6, 8, 12 GiB and so on,
    /// up to 3 TiB. Integers only, as the specification requires.
    #[expect(
        clippy::expect_used,
        reason = "WorkFactor::of refuses a level above 21, and 3 * 2^30 KiB is below 2^32 - 1"
    )]
    pub fn memory_kib(self) -> u32 {
        let kib = (2 + u64::from(self.memory_level % 2)) << (20 + self.memory_level / 2);
        u32::try_from(kib).expect("level 21 is 3 * 2^30 KiB, below the Argon2 limit of 2^32 - 1")
    }

    /// [`WorkFactor::memory_kib`] in bytes.
    pub fn memory_bytes(self) -> u64 {
        u64::from(self.memory_kib()) * 1024
    }

    /// The memory of every Argon2 call as [`memory_text`] writes it: "2 GiB" at level 0.
    pub fn memory_text(self) -> String {
        memory_text(self.memory_bytes())
    }

    /// Refuses a memory level above `highest`, the most a build or host provides, such as a
    /// browser's (`MEMORY_LEVEL_NOT_SUPPORTED_HERE`), before any memory is used.
    pub fn require_level(self, highest: u32) -> Result<(), MhfeError> {
        if self.memory_level > highest {
            return Err(MhfeError::MemoryLevelNotSupportedHere {
                level: self.memory_level,
                highest_supported: highest,
            });
        }
        Ok(())
    }

    /// Expected native time of one operation, in seconds, as a range: about one to two minutes
    /// at the defaults on a current computer, growing with the passes and the memory. At PIM
    /// 1023 this gives roughly 17 to 34 hours.
    pub fn estimated_seconds(self) -> (u64, u64) {
        let scale = u64::from(self.pim + 1) * u64::from(self.memory_kib());
        let default_memory_kib = u64::from(WorkFactor::default().memory_kib());
        (
            DEFAULT_SECONDS_LOW * scale / default_memory_kib,
            DEFAULT_SECONDS_HIGH * scale / default_memory_kib,
        )
    }

    /// Memory and passes of every Argon2id call at these settings.
    pub fn argon2_cost(self) -> Argon2Cost {
        Argon2Cost {
            memory_kib: self.memory_kib(),
            passes: self.passes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB_IN_KIB: u64 = 1 << 20;

    #[test]
    fn memory_is_written_in_gibibytes_or_whole_tebibytes() {
        const GIB: u64 = 1 << 30;
        assert_eq!(memory_text(3 * GIB), "3 GiB");
        assert_eq!(memory_text(GIB + GIB / 2), "1.5 GiB");
        assert_eq!(memory_text(GIB / 10 - 1), "0.0 GiB");
        assert_eq!(WorkFactor::default().memory_text(), "2 GiB");
        assert_eq!(WorkFactor::new(0, 19).unwrap().memory_text(), "1536 GiB");
        assert_eq!(
            WorkFactor::new(0, MAX_MEMORY_LEVEL).unwrap().memory_text(),
            "3 TiB"
        );
    }

    #[test]
    fn domain_strings_are_built_from_the_suite_identifier() {
        assert_eq!(DS_SALT, format!("{SUITE_ID}/ROUND-SALT").as_bytes());
        assert_eq!(DS_MASK, format!("{SUITE_ID}/ROUND-MASK").as_bytes());
        let same_length = SAME_LENGTH_SUITE_ID;
        assert_eq!(
            SAME_LENGTH_DS_SALT,
            format!("{same_length}/ROUND-SALT").as_bytes()
        );
        assert_eq!(
            SAME_LENGTH_DS_MASK,
            format!("{same_length}/ROUND-MASK").as_bytes()
        );
    }

    #[test]
    fn recovery_selects_the_suite_by_word_count() {
        assert_eq!(Suite::of_container(24), Ok(Suite::TwentyFourWords));
        for words in [12, 15, 18, 21] {
            assert_eq!(Suite::of_container(words), Ok(Suite::SameLength));
        }
        assert_eq!(
            Suite::of_container(13),
            Err(MhfeError::InvalidWordCount(13))
        );
        assert_eq!(Suite::default(), Suite::TwentyFourWords);
        assert_eq!(Suite::SameLength.id(), "MHFE-BIP39-LP-EXPERIMENTAL-4");
    }

    #[test]
    fn memory_levels_follow_the_specified_series() {
        let expected_gib = [2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64];
        for (level, gib) in expected_gib.into_iter().enumerate() {
            let work = WorkFactor::new(0, level as u32).unwrap();
            assert_eq!(
                u64::from(work.memory_kib()),
                gib * GIB_IN_KIB,
                "level {level}"
            );
        }
        let highest = WorkFactor::new(0, MAX_MEMORY_LEVEL).unwrap();
        assert_eq!(
            u64::from(highest.memory_kib()),
            3 * (1 << 30),
            "3 TiB at level 21"
        );
    }

    #[test]
    fn passes_grow_with_the_pim() {
        assert_eq!(WorkFactor::default().passes(), 12);
        assert_eq!(WorkFactor::new(1, 0).unwrap().passes(), 24);
        assert_eq!(WorkFactor::new(MAX_PIM, 0).unwrap().passes(), 12 * 1024);
    }

    #[test]
    fn time_estimates_scale_with_both_settings() {
        assert_eq!(WorkFactor::default().estimated_seconds(), (60, 120));
        assert_eq!(
            WorkFactor::new(1, 1).unwrap().estimated_seconds(),
            (180, 360)
        );
        let (low, high) = WorkFactor::new(MAX_PIM, 0).unwrap().estimated_seconds();
        assert_eq!((low / 3600, high / 3600), (17, 34));
    }

    #[test]
    fn out_of_range_settings_are_rejected() {
        assert_eq!(
            WorkFactor::new(1024, 0),
            Err(MhfeError::InvalidPim {
                pim: 1024,
                settings: Settings::Current
            })
        );
        assert_eq!(
            WorkFactor::new_settings(0, 22).unwrap_err().to_string(),
            "the new memory level must be a whole number from 0 to 21, not 22"
        );
        assert_eq!(
            WorkFactor::new(0, 22),
            Err(MhfeError::InvalidMemoryLevel {
                level: 22,
                settings: Settings::Current
            })
        );
        assert_eq!(
            WorkFactor::new(u32::MAX, u32::MAX),
            Err(MhfeError::InvalidPim {
                pim: u32::MAX,
                settings: Settings::Current
            })
        );
    }
}
