//! The two suites and their two settings (specification: "Suite parameters", "Suite 4" and
//! "Work factor").

use crate::text::memory_text;

use std::fmt;

use crate::packing;
use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};
mod format_error;
pub use format_error::FormatError;
mod error;
pub use error::SettingsError;

/// Memory and passes of one Argon2id call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory in KiB, the unit Argon2 uses.
    memory_kib: u32,
    /// Passes over the memory, Argon2's `t`.
    passes: u32,
}

impl Argon2Cost {
    /// Raw Argon2 parameters, in KiB and passes. The backend validates them on derivation;
    /// a suite's validated parameters come from [`WorkFactor::argon2_cost`].
    pub const fn new(memory_kib: u32, passes: u32) -> Self {
        Self { memory_kib, passes }
    }

    /// Memory in KiB, the unit Argon2 uses.
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Passes over the memory, Argon2's `t`.
    pub const fn passes(self) -> u32 {
        self.passes
    }

    /// The memory in bytes.
    pub fn memory_bytes(self) -> u64 {
        u64::from(self.memory_kib) * 1024
    }
}

/// The length of an original phrase: 12, 15, 18, 21 or 24 words, the BIP39 lengths MHFE takes.
///
/// It is made only by [`WordCount::new`], so it never holds any other number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordCount(usize);

impl WordCount {
    /// Refuses, before a container is read, a built-in check at a length that has none in any container
    /// (`INVALID_WORD_COUNT`): only a 12- to 21-word original carries one.
    pub fn require_built_in_check(self) -> Result<(), FormatError> {
        if !SHORT_WORD_COUNTS.contains(&self.get()) {
            return Err(FormatError::NoBuiltInCheckAtLength(self.get()));
        }
        Ok(())
    }

    /// Refuses every other number with [`FormatError::InvalidWordCount`].
    pub fn new(words: usize) -> Result<Self, FormatError> {
        packing::entropy_bytes(words)?;
        Ok(Self(words))
    }

    /// The number of words.
    pub fn get(self) -> usize {
        self.0
    }

    /// The bytes of entropy a BIP39 phrase of this length carries: 16 for 12 words, 32 for 24.
    pub fn entropy_bytes(self) -> usize {
        packing::entropy_of_words(self.0)
    }
}

/// How recovery of a 24-word container learns the length of the original phrase. A same-length
/// container keeps its original's length and takes only [`PhraseLength::Detect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseLength {
    /// Tests the 12-, 15-, 18- and 21-word layouts and falls back to 24 words.
    Detect,
    /// The length the user states. The layouts are tested all the same, and a built-in check that
    /// passes takes precedence over the stated length (the specification's recovery rules): a
    /// person can misremember a length, while a check passes by chance at most once in 2^32.
    Words(WordCount),
}

impl PhraseLength {
    /// The word count a front end passes as a number, 0 standing for detection, as the browser
    /// package and `--words auto` take it.
    pub fn from_count(count: usize) -> Result<Self, FormatError> {
        match count {
            0 => Ok(Self::Detect),
            words => WordCount::new(words).map(Self::Words),
        }
    }

    /// The stated word count; `None` for detection.
    pub(crate) fn stated(self) -> Option<usize> {
        match self {
            Self::Detect => None,
            Self::Words(words) => Some(words.get()),
        }
    }
}

/// Suite identifier; the round domain strings are built from it.
pub const SUITE_ID: &str = "MHFE-BIP39-256-EXPERIMENTAL-3";
/// Domain string for the round salt: `SUITE_ID || "/ROUND-SALT"`, no terminating NUL.
pub(crate) const DS_SALT: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-SALT";
/// Domain string for the round mask: `SUITE_ID || "/ROUND-MASK"`, no terminating NUL.
pub(crate) const DS_MASK: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-MASK";

/// Suite 4, which keeps the length of a 12- to 21-word original.
pub const SAME_LENGTH_SUITE_ID: &str = "MHFE-BIP39-LP-EXPERIMENTAL-4";
/// Suite 4's salt domain: `SAME_LENGTH_SUITE_ID || "/ROUND-SALT"`.
pub(crate) const SAME_LENGTH_DS_SALT: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-SALT";
/// Suite 4's mask domain: `SAME_LENGTH_SUITE_ID || "/ROUND-MASK"`.
pub(crate) const SAME_LENGTH_DS_MASK: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-MASK";

/// The suite of a container. Suite 3 is the default for every original; suite 4 is used only
/// when the user chooses it ("Choosing the suite").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Suite {
    /// Suite 3: every original becomes a 24-word container. A 12- to 21-word original carries
    /// a check value, so a wrong password is detected, and every container looks the same.
    #[default]
    TwentyFourWords,
    /// Suite 4: a 12-, 15-, 18- or 21-word original becomes a container of the same length.
    ///
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
    pub fn of_container(words: usize) -> Result<Self, FormatError> {
        match words {
            STATE_WORDS => Ok(Self::TwentyFourWords),
            words if SHORT_WORD_COUNTS.contains(&words) => Ok(Self::SameLength),
            other => Err(FormatError::InvalidWordCount(other)),
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
    pub fn require_original(self, words: usize) -> Result<(), FormatError> {
        if self == Self::SameLength && words == STATE_WORDS {
            return Err(FormatError::SameLengthNeedsShortPhrase);
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
    pub fn new(pim: u32, memory_level: u32) -> Result<Self, SettingsError> {
        Self::of(Settings::Current, pim, memory_level)
    }

    /// [`WorkFactor::new`] for the new settings of a rekey: a refusal names them as the new PIM or
    /// the new memory level, so that it is not taken for one of the old container's.
    pub fn new_settings(pim: u32, memory_level: u32) -> Result<Self, SettingsError> {
        Self::of(Settings::New, pim, memory_level)
    }

    /// [`WorkFactor::new`] for the settings `settings`, which a refusal names.
    pub(crate) fn of(
        settings: Settings,
        pim: u32,
        memory_level: u32,
    ) -> Result<Self, SettingsError> {
        if pim > MAX_PIM {
            return Err(SettingsError::InvalidPim { pim, settings });
        }
        if memory_level > MAX_MEMORY_LEVEL {
            return Err(SettingsError::InvalidMemoryLevel {
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
    ///
    /// # Panics
    ///
    /// Never: a level above 21 is refused when the settings are made.
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

    /// The memory of every Argon2 call as a display size: "2 GiB" at level 0.
    pub fn memory_text(self) -> String {
        memory_text(self.memory_bytes())
    }

    /// Refuses a memory level above `highest`, the most a build or host provides, such as a
    /// browser's (`MEMORY_LEVEL_NOT_SUPPORTED_HERE`), before any memory is used.
    pub fn require_level(self, highest: u32) -> Result<(), SettingsError> {
        if self.memory_level > highest {
            return Err(SettingsError::MemoryLevelNotSupportedHere {
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
            Err(FormatError::InvalidWordCount(13))
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
            Err(SettingsError::InvalidPim {
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
            Err(SettingsError::InvalidMemoryLevel {
                level: 22,
                settings: Settings::Current
            })
        );
        assert_eq!(
            WorkFactor::new(u32::MAX, u32::MAX),
            Err(SettingsError::InvalidPim {
                pim: u32::MAX,
                settings: Settings::Current
            })
        );
    }
}
