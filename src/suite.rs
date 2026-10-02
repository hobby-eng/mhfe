//! The two suites and their two settings (specification: "Suite parameters", "Suite 4" and
//! "Work factor").

use crate::engine::Argon2Cost;
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
            24 => Ok(Self::TwentyFourWords),
            12 | 15 | 18 | 21 => Ok(Self::SameLength),
            other => Err(MhfeError::InvalidWordCount(other)),
        }
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

impl WorkFactor {
    /// Accepts PIM `0..=1023` and memory level `0..=21`, before any memory is allocated.
    pub fn new(pim: u32, memory_level: u32) -> Result<Self, MhfeError> {
        if pim > MAX_PIM {
            return Err(MhfeError::InvalidPim(pim));
        }
        if memory_level > MAX_MEMORY_LEVEL {
            return Err(MhfeError::InvalidMemoryLevel(memory_level));
        }
        Ok(Self { pim, memory_level })
    }

    pub fn pim(self) -> u32 {
        self.pim
    }

    pub fn memory_level(self) -> u32 {
        self.memory_level
    }

    /// `t(PIM) = 12 * (PIM + 1)`.
    pub fn passes(self) -> u32 {
        BASE_PASSES * (self.pim + 1)
    }

    /// `m(MEM) = (2 + MEM mod 2) * 2^(20 + floor(MEM / 2))` KiB: 2, 3, 4, 6, 8, 12 GiB and so on,
    /// up to 3 TiB. Integers only, as the specification requires.
    pub fn memory_kib(self) -> u32 {
        let kib = (2 + u64::from(self.memory_level % 2)) << (20 + self.memory_level / 2);
        u32::try_from(kib).expect("level 21 is 3 * 2^30 KiB, below the Argon2 limit of 2^32 - 1")
    }

    pub fn memory_bytes(self) -> u64 {
        u64::from(self.memory_kib()) * 1024
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
        assert_eq!(WorkFactor::new(1024, 0), Err(MhfeError::InvalidPim(1024)));
        assert_eq!(
            WorkFactor::new(0, 22),
            Err(MhfeError::InvalidMemoryLevel(22))
        );
        assert_eq!(
            WorkFactor::new(u32::MAX, u32::MAX),
            Err(MhfeError::InvalidPim(u32::MAX))
        );
    }
}
