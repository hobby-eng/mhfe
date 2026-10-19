//! Exact strengths of random draws, shared by recipes and their presentation.

use std::fmt;

use super::{MILLIBITS_PER_BIT, MILLIBITS_PER_CHARACTER};
use crate::eff::MILLIBITS_PER_WORD;

/// A strength in thousandths of a bit. It describes a random draw, without estimating how a
/// person chose a password; [`crate::strength::Strength`] does that separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Millibits(u128);

impl Millibits {
    /// A strength already counted in thousandths of a bit.
    pub const fn new(value: usize) -> Self {
        Self(value as u128)
    }

    /// The strength of `count` independently drawn EFF words; a check word adds none.
    ///
    /// Every `usize` count fits: arithmetic uses 128 bits, including on 64-bit hosts.
    pub const fn words(count: usize) -> Self {
        Self(count as u128 * MILLIBITS_PER_WORD as u128)
    }

    /// The strength of `count` independently drawn characters of the recipe's alphabet.
    pub const fn characters(count: usize) -> Self {
        Self(count as u128 * MILLIBITS_PER_CHARACTER as u128)
    }

    /// The exact count of thousandths, wide enough for any supported host's draw count.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// The strength in bits, for consumers that need a number rather than display text.
    pub fn bits(self) -> f64 {
        self.0 as f64 / f64::from(MILLIBITS_PER_BIT)
    }
}

impl fmt::Display for Millibits {
    /// Bits rounded half up to one decimal, without floating-point or addition overflow.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const TENTHS_PER_BIT: u128 = 10;
        let per_tenth = u128::from(MILLIBITS_PER_BIT) / TENTHS_PER_BIT;
        let tenths = self.0 / per_tenth + u128::from(self.0 % per_tenth >= per_tenth / 2);
        write!(
            formatter,
            "{}.{}",
            tenths / TENTHS_PER_BIT,
            tenths % TENTHS_PER_BIT
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strengths_keep_exact_answers_beyond_the_host_integer_range() {
        // Decimal integer products computed independently with Python, not a usize product.
        let cases: &[(u64, u128, u128)] = &[
            (0, 0, 0),
            (1, 12_925, 5_833),
            (32, 413_600, 186_656),
            (64, 827_200, 373_312),
            (332_299, 4_294_964_575, 1_938_300_067),
            (332_300, 4_294_977_500, 1_938_305_900),
            (4_294_967_295, 55_512_452_287_875, 25_052_544_231_735),
            (
                18_446_744_073_709_551_615,
                238_424_167_152_695_954_623_875,
                107_599_858_181_947_814_570_295,
            ),
        ];
        for &(count, words, characters) in cases {
            if let Ok(count) = usize::try_from(count) {
                assert_eq!(Millibits::words(count).get(), words);
                assert_eq!(Millibits::characters(count).get(), characters);
                assert!(Millibits::words(count).bits().is_finite());
            }
        }
    }

    #[test]
    fn strengths_cross_the_first_usize_overflow_without_wrapping() {
        let cases = if usize::BITS == 64 {
            [
                (
                    MILLIBITS_PER_WORD,
                    18_446_744_073_709_540_875,
                    18_446_744_073_709_553_800,
                ),
                (
                    MILLIBITS_PER_CHARACTER,
                    18_446_744_073_709_549_984,
                    18_446_744_073_709_555_817,
                ),
            ]
        } else {
            [
                (MILLIBITS_PER_WORD, 4_294_964_575, 4_294_977_500),
                (MILLIBITS_PER_CHARACTER, 4_294_966_226, 4_294_972_059),
            ]
        };
        for (unit, last, next) in cases {
            let strength = if unit == MILLIBITS_PER_WORD {
                Millibits::words
            } else {
                Millibits::characters
            };
            let count = usize::MAX / unit;
            assert_eq!(strength(count).get(), last);
            assert_eq!(strength(count + 1).get(), next);
            assert!(strength(count + 1).get() > usize::MAX as u128);
        }
    }
}
