//! Exact strengths of random draws, shared by recipes and their presentation.

use std::fmt;

use super::{MILLIBITS_PER_BIT, MILLIBITS_PER_CHARACTER};
use crate::eff::MILLIBITS_PER_WORD;

/// A strength in thousandths of a bit. It describes a random draw, without estimating how a
/// person chose a password; [`crate::strength::Strength`] does that separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Millibits(usize);

impl Millibits {
    /// A strength already counted in thousandths of a bit.
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    /// The strength of `count` independently drawn EFF words; a check word adds none.
    pub const fn words(count: usize) -> Self {
        Self(count * MILLIBITS_PER_WORD)
    }

    /// The strength of `count` independently drawn characters of the recipe's alphabet.
    pub const fn characters(count: usize) -> Self {
        Self(count * MILLIBITS_PER_CHARACTER)
    }

    /// The exact count of thousandths.
    pub const fn get(self) -> usize {
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
        const TENTHS_PER_BIT: usize = 10;
        let per_tenth = MILLIBITS_PER_BIT as usize / TENTHS_PER_BIT;
        let tenths = self.0 / per_tenth + usize::from(self.0 % per_tenth >= per_tenth / 2);
        write!(
            formatter,
            "{}.{}",
            tenths / TENTHS_PER_BIT,
            tenths % TENTHS_PER_BIT
        )
    }
}
