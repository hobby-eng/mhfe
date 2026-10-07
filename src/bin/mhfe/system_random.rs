//! The operating system's random generator as the library's [`RandomSource`].

use mhfe::random::RandomSource;
use mhfe::MhfeError;

/// Random bytes straight from the operating system.
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        getrandom::fill(bytes).map_err(|error| MhfeError::RandomFailed(error.to_string()))
    }
}
