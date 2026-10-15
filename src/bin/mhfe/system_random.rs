//! The operating system's random generator as the library's [`RandomSource`].

use mhfe::random::{RandomError, RandomSource};

/// Random bytes straight from the operating system.
pub(crate) struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(bytes).map_err(|error| RandomError::OperatingSystem(error.raw_os_error()))
    }
}
