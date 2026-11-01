//! Argon2id on the reference C code of mhfe-core, with one work area for all twelve rounds, and the
//! checks of the computer's memory before it is reserved.

use mhfe_core::{NativeArgon2, WorkFactor};

use super::{error_of, ffi};
use crate::suite::{memory_bytes, require_level};
use crate::MhfeError;

/// The highest memory level this build supports: every level, since native builds are 64-bit.
pub const HIGHEST_MEMORY_LEVEL: u32 = WorkFactor::MAX_MEMORY_LEVEL;

/// Free memory as the operating system reports it, or `None` where it gives no figure. On Linux
/// this is the lower of the computer's figure and the room left in the process's control group,
/// such as a container's memory limit.
pub fn available_memory_bytes() -> Option<u64> {
    ffi::available_memory_bytes()
}

/// Checks, without allocating anything, that this build and computer can run `work`: the memory
/// level is supported and the memory is free.
/// A program calls it before asking for secrets and reserves the memory after the password is
/// encoded, the order the specification gives for creating a container.
pub fn check_can_run(work: WorkFactor) -> Result<(), MhfeError> {
    require_level(work, HIGHEST_MEMORY_LEVEL)?;
    check_free_memory(memory_bytes(work))
}

/// The highest memory level whose memory the computer reports as free, if it reports any.
pub fn highest_available_level() -> Option<u32> {
    let available = available_memory_bytes()?;
    (0..=HIGHEST_MEMORY_LEVEL)
        .rev()
        .filter_map(|level| WorkFactor::new(0, level).ok())
        .find(|&work| memory_bytes(work) <= available)
        .map(WorkFactor::memory_level)
}

/// Checks that the computer can run `work` and reserves its memory once; every round of the
/// operation then reuses it. Errors: those of [`check_can_run`], then
/// [`MhfeError::MemoryAllocation`] when the system refuses the memory.
pub fn reserve(work: WorkFactor) -> Result<NativeArgon2, MhfeError> {
    check_can_run(work)?;
    NativeArgon2::new(work.memory_kib()).map_err(|error| error_of(error, memory_bytes(work)))
}

fn check_free_memory(needed_bytes: u64) -> Result<(), MhfeError> {
    match available_memory_bytes() {
        Some(available_bytes) if available_bytes < needed_bytes => {
            Err(MhfeError::NotEnoughMemory {
                needed_bytes,
                available_bytes,
            })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use mhfe_core::Argon2Engine;

    use super::*;
    use crate::engine::KEY_BYTES;

    #[test]
    fn refuses_more_memory_than_the_computer_reports() {
        let Some(available) = available_memory_bytes() else {
            return; // This platform reports no figure; nothing to check.
        };
        match check_free_memory(available.saturating_add(1 << 30)) {
            Err(MhfeError::NotEnoughMemory { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("more memory than available was accepted"),
        }
    }

    #[test]
    fn the_refusals_of_the_core_engine_become_mhfe_errors() {
        let mut engine = NativeArgon2::new(64).unwrap();
        let mut key = [0u8; KEY_BYTES];
        let refusal = engine
            .argon2id(b"password", b"0123456789abcdef", 128, 1, &mut key)
            .unwrap_err();
        assert_eq!(
            error_of(refusal, 128 << 10),
            MhfeError::MemoryAllocation { bytes: 128 << 10 }
        );
        assert_eq!(
            error_of(mhfe_core::Error::Argon2Failed { code: -33 }, 0),
            MhfeError::Argon2("the reference code returned error -33".to_owned())
        );
    }

    /// The sanity tag from the implementation brief: one full-size Argon2id call at suite 3
    /// defaults. It takes several seconds and 2 GiB, so it runs only on request.
    #[test]
    #[ignore = "full-size Argon2id: 2 GiB and several seconds"]
    fn full_size_call_matches_openssl() {
        let work = WorkFactor::default();
        let mut engine = reserve(work).unwrap();
        let mut key = [0u8; KEY_BYTES];
        engine
            .argon2id(
                b"public test password",
                b"0123456789abcdef",
                work.memory_kib(),
                work.passes(),
                &mut key,
            )
            .unwrap();
        assert_eq!(
            hex::encode(key),
            "80ffc8d9bb2f27b317141892e8a49c645d43f3f56fff099c7b10b2ab9ea0fdca"
        );
    }
}
