//! Argon2id on the vendored reference C code, with one work area for all twelve rounds.

use super::ffi::{self, Argon2Inputs, WorkArea, ARGON2_VERSION_13};
use super::{Argon2Cost, Argon2Engine, KEY_BYTES, LANES, SALT_BYTES};
use crate::{MhfeError, WorkFactor};

// A native 32-bit build cannot run even level 0: Rust refuses an allocation of 2 GiB or more
// there (a layout may not exceed isize::MAX), and the reference C code would stop at 2 GiB anyway.
// Such a build is refused here rather than failing at the first operation. The browser build is a
// 32-bit WebAssembly one too, but it uses its own Emscripten allocator (see engine/browser.rs).
#[cfg(not(target_pointer_width = "64"))]
compile_error!("the native MHFE engine needs a 64-bit target: suite 3 needs at least 2 GiB");

/// The highest memory level this build supports: every level, since native builds are 64-bit.
pub const HIGHEST_MEMORY_LEVEL: u32 = crate::MAX_MEMORY_LEVEL;

/// Free memory as the operating system reports it, or `None` where it gives no figure. On Linux
/// this is the lower of the computer's figure and the room left in the process's control group,
/// such as a container's memory limit.
pub fn available_memory_bytes() -> Option<u64> {
    ffi::available_memory_bytes()
}

/// Argon2id on the reference C code with its four lanes in parallel threads.
pub struct NativeEngine {
    cost: Argon2Cost,
    work_area: WorkArea,
}

/// Checks, without allocating anything, that this build and computer can run `work`: the memory
/// level is supported, the processor has the instructions of this build, and the memory is free.
/// A program calls it before asking for secrets and reserves the memory after the password is
/// encoded, the order the specification gives for creating a container.
pub fn check_can_run(work: WorkFactor) -> Result<(), MhfeError> {
    if work.memory_level() > HIGHEST_MEMORY_LEVEL {
        return Err(MhfeError::MemoryLevelNotSupportedHere {
            level: work.memory_level(),
            highest_supported: HIGHEST_MEMORY_LEVEL,
        });
    }
    check_processor()?;
    check_free_memory(work.memory_bytes())
}

impl NativeEngine {
    /// Checks that the computer can run `work` and reserves its memory once; every round of the
    /// operation then reuses it.
    pub fn new(work: WorkFactor) -> Result<Self, MhfeError> {
        check_can_run(work)?;
        Self::allocate(work.argon2_cost())
    }

    /// A much cheaper engine for fast unit tests. It exists only in test builds; the release
    /// check `scripts/check-release-artifacts.sh` looks for [`REDUCED_COST_MARKER`] to prove it.
    #[cfg(test)]
    pub(crate) fn reduced_for_tests(cost: Argon2Cost) -> Result<Self, MhfeError> {
        assert!(!REDUCED_COST_MARKER.is_empty());
        check_processor()?;
        check_free_memory(cost.memory_bytes())?;
        Self::allocate(cost)
    }

    fn allocate(cost: Argon2Cost) -> Result<Self, MhfeError> {
        let work_area = WorkArea::allocate(cost.memory_bytes())?;
        Ok(Self { cost, work_area })
    }
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

impl Argon2Engine for NativeEngine {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        let inputs = Argon2Inputs {
            password,
            salt,
            secret: &[],
            associated_data: &[],
            passes: self.cost.passes,
            memory_kib: self.cost.memory_kib,
            lanes: LANES,
            threads: LANES,
            version: ARGON2_VERSION_13,
        };
        ffi::argon2id(&inputs, &mut self.work_area, key)
    }
}

/// A build with the `ssse3` feature runs SSSE3 instructions in the Argon2 code. On a processor
/// without them it would stop with "Illegal instruction", so it refuses before any of them runs.
fn check_processor() -> Result<(), MhfeError> {
    #[cfg(all(target_arch = "x86_64", feature = "ssse3"))]
    return require_ssse3(std::arch::is_x86_feature_detected!("ssse3"));
    #[cfg(not(all(target_arch = "x86_64", feature = "ssse3")))]
    Ok(())
}

#[cfg(any(test, all(target_arch = "x86_64", feature = "ssse3")))]
fn require_ssse3(processor_has_ssse3: bool) -> Result<(), MhfeError> {
    if processor_has_ssse3 {
        Ok(())
    } else {
        Err(MhfeError::ProcessorNotSupported(
            "this build of mhfe needs a processor with SSSE3, which this computer lacks; use the \
             standard build, the one without \"ssse3\" in its name"
                .to_owned(),
        ))
    }
}

/// Present only in test builds. A release binary or WebAssembly module that contains this text
/// would contain the reduced test engine, and the release check fails.
#[cfg(test)]
#[used]
pub(crate) static REDUCED_COST_MARKER: &str = "MHFE-TEST-ONLY-REDUCED-ARGON2-COST";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_same_key_as_the_c_reference_at_a_small_cost() {
        let cost = Argon2Cost {
            memory_kib: 1024,
            passes: 1,
        };
        let mut engine = NativeEngine::reduced_for_tests(cost).unwrap();
        let mut key = [0u8; KEY_BYTES];
        engine
            .derive(b"public test password", b"0123456789abcdef", &mut key)
            .unwrap();
        // Same inputs as scripts/verify-argon2-wasm.mjs, tag computed with OpenSSL.
        assert_eq!(
            hex::encode(key),
            "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2"
        );
    }

    #[test]
    fn an_ssse3_build_refuses_a_processor_without_ssse3() {
        assert_eq!(require_ssse3(true), Ok(()));
        let error = require_ssse3(false).unwrap_err();
        assert_eq!(error.code(), "PROCESSOR_NOT_SUPPORTED");
        assert!(error.to_string().contains("SSSE3"));
    }

    #[test]
    fn refuses_more_memory_than_the_computer_reports() {
        let Some(available) = available_memory_bytes() else {
            return; // This platform reports no figure; nothing to check.
        };
        let too_much = Argon2Cost {
            memory_kib: u32::try_from((available / 1024).saturating_add(1024 * 1024))
                .unwrap_or(u32::MAX),
            passes: 1,
        };
        match NativeEngine::reduced_for_tests(too_much) {
            Err(MhfeError::NotEnoughMemory { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("more memory than available was accepted"),
        }
    }

    /// The sanity tag from the implementation brief: one full-size Argon2id call at suite 3
    /// defaults. It takes several seconds and 2 GiB, so it runs only on request.
    #[test]
    #[ignore = "full-size Argon2id: 2 GiB and several seconds"]
    fn full_size_call_matches_openssl() {
        let mut engine = NativeEngine::new(WorkFactor::default()).unwrap();
        let mut key = [0u8; KEY_BYTES];
        engine
            .derive(b"public test password", b"0123456789abcdef", &mut key)
            .unwrap();
        assert_eq!(
            hex::encode(key),
            "80ffc8d9bb2f27b317141892e8a49c645d43f3f56fff099c7b10b2ab9ea0fdca"
        );
    }
}
