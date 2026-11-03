//! Argon2id as MHFE uses it: version 1.3, four lanes, a 16-byte salt, an empty secret and empty
//! associated data, and a 32-byte output. Only the memory and the number of passes change.
//!
//! Native builds call mhfe-core's engine on RustCrypto's `argon2` ([`mhfe_core::NativeArgon2`]);
//! the WebAssembly build calls an Emscripten build of the vendored reference C code through
//! JavaScript.

use crate::MhfeError;

// The two sizes are deliberate copies of those in the core's src/engine.rs, which keeps them
// private: a change goes to both.
/// Length of the round salt `S_i`.
pub const SALT_BYTES: usize = 16;
/// Length of the Argon2id output `K_i`.
pub const KEY_BYTES: usize = 32;

/// Memory and passes of one Argon2id call.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Argon2Cost {
    /// Memory in KiB, the unit Argon2 uses.
    pub(crate) memory_kib: u32,
    /// Passes over the memory, Argon2's `t`.
    pub(crate) passes: u32,
}

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
impl Argon2Cost {
    /// The memory in bytes.
    pub(crate) fn memory_bytes(self) -> u64 {
        u64::from(self.memory_kib) * 1024
    }
}

/// The error of a refusal of the core's engine for `bytes` of memory.
pub(crate) fn error_of(error: mhfe_core::Error, bytes: u64) -> MhfeError {
    match error {
        mhfe_core::Error::OutOfMemory => MhfeError::MemoryAllocation { bytes },
        other => other.into(),
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub mod browser;
// Read by ffi.rs on Linux only, where containers and systemd units limit memory per group.
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(not(target_arch = "wasm32"))]
mod ffi;
#[cfg(any(
    not(target_arch = "wasm32"),
    all(feature = "browser-core", target_arch = "wasm32")
))]
pub(crate) mod known_answers;
#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub use known_answers::{BrowserArgon2Check, BrowserArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use known_answers::{NativeArgon2Check, NativeArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use native::{
    available_memory_bytes, check_can_run, highest_available_level, reserve, swap_forbidden,
    HIGHEST_MEMORY_LEVEL,
};
