//! Argon2id as MHFE uses it: version 1.3, four lanes, a 16-byte salt, an empty secret and empty
//! associated data, and a 32-byte output. Only the memory and the number of passes change.
//!
//! One engine runs everywhere: the vendored reference C implementation. Native builds call it
//! directly ([`NativeEngine`]); the WebAssembly build calls its Emscripten build through
//! JavaScript.

use crate::MhfeError;

/// Argon2id lanes, fixed by the specification. They run in parallel where threads exist.
pub const LANES: u32 = 4;
/// Length of the round salt `S_i`.
pub const SALT_BYTES: usize = 16;
/// Length of the Argon2id output `K_i`.
pub const KEY_BYTES: usize = 32;

/// Memory and passes of one Argon2id call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory in KiB, the unit Argon2 uses.
    pub memory_kib: u32,
    pub passes: u32,
}

impl Argon2Cost {
    pub fn memory_bytes(self) -> u64 {
        u64::from(self.memory_kib) * 1024
    }
}

/// Computes `Argon2id(password, salt)` at the cost the engine was created for.
pub trait Argon2Engine {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError>;
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub(crate) mod browser;
// Read by ffi.rs on Linux only, where containers and systemd units limit memory per group.
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(not(target_arch = "wasm32"))]
mod ffi;
#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use ffi::{lock_pages, unlock_pages};
#[cfg(not(target_arch = "wasm32"))]
pub use native::{available_memory_bytes, check_can_run, NativeEngine, HIGHEST_MEMORY_LEVEL};
