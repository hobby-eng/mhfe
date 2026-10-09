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

/// What a key holds before an engine writes it. An engine that leaves it as it was, or gives only
/// zeros, did not compute Argon2: a broken bridge to the browser's Argon2 build, or a call that
/// returned without its work. Either is refused rather than used as a round key. A real Argon2id
/// tag equals either value with probability 2^-255.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
const UNWRITTEN_KEY: [u8; KEY_BYTES] = [0xa5; KEY_BYTES];

/// Fills `key` with [`UNWRITTEN_KEY`] before an engine writes it.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) fn mark_key_unwritten(key: &mut [u8; KEY_BYTES]) {
    *key = UNWRITTEN_KEY;
}

/// Refuses a key that the engine left unwritten or set to zeros, with [`MhfeError::Argon2`].
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) fn check_key_written(key: &mut [u8; KEY_BYTES]) -> Result<(), MhfeError> {
    if *key == UNWRITTEN_KEY || key.iter().all(|&byte| byte == 0) {
        *key = [0; KEY_BYTES];
        return Err(MhfeError::Argon2(
            "the Argon2 engine returned without writing the key".to_owned(),
        ));
    }
    Ok(())
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

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use ffi::{lock_pages, page_size, unlock_pages};
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub use known_answers::{BrowserArgon2Check, BrowserArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use known_answers::{NativeArgon2Check, NativeArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use native::{
    available_memory_bytes, check_can_run, highest_available_level, NativeEngine,
    HIGHEST_MEMORY_LEVEL,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unwritten_or_zero_key_is_refused() {
        let mut key = [0u8; KEY_BYTES];
        mark_key_unwritten(&mut key);
        assert_eq!(
            check_key_written(&mut key).unwrap_err().code(),
            "ARGON2_FAILED"
        );
        assert_eq!(key, [0; KEY_BYTES], "the refused key is cleared");
        assert!(check_key_written(&mut [0; KEY_BYTES]).is_err());
        let mut written = [0u8; KEY_BYTES];
        written[31] = 1;
        assert_eq!(check_key_written(&mut written), Ok(()));
        let mut almost = UNWRITTEN_KEY;
        almost[0] ^= 1;
        assert_eq!(check_key_written(&mut almost), Ok(()));
    }
}
