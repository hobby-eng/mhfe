//! Argon2id as MHFE uses it: version 1.3, four lanes, a 16-byte salt, an empty secret and empty
//! associated data, and a 32-byte output. Only the memory and the number of passes change.
//!
//! One engine runs everywhere: the vendored reference C implementation. Native builds call it
//! directly ([`NativeEngine`]); the WebAssembly build calls its Emscripten build through
//! JavaScript.

mod error;
pub use error::{Argon2Failure, EngineError, ReferenceMessage};

/// The selected native reference core, as its diagnostics identify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgonCore {
    /// The x86-64 SSE2 core.
    Sse2,
    /// The x86-64 SSSE3 core.
    Ssse3,
    /// The portable reference core used by other native targets.
    Portable,
}
impl ArgonCore {
    /// The source and instruction set named in native diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sse2 => "opt.c with SSE2",
            Self::Ssse3 => "opt.c with SSSE3",
            Self::Portable => "ref.c",
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn native(ssse3: bool) -> Self {
        if cfg!(target_arch = "x86_64") {
            if ssse3 {
                Self::Ssse3
            } else {
                Self::Sse2
            }
        } else {
            Self::Portable
        }
    }
}
impl std::fmt::Display for ArgonCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Argon2id lanes, fixed by the specification. They run in parallel where threads exist.
pub const LANES: u32 = 4;
/// Length of the round salt `S_i`.
pub const SALT_BYTES: usize = 16;
/// Length of the Argon2id output `K_i`.
pub const KEY_BYTES: usize = 32;

pub use crate::suite::Argon2Cost;

/// Computes `Argon2id(password, salt)` at the cost the engine was created for.
pub trait Argon2Engine {
    /// Writes the 32-byte Argon2id tag of `password` and `salt` into `key`; an engine that cannot
    /// compute it returns [`EngineError::Argon2`] or the error of its memory.
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), EngineError>;
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

/// Refuses a key that the engine left unwritten or set to zeros, with [`EngineError::Argon2`].
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) fn check_key_written(key: &mut [u8; KEY_BYTES]) -> Result<(), EngineError> {
    if *key == UNWRITTEN_KEY || key.iter().all(|&byte| byte == 0) {
        *key = [0; KEY_BYTES];
        return Err(EngineError::Argon2(Argon2Failure::UnwrittenKey));
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

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub use known_answers::{BrowserArgon2Check, BrowserArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use known_answers::{NativeArgon2Check, NativeArgon2SizesCheck};
#[cfg(not(target_arch = "wasm32"))]
pub use native::{NativeEngine, HIGHEST_MEMORY_LEVEL};

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
