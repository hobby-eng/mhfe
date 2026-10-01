//! Argon2id in the browser: the Emscripten build of the same reference C code, which the worker
//! (web/mhfe-worker.js) hands to the WebAssembly core as a JavaScript object.

use wasm_bindgen::prelude::*;

use super::{Argon2Cost, Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::{MhfeError, WorkFactor};

/// WebAssembly addresses at most 4 GiB, and the reference code limits a 32-bit build to 2 GiB of
/// Argon2 memory, so a browser supports memory level 0 only.
pub const HIGHEST_BROWSER_MEMORY_LEVEL: u32 = 0;

#[wasm_bindgen]
extern "C" {
    /// The worker's Argon2 object; see `argon2Engine` in web/argon2-engine.js.
    pub type JsArgon2;

    /// Fills `key` with Argon2id(password, salt) at the given cost, four lanes, version 1.3.
    /// The slices are views into this module's memory, so no JavaScript copy of the password is
    /// made on the way. Throws an Error whose message starts with an error code on failure.
    #[wasm_bindgen(method, catch)]
    fn derive(
        this: &JsArgon2,
        password: &[u8],
        salt: &[u8],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8],
    ) -> Result<(), JsValue>;
}

pub struct BrowserEngine {
    argon2: JsArgon2,
    cost: Argon2Cost,
}

impl BrowserEngine {
    /// Refuses memory levels a browser cannot provide before any memory is used.
    pub fn new(argon2: JsArgon2, work: WorkFactor) -> Result<Self, MhfeError> {
        if work.memory_level() > HIGHEST_BROWSER_MEMORY_LEVEL {
            return Err(MhfeError::MemoryLevelNotSupportedHere {
                level: work.memory_level(),
                highest_supported: HIGHEST_BROWSER_MEMORY_LEVEL,
            });
        }
        Ok(Self {
            argon2,
            cost: work.argon2_cost(),
        })
    }
}

impl Argon2Engine for BrowserEngine {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        self.argon2
            .derive(password, salt, self.cost.memory_kib, self.cost.passes, key)
            .map_err(|error| {
                let message = error
                    .as_string()
                    .or_else(|| {
                        js_sys::Reflect::get(&error, &"message".into())
                            .ok()?
                            .as_string()
                    })
                    .unwrap_or_else(|| "the browser Argon2 engine failed".to_owned());
                if message.starts_with("MEMORY_ALLOCATION_FAILED") {
                    MhfeError::MemoryAllocation {
                        bytes: self.cost.memory_bytes(),
                    }
                } else {
                    MhfeError::Argon2(message)
                }
            })
    }
}
