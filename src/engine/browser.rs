//! Argon2id in the browser: the Emscripten build of the same reference C code, which the worker
//! (web/core-worker.js) hands to the WebAssembly core as a JavaScript object.

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

    /// Grows the Argon2 build's memory to the work area of `memory_kib` once and frees it again,
    /// so that a session learns at its start whether the browser can provide it.
    #[wasm_bindgen(method, catch)]
    fn reserve(this: &JsArgon2, memory_kib: u32) -> Result<(), JsValue>;
}

pub struct BrowserEngine {
    argon2: JsArgon2,
    cost: Argon2Cost,
}

impl BrowserEngine {
    /// Refuses memory levels a browser cannot provide before any memory is used.
    pub fn new(argon2: JsArgon2, work: WorkFactor) -> Result<Self, MhfeError> {
        work.require_level(HIGHEST_BROWSER_MEMORY_LEVEL)?;
        Ok(Self {
            argon2,
            cost: work.argon2_cost(),
        })
    }

    /// Reserves the Argon2 work area now rather than at the first round: a session of several
    /// operations then fails at once, before anything is asked, when the browser cannot give it.
    pub fn reserve(&self) -> Result<(), MhfeError> {
        self.argon2
            .reserve(self.cost.memory_kib)
            .map_err(|error| error_of(error, self.cost))
    }

    /// Runs the known answer of the page's Argon2 build ([`BrowserArgon2Check::verify`]): an
    /// operation calls it before its first round and after its last, so that a build that went
    /// wrong in between, such as in the optimized code a browser makes of a long loop, is not
    /// trusted with the result.
    ///
    /// [`BrowserArgon2Check::verify`]: super::BrowserArgon2Check::verify
    pub fn verify_known_answer(&self) -> Result<(), MhfeError> {
        super::BrowserArgon2Check::new(&self.argon2).verify()
    }
}

/// Fills `key` with Argon2id(password, salt) at `cost` through the page's Argon2 build, as every
/// call of the engine and of its known-answer check does.
pub(super) fn derive_with(
    argon2: &JsArgon2,
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    cost: Argon2Cost,
    key: &mut [u8; KEY_BYTES],
) -> Result<(), MhfeError> {
    super::mark_key_unwritten(key);
    argon2
        .derive(password, salt, cost.memory_kib, cost.passes, key)
        .map_err(|error| error_of(error, cost))?;
    // A bridge that wrote into a stale view of this module's memory, or not at all, leaves the
    // key as it was.
    super::check_key_written(key)
}

/// The error of a failed call of the Argon2 build: "MEMORY_ALLOCATION_FAILED: …" becomes
/// [`MhfeError::MemoryAllocation`], anything else [`MhfeError::Argon2`].
fn error_of(error: JsValue, cost: Argon2Cost) -> MhfeError {
    let message = crate::wasm_api::js_message(&error)
        .unwrap_or_else(|| "the browser Argon2 engine failed".to_owned());
    if message.starts_with("MEMORY_ALLOCATION_FAILED") {
        MhfeError::MemoryAllocation {
            bytes: cost.memory_bytes(),
        }
    } else {
        MhfeError::Argon2(message)
    }
}

impl Argon2Engine for BrowserEngine {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        derive_with(&self.argon2, password, salt, self.cost, key)
    }
}
