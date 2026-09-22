use crate::{
    suite_parameters, DecryptionResult, EncryptionResult, MhfeEngine, MhfeError,
    NormalizedPassword, API_VERSION,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_error(error: MhfeError) -> JsError {
    JsError::new(&format!("{}: {error}", error.code()))
}

fn json_error(error: serde_json::Error) -> JsError {
    JsError::new(&format!("SERIALIZATION_FAILURE: {error}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserEncryptionResult<'a> {
    api_version: u32,
    suite_id: &'a str,
    pim: u32,
    effective_passes: u32,
    source_words: usize,
    encrypted_mnemonic: &'a str,
}

impl<'a> From<&'a EncryptionResult> for BrowserEncryptionResult<'a> {
    fn from(result: &'a EncryptionResult) -> Self {
        Self {
            api_version: API_VERSION,
            suite_id: &result.suite_id,
            pim: result.pim,
            effective_passes: result.effective_passes,
            source_words: result.source_words,
            encrypted_mnemonic: &result.encrypted_mnemonic,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserDecryptionResult<'a> {
    api_version: u32,
    suite_id: &'a str,
    pim: u32,
    effective_passes: u32,
    source_words: usize,
    recovered_mnemonic: &'a str,
    recovery_verifier: &'static str,
}

impl<'a> From<&'a DecryptionResult> for BrowserDecryptionResult<'a> {
    fn from(result: &'a DecryptionResult) -> Self {
        Self {
            api_version: API_VERSION,
            suite_id: &result.suite_id,
            pim: result.pim,
            effective_passes: result.effective_passes,
            source_words: result.source_words,
            recovered_mnemonic: &result.recovered_mnemonic,
            recovery_verifier: if result.recovery_verified {
                "matched"
            } else {
                "unavailable"
            },
        }
    }
}

/// Browser-facing MHFE engine.
///
/// Construct and call this object inside a dedicated Web Worker. Each instance
/// owns and reuses one 512 MiB Argon2 work area. Dropping/freeing the object
/// zeroizes that reachable work area. Terminating the Worker is the supported
/// cancellation mechanism for an active synchronous operation.
#[wasm_bindgen(js_name = MhfeEngine)]
pub struct WasmMhfeEngine {
    inner: MhfeEngine,
    password: Option<NormalizedPassword>,
}

#[wasm_bindgen(js_class = MhfeEngine)]
impl WasmMhfeEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(pim: u32) -> Result<WasmMhfeEngine, JsError> {
        Ok(Self {
            inner: MhfeEngine::new(pim).map_err(js_error)?,
            password: None,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn pim(&self) -> u32 {
        self.inner.pim()
    }

    #[wasm_bindgen(getter, js_name = effectivePasses)]
    pub fn effective_passes(&self) -> u32 {
        self.inner.effective_passes()
    }

    /// Load an ASCII password. ASCII is unchanged by Unicode 18 NPSS-NFKD.
    #[wasm_bindgen(js_name = setAsciiPassword)]
    pub fn set_ascii_password(&mut self, password: &str) -> Result<(), JsError> {
        self.password = Some(NormalizedPassword::from_test_ascii(password).map_err(js_error)?);
        Ok(())
    }

    /// Load already-normalized Unicode 18 NPSS-NFKD UTF-8 bytes. Ownership is
    /// moved into a zeroizing Rust object without retaining another Rust copy.
    #[wasm_bindgen(js_name = setPreNormalizedPassword)]
    pub fn set_pre_normalized_password(&mut self, password_utf8: Vec<u8>) -> Result<(), JsError> {
        self.password =
            Some(NormalizedPassword::from_npss_nfkd_utf8_owned(password_utf8).map_err(js_error)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = clearPassword)]
    pub fn clear_password(&mut self) {
        self.password = None;
    }

    #[wasm_bindgen(js_name = encryptJson)]
    pub fn encrypt_json(&mut self, mnemonic: &str) -> Result<String, JsError> {
        let password = self
            .password
            .as_ref()
            .ok_or(MhfeError::PasswordNotSet)
            .map_err(js_error)?;
        let result = self
            .inner
            .encrypt_mnemonic(mnemonic, password)
            .map_err(js_error)?;
        serde_json::to_string(&BrowserEncryptionResult::from(&result)).map_err(json_error)
    }

    #[wasm_bindgen(js_name = decryptJson)]
    pub fn decrypt_json(
        &mut self,
        container: &str,
        source_words: usize,
    ) -> Result<String, JsError> {
        let password = self
            .password
            .as_ref()
            .ok_or(MhfeError::PasswordNotSet)
            .map_err(js_error)?;
        let result = self
            .inner
            .decrypt_mnemonic(container, source_words, password)
            .map_err(js_error)?;
        serde_json::to_string(&BrowserDecryptionResult::from(&result)).map_err(json_error)
    }

    #[wasm_bindgen(js_name = decryptAutoJson)]
    pub fn decrypt_auto_json(&mut self, container: &str) -> Result<String, JsError> {
        let password = self
            .password
            .as_ref()
            .ok_or(MhfeError::PasswordNotSet)
            .map_err(js_error)?;
        let result = self
            .inner
            .decrypt_mnemonic_auto(container, password)
            .map_err(js_error)?;
        serde_json::to_string(&BrowserDecryptionResult::from(&result)).map_err(json_error)
    }
}

#[wasm_bindgen(js_name = suiteParametersJson)]
pub fn suite_parameters_json() -> Result<String, JsError> {
    serde_json::to_string(&suite_parameters()).map_err(json_error)
}
