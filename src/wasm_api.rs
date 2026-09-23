use crate::{
    suite_parameters, CycleWalkControl, CycleWalkDecryptionResult, CycleWalkEncryptionResult,
    CycleWalkProgress, DecryptionResult, EncryptionResult, MhfeEngine, MhfeError,
    NormalizedPassword, API_VERSION,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn checked_pim(pim: f64) -> Result<u32, JsError> {
    if !pim.is_finite() || pim.fract() != 0.0 || pim < 0.0 || pim > crate::MAX_PIM as f64 {
        return Err(JsError::new(&format!(
            "INVALID_PIM: PIM must be an integer from 0 through {}",
            crate::MAX_PIM
        )));
    }
    Ok(pim as u32)
}

fn checked_source_words(source_words: f64) -> Result<usize, JsError> {
    if !source_words.is_finite()
        || source_words.fract() != 0.0
        || ![12.0, 15.0, 18.0, 21.0, 24.0].contains(&source_words)
    {
        return Err(JsError::new(
            "INVALID_SOURCE_WORDS: sourceWords must be 12, 15, 18, 21, or 24",
        ));
    }
    Ok(source_words as usize)
}

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserCycleWalkEncryptionResult<'a> {
    api_version: u32,
    suite_id: &'a str,
    profile_id: &'a str,
    pim: u32,
    effective_passes: u32,
    source_words: usize,
    iterations: u64,
    preserved_final_word: &'a str,
    encrypted_mnemonic: &'a str,
}

impl<'a> From<&'a CycleWalkEncryptionResult> for BrowserCycleWalkEncryptionResult<'a> {
    fn from(result: &'a CycleWalkEncryptionResult) -> Self {
        Self {
            api_version: API_VERSION,
            suite_id: &result.suite_id,
            profile_id: &result.profile_id,
            pim: result.pim,
            effective_passes: result.effective_passes,
            source_words: result.source_words,
            iterations: result.iterations,
            preserved_final_word: &result.preserved_final_word,
            encrypted_mnemonic: &result.encrypted_mnemonic,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserCycleWalkDecryptionResult<'a> {
    api_version: u32,
    suite_id: &'a str,
    profile_id: &'a str,
    pim: u32,
    effective_passes: u32,
    source_words: usize,
    iterations: u64,
    preserved_final_word: &'a str,
    recovered_mnemonic: &'a str,
}

impl<'a> From<&'a CycleWalkDecryptionResult> for BrowserCycleWalkDecryptionResult<'a> {
    fn from(result: &'a CycleWalkDecryptionResult) -> Self {
        Self {
            api_version: API_VERSION,
            suite_id: &result.suite_id,
            profile_id: &result.profile_id,
            pim: result.pim,
            effective_passes: result.effective_passes,
            source_words: result.source_words,
            iterations: result.iterations,
            preserved_final_word: &result.preserved_final_word,
            recovered_mnemonic: &result.recovered_mnemonic,
        }
    }
}

fn emit_cycle_walk_progress(
    callback: &js_sys::Function,
    progress: CycleWalkProgress,
) -> Result<CycleWalkControl, String> {
    let json = serde_json::to_string(&progress).map_err(|error| error.to_string())?;
    let result = callback
        .call1(&JsValue::UNDEFINED, &JsValue::from_str(&json))
        .map_err(|error| format!("{error:?}"))?;
    Ok(if result.as_bool() == Some(false) {
        CycleWalkControl::Cancel
    } else {
        CycleWalkControl::Continue
    })
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
    pub fn new(pim: f64) -> Result<WasmMhfeEngine, JsError> {
        let pim = checked_pim(pim)?;
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

    #[wasm_bindgen(js_name = encryptPreservingFinalWordJson)]
    pub fn encrypt_preserving_final_word_json(
        &mut self,
        mnemonic: &str,
        progress_callback: &js_sys::Function,
    ) -> Result<String, JsError> {
        let password = self
            .password
            .as_ref()
            .ok_or(MhfeError::PasswordNotSet)
            .map_err(js_error)?;
        let mut callback_error = None;
        let result = self.inner.encrypt_preserving_final_word_with_progress(
            mnemonic,
            password,
            |progress| match emit_cycle_walk_progress(progress_callback, progress) {
                Ok(control) => control,
                Err(error) => {
                    callback_error = Some(error);
                    CycleWalkControl::Cancel
                }
            },
        );
        if let Some(error) = callback_error {
            return Err(JsError::new(&format!("PROGRESS_CALLBACK_FAILURE: {error}")));
        }
        let result = result.map_err(js_error)?;
        serde_json::to_string(&BrowserCycleWalkEncryptionResult::from(&result)).map_err(json_error)
    }

    #[wasm_bindgen(js_name = decryptJson)]
    pub fn decrypt_json(&mut self, container: &str, source_words: f64) -> Result<String, JsError> {
        let source_words = checked_source_words(source_words)?;
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

    #[wasm_bindgen(js_name = decryptPreservingFinalWordJson)]
    pub fn decrypt_preserving_final_word_json(
        &mut self,
        container: &str,
        progress_callback: &js_sys::Function,
    ) -> Result<String, JsError> {
        let password = self
            .password
            .as_ref()
            .ok_or(MhfeError::PasswordNotSet)
            .map_err(js_error)?;
        let mut callback_error = None;
        let result = self.inner.decrypt_preserving_final_word_with_progress(
            container,
            password,
            |progress| match emit_cycle_walk_progress(progress_callback, progress) {
                Ok(control) => control,
                Err(error) => {
                    callback_error = Some(error);
                    CycleWalkControl::Cancel
                }
            },
        );
        if let Some(error) = callback_error {
            return Err(JsError::new(&format!("PROGRESS_CALLBACK_FAILURE: {error}")));
        }
        let result = result.map_err(js_error)?;
        serde_json::to_string(&BrowserCycleWalkDecryptionResult::from(&result)).map_err(json_error)
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
