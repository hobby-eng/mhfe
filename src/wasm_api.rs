//! The WebAssembly API that web/mhfe-worker.js calls. Each call runs one whole operation
//! synchronously inside the worker; the worker reports progress and the page cancels by
//! terminating the worker.
//!
//! Passwords arrive as UTF-8 bytes and are wiped here after use. Results leave as JSON text:
//! a recovered phrase has to become a JavaScript string to be shown, and such strings cannot be
//! wiped, so the page should show it only on request and drop it soon after.

use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::engine::browser::{BrowserEngine, JsArgon2, HIGHEST_BROWSER_MEMORY_LEVEL};
use crate::wallet::{parse_fingerprint, BitcoinAddress, DerivationPath, SearchLimits};
use crate::{
    Mhfe, MhfeError, Password, PhraseLength, Recovery, Reference, WordCount, MAX_MEMORY_LEVEL,
    MAX_PIM, ROUNDS, SUITE_ID,
};

/// Changes when this API changes incompatibly.
const API_VERSION: u32 = 6;

/// "CODE: message", the form the worker and the client parse.
fn js_error(error: MhfeError) -> JsError {
    JsError::new(&format!("{}: {error}", error.code()))
}

fn serialization_error(error: serde_json::Error) -> JsError {
    JsError::new(&format!("INTERNAL_ERROR: {error}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuiteParameters {
    api_version: u32,
    suite_id: &'static str,
    rounds: u32,
    max_pim: u32,
    max_memory_level: u32,
    highest_browser_memory_level: u32,
}

/// The fixed suite values and the limits of the browser build.
#[wasm_bindgen(js_name = suiteParameters)]
pub fn suite_parameters() -> Result<String, JsError> {
    serde_json::to_string(&SuiteParameters {
        api_version: API_VERSION,
        suite_id: SUITE_ID,
        rounds: ROUNDS,
        max_pim: MAX_PIM,
        max_memory_level: MAX_MEMORY_LEVEL,
        highest_browser_memory_level: HIGHEST_BROWSER_MEMORY_LEVEL,
    })
    .map_err(serialization_error)
}

/// Checks an original phrase before anything runs; returns its word count.
#[wasm_bindgen(js_name = checkPhrase)]
pub fn check_phrase(phrase: &str) -> Result<u32, JsError> {
    crate::check_phrase(phrase)
        .map(|words| words as u32)
        .map_err(js_error)
}

/// Checks an original phrase and returns it with every word written out.
#[wasm_bindgen(js_name = readPhrase)]
pub fn read_phrase(phrase: &str) -> Result<String, JsError> {
    crate::read_phrase(phrase)
        .map(|phrase| phrase.to_string())
        .map_err(js_error)
}

/// The lengths other than the phrase's own that automatic detection would also accept after
/// recovery: almost always empty. When not, the page should tell the user to note the word count
/// and to choose it during recovery.
#[wasm_bindgen(js_name = otherDetectedLengths)]
pub fn other_detected_lengths(phrase: &str) -> Result<Vec<u32>, JsError> {
    let lengths = crate::other_detected_lengths(phrase).map_err(js_error)?;
    Ok(lengths.into_iter().map(|words| words as u32).collect())
}

/// Checks a container and returns it with every word written out.
#[wasm_bindgen(js_name = checkContainer)]
pub fn check_container(container: &str) -> Result<String, JsError> {
    crate::check_container(container).map_err(js_error)
}

/// Checks a password before anything runs. The bytes are wiped afterwards.
#[wasm_bindgen(js_name = checkPassword)]
pub fn check_password(password_utf8: Vec<u8>) -> Result<(), JsError> {
    password_from(password_utf8).map(|_| ())
}

/// Encrypts `phrase` and returns the 24-word container once its check has passed.
///
/// After the first twelve rounds `on_unverified` receives the container, so that a page can
/// show it, marked as not yet verified, while the check runs.
#[wasm_bindgen]
pub fn encrypt(
    phrase: &str,
    password_utf8: Vec<u8>,
    pim: f64,
    memory_level: f64,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
    on_unverified: &js_sys::Function,
) -> Result<String, JsError> {
    let password = password_from(password_utf8)?;
    let mut mhfe = mhfe_for(pim, memory_level, argon2)?;
    let mut on_progress = |round, rounds| report(on_round, round, rounds);
    let new = mhfe
        .encrypt_unchecked(phrase, &password, &mut on_progress)
        .map_err(js_error)?;
    on_unverified
        .call1(&JsValue::UNDEFINED, &JsValue::from_str(&new.words))
        .map_err(|_| js_error(MhfeError::Cancelled))?;
    mhfe.check_new_container(&new, &password, &mut on_progress)
        .map_err(js_error)?;
    Ok(new.words.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateJson<'a> {
    words: usize,
    verified: bool,
    phrase: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryJson<'a> {
    /// "phrase" for one result, "ambiguous" when several lengths passed their check.
    kind: &'static str,
    candidates: Vec<CandidateJson<'a>>,
}

/// Recovers the phrase. `words` is 0 for automatic detection, otherwise the chosen length.
/// Returns JSON: `{ kind, candidates: [{ words, verified, phrase }] }`.
#[wasm_bindgen]
pub fn decrypt(
    container: &str,
    password_utf8: Vec<u8>,
    pim: f64,
    memory_level: f64,
    words: f64,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
) -> Result<String, JsError> {
    let password = password_from(password_utf8)?;
    let length = match whole_number(words, "INVALID_WORD_COUNT", "the word count")? {
        0 => PhraseLength::Detect,
        words => PhraseLength::Words(WordCount::new(words as usize).map_err(js_error)?),
    };
    let mut mhfe = mhfe_for(pim, memory_level, argon2)?;
    let recovery = mhfe
        .decrypt(container, &password, length, &mut |round, rounds| {
            report(on_round, round, rounds)
        })
        .map_err(js_error)?;
    let (kind, phrases) = match recovery {
        Recovery::Phrase(phrase) => ("phrase", vec![phrase]),
        Recovery::Ambiguous(candidates) => ("ambiguous", candidates),
    };
    let json = RecoveryJson {
        kind,
        candidates: phrases
            .iter()
            .map(|candidate| CandidateJson {
                words: candidate.words,
                verified: candidate.verified,
                phrase: &candidate.phrase,
            })
            .collect(),
    };
    serde_json::to_string(&json).map_err(serialization_error)
}

/// The rehearsal check; returns only whether the recovery matches the reference.
///
/// `reference_kind` is "address", "fingerprint" or "words"; `reference` is the address, the
/// eight hex digits or the word count; `path` is empty for the standard path search.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn check(
    container: &str,
    password_utf8: Vec<u8>,
    pim: f64,
    memory_level: f64,
    reference_kind: &str,
    reference: &str,
    path: &str,
    passphrase_utf8: Vec<u8>,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
) -> Result<bool, JsError> {
    // Both secrets are put under a wiping owner before anything can fail, so that no early
    // return drops either of them unwiped. The passphrase is read in place, without a copy.
    let passphrase_bytes = Zeroizing::new(passphrase_utf8);
    let password = password_from(password_utf8)?;
    let passphrase = std::str::from_utf8(&passphrase_bytes)
        .map_err(|_| JsError::new("INVALID_PASSPHRASE: the BIP39 passphrase is not UTF-8"))?;
    let address: BitcoinAddress;
    let derivation_path: Option<DerivationPath>;
    let reference = match reference_kind {
        "address" => {
            address = reference.parse().map_err(js_error)?;
            derivation_path = match path {
                "" => None,
                text => Some(text.parse().map_err(js_error)?),
            };
            Reference::Address {
                address: &address,
                passphrase,
                path: derivation_path.as_ref(),
                limits: SearchLimits::default(),
            }
        }
        "fingerprint" => Reference::Fingerprint {
            fingerprint: parse_fingerprint(reference).map_err(js_error)?,
            passphrase,
        },
        "words" => Reference::BuiltInCheck {
            words: reference
                .parse()
                .map_err(|_| MhfeError::InvalidWordCount(0))
                .and_then(WordCount::new)
                .map_err(js_error)?,
        },
        other => {
            return Err(JsError::new(&format!(
                "INVALID_REQUEST: unknown reference kind {other}"
            )))
        }
    };
    let mut mhfe = mhfe_for(pim, memory_level, argon2)?;
    mhfe.check(container, &password, &reference, &mut |round, rounds| {
        report(on_round, round, rounds)
    })
    .map_err(js_error)
}

fn password_from(password_utf8: Vec<u8>) -> Result<Password, JsError> {
    let bytes = Zeroizing::new(password_utf8);
    Password::from_utf8(&bytes).map_err(js_error)
}

fn mhfe_for(pim: f64, memory_level: f64, argon2: JsArgon2) -> Result<Mhfe<BrowserEngine>, JsError> {
    let pim = whole_number(pim, "INVALID_PIM", "the PIM")?;
    let memory_level = whole_number(memory_level, "INVALID_MEMORY_LEVEL", "the memory level")?;
    let work = crate::WorkFactor::new(pim, memory_level).map_err(js_error)?;
    let engine = BrowserEngine::new(argon2, work).map_err(js_error)?;
    Ok(Mhfe::with_engine(work, engine))
}

/// A setting or word count as JavaScript passed it. wasm-bindgen would turn a `u32` parameter
/// into the number modulo 2^32, so that 2^32 became 0 and -1 became 4294967295; taking the
/// number as it is lets anything but a whole number in the `u32` range be refused with the
/// error code `code`. The range checks of the caller then apply to the exact value.
fn whole_number(value: f64, code: &str, name: &str) -> Result<u32, JsError> {
    // NaN and the infinities have a NaN fractional part, so they fail the first test.
    if value.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&value) {
        Ok(value as u32)
    } else {
        Err(JsError::new(&format!(
            "{code}: {name} must be a whole number, not {value}"
        )))
    }
}

/// Tells the worker that round `round` of `rounds` starts: 24 for an encryption, which checks
/// its result, and 12 otherwise. An exception thrown there stops the operation.
fn report(on_round: &js_sys::Function, round: u32, rounds: u32) -> Result<(), MhfeError> {
    on_round
        .call2(
            &JsValue::UNDEFINED,
            &JsValue::from(round),
            &JsValue::from(rounds),
        )
        .map(|_| ())
        .map_err(|_| MhfeError::Cancelled)
}
