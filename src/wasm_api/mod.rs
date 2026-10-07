//! The WebAssembly API of the browser package, as independent modules, each behind its own Cargo
//! feature and used by its own JavaScript class (web/). The package builds them all into one
//! WebAssembly, since they share most of their code; another program can build only the ones it
//! needs:
//!
//! - core: encryption, recovery, the rehearsal check, rekey, hidden wallets and the self-test, with
//!   Argon2;
//! - repair: repair words and the repair of a damaged plate;
//! - passwords: the password check word, the password generator and the strength estimate;
//! - wallet: the wallet check of a phrase, fingerprints, address search scopes and new phrases.
//!
//! The bindings only translate: every rule lives in the library. Secrets, the seed phrases among
//! them, arrive as UTF-8 bytes and are wiped here after use ([`SecretText`]): wasm-bindgen copies
//! a text argument into this module's memory and frees it without overwriting it. A container
//! arrives as text, as the library keeps it: without its password it reveals nothing of the
//! phrase. Results that hold a secret leave as a JavaScript string made from a wiped buffer; such
//! strings cannot be wiped in JavaScript, so a page shows them only on request and drops them soon
//! after.
//!
//! Each module also exports its self-check (`selfCheckCore`, `selfCheckArgon2`,
//! `selfCheckRepair`, `selfCheckPasswords`, `selfCheckWallet`): the library's set of known
//! answers for the parts that module computes ([`crate::self_check::sets`]), which its class runs
//! once before the first operation and again in the page's full self-test.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::self_check::{ComponentResult, SelfCheck, Tier};
use crate::MhfeError;

#[cfg(feature = "browser-core")]
mod core;
#[cfg(feature = "browser-passwords")]
mod passwords;
#[cfg(feature = "browser-repair")]
mod repair;
#[cfg(feature = "browser-wallet")]
mod wallet;

/// The release version of the package, the same in every module: the one identity a page checks.
#[wasm_bindgen(js_name = packageVersion)]
pub fn package_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// "CODE: message", the form the workers and the clients parse.
pub(crate) fn js_error(error: MhfeError) -> JsError {
    JsError::new(&format!("{}: {error}", error.code()))
}

pub(crate) fn serialization_error(error: serde_json::Error) -> JsError {
    JsError::new(&format!("INTERNAL_ERROR: {error}"))
}

/// A result without secrets as JSON text.
pub(crate) fn json(value: &impl Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(serialization_error)
}

/// One part of a self-check as a page reads it. The detail names a case by its place, never a
/// secret, a coin or a vector's text (see [`crate::self_check::ComponentOutcome`]).
#[derive(Serialize)]
struct ComponentJson<'a> {
    id: &'static str,
    label: &'static str,
    /// "passed", "warning", "notAvailable", "notRun" or "failed".
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

impl<'a> ComponentJson<'a> {
    fn of(result: &'a ComponentResult) -> Self {
        Self {
            id: result.id(),
            label: result.label(),
            outcome: result.outcome().name(),
            detail: result.outcome().detail(),
        }
    }
}

#[derive(Serialize)]
struct SelfCheckJson<'a> {
    version: &'static str,
    tier: &'static str,
    passed: bool,
    /// Every part of the set in its order, the skipped ones included, so that the page can place
    /// the outcomes it has from another module among those of this run.
    ids: Vec<&'static str>,
    /// The parts that ran, in their order.
    components: Vec<ComponentJson<'a>>,
}

/// Runs `set` at the tier named `tier`, "startup" or "full" (INVALID_REQUEST otherwise), without
/// the parts `skip_ids`, which another module of the page has checked already. `on_start(id,
/// label)` hears of each part just before it runs, so that the worker can name the part in which
/// the WebAssembly stopped, and `on_result(json)` gets each outcome as soon as it is known.
/// Returns JSON `{ version, tier, passed, ids, components: [{ id, label, outcome, detail? }] }`.
pub(crate) fn run_self_check(
    set: SelfCheck<'_>,
    tier: &str,
    skip_ids: &[String],
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    let tier = Tier::from_name(tier).map_err(js_error)?;
    let ids = set.ids();
    let skip: Vec<&str> = skip_ids.iter().map(String::as_str).collect();
    let mut set = set.skip(&skip);
    // The callbacks only report progress, so a page callback that throws does not stop the check:
    // its outcome comes with the result either way.
    let report = set.run(
        tier,
        &mut |id, label| {
            let _ = on_start.call2(
                &JsValue::UNDEFINED,
                &JsValue::from_str(id),
                &JsValue::from_str(label),
            );
        },
        &mut |result| {
            if let Ok(text) = serde_json::to_string(&ComponentJson::of(result)) {
                let _ = on_result.call1(&JsValue::UNDEFINED, &JsValue::from_str(&text));
            }
        },
    );
    json(&SelfCheckJson {
        version: env!("CARGO_PKG_VERSION"),
        tier: report.tier().name(),
        passed: report.passed(),
        ids,
        components: report.results().iter().map(ComponentJson::of).collect(),
    })
}

/// A result that holds a secret as JSON text. It is written twice: once to learn its length, then
/// into a buffer of exactly that size, so that no growing buffer leaves a partial copy behind; the
/// buffer is wiped once the JavaScript string is made from it.
#[cfg(any(
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub(crate) fn secret_json(value: &impl Serialize) -> Result<js_sys::JsString, JsError> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value).map_err(serialization_error)?;
    let mut buffer = zeroize::Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *buffer, value).map_err(serialization_error)?;
    let text = std::str::from_utf8(&buffer)
        .map_err(|_| JsError::new("INTERNAL_ERROR: the result is not UTF-8"))?;
    Ok(js_sys::JsString::from(text))
}

/// Counts the bytes written to it, and keeps none.
#[cfg(any(
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
struct ByteCounter(usize);

#[cfg(any(
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Secret UTF-8 bytes from JavaScript, wiped when dropped, read as text in place.
#[cfg(any(
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub(crate) struct SecretText(zeroize::Zeroizing<Vec<u8>>);

#[cfg(any(
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
impl SecretText {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    #[cfg(feature = "browser-core")]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The text, or `error` when the bytes are not UTF-8.
    pub(crate) fn text(&self, error: MhfeError) -> Result<&str, JsError> {
        std::str::from_utf8(&self.0).map_err(|_| js_error(error))
    }

    /// The text of a seed phrase, or INVALID_PHRASE when the bytes are not UTF-8.
    #[cfg(any(feature = "browser-core", feature = "browser-wallet"))]
    pub(crate) fn phrase(&self) -> Result<&str, JsError> {
        self.text(MhfeError::InvalidPhrase("it is not UTF-8 text".to_owned()))
    }
}

/// A setting or count as JavaScript passed it. wasm-bindgen would turn a `u32` parameter into the
/// number modulo 2^32, so that 2^32 became 0 and -1 became 4294967295; taking the number as it is
/// lets anything but a whole number in the `u32` range be refused with the error code `code`.
#[cfg(any(
    feature = "browser-core",
    feature = "browser-repair",
    feature = "browser-passwords"
))]
pub(crate) fn whole_number(value: f64, code: &str, name: &str) -> Result<u32, JsError> {
    // NaN and the infinities have a NaN fractional part, so they fail the first test.
    if value.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&value) {
        Ok(value as u32)
    } else {
        Err(JsError::new(&format!(
            "{code}: {name} must be a whole number, not {value}"
        )))
    }
}

/// The page's random source, `{ fill(bytes) }`, which calls `crypto.getRandomValues`. The bytes
/// are a view of this module's memory, so the source fills them in place.
#[cfg(any(feature = "browser-passwords", feature = "browser-wallet"))]
#[wasm_bindgen]
extern "C" {
    pub(crate) type JsRandom;

    #[wasm_bindgen(method, catch, js_name = fill)]
    fn fill_bytes(this: &JsRandom, bytes: &mut [u8]) -> Result<(), JsValue>;
}

#[cfg(any(feature = "browser-passwords", feature = "browser-wallet"))]
impl crate::random::RandomSource for JsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self.fill_bytes(bytes).map_err(|error| {
            MhfeError::RandomFailed(format!(
                "the page's random source failed: {}",
                js_message(&error)
            ))
        })
    }
}

/// The message of a JavaScript error, such as the browser's own words when getRandomValues
/// refuses, so that the cause reaches the page.
#[cfg(any(feature = "browser-passwords", feature = "browser-wallet"))]
fn js_message(error: &JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(error, &JsValue::from_str("message"))
                .ok()?
                .as_string()
        })
        .unwrap_or_else(|| "it threw something other than an Error".to_owned())
}

/// A review choice of the password check word as a page passes it: `kind` is "" or "asTyped" for
/// the text as typed, "corrected" for its written form, or "repair" with the word's `position`.
#[cfg(any(feature = "browser-core", feature = "browser-passwords"))]
pub(crate) fn review_choice(
    kind: &str,
    position: f64,
) -> Result<Option<crate::check_word::ReviewChoice>, JsError> {
    use crate::check_word::ReviewChoice;
    match kind {
        "" | "asTyped" => Ok(None),
        "corrected" => Ok(Some(ReviewChoice::Corrected)),
        "repair" => {
            let position = whole_number(position, "INVALID_REQUEST", "the repair position")?;
            Ok(Some(ReviewChoice::Repair(position as usize)))
        }
        other => Err(js_error(MhfeError::InvalidRequest(format!(
            "unknown password choice {other}"
        )))),
    }
}
