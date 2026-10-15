//! Shared translation of a thrown JavaScript value, below the engine and its browser bindings.

use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

/// The thrown text in a wiping owner (an exception might contain a misplaced secret), or an Error's message; `None` for another value, which the caller names.
pub(crate) fn message(error: &JsValue) -> Option<Zeroizing<String>> {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(error, &JsValue::from_str("message"))
                .ok()?
                .as_string()
        })
        .map(Zeroizing::new)
}
