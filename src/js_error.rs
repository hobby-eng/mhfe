//! Shared translation of a thrown JavaScript value, below the engine and its browser bindings.

use wasm_bindgen::JsValue;

/// The thrown text, or an Error's message; `None` for another value, which the caller names.
pub(crate) fn message(error: &JsValue) -> Option<String> {
    error.as_string().or_else(|| {
        js_sys::Reflect::get(error, &JsValue::from_str("message"))
            .ok()?
            .as_string()
    })
}
