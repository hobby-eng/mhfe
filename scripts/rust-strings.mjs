// What the checks of the browser package read from the Rust sources: their string literals, and
// those that are vectors, which no script of the package and no module built without their part
// may carry; and a WebAssembly with one of them damaged, whose self-check must fail
// (scripts/verify-browser-package.mjs, scripts/verify-single-modules.mjs).

import { RustSource } from "./rust-source.mjs";

/** UTF-8 string bodies decoded by the shared bounded Rust lexical reader. */
export function rustStrings(source) {
  return new RustSource(source).strings();
}

/**
 * Whether a string of a known-answers file is a vector: 8 or more characters with a digit and no
 * space (an address, a key, a digest), or a phrase of 12 words or more.
 */
export function isVectorText(text) {
  return (
    text.length >= 8 &&
    ((/[0-9]/u.test(text) && !text.includes(" ")) || text.split(" ").length >= 12)
  );
}

/**
 * The bytes of `wasm` with the last byte of every copy of `text` changed, as a fault of the
 * download, the disk or the memory would damage a vector. Throws when `wasm` holds no copy.
 */
export function damagedCopies(wasm, text) {
  const bytes = Buffer.from(wasm);
  const needle = Buffer.from(text);
  let copies = 0;
  for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) {
    bytes[at + needle.length - 1] ^= 1;
    copies += 1;
  }
  if (copies === 0) throw new Error(`the WebAssembly holds no copy of ${text}`);
  return bytes;
}
