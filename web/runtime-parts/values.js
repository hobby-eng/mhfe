// @ts-check
// Small shared value readers and presentation.

/**
 * Whether `value` is an object, whose fields any code may read, each of a type not known yet.
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The message of an error that a browser interface or the WebAssembly threw or rejected with, as
 * text: they give Error objects, and anything else has no message ("undefined").
 * @param {unknown} error
 */
export function messageOf(error) {
  return String(isRecord(error) ? error.message : undefined);
}

/**
 * Counts as a message lists them, the last after "or": "12, 15, 18 or 21" (src/phrase.rs).
 * @param {readonly number[]} counts
 */
export function countsText(counts) {
  return counts.length < 2
    ? counts.join("")
    : `${counts.slice(0, -1).join(", ")} or ${counts.at(-1)}`;
}

/**
 * A page shows an error message as it is, so it starts with a capital letter, as the messages of
 * the command-line tool do. The Rust core's messages start in lower case to fit inside a sentence.
 * @param {string} text
 */
export function sentence(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
