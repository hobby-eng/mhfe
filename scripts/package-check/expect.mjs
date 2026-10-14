// How the checks of the browser package compare what they get: a refusal by its code or its whole
// message, the named fields of a result, lists in one order, and a turn of the event loop for the
// events of the page and its workers to arrive.
import assert from "node:assert/strict";

/** Expects `action` to throw the WebAssembly's error with `code`, "CODE: message". */
export function expectCode(code, action) {
  assert.throws(action, (error) => error.message.startsWith(`${code}: `), code);
}

/** Like expectCode, for the whole message, "CODE: message" as the WebAssembly throws it. */
export function expectMessage(message, action, description = message) {
  assert.throws(action, { message }, description);
}

/** The round callback of a refusal that must come before any Argon2 round. */
export function noRoundExpected(stage, round) {
  throw new Error(`the refusal came after ${stage} round ${round} had started`);
}

/** The named fields of an object, to compare them without the others. */
export function fieldsOf(object, names) {
  return Object.fromEntries(names.map((name) => [name, object[name]]));
}

/** The texts of `values` in a new array, in the order of sort() without a comparator. */
export function sorted(values) {
  // sort() without a comparator orders strings by their UTF-16 code units, as < does.
  return [...values].sort((left, right) => (left < right ? -1 : Number(left > right)));
}

/** Lets the event loop turn once, so that the replies of the workers reach the page. */
export const nextTurn = () => new Promise((resolve) => setTimeout(resolve, 0));
