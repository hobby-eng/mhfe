// @ts-check
// Page callback failures and asynchronous answers.
import { MhfeError } from "./errors.js";

/**
 * The error of a page's callback named `name` that threw or rejected with `cause`.
 * @param {string} name
 * @param {unknown} cause
 */
export function callbackFailed(name, cause) {
  const option = Object.hasOwn(PAGE_CALLBACKS, name) ? PAGE_CALLBACKS[name] : name;
  return new MhfeError("CALLBACK_FAILED", `The page's ${option} callback failed.`, { cause });
}

/**
 * The page's option that each worker message reaches, which a failure names rather than the
 * message (AUD-024-API007).
 * @type {Record<string, string>}
 */
const PAGE_CALLBACKS = {
  progress: "onProgress",
  componentStart: "onProgress",
  component: "onProgress",
  draws: "onProgress",
  unverified: "onUnverified",
  noLength: "onNoLength",
  ownerCheck: "owner",
  confirmAgain: "onConfirmAgain",
};

/**
 * The page's answer of `callback` to `value`; what the page's own function throws or rejects with
 * becomes CALLBACK_FAILED naming `name`, its option, with the page's error as the cause. A class
 * then checks the answer, and its refusal ends the operation as it is.
 * @template V, T
 * @param {(value: V) => T | PromiseLike<T>} callback
 * @param {V} value
 * @param {string} name
 * @returns {Promise<T>}
 */
export async function askPage(callback, value, name) {
  try {
    return await callback(value);
  } catch (cause) {
    throw callbackFailed(name, cause);
  }
}
