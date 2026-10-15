// @ts-check
// Shared page argument validation.
import { MhfeError } from "./errors.js";
/** @import { MhfePasswordRepair } from "../runtime.d.ts" */

/**
 * The highest word position the Rust core reads (a 32-bit number): of a password's repair, which
 * it refuses above the password's words (PASSWORD_REPAIR_NOT_OFFERED), and of a chosen word of a
 * new phrase, which it refuses above 24 (INVALID_WORD_WISH).
 */
export const HIGHEST_WORD_POSITION = 0xffff_ffff;

/**
 * A review choice of the password check word: undefined or "asTyped" keeps the password as typed,
 * "corrected" takes its written form, `{ repair: position }` the repair at that word. Gives the
 * choice and the position as the worker takes them.
 * @param {MhfePasswordRepair | undefined} choice
 * @param {string} name
 * @returns {[choice: string, position: number]}
 */
export function describeChoice(choice, name) {
  if (choice === undefined || choice === "asTyped") return ["", 0];
  if (choice === "corrected") return ["corrected", 0];
  if (choice !== null && typeof choice === "object" && Number.isSafeInteger(choice.repair)) {
    // Deliberate copy of MhfeError::PasswordRepairNotOffered: 0 is the worker's no-repair
    // sentinel. The package tests compare this refusal with the library (AUD-024-API002).
    if (choice.repair < 1 || choice.repair > HIGHEST_WORD_POSITION) {
      throw new MhfeError(
        "PASSWORD_REPAIR_NOT_OFFERED",
        "The review of this password did not offer that choice",
      );
    }
    return ["repair", choice.repair];
  }
  throw new TypeError(
    `${name} must be "asTyped", "corrected" or { repair: position }, a word number from 1.`,
  );
}

/**
 * Text, such as a phrase or an address, is a string; anything else is a TypeError.
 * @param {unknown} value
 * @param {string} name
 * @returns {asserts value is string}
 */
export function requireText(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string.`);
}

/**
 * Refuses an own key of `options` that `method` does not take, with a TypeError that names it, as
 * a misspelled option such as PIM for pim would otherwise fall back to its default unseen
 * (AUD-024-API003). A key whose value is undefined counts as absent; a value that is not an object
 * is left to the method's own checks.
 * @param {unknown} options
 * @param {readonly string[]} keys
 * @param {string} method
 */
export function requireKnownKeys(options, keys, method) {
  if (typeof options !== "object" || options === null) return;
  for (const [key, value] of Object.entries(options)) {
    if (value !== undefined && !keys.includes(key)) {
      throw new TypeError(
        `${method}() has no option ${JSON.stringify(key)}; its options are ${keys.join(", ")}.`,
      );
    }
  }
}

/**
 * Makes each method of `prototype` that `optionKeys` names refuse an options object with a key it
 * does not take ([`requireKnownKeys`]), before the method itself runs; the methods are async, so
 * the refusal rejects their promise. The lists stand beside each class, one place for its options.
 * @param {object} prototype
 * @param {Record<string, readonly string[]>} optionKeys
 */
export function refuseUnknownOptions(prototype, optionKeys) {
  for (const [name, keys] of Object.entries(optionKeys)) {
    const method = /** @type {(...args: unknown[]) => Promise<unknown>} */ (
      Reflect.get(prototype, name)
    );
    Object.defineProperty(prototype, name, {
      configurable: true,
      writable: true,
      /** @param {unknown[]} args */
      async value(...args) {
        requireKnownKeys(args[0], keys, name);
        return Reflect.apply(method, this, args);
      },
    });
  }
}

/**
 * A choice that is true or false; anything else is a TypeError.
 * @param {unknown} value
 * @param {string} name
 * @returns {asserts value is boolean}
 */
export function requireBoolean(value, name) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be a boolean.`);
}

/**
 * A callback of the page, which it may leave out; anything else is a TypeError.
 * @param {unknown} value
 * @param {string} name
 */
export function requireCallback(value, name) {
  if (value !== undefined && typeof value !== "function") {
    throw new TypeError(`${name} must be a function.`);
  }
}
