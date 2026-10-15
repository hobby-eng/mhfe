// @ts-check
/** @import { MhfeErrorCode } from "../../runtime/runtime.js" */
import {
  HIGHEST_BROWSER_MEMORY_LEVEL,
  MAX_PIM,
  MAX_MEMORY_LEVEL,
  WORD_COUNTS,
  REPAIR_WORD_COUNTS,
} from "./values.js";
import { requireSecret, secretOrEmpty, MhfeError, countsText } from "../../runtime/runtime.js";

/**
 * An answer given whether the wallet has a BIP39 passphrase: true or false, nothing else.
 * @param {unknown} walletHasPassphrase
 */
export function requireWalletPassphrase(walletHasPassphrase) {
  if (typeof walletHasPassphrase !== "boolean") {
    throw new TypeError(
      "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.",
    );
  }
}

/**
 * A new password typed twice: both a string or a Uint8Array, a TypeError otherwise; `name` names
 * the password. The two are compared by the library, after the password's own rules
 * (check_word::check_typed_twice), as the command-line tool compares them, so that both give the
 * same refusal. A repetition left out is an empty one, which differs.
 * @param {unknown} password
 * @param {unknown} passwordRepeat
 * @param {string} name
 */
export function requireRepetition(password, passwordRepeat, name) {
  requireSecret(password, name);
  return secretOrEmpty(passwordRepeat, `repeated ${name}`);
}

/**
 * The PIM and memory level, including the browser's memory limit; `isNew` for the new settings of
 * a rekey. Each refusal of a number is the library's sentence for the same code and value
 * (MhfeError's InvalidPim and InvalidMemoryLevel, WorkFactor::new_settings), which
 * scripts/verify-browser-package.mjs keeps in step, before any secret reaches a worker; a value of
 * another type is not repeated (shownNumber).
 * @param {number} pim
 * @param {number} memoryLevel
 * @param {boolean} [isNew]
 */
export function requireSettings(pim, memoryLevel, isNew = false) {
  requireSettingValues(pim, memoryLevel, isNew);
  // Deliberate copy of WorkFactor::require_level's refusal, with its code and message, before any
  // secret reaches a worker; scripts/verify-browser-package.mjs keeps the two in step.
  if (memoryLevel > HIGHEST_BROWSER_MEMORY_LEVEL) {
    throw new MhfeError(
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      `Memory level ${memoryLevel} needs more memory than this environment can use; the highest ` +
        `supported level here is ${HIGHEST_BROWSER_MEMORY_LEVEL}. Use the command-line tool on a ` +
        "64-bit system for higher levels",
    );
  }
}

/** Settings for a description need their valid ranges, without reserving browser memory.
 * @param {number} pim
 * @param {number} memoryLevel
 * @param {boolean} [isNew] */
export function requireSettingValues(pim, memoryLevel, isNew = false) {
  const side = isNew ? "new " : "";
  requireSetting(pim, MAX_PIM, "INVALID_PIM", `${side}PIM`);
  requireSetting(memoryLevel, MAX_MEMORY_LEVEL, "INVALID_MEMORY_LEVEL", `${side}memory level`);
}

/**
 * A setting `name`, a whole number from 0 to `highest`; refused with `code` otherwise.
 * @param {number} value
 * @param {number} highest
 * @param {MhfeErrorCode} code
 * @param {string} name
 */
export function requireSetting(value, highest, code, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > highest) {
    throw new MhfeError(
      code,
      `The ${name} must be a whole number from 0 to ${highest}, not ${shownNumber(value)}`,
    );
  }
}

/**
 * A value a page gave for a number, as a refusal names it: a number as it is, anything else only
 * as "a number" it is not, as a text pasted into the wrong field may be a secret (CORE-24).
 * @param {unknown} value
 */
export function shownNumber(value) {
  return typeof value === "number" ? String(value) : "a number";
}

/**
 * The length of an original seed phrase: 0 to detect it, or a word count; refused with the
 * library's sentence (MhfeError::InvalidWordCount).
 * @param {unknown} words
 * @returns {asserts words is number}
 */
export function requireWordCount(words) {
  if (words !== 0 && (typeof words !== "number" || !WORD_COUNTS.includes(words))) {
    throw new MhfeError(
      "INVALID_WORD_COUNT",
      `The original seed phrase must have ${countsText(WORD_COUNTS)} words, not ` +
        shownNumber(words),
    );
  }
}

/**
 * 0 for no repair words, or a card's count; refused with the library's sentence
 * (repair::require_count).
 * @param {number} count
 */
export function requireRepairWordCount(count) {
  if (!REPAIR_WORD_COUNTS.includes(count)) {
    throw new MhfeError(
      "INVALID_REPAIR_WORDS",
      `The repair words cannot be used: a card has ${countsText(REPAIR_WORD_COUNTS.slice(1))} ` +
        `repair words, not ${shownNumber(count)}`,
    );
  }
}
