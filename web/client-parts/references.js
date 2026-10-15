// @ts-check
/** @import { DescribedConfirmation } from "../types/client-shared.d.ts" */
import {
  WALLET_SEARCH_FORMS,
  ADDRESS_REFERENCE_FORMS,
  CHECK_REFERENCE_FORMS,
  REFERENCE_KINDS,
  REFERENCE_KEYS,
  BUILT_IN_CHECK_WORD_COUNTS,
} from "./values.js";
import { requireWordCount } from "./input.js";
import { requireText, MhfeError, countsText, askPage } from "../../runtime/runtime.js";
/** @import { OwnerCallback, PageOwner } from "../types/client-shared.d.ts" */

/**
 * The reference of a search for missing words: an address or a fingerprint, and with the owner's
 * wallet (`ofWallet`) also `{ walletCheck: true }` or `{ builtInCheck: true }`.
 * @param {Record<string, unknown> | undefined} reference
 * @param {boolean} ofWallet
 * @returns {[kind: string, reference: string, coin: string, path: string]}
 */
export function describeSearchReference(reference, ofWallet) {
  const forms = ofWallet ? WALLET_SEARCH_FORMS : ADDRESS_REFERENCE_FORMS;
  const isObject = reference !== null && typeof reference === "object";
  if (ofWallet && isObject && reference.builtInCheck !== undefined) {
    if (reference.builtInCheck !== true || Object.keys(reference).length !== 1) {
      throw new TypeError(`reference must be exactly one of ${forms}.`);
    }
    return ["builtInCheck", "", "", ""];
  }
  if (
    isObject &&
    (reference.words !== undefined || (!ofWallet && reference.walletCheck !== undefined))
  ) {
    throw new TypeError(`reference must be exactly one of ${forms}.`);
  }
  return describeReference(reference, "reference", forms);
}

/**
 * The one reference of a check. Exactly one of address, fingerprint, words and walletCheck must
 * be given: with several, the check would silently use only one of them. Any other key, such as a
 * passphrase inside the reference instead of beside it, or a misspelled one, is refused rather
 * than dropped; `name` is what the page calls the object.
 * @param {unknown} value
 * @param {string} [name]
 * @param {string} [forms] The forms this operation accepts, in its refusal.
 * @returns {[kind: string, reference: string, coin: string, path: string]}
 */
export function describeReference(value, name = "reference", forms = CHECK_REFERENCE_FORMS) {
  const isObject = value !== null && typeof value === "object";
  // The fields of an object, of types not known yet; anything else has none and is refused below.
  const reference = /** @type {Record<string, unknown>} */ (isObject ? value : {});
  const given = (/** @type {string} */ kind) =>
    Object.hasOwn(reference, kind) && reference[kind] !== undefined;
  const kinds = isObject ? REFERENCE_KINDS.filter(given) : [];
  if (kinds.length !== 1) {
    throw new TypeError(`${name} must be exactly one of ${forms}.`);
  }
  const unknown = Object.keys(reference).find((key) => given(key) && !REFERENCE_KEYS.includes(key));
  if (unknown === "passphrase") {
    throw new TypeError(`passphrase is given beside the ${name}, not inside it.`);
  }
  if (unknown !== undefined) throw new TypeError(`${name}.${unknown} is not a key of a ${name}.`);
  for (const key of ["coin", "path"]) {
    if (reference[key] !== undefined && kinds[0] !== "address") {
      throw new TypeError(`${name}.${key} belongs only to an address ${name}.`);
    }
  }
  switch (kinds[0]) {
    case "address":
      requireText(reference.address, `${name}.address`);
      if (reference.path !== undefined) requireText(reference.path, `${name}.path`);
      // No coin is the default, so that a page for one coin names no other.
      if (reference.coin === undefined) {
        throw new TypeError(
          `${name}.coin must name the coin of the address, an id of MhfeWallet.parameters().coins.`,
        );
      }
      requireText(reference.coin, `${name}.coin`);
      return ["address", reference.address, reference.coin, reference.path ?? ""];
    case "fingerprint":
      requireText(reference.fingerprint, `${name}.fingerprint`);
      return ["fingerprint", reference.fingerprint, "", ""];
    case "walletCheck":
      if (reference.walletCheck !== true) throw new TypeError(`${name}.walletCheck must be true.`);
      return ["walletCheck", "", "", ""];
    default:
      // 0 detects the length (the library's detection).
      requireWordCount(reference.words);
      // Deliberate copy of rehearsal::require_built_in_check_length's refusal, with its code and
      // message, before any secret reaches a worker; scripts/verify-browser-package.mjs keeps the
      // two in step.
      if (reference.words !== 0 && !BUILT_IN_CHECK_WORD_COUNTS.includes(reference.words)) {
        throw new MhfeError(
          "INVALID_WORD_COUNT",
          `A ${reference.words}-word original seed phrase has no built-in check (only ` +
            `${countsText(BUILT_IN_CHECK_WORD_COUNTS)} words have one); compare it with a ` +
            "receiving address or the master key fingerprint of the wallet instead",
        );
      }
      return ["words", String(reference.words), "", ""];
  }
}

export const CHECK_PASSPHRASE_REFERENCES = "an address, a fingerprint or the wallet check";

export const REKEY_PASSPHRASE_REFERENCES = "an address or a fingerprint";

/**
 * A passphrase belongs only to the `references` that take one: a non-empty one with the built-in
 * check or the owner is a TypeError, before any secret reaches a worker (the core refuses it too,
 * rehearsal::refuse_unused_passphrase).
 * @param {string} confirmKind
 * @param {unknown} passphrase
 * @param {string} references
 */
export function requirePassphraseFits(confirmKind, passphrase, references) {
  // Only a string or bytes has a length here; any other type is refused when it is encoded.
  const givenPassphrase =
    (typeof passphrase === "string" || passphrase instanceof Uint8Array) && passphrase.length > 0;
  if (givenPassphrase && ["builtInCheck", "words", "owner"].includes(confirmKind)) {
    throw new TypeError(`passphrase belongs only to ${references}.`);
  }
}

/**
 * The confirmation of a rekey: the built-in check, the owner, or an address or fingerprint of the
 * wallet. A key whose value is undefined counts as not given, as for a check's reference.
 * @param {unknown} value
 * @returns {DescribedConfirmation}
 */
export function describeConfirmation(value) {
  if (value === null || typeof value !== "object") {
    throw new TypeError(
      "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
        "{ fingerprint } or { owner }.",
    );
  }
  // An object, as checked, whose fields are of types not known yet.
  const confirmation = /** @type {Record<string, unknown>} */ (value);
  const given = Object.keys(confirmation).filter((key) => confirmation[key] !== undefined);
  if (given.includes("builtInCheck")) {
    if (confirmation.builtInCheck !== true || given.length !== 1) {
      throw new TypeError("confirmation must be exactly one kind; builtInCheck must be true.");
    }
    return ["builtInCheck", "", "", "", undefined];
  }
  if (given.includes("owner")) {
    if (typeof confirmation.owner !== "function" || given.length !== 1) {
      throw new TypeError("confirmation must be exactly one kind; owner must be a function.");
    }
    // Whatever the page's callback throws, even an MhfeError of another call, ends the rekey
    // with CALLBACK_FAILED and the page's error as the cause. Its answer, true or
    // `{ passphrase }`, goes on as it is (answerOwner).
    /** @type {PageOwner} */
    const owner = (check) =>
      // A function of the page, as checked when the confirmation was given.
      askPage(
        (value) => /** @type {{ owner: OwnerCallback }} */ (confirmation).owner(value),
        check,
        "owner",
      );
    return ["owner", "", "", "", owner];
  }
  if (given.includes("words")) {
    throw new TypeError("a rekey is confirmed by { builtInCheck: true }, not by a word count.");
  }
  if (given.includes("walletCheck")) {
    throw new TypeError(
      "a rekey is confirmed by an address or a fingerprint, not by the wallet check.",
    );
  }
  if (!given.includes("address") && !given.includes("fingerprint")) {
    throw new TypeError(
      "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
        "{ fingerprint } or { owner }.",
    );
  }
  if (given.includes("address") && given.includes("fingerprint")) {
    throw new TypeError("confirmation must be exactly one kind: an address or a fingerprint.");
  }
  const [kind, reference, coin, path] = describeReference(confirmation, "confirmation");
  return [kind, reference, coin, path, undefined];
}
