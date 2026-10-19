// @ts-check
// Stable errors and package identity.
/** @import { MhfeErrorCode, MhfeSelfCheckReport } from "../runtime.d.ts" */

/**
 * The build of the package these files come from, which scripts/stamp-build-id.mjs derives from
 * every file a page loads before it stamps any: runtime/mhfe.wasm, this file, runtime/worker.js,
 * each class file and both Argon2 builds. It writes it into each of these, the WebAssembly's
 * custom section "mhfe-build" included; the classes and the worker compare them, so that parts of
 * different builds, even ones that differ in a script alone, are never used together.
 * "development" before the build stamps it.
 */
export const BUILD_ID = "development";

/** The errors every module class rejects with: a stable code and a sentence a page can show. */
export class MhfeError extends Error {
  /** @type {MhfeErrorCode} */
  #code;
  /** @type {MhfeSelfCheckReport | undefined} */
  #report;
  /**
   * `options.cause` keeps the original error, as for CALLBACK_FAILED; `options.report` the
   * self-check report of SELF_CHECK_FAILED.
   * @param {MhfeErrorCode} code
   * @param {string} message
   * @param {{ cause?: unknown, report?: MhfeSelfCheckReport }} [options]
   */
  constructor(code, message, options) {
    super(message, options);
    this.name = "MhfeError";
    this.#code = code;
    this.#report = options?.report;
  }

  /** The immutable machine-readable refusal code. */
  get code() {
    return this.#code;
  }

  /** The self-check report attached to this refusal, when any. */
  get report() {
    return this.#report;
  }
}

/**
 * Deliberate copy of MhfeErrorCode: the declaration is type-only, while worker messages need
 * membership checks at runtime. package-check/manifest.mjs compares every value with that type.
 * @type {readonly MhfeErrorCode[]}
 */
const KNOWN_ERROR_CODES = [
  "INVALID_PHRASE",
  "INVALID_CONTAINER",
  "INVALID_WORD_COUNT",
  "SAME_LENGTH_NEEDS_SHORT_PHRASE",
  "LENGTH_CHOICE_NOT_APPLICABLE",
  "NO_BUILT_IN_CHECK",
  "NO_WALLET_CHECK",
  "NO_HIDDEN_WALLETS",
  "REFERENCE_REQUIRED",
  "REFERENCE_MISMATCH",
  "HIDDEN_WALLET_PASSES_CHECK",
  "INVALID_REPAIR_WORDS",
  "REPAIR_NOT_POSSIBLE",
  "TOO_MANY_MISSING_WORDS",
  "SEVERAL_CANDIDATES_MATCH",
  "AMBIGUOUS_LENGTH",
  "LENGTH_DIFFERS",
  "INVALID_PIM",
  "INVALID_MEMORY_LEVEL",
  "EMPTY_PASSWORD",
  "PASSWORD_TOO_LONG",
  "INVALID_PASSWORD_UTF8",
  "CONTROL_CHARACTER_IN_PASSWORD",
  "UNASSIGNED_CHARACTER",
  "VERIFIER_MISMATCH",
  "FIXED_POINT",
  "VERIFICATION_FAILED",
  "SELF_CHECK_FAILED",
  "PACKAGE_MISMATCH",
  "CANCELLED",
  "INVALID_ADDRESS",
  "INVALID_DERIVATION_PATH",
  "INVALID_FINGERPRINT",
  "NOT_ENOUGH_MEMORY",
  "MEMORY_ALLOCATION_FAILED",
  "MEMORY_PROTECTION_FAILED",
  "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
  "ARGON2_FAILED",
  "INVALID_PASSPHRASE",
  "PASSPHRASE_TOO_LONG",
  "INVALID_REQUEST",
  "INVALID_COIN",
  "INVALID_PASSWORD_SIZE",
  "INVALID_DICE_ROLLS",
  "PASSWORD_REPAIR_NOT_OFFERED",
  "PASSWORDS_DIFFER",
  "WALLET_CHECK_NEEDS_PASSPHRASE",
  "RANDOM_FAILED",
  "PASSWORD_ALREADY_USED",
  "NEW_PASSWORD_SAME_AS_OLD",
  "NOT_CONFIRMED_BY_OWNER",
  "INTERNAL_ERROR",
  "INVALID_PASSWORD_TEXT",
  "PASSPHRASES_DIFFER",
  "INVALID_WORD_WISH",
  "BUSY",
  "SESSION_CLOSED",
  "WORKER_FAILED",
  "CALLBACK_FAILED",
];

/**
 * Membership of the protocol's declared error-code enum.
 * @param {unknown} value
 * @returns {value is MhfeErrorCode}
 */
export function isErrorCode(value) {
  return typeof value === "string" && KNOWN_ERROR_CODES.some((code) => code === value);
}

/** The error of an operation that cancel() stopped. */
export class MhfeCancelledError extends MhfeError {
  constructor() {
    super("CANCELLED", "The operation was cancelled.");
    this.name = "MhfeCancelledError";
  }
}

/**
 * Parts of the package that come from different builds (PACKAGE_MISMATCH): `what` says which, and
 * the advice follows. Deliberate copy: the worker says it in the same words
 * (web/worker-runtime.js), as a worker script imports nothing; the package checks compare both.
 * @param {string} what
 */
export function packageMismatch(what) {
  return new MhfeError(
    "PACKAGE_MISMATCH",
    `${what}: take every file of the package from one build.`,
  );
}
