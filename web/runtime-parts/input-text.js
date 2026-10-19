// @ts-check
// Raw UTF-8 admission before a page or worker transport makes an owned text copy.
import { requireText } from "./arguments.js";
import { MhfeError, packageMismatch } from "./errors.js";
import { isRecord } from "./values.js";
import { encodeSecret, requireSecret } from "./secrets.js";

// Use the intrinsic size: a Uint8Array subclass can shadow its public byteLength property.
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BYTE_LENGTH = typedArrayGetter("byteLength");
const TYPED_ARRAY_BYTE_OFFSET = typedArrayGetter("byteOffset");
const TYPED_ARRAY_BUFFER = typedArrayGetter("buffer");

/**
 * Refuses non-string, ill-formed UTF-16 or oversized raw UTF-8 text without encoding or copying.
 * `maxBytes` comes from the library's parameters().maxInputTextBytes; this does not validate
 * BIP39 words or apply the independent normalized password/passphrase rules. Wrong types or a
 * malformed limit throw TypeError; invalid/oversized text throws MhfeError(INVALID_REQUEST).
 * @param {unknown} value
 * @param {number} maxBytes
 * @param {string} name
 * @returns {asserts value is string}
 */
export function requireInputText(value, maxBytes, name) {
  requireText(value, name);
  if (!isTextLimit(maxBytes)) throw new TypeError("maxBytes must be a positive safe integer.");
  let bytes = 0;
  // Deliberate copy of encodeSecret's lone-surrogate refusal: raw admission counts in the same
  // bounded pass instead of scanning all text first. Package checks compare both boundaries
  // with the published UTF-8 probe and compare this counter with TextEncoder.
  for (let at = 0; at < value.length; at++) {
    const unit = value.charCodeAt(at);
    // Unicode scalar UTF-8 widths: 1/2/3 bytes, or 4 for one paired UTF-16 surrogate pair.
    if (unit >= 0xd800 && unit <= 0xdfff) {
      const next = value.charCodeAt(at + 1);
      if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) {
        throw new MhfeError("INVALID_REQUEST", `The ${name} is not valid Unicode text.`);
      }
      bytes += 4;
      at++;
    } else {
      bytes += unit <= 0x7f ? 1 : unit <= 0x7ff ? 2 : 3;
    }
    if (bytes > maxBytes) {
      throw new MhfeError(
        "INVALID_REQUEST",
        `The ${name} is longer than ${maxBytes} raw UTF-8 bytes.`,
      );
    }
  }
}

/** A library-owned raw limit shared by admissions at one module's transport boundary. */
export class InputTextBoundary {
  /** @type {() => Promise<unknown>} */
  #readParameters;
  /** @type {Promise<number> | null} */
  #limit = null;

  /** @param {() => Promise<unknown>} readParameters */
  constructor(readParameters) {
    this.#readParameters = readParameters;
  }

  /**
   * Checks type before starting a parameter worker, then admits borrowed text before any copy.
   * Concurrent calls share one read; a failed read is retryable, and only the scalar is cached.
   * @param {unknown} value
   * @param {string} name
   */
  async read(value, name) {
    requireText(value, name);
    requireInputText(value, await this.#maximum(), name);
  }

  /**
   * Admits raw size and returns an owned byte copy in the same turn after parameters arrive.
   * String Unicode is checked here; supplied bytes are decoded by the library boundary.
   * The recipient owns and wipes these bytes; caller-owned Uint8Array data remains unchanged.
   * @param {unknown} value
   * @param {string} name
   */
  async copy(value, name) {
    requireSecret(value, name);
    const maximum = await this.#maximum();
    if (typeof value === "string") {
      requireInputText(value, maximum, name);
    } else {
      if (
        TYPED_ARRAY_BYTE_LENGTH === undefined ||
        TYPED_ARRAY_BYTE_OFFSET === undefined ||
        TYPED_ARRAY_BUFFER === undefined
      )
        throw packageMismatch("Typed array sizes are unavailable");
      const bytes = TYPED_ARRAY_BYTE_LENGTH.call(value);
      if (bytes > maximum) {
        throw new MhfeError(
          "INVALID_REQUEST",
          `The ${name} is longer than ${maximum} raw UTF-8 bytes.`,
        );
      }
      // Fix the admitted length: another worker can grow a shared backing buffer between
      // admission and copying a length-tracking view. Content remains caller-mutable.
      const admitted = new Uint8Array(
        TYPED_ARRAY_BUFFER.call(value),
        TYPED_ARRAY_BYTE_OFFSET.call(value),
        bytes,
      );
      return new Uint8Array(admitted);
    }
    return encodeSecret(value, name).bytes;
  }

  #maximum() {
    this.#limit ??= this.#readParameters()
      .then(inputTextLimit)
      .catch((error) => {
        this.#limit = null;
        throw error;
      });
    return this.#limit;
  }
}

/** The intrinsic accessor is captured once and always called with an explicit typed-array receiver.
 * @param {string} name */
function typedArrayGetter(name) {
  // oxlint-disable-next-line typescript/unbound-method -- every captured getter uses .call(value)
  return Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, name)?.get;
}

/** @param {unknown} value
 * @returns {value is number} */
function isTextLimit(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/** @param {unknown} parameters */
function inputTextLimit(parameters) {
  const limit = isRecord(parameters) ? parameters.maxInputTextBytes : undefined;
  if (!isTextLimit(limit)) throw packageMismatch("The raw text limit is missing or invalid");
  return limit;
}
