// @ts-check
// Owned secret bytes and their explicit transfer/wipe lifecycle.
import { MhfeError } from "./errors.js";
/** @import { MhfeSecret } from "../runtime.d.ts" */

// SECRET_OWNERS_BEGIN
/** A byte buffer owned by this operation; wiping is best effort in JavaScript. */
export class SecretBytes {
  /** @type {Uint8Array} */
  #bytes;
  // Deliberate copy: page and classic worker share this owner; the package compares both.

  /** Takes ownership of an already copied or transferred buffer, without another copy.
   * @param {Uint8Array} bytes */
  constructor(bytes) {
    this.#bytes = bytes;
  }

  /** The owned bytes, for protocol serialization or a library call. */
  get bytes() {
    return this.#bytes;
  }

  /** Erases the live buffer; a detached buffer is already owned by the receiver. */
  wipe() {
    if (this.#bytes.byteLength > 0) this.#bytes.fill(0);
  }
}

/** A request owns every secret at any depth and supplies its plain wire value and transfer list. */
export class SecretRequest {
  /** @type {Set<SecretBytes>} */
  #secrets = new Set();
  // Deliberate copy: page and classic worker share this owner; the package compares both.
  /** @type {unknown} */
  #message;

  /** Collects byte owners by type, never by a field name. Cycles and repeated references are safe.
   * @param {unknown} message */
  constructor(message) {
    /** @type {WeakMap<object, object>} */
    const seen = new WeakMap();
    /** @param {unknown} value
     * @returns {unknown} */
    const wire = (value) => {
      if (value instanceof SecretBytes) {
        this.#secrets.add(value);
        return value.bytes;
      }
      if (value instanceof Uint8Array) {
        this.#secrets.add(new SecretBytes(value));
        return value;
      }
      if (typeof value !== "object" || value === null) return value;
      const known = seen.get(value);
      if (known !== undefined) return known;
      if (Array.isArray(value)) {
        /** @type {unknown[]} */
        const items = [];
        seen.set(value, items);
        for (const item of value) items.push(wire(item));
        return items;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) return value;
      /** @type {Record<string, unknown>} */
      const record = {};
      seen.set(value, record);
      for (const [key, item] of Object.entries(value)) {
        Object.defineProperty(record, key, { value: wire(item), enumerable: true });
      }
      return record;
    };
    this.#message = wire(message);
  }

  /** The serializable value, with owners replaced by their byte buffers. */
  get message() {
    return this.#message;
  }

  /** Each transferable secret buffer once, independent of its name and nesting. */
  get transfer() {
    return [...new Set([...this.#secrets].map((secret) => secret.bytes.buffer))].filter(
      (buffer) => buffer instanceof ArrayBuffer,
    );
  }

  /** Erases all buffers this request owns, including partially constructed answers. */
  wipe() {
    for (const secret of this.#secrets) secret.wipe();
  }
}

// Older browsers may lack Symbol.dispose; the owners still have explicit wipe().
const disposeSymbol = Reflect.get(Symbol, "dispose");
if (typeof disposeSymbol === "symbol") {
  for (const Owner of [SecretBytes, SecretRequest]) {
    Object.defineProperty(Owner.prototype, disposeSymbol, {
      /** @this {SecretBytes | SecretRequest} */
      value() {
        this.wipe();
      },
    });
  }
}
// SECRET_OWNERS_END

/**
 * A secret is given as text or as its UTF-8 bytes; anything else is a TypeError.
 * @param {unknown} value
 * @param {string} name
 * @returns {asserts value is MhfeSecret}
 */
export function requireSecret(value, name) {
  if (typeof value !== "string" && !(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a string or a Uint8Array.`);
  }
}

/**
 * A secret that a method lets the caller leave out, which is then empty, such as a repetition or
 * a BIP39 passphrase. Only a value left out (undefined) is: one given, null included, is checked
 * as every secret is, so that a wrong type is a TypeError instead of an empty secret that the
 * library refuses with another code (AUD-016-API003).
 * @param {unknown} value
 * @param {string} name
 * @returns {MhfeSecret}
 */
export function secretOrEmpty(value, name) {
  if (value === undefined) return "";
  requireSecret(value, name);
  return value;
}

/**
 * Owned UTF-8 bytes of a phrase, password, passphrase or dice digits, in a Uint8Array of their
 * own, which the transfer to the worker empties and a refusal wipes. A JavaScript string may hold
 * a lone surrogate, which TextEncoder would silently turn into U+FFFD, so such a string is refused
 * instead. Bytes are copied into a new array rather than with their own slice(): a subclass such
 * as Node's Buffer, or the Buffer that bundlers add to a page, slices into a view of the caller's
 * memory, which the transfer would empty and a refusal would wipe. An empty password is the
 * library's to refuse (EMPTY_PASSWORD), in the order of its rules, as the command-line tool does.
 * @param {unknown} value
 * @param {string} name
 * @returns {SecretBytes}
 */
export function encodeSecret(value, name) {
  requireSecret(value, name);
  let bytes;
  if (typeof value === "string") {
    if (!isWellFormed(value)) {
      throw new MhfeError(
        "INVALID_PASSWORD_TEXT",
        `The ${name} contains an unpaired surrogate, which is not valid text.`,
      );
    }
    bytes = new TextEncoder().encode(value);
  } else {
    bytes = new Uint8Array(value);
  }
  return new SecretBytes(bytes);
}

/**
 * Whether `text` holds no lone surrogate.
 * @param {string} text
 */
function isWellFormed(text) {
  if (typeof text.isWellFormed === "function") return text.isWellFormed();
  // With the u flag a valid pair is one code point, so only a lone surrogate matches.
  return !/[\uD800-\uDFFF]/u.test(text);
}
