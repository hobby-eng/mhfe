// The parts of Node.js's API that the package checks were written with, for the module worker of
// `cargo xtask package-check`: `assert` as "node:assert/strict" gives it, `Buffer`,
// `resolveObjectURL`, the files the task hands over as `read`, and the Argon2 builds as `require`
// gave them. Each covers only what the checks use, with Node's meaning, and what would otherwise
// pass by mistake fails loudly.

/** A failed check, with what was expected and what came. */
class AssertionError extends Error {
  constructor(message) {
    super(message);
    this.name = "AssertionError";
  }
}

/** A short text of `value` for a failure message. */
function printed(value) {
  if (typeof value === "string") return JSON.stringify(value).slice(0, 400);
  if (value instanceof Uint8Array) return `${value.constructor.name}(${value.length})`;
  try {
    return (JSON.stringify(value) ?? String(value)).slice(0, 400);
  } catch {
    return String(value);
  }
}

/** Fails with `message`, or with what was compared when no message was given. */
function fail(message, actual, expected, operator) {
  throw new AssertionError(
    message ?? `${operator}: ${printed(actual)} and ${printed(expected)}`,
  );
}

/** The own enumerable keys of `object`, symbols included, as Node's deepStrictEqual reads them. */
function ownKeys(object) {
  return Reflect.ownKeys(object).filter((key) =>
    Object.prototype.propertyIsEnumerable.call(object, key)
  );
}

/** Node's deepStrictEqual for the kinds of values the checks compare. */
function isDeepStrictEqual(actual, expected) {
  if (Object.is(actual, expected)) return true;
  if (
    typeof actual !== "object" || typeof expected !== "object" || actual === null ||
    expected === null
  ) {
    return false;
  }
  if (Object.getPrototypeOf(actual) !== Object.getPrototypeOf(expected)) return false;
  const tag = Object.prototype.toString.call(actual);
  if (tag !== Object.prototype.toString.call(expected)) return false;
  if (ArrayBuffer.isView(actual)) {
    if (actual.byteLength !== expected.byteLength) return false;
    const left = new Uint8Array(actual.buffer, actual.byteOffset, actual.byteLength);
    const right = new Uint8Array(expected.buffer, expected.byteOffset, expected.byteLength);
    if (!left.every((byte, index) => byte === right[index])) return false;
    return sameKeys(actual, expected, (key) => typeof key !== "string" || !/^\d+$/u.test(key));
  }
  if (!Array.isArray(actual) && tag !== "[object Object]") {
    throw new Error(`deepEqual of ${tag} is not supported by xtask/pages/package/support.js`);
  }
  if (Array.isArray(actual) && actual.length !== expected.length) return false;
  return sameKeys(actual, expected, () => true);
}

/** Whether the own enumerable keys that `kept` keeps are the same and their values equal. */
function sameKeys(actual, expected, kept) {
  const left = ownKeys(actual).filter(kept);
  const right = ownKeys(expected).filter(kept);
  if (left.length !== right.length) return false;
  return left.every((key) =>
    Object.prototype.propertyIsEnumerable.call(expected, key) &&
    isDeepStrictEqual(actual[key], expected[key])
  );
}

/** Node's check of a thrown or rejected `error` against `expected`, with its message. */
function validateError(error, expected, message) {
  if (typeof expected === "function") {
    if (expected.prototype !== undefined && error instanceof expected) return;
    if (Error.isPrototypeOf(expected) || expected === Error) {
      fail(message ?? `the error is not a ${expected.name}: ${printed(error?.message)}`);
    }
    const verdict = expected.call({}, error);
    if (verdict !== true) {
      fail(message ?? `the validation function returned ${printed(verdict)} for ${error}`);
    }
    return;
  }
  const keys = typeof expected === "object" && expected !== null ? Reflect.ownKeys(expected) : [];
  if (keys.length === 0) {
    throw new Error("assert.throws and assert.rejects take a class, a function or an object");
  }
  for (const key of keys) {
    const want = expected[key];
    const got = error?.[key];
    if (!(key in Object(error)) || !isDeepStrictEqual(got, want)) {
      fail(message, got, want, `the error's ${String(key)}`);
    }
  }
}

/** "node:assert/strict" as far as the checks use it. */
const assert = {
  ok: (value, message) => {
    if (!value) fail(message ?? `${printed(value)} is not truthy`);
  },
  equal: (actual, expected, message) => {
    if (!Object.is(actual, expected)) fail(message, actual, expected, "equal");
  },
  notEqual: (actual, expected, message) => {
    if (Object.is(actual, expected)) fail(message, actual, expected, "notEqual");
  },
  deepEqual: (actual, expected, message) => {
    if (!isDeepStrictEqual(actual, expected)) fail(message, actual, expected, "deepEqual");
  },
  match: (text, pattern, message) => {
    if (typeof text !== "string" || !pattern.test(text)) {
      fail(message, text, String(pattern), "match");
    }
  },
  fail: (message) => fail(message ?? "failed"),
  throws: (action, expected, message) => {
    try {
      action();
    } catch (error) {
      validateError(error, expected, message);
      return;
    }
    fail(message ?? "Missing expected exception.");
  },
  doesNotThrow: (action, message) => {
    try {
      action();
    } catch (error) {
      fail(message ?? `Got unwanted exception: ${error}`);
    }
  },
  rejects: async (promise, expected, message) => {
    try {
      await promise;
    } catch (error) {
      validateError(error, expected, message);
      return;
    }
    fail(message ?? "Missing expected rejection.");
  },
};

/**
 * Node's Buffer as far as the checks use it: bytes from text in UTF-8, hex or base64, text in UTF-8
 * or hex, and a search for a run of bytes. Like Node's, and like the Buffer that bundlers add to a
 * page, its slice() is a view of the same memory, which a check of the classes relies on.
 */
class Buffer extends Uint8Array {
  /** The bytes of `value`: a text in `encoding`, a copy of bytes, or a view of an ArrayBuffer. */
  static from(value, encoding = "utf8") {
    if (typeof value === "string") {
      if (encoding === "utf8") return Buffer.#of(new TextEncoder().encode(value));
      if (encoding === "hex") {
        return Buffer.#of(Uint8Array.from(value.match(/../gu) ?? [], (pair) => parseInt(pair, 16)));
      }
      if (encoding === "base64") {
        return Buffer.#of(Uint8Array.from(atob(value), (char) => char.charCodeAt(0)));
      }
      throw new Error(`Buffer.from with ${encoding} is not supported here`);
    }
    if (value instanceof ArrayBuffer) return new Buffer(value);
    return Buffer.#of(Uint8Array.from(value));
  }

  /** The bytes of all of `list` in order. */
  static concat(list) {
    const joined = new Buffer(list.reduce((length, each) => length + each.length, 0));
    let at = 0;
    for (const each of list) {
      joined.set(each, at);
      at += each.length;
    }
    return joined;
  }

  /** The length of `text` in UTF-8. */
  static byteLength(text) {
    return new TextEncoder().encode(text).length;
  }

  static #of(bytes) {
    return new Buffer(bytes.buffer, bytes.byteOffset, bytes.length);
  }

  toString(encoding = "utf8") {
    if (encoding === "utf8") return new TextDecoder().decode(this);
    if (encoding === "hex") {
      return Array.from(this, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    throw new Error(`Buffer.toString with ${encoding} is not supported here`);
  }

  slice(start, end) {
    return this.subarray(start, end);
  }

  /** Where the bytes of `needle` start, from `from` on, or -1. */
  indexOf(needle, from = 0) {
    if (!(needle instanceof Uint8Array) || needle.length === 0) {
      throw new Error("Buffer.indexOf is supported here for bytes alone");
    }
    const first = needle[0];
    for (let at = super.indexOf(first, from); at !== -1; at = super.indexOf(first, at + 1)) {
      if (at + needle.length > this.length) return -1;
      if (needle.every((byte, index) => this[at + index] === byte)) return at;
    }
    return -1;
  }

  /** Node's takes text and bytes, of which Uint8Array's own would never find any. */
  includes() {
    throw new Error("Buffer.includes is not supported here");
  }

  /** Node's takes text and bytes, of which Uint8Array's own would never find any. */
  lastIndexOf() {
    throw new Error("Buffer.lastIndexOf is not supported here");
  }
}

/** The file at `path` of `files`, as `cargo xtask package-check` handed it over. */
function read(path, files = FILES) {
  const base64 = files[path];
  if (base64 === undefined) throw new Error(`cargo xtask package-check did not hand over ${path}`);
  return Buffer.from(base64, "base64");
}

/** The file at `path` of the other build that `cargo xtask package-check` stamped. */
const readOtherBuild = (path) => read(path, OTHER_BUILD_FILES);

// The Blob behind each object URL, as Node's resolveObjectURL gives it: the stand-in workers read
// the script a class starts them with.
const blobsByUrl = new Map();
const createObjectURLOfBrowser = URL.createObjectURL;
URL.createObjectURL = (object) => {
  const url = createObjectURLOfBrowser.call(URL, object);
  blobsByUrl.set(url, object);
  return url;
};
const resolveObjectURL = (url) => blobsByUrl.get(url);
/** The URL of the module `text`: unlike a `data:` module, it can import another in Firefox. */
const moduleUrl = (text) =>
  createObjectURLOfBrowser.call(URL, new Blob([text], { type: "text/javascript" }));

/**
 * The factory of the Argon2 build at `path`, which defines `name`, as Node's require gave it. Its
 * lane workers run the same script from a Blob, as web/core-worker.js starts them, and it keeps the
 * real Worker when the checks of the classes replace the global one.
 */
function argon2Build(path, name) {
  const script = read(path).toString();
  const create = new Function("Worker", `${script}\nreturn ${name};`)(Worker);
  const lanes = new Blob([script], { type: "text/javascript" });
  return () => create({ mainScriptUrlOrBlob: lanes });
}
