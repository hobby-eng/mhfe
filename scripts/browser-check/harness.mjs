// The harness of the page of scripts/verify-browsers.mjs: its record of the results, the
// comparisons its checks make, and the order in which it runs them.
//
// Every module of this folder but page-values.mjs holds page code: functions that never run under
// Node.js. The runner puts the source text of every function they export into one block of the
// page script, after the package's classes and the constants of the runner's `sources` and of
// page-values.mjs, and then calls runPage(). The functions reach one another, those classes and
// constants and the page's record by name, as names of that block: none imports anything or uses
// a value of its module, and what one step of a check needs from another comes as a parameter.

/** The page's record, which the page script declares as `results`, `failures` and `progress`. */
export function pageRecord() {
  const results = [];
  const failures = [];
  // What the page has done so far, which the script outside reads while it waits: a page that
  // stops shows its partial results and the check it was in (AUD-023-BLD005). `updated` is the
  // page's time of its last result or drawing report.
  const progress = { results, failures, running: "starting", updated: Date.now() };
  window.mhfeProgress = progress;
  return { results, failures, progress };
}

/** Runs the checks, and leaves their outcome in window.mhfeCheck for the script outside. */
export function runPage() {
  main()
    .then((mode) => {
      window.mhfeCheck = { mode, results, failures };
    })
    .catch((error) => {
      failures.push("page error: " + (error.code ?? "") + " " + error.message);
      window.mhfeCheck = { mode: null, results, failures };
    });
}

/** Runs every check in turn, and resolves to the mode the client ran in. */
export async function main() {
  // The core takes the package's WebAssembly as bytes; the other classes share one compiled
  // module, as a page that uses several classes does.
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm: bytes(WASM_BASE64),
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
  });
  const compiled = await WebAssembly.compile(bytes(WASM_BASE64));
  const repair = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: compiled });
  const passwords = new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled });
  const wallet = new MhfeWallet({ workerSource: WORKER_SOURCE, wasm: compiled });
  // Containers the encryption checks make, for the checks of the other methods.
  const made = {};

  await checkStartupChecks(client, repair, passwords, wallet);
  await checkConstruction(client, compiled);
  await checkReading(client);
  await checkEncrypt(client, repair, made);
  await checkDecrypt(client, wallet, made);
  await checkRehearsal(client, made);
  await checkCancelAndCallbacks(client);
  await checkMemoryFailures(client);
  await checkRekey(client, repair, wallet, made);
  await checkHiddenWallets(client, wallet, made);
  await checkSelfTest(client);
  await checkFullChecks(client, repair, passwords, wallet);
  await checkFailingSelfCheck(compiled);
  await checkArgon2Start();
  await checkRepair(repair);
  await checkPasswords(passwords);
  await checkWallet(wallet);
  await checkRuntime(client, passwords, wallet, compiled);
  return client.mode();
}

/** Notes that the page is still working, on `running` if given. */
export function working(running = progress.running) {
  progress.running = running;
  progress.updated = Date.now();
}

/** Records a check: "ok" when `condition` holds, otherwise "FAIL" and a failure. */
export function expect(condition, description) {
  results.push((condition ? "ok   " : "FAIL ") + description);
  if (!condition) failures.push(description);
  working();
}

/** Expects `promise` to reject with `code`, and with `cause` and `message` when they are given. */
export async function expectRejection(promise, code, description, cause, message) {
  try {
    await promise;
    expect(false, description + " (it resolved)");
  } catch (error) {
    const sameCause = cause === undefined || error.cause === cause;
    const sameMessage = message === undefined || error.message === message;
    expect(
      error.code === code && sameCause && sameMessage,
      description + " -> " + error.code + ": " + error.message,
    );
  }
}

/** A heading in the results, one per class or method. */
export function group(title) {
  results.push("-- " + title);
  working(title);
}

/** Like expect, but a failure shows the value that was received. */
export function expectEqual(actual, expected, description) {
  const equal = sameValue(actual, expected);
  expect(equal, equal ? description : `${description}: got ${JSON.stringify(actual)}`);
}

/**
 * Like expectRejection, for a code that several causes share: the message must also contain
 * `message`, which tells the cause.
 */
export async function expectRefusal(promise, code, message, description) {
  const error = await rejectionOf(promise);
  expect(
    error?.code === code && error.message.includes(message),
    `${description} -> ${error === null ? "it resolved" : `${error.code}: ${error.message}`}`,
  );
}

/** Like expectRefusal, for the whole message. */
export async function expectExactRefusal(promise, code, message, description) {
  const error = await rejectionOf(promise);
  expect(
    error?.code === code && error.message === message,
    `${description} -> ${error === null ? "it resolved" : `${error.code}: ${error.message}`}`,
  );
}

/**
 * A TypeError of the package, told apart from an accidental one, such as "Cannot read
 * properties of undefined", by `message`, a distinctive part of the message the package throws.
 */
export function isTypeError(error, message) {
  return error instanceof TypeError && error.message.includes(message);
}

/** Expects `promise` to reject with a TypeError of the package whose message contains `message`. */
export async function expectTypeError(promise, message, description) {
  const error = await rejectionOf(promise);
  expect(
    isTypeError(error, message),
    `${description} -> ${error === null ? "it resolved" : `${error.name}: ${error.message}`}`,
  );
}

/** Like expectTypeError, for the whole message. */
export async function expectExactTypeError(promise, message, description) {
  const error = await rejectionOf(promise);
  expect(
    error instanceof TypeError && error.message === message,
    `${description} -> ${error === null ? "it resolved" : `${error.name}: ${error.message}`}`,
  );
}

/** Expects `action` to throw a TypeError of the package whose message contains `message`. */
export function expectThrownTypeError(action, message, description) {
  try {
    action();
    expect(false, description + " (nothing was thrown)");
  } catch (error) {
    expect(isTypeError(error, message), `${description} -> ${error.name}: ${error.message}`);
  }
}

/** "resolved", "rejected", or "pending" when the promise has not settled after `ms`. */
export async function outcomeWithin(promise, ms) {
  let timer;
  const pending = new Promise((resolve) => {
    timer = setTimeout(() => resolve("pending"), ms);
  });
  const settled = promise.then(
    () => "resolved",
    () => "rejected",
  );
  const outcome = await Promise.race([settled, pending]);
  clearTimeout(timer);
  return outcome;
}

/** The error a promise rejects with, or null when it resolves. */
export async function rejectionOf(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    return error;
  }
}

/** Whether two JSON-like values are equal, objects whatever the order of their keys. */
export function sameValue(a, b) {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const keys = Object.keys(a);
  return (
    keys.length === Object.keys(b).length &&
    keys.every((key) => Object.hasOwn(b, key) && sameValue(a[key], b[key]))
  );
}

/** The named fields of an object, to compare them without the others. */
export function fieldsOf(object, names) {
  return Object.fromEntries(names.map((name) => [name, object?.[name]]));
}

/** A progress callback and the "stage round/rounds" lines it has received, in order. */
export function progressLog() {
  const lines = [];
  return {
    lines,
    onProgress: ({ stage, round, rounds }) => lines.push(`${stage} ${round}/${rounds}`),
  };
}

/** The progress lines of rounds `first` to `last` of `rounds` in `stage`. */
export function roundLines(stage, first, last, rounds) {
  return Array.from(
    { length: last - first + 1 },
    (_, index) => `${stage} ${first + index}/${rounds}`,
  );
}

/**
 * The progress lines of a rekey of a 12-word phrase in 36 rounds: the recovery's, the lines
 * `afterRecovery`, the encryption's, the lines `afterEncryption` and the check's.
 */
export function rekeyLines(afterRecovery, afterEncryption) {
  return [
    ...roundLines("recover", 1, 12, 36),
    ...afterRecovery,
    ...roundLines("encrypt", 13, 24, 36),
    ...afterEncryption,
    ...roundLines("check", 25, 36, 36),
  ];
}

/** The bytes of a base64 text, such as the package's WebAssembly. */
export function bytes(base64) {
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

/** The UTF-8 bytes of a text. */
export function encode(text) {
  return new TextEncoder().encode(text);
}
