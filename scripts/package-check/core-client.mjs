// Part 4 of the checks of the browser package (scripts/verify-browser-package.mjs): the core
// client, MhfeClient, against the stand-in worker: what it sends each worker and how it passes the
// replies on, its refusals (client-refusals.mjs), the rekey's questions (client-rekey.mjs), a
// session of hidden wallets, and its copies of secrets, which it wipes.
import assert from "node:assert/strict";

import { PHRASE } from "../public-test-data.mjs";
import { checkClientRefusals, checkMisplacedPassphrases, clientCalls } from "./client-refusals.mjs";
import { checkRekeyCallbacks } from "./client-rekey.mjs";
import { nextTurn } from "./expect.mjs";
import { sources } from "./page-classes.mjs";
import {
  RealTextEncoder,
  RefusedWorker,
  StandInWorker,
  encoderKeeping,
  started,
} from "./stand-in-worker.mjs";
import { TEST_PASSPHRASE, TEST_PASSWORD, encode } from "./test-values.mjs";

/**
 * The core client passes its checks with a stand-in worker; gives the client, whose slot part 4b
 * uses again.
 */
export async function checkCoreClient(classes, libraryMessages) {
  const { MhfeClient, MhfeCancelledError, MhfeError } = classes;
  const client = new MhfeClient(sources);
  assert.equal(client.mode(), "standard");
  assert.equal(client.maxSupportedMemLevel(), 0);
  await checkEncryptRequest(client);
  await checkUnansweredEncrypt(client);
  await checkFastMode(client);
  await checkReadingAndSearch(client, MhfeCancelledError);
  await checkClientRefusals(client, libraryMessages);
  await checkMisplacedPassphrases(client);
  await checkFailingOperations(client);
  await checkRekeyCallbacks(client, MhfeError);
  await checkHiddenWalletSession(client, MhfeCancelledError);
  await checkCopiesWiped(client);
  await checkCallerArrays(client);
  console.log("The core client passes its checks with a stand-in worker.");
  return client;
}

/** What an encryption sends its worker, and how the worker's replies reach the page. */
async function checkEncryptRequest(client) {
  const progress = [];
  const password = encode("public test password");
  const pending = client.encrypt({
    phrase: PHRASE,
    password,
    passwordRepeat: password.slice(),
    repairWordCount: 4,
    walletHasPassphrase: false,
    onProgress: (step) => progress.push(`${step.stage} ${step.round}/${step.rounds}`),
    onUnverified: ({ container }) => progress.push(`unverified ${container}`),
  });
  let worker = await started();
  assert.equal(await worker.script.text(), "single-threaded source\n;\nworker source");
  assert.equal(worker.messages[0].argon2Script, null);
  assert.equal(worker.messages[0].sameLength, false, "24 words unless the page asks otherwise");
  assert.equal(worker.messages[0].repairWordCount, 4);
  assert.equal(
    worker.messages[0].walletHasPassphrase,
    false,
    "the page's answer goes to the worker",
  );
  assert.equal(worker.messages[0].module, "core");
  assert.ok(
    worker.messages[0].compiled instanceof WebAssembly.Module,
    "compiled once, not per worker",
  );
  assert.deepEqual([...worker.messages[0].password], [...password], "the worker gets the password");
  assert.equal(password.length, 20, "the caller's array is copied, not emptied");
  // The phrase goes as bytes too, transferred with the passwords, so that the worker and the
  // WebAssembly wipe it (AUD-010); the non-secret request carries none of the secrets.
  assert.ok(worker.messages[0].phrase instanceof Uint8Array, "the phrase goes as bytes");
  assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE);
  assert.deepEqual(
    worker.transfers[0].map(({ byteLength }) => byteLength),
    [PHRASE.length, 20, 20],
    "the phrase and both passwords are transferred, in buffers of their own",
  );
  worker.reply({ type: "progress", value: { stage: "encrypt", round: 12, rounds: 24 } });
  worker.reply({ type: "unverified", value: { container: "c", containerFingerprint: "00000000" } });
  worker.reply({ type: "progress", value: { stage: "check", round: 13, rounds: 24 } });
  worker.reply({ type: "result", result: { container: "c" } });
  assert.deepEqual(await pending, { container: "c" });
  assert.deepEqual(progress, ["encrypt 12/24", "unverified c", "check 13/24"]);
  assert.equal(worker.terminated, true, "each worker ends with its operation");
}

/**
 * Without an answer, left out or null, the client sends none, and the core names any passphrase
 * of the wallet in what to keep.
 */
async function checkUnansweredEncrypt(client) {
  let worker;
  for (const { description, options } of [
    { description: "left out", options: {} },
    { description: "null", options: { walletHasPassphrase: null } },
  ]) {
    const unanswered = client.encrypt({
      phrase: PHRASE,
      password: "p",
      passwordRepeat: "p",
      ...options,
    });
    worker = await started();
    assert.equal(
      worker.messages[0].walletHasPassphrase,
      options.walletHasPassphrase,
      `encrypt with walletHasPassphrase ${description} sends no answer to the worker`,
    );
    worker.reply({ type: "result", result: { container: "c" } });
    assert.deepEqual(await unanswered, { container: "c" });
  }
}

/** On a cross-origin isolated page the threaded build runs; the core's message is a sentence. */
async function checkFastMode(client) {
  let worker;
  globalThis.crossOriginIsolated = true;
  assert.equal(client.mode(), "fast");
  const fast = client.decrypt({ container: "c", password: "public test password" });
  await assert.rejects(client.decrypt({ container: "c", password: "x" }), { code: "BUSY" });
  worker = await started();
  assert.equal(await worker.script.text(), "threaded source\n;\nworker source");
  assert.equal(await worker.messages[0].argon2Script.text(), "threaded source");
  worker.reply({
    type: "error",
    error: { code: "VERIFIER_MISMATCH", message: "the password or the settings are wrong" },
  });
  // The core's message becomes a sentence that a page can show as it is.
  await assert.rejects(fast, {
    code: "VERIFIER_MISMATCH",
    message: "The password or the settings are wrong",
  });
  delete globalThis.crossOriginIsolated;
}

/** Reading words never waits for a long operation; the searches send what they need. */
async function checkReadingAndSearch(client, MhfeCancelledError) {
  let worker;
  // Reading words starts a worker with the core only, and never waits for a long operation.
  const long = client.check({ container: "c", password: "p", reference: { words: 12 } });
  const reading = client.readContainer("DONA stov");
  worker = await started(({ operation }) => operation === "describeContainer");
  assert.equal(await worker.script.text(), "worker source");
  assert.equal(worker.messages[0].operation, "describeContainer");
  assert.equal(worker.messages[0].password, undefined);
  worker.reply({ type: "result", result: { container: "donate stove" } });
  assert.deepEqual(await reading, { container: "donate stove" });
  client.cancel();
  await assert.rejects(long, (error) => error instanceof MhfeCancelledError);

  // A search with the decoy wallet sends no password and one with the owner's wallet does; both
  // pass the worker's progress on, and a reference that does not belong to the search is a
  // TypeError.
  const decoyProgress = [];
  const decoySearch = client.searchDecoy({
    container: "c ?",
    reference: { fingerprint: "487a156e" },
    onProgress: (value) => decoyProgress.push(value),
  });
  worker = await started(({ operation }) => operation === "searchDecoy");
  assert.equal(worker.messages[0].password, undefined);
  assert.deepEqual(
    [worker.messages[0].referenceKind, worker.messages[0].reference],
    ["fingerprint", "487a156e"],
  );
  worker.reply({ type: "progress", value: { stage: "search", candidate: 8, candidates: 8 } });
  worker.reply({ type: "result", result: { found: false } });
  assert.deepEqual(await decoySearch, { found: false });
  assert.deepEqual(decoyProgress, [{ stage: "search", candidate: 8, candidates: 8 }]);
  const walletSearch = client.searchWallet({
    container: "c ?",
    password: "p",
    reference: { builtInCheck: true },
  });
  worker = await started(({ operation }) => operation === "searchWallet");
  assert.equal(worker.messages[0].referenceKind, "builtInCheck");
  assert.ok(worker.messages[0].password instanceof Uint8Array, "the password goes as bytes");
  worker.reply({ type: "result", result: { found: false } });
  assert.deepEqual(await walletSearch, { found: false });
  await assert.rejects(
    client.searchDecoy({ container: "c ?", reference: { walletCheck: true } }),
    TypeError,
  );
  await assert.rejects(
    client.searchWallet({ container: "c ?", password: "p", reference: { builtInCheck: "yes" } }),
    TypeError,
  );
}

/** A check that fails after the container was shown, and a callback of the page that throws. */
async function checkFailingOperations(client) {
  const { encrypt } = clientCalls(client);
  let worker;
  // A check that fails after the container was shown rejects, so the page can mark it as wrong.
  const shown = [];
  const failing = encrypt({
    password: "p",
    onUnverified: ({ container }) => shown.push(container),
  });
  worker = await started();
  worker.reply({ type: "unverified", value: { container: "c", containerFingerprint: "0" } });
  worker.reply({ type: "error", error: { code: "VERIFICATION_FAILED", message: "wrong" } });
  await assert.rejects(failing, { code: "VERIFICATION_FAILED" });
  assert.deepEqual(shown, ["c"]);

  // A callback of the page that throws stops the operation: the worker ends, the promise rejects
  // with CALLBACK_FAILED and the page's error as the cause, and later messages are ignored.
  for (const { name, message } of [
    {
      name: "onProgress",
      message: { type: "progress", value: { stage: "encrypt", round: 1, rounds: 24 } },
    },
    {
      name: "onUnverified",
      message: { type: "unverified", value: { container: "c", containerFingerprint: "0" } },
    },
  ]) {
    const pageError = new Error(`page bug in ${name}`);
    const calls = [];
    const broken = encrypt({
      password: "p",
      onProgress: () => {
        calls.push("progress");
        if (name === "onProgress") throw pageError;
      },
      onUnverified: () => {
        calls.push("unverified");
        if (name === "onUnverified") throw pageError;
      },
    });
    const brokenWorker = await started();
    brokenWorker.reply(message);
    brokenWorker.reply({ type: "progress", value: { stage: "encrypt", round: 2, rounds: 24 } });
    brokenWorker.reply({ type: "result", result: { container: "c" } });
    await assert.rejects(
      broken,
      (error) => error.code === "CALLBACK_FAILED" && error.cause === pageError,
    );
    assert.equal(brokenWorker.terminated, true, `the worker stops when ${name} throws`);
    assert.equal(
      calls.length,
      1,
      `nothing of the stopped operation reaches the page after ${name}`,
    );
  }
}

/**
 * A session of hidden wallets: ready, a wallet per password, refusals keep it open, close ends
 * it.
 */
async function checkHiddenWalletSession(client, MhfeCancelledError) {
  let worker;
  const opening = client.openHiddenWallets({ container: "c", mainPassphrase: "" });
  worker = await started();
  worker.reply({ type: "ask", question: "ready", value: null });
  const session = await opening;
  await assert.rejects(client.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
  const first = session.open({ password: "one", passwordRepeat: "one" });
  await nextTurn();
  assert.equal(new TextDecoder().decode(worker.messages[1].value.password), "one");
  worker.reply({ type: "ask", question: "opened", value: { phrase: "w", words: 24 } });
  assert.deepEqual(await first, { phrase: "w", words: 24 });
  const again = session.open({ password: "one", passwordRepeat: "one" });
  await nextTurn();
  worker.reply({
    type: "ask",
    question: "refused",
    value: { code: "PASSWORD_ALREADY_USED", message: "this password was already used here" },
  });
  await assert.rejects(again, { code: "PASSWORD_ALREADY_USED" });
  // The library compares a password and its repetition, after the password's own rules, as the
  // command-line tool does: both reach the worker, which refuses them.
  const differing = session.open({ password: "a", passwordRepeat: "b" });
  await nextTurn();
  assert.equal(new TextDecoder().decode(worker.messages[3].value.passwordRepeat), "b");
  worker.reply({
    type: "ask",
    question: "refused",
    value: { code: "PASSWORDS_DIFFER", message: "the password and its repetition differ" },
  });
  await assert.rejects(differing, { code: "PASSWORDS_DIFFER" });
  // A repetition that cannot be encoded is refused before the worker hears of it, and the copy of
  // the password made first is wiped (AUD-011-SEC001); the session stays open.
  const sessionCopies = [];
  globalThis.TextEncoder = encoderKeeping(["synthetic session password"], sessionCopies);
  await assert.rejects(
    session.open({ password: "synthetic session password", passwordRepeat: "a\uD800" }),
    { code: "INVALID_PASSWORD_TEXT" },
  );
  globalThis.TextEncoder = RealTextEncoder;
  assert.equal(sessionCopies.length, 1, "the password was encoded once");
  assert.ok(
    sessionCopies[0].every((byte) => byte === 0),
    "the password's copy is wiped when its repetition is refused",
  );
  assert.equal(worker.messages.length, 4, "a refused repetition did not reach the worker");
  // A password of another type is a TypeError there too, before the entries are compared.
  for (const value of [new Uint16Array([112]), new ArrayBuffer(1), 5]) {
    await assert.rejects(session.open({ password: value, passwordRepeat: value }), {
      name: "TypeError",
      message: "password must be a string or a Uint8Array.",
    });
  }
  assert.equal(worker.messages.length, 4, "no password of a wrong type reached the worker");
  // The worker waits for the page, so closing asks it to free the session, which wipes it.
  const closing = session.close();
  await nextTurn();
  assert.deepEqual(worker.messages.at(-1), { type: "answer", value: { close: true } });
  await assert.rejects(session.open({ password: "x", passwordRepeat: "x" }), {
    code: "SESSION_CLOSED",
  });
  worker.reply({ type: "result", result: { closed: true } });
  await closing;
  assert.equal(worker.terminated, true, "closing the session ends its worker");

  // Closed while a wallet opens, the session stops its worker at once.
  const reopening = client.openHiddenWallets({ container: "c", mainPassphrase: "" });
  worker = await started();
  worker.reply({ type: "ask", question: "ready", value: null });
  const busySession = await reopening;
  const interrupted = busySession.open({ password: "one", passwordRepeat: "one" });
  await nextTurn();
  await busySession.close();
  assert.equal(worker.terminated, true, "a close during an open stops the worker");
  await assert.rejects(interrupted, (error) => error instanceof MhfeCancelledError);
}

/** The client's byte copies of secrets are wiped when an operation cannot start. */
async function checkCopiesWiped(client) {
  const copies = [];
  globalThis.TextEncoder = encoderKeeping([TEST_PASSWORD, TEST_PASSPHRASE, PHRASE], copies);
  const fingerprintCheck = (options) =>
    client.check({
      container: "c",
      password: TEST_PASSWORD,
      reference: { fingerprint: "00000000" },
      passphrase: TEST_PASSPHRASE,
      ...options,
    });
  await assert.rejects(fingerprintCheck({ pim: -1 }), { code: "INVALID_PIM" });
  assert.equal(copies.length, 0, "settings are checked before any secret is copied");
  globalThis.Worker = RefusedWorker;
  await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
  assert.equal(copies.length, 2, "the password and the passphrase were copied");
  assert.ok(
    copies.every((bytes) => bytes.every((byte) => byte === 0)),
    "both copies are wiped when the worker does not start",
  );
  globalThis.Worker = StandInWorker;
  // A browser that refuses the Blob URL ends the operation the same way, and frees its slot.
  const realCreateObjectURL = Object.getOwnPropertyDescriptor(URL, "createObjectURL");
  URL.createObjectURL = () => {
    throw new Error("refused by the stand-in");
  };
  copies.length = 0;
  await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
  await assert.rejects(
    fingerprintCheck({}),
    { code: "WORKER_FAILED" },
    "not BUSY: the slot is free",
  );
  assert.equal(copies.length, 4);
  assert.ok(
    copies.every((bytes) => bytes.every((byte) => byte === 0)),
    "the copies are wiped when the Blob URL is refused",
  );
  // The phrase's copy is wiped with the passwords' when an encryption cannot start.
  copies.length = 0;
  await assert.rejects(
    client.encrypt({
      phrase: PHRASE,
      password: TEST_PASSWORD,
      passwordRepeat: TEST_PASSWORD,
      walletHasPassphrase: false,
    }),
    { code: "WORKER_FAILED" },
  );
  assert.deepEqual(
    copies.map((bytes) => bytes.length),
    [PHRASE.length, TEST_PASSWORD.length, TEST_PASSWORD.length],
    "the phrase and both passwords were copied",
  );
  assert.ok(
    copies.every((bytes) => bytes.every((byte) => byte === 0)),
    "the phrase's copy is wiped too",
  );
  Object.defineProperty(URL, "createObjectURL", realCreateObjectURL);
  globalThis.TextEncoder = RealTextEncoder;
}

// A caller's array is copied into a plain Uint8Array of the package's own, which alone is
// transferred and wiped, whatever the array's own slice() gives (AUD-010). Node's Buffer, and the
// Buffer that bundlers add to a page, slice into views of the caller's memory, here of Node's
// shared pool of small buffers. The caller's array keeps its length and bytes after an operation
// and after every refusal, and the same array may be given as the password and its repetition.
class ViewSlicing extends Uint8Array {
  slice(start, end) {
    return this.subarray(start, end);
  }
}
const callerArrays = {
  "a Uint8Array whose slice() gives a view": (text) => ViewSlicing.from(encode(text)),
  "Node's Buffer": (text) => Buffer.from(text),
};

/** A caller's array is copied into the package's own, which alone is transferred and wiped. */
async function checkCallerArrays(client) {
  for (const [kind, arrayOf] of Object.entries(callerArrays)) {
    await checkCallerArray(client, kind, arrayOf);
  }
}

/** A caller's array of `kind`, from `arrayOf`, as password, repetition and passphrase. */
async function checkCallerArray(client, kind, arrayOf) {
  let worker;
  const given = arrayOf(TEST_PASSWORD);
  const passphraseGiven = arrayOf(TEST_PASSPHRASE);
  const keeps = (array, text, when) => {
    assert.equal(array.length, text.length, `${kind} keeps its length ${when}`);
    assert.equal(new TextDecoder().decode(array), text, `${kind} keeps its bytes ${when}`);
  };
  const operation = client.encrypt({
    phrase: PHRASE,
    password: given,
    passwordRepeat: given,
    walletHasPassphrase: false,
  });
  worker = await started();
  const transferred = worker.transfers[0];
  assert.ok(
    transferred.every(
      ({ buffer }) =>
        buffer !== given.buffer && Object.getPrototypeOf(buffer) === ArrayBuffer.prototype,
    ),
    `${kind}: only the package's own buffers are transferred`,
  );
  assert.equal(
    new Set(transferred.map(({ buffer }) => buffer)).size,
    transferred.length,
    `${kind}: no buffer twice`,
  );
  assert.deepEqual(
    transferred.map(({ byteLength }) => byteLength),
    [PHRASE.length, TEST_PASSWORD.length, TEST_PASSWORD.length],
    `${kind}: copies of the exact size, not the caller's whole buffer`,
  );
  for (const field of ["password", "passwordRepeat"]) {
    assert.equal(
      Object.getPrototypeOf(worker.messages[0][field]),
      Uint8Array.prototype,
      `${kind}: the worker gets a plain Uint8Array as ${field}`,
    );
    assert.equal(new TextDecoder().decode(worker.messages[0][field]), TEST_PASSWORD);
  }
  keeps(given, TEST_PASSWORD, "after the transfer");
  worker.reply({ type: "result", result: { container: "c" } });
  await operation;
  keeps(given, TEST_PASSWORD, "after the operation");
  // Refused by the worker: the repetition differs, which the library compares after the
  // password's own rules; the page's arrays stay as given.
  const otherGiven = arrayOf("another public test password");
  const differing = client.encrypt({
    phrase: PHRASE,
    password: given,
    passwordRepeat: otherGiven,
    walletHasPassphrase: false,
  });
  worker = await started();
  assert.equal(
    new TextDecoder().decode(worker.messages[0].passwordRepeat),
    "another public test password",
  );
  worker.reply({
    type: "error",
    error: { code: "PASSWORDS_DIFFER", message: "the password and its repetition differ" },
  });
  await assert.rejects(differing, { code: "PASSWORDS_DIFFER" });
  keeps(given, TEST_PASSWORD, "after its repetition was refused");
  keeps(otherGiven, "another public test password", "as a repetition that was refused");
  globalThis.Worker = RefusedWorker;
  await assert.rejects(
    client.check({
      container: "c",
      password: given,
      reference: { fingerprint: "00000000" },
      passphrase: passphraseGiven,
    }),
    { code: "WORKER_FAILED" },
  );
  globalThis.Worker = StandInWorker;
  keeps(given, TEST_PASSWORD, "after the worker did not start");
  keeps(passphraseGiven, TEST_PASSPHRASE, "as a passphrase after the worker did not start");
}
