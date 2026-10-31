// A session of hidden wallets: ready, a wallet per password, refusals keep it open, close ends it.
const opening = client.openHiddenWallets({ container: "c", mainPassphrase: "" });
worker = await started();
worker.reply({ type: "ask", question: "ready", value: null });
const session = await opening;
await assert.rejects(client.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
const first = session.open({ password: "one", passwordRepeat: "one" });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(new TextDecoder().decode(worker.messages[1].value.password), "one");
worker.reply({ type: "ask", question: "opened", value: { phrase: "w", words: 24 } });
assert.deepEqual(await first, { phrase: "w", words: 24 });
const again = session.open({ password: "one", passwordRepeat: "one" });
await new Promise((resolve) => setTimeout(resolve, 0));
worker.reply({
  type: "ask",
  question: "refused",
  value: { code: "PASSWORD_ALREADY_USED", message: "this password was already used here" },
});
await assert.rejects(again, { code: "PASSWORD_ALREADY_USED" });
// The library compares a password and its repetition, after the password's own rules, as the
// command-line tool does: both reach the worker, which refuses them.
const differing = session.open({ password: "a", passwordRepeat: "b" });
await new Promise((resolve) => setTimeout(resolve, 0));
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
const EncoderOfSession = globalThis.TextEncoder;
globalThis.TextEncoder = class extends EncoderOfSession {
  encode(text) {
    const bytes = super.encode(text);
    if (text === "synthetic session password") sessionCopies.push(bytes);
    return bytes;
  }
};
await assert.rejects(
  session.open({ password: "synthetic session password", passwordRepeat: "a\uD800" }),
  { code: "INVALID_PASSWORD_TEXT" },
);
globalThis.TextEncoder = EncoderOfSession;
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
await new Promise((resolve) => setTimeout(resolve, 0));
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
await new Promise((resolve) => setTimeout(resolve, 0));
await busySession.close();
assert.equal(worker.terminated, true, "a close during an open stops the worker");
await assert.rejects(interrupted, (error) => error instanceof MhfeCancelledError);

// The client's byte copies of secrets are wiped when an operation cannot start.
const TEST_PASSPHRASE = "public test passphrase";
const copies = [];
const RealTextEncoder = globalThis.TextEncoder;
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSWORD || text === TEST_PASSPHRASE || text === PHRASE) copies.push(bytes);
    return bytes;
  }
};
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
globalThis.Worker = class {
  constructor() {
    throw new Error("refused by the stand-in");
  }
};
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
assert.equal(copies.length, 2, "the password and the passphrase were copied");
assert.ok(
  copies.every((bytes) => bytes.every((byte) => byte === 0)),
  "both copies are wiped when the worker does not start",
);
globalThis.Worker = StandInWorker;
// A browser that refuses the Blob URL ends the operation the same way, and frees its slot.
const realCreateObjectURL = URL.createObjectURL;
URL.createObjectURL = () => {
  throw new Error("refused by the stand-in");
};
copies.length = 0;
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" }, "not BUSY: the slot is free");
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
URL.createObjectURL = realCreateObjectURL;
globalThis.TextEncoder = RealTextEncoder;

// A caller's array is copied into a plain Uint8Array of the package's own, which alone is
// transferred and wiped, whatever the array's own slice() gives (AUD-010). Node's Buffer, and the
// Buffer that bundlers add to a page, slice into views of the caller's memory, and a small one is
// itself a view into a shared pool of other bytes. The caller's array keeps its length and bytes
// after an operation and after every refusal, and the same array may be given as the password and
// its repetition.
class ViewSlicing extends Uint8Array {
  slice(start, end) {
    return this.subarray(start, end);
  }
}
const callerArrays = {
  "a Uint8Array whose slice() gives a view": (text) => ViewSlicing.from(encode(text)),
  // A view away from the start of a larger buffer, whatever their sizes: a copy of the caller's
  // whole buffer then shows in its size.
  "Node's Buffer": (text) => {
    const bytes = encode(text);
    const start = 100;
    const pool = new Buffer(start + bytes.length + start);
    pool.set(bytes, start);
    return pool.subarray(start, start + bytes.length);
  },
};
for (const [kind, arrayOf] of Object.entries(callerArrays)) {
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
  globalThis.Worker = class {
    constructor() {
      throw new Error("refused by the stand-in");
    }
  };
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
console.log("The core client passes its checks with a stand-in worker.");

// The quick modules: each call in a worker of its own, terminated afterwards.
const repairClient = new MhfeRepair({ workerSource: "repair worker", wasm });
const card = repairClient.repairWords({ container: "c", count: 4 });
worker = await started();
assert.equal(await worker.script.text(), "repair worker");
assert.equal(worker.messages[0].module, "repair");
assert.equal(worker.messages[0].operation, "repairWords");
worker.reply({ type: "result", result: { words: "w" } });
assert.deepEqual(await card, { words: "w" });
assert.equal(worker.terminated, true);
await assert.rejects(repairClient.repairWords({ container: "c", count: "4" }), TypeError);
// A reply or a question named after an Object.prototype member, or unknown to the page, reaches
// no page code: it ends the job as a fault of the package, and no answer is sent (AUD-015-SEC007).
for (
  const reply of [
    { type: "valueOf", value: null },
    { type: "constructor", value: null },
    { type: "__proto__", value: null },
    { type: "notAKnownType", value: null },
    { type: "ask", question: "toString", value: null },
    { type: "ask", question: "notAKnownQuestion", value: null },
  ]
) {
  const asking = repairClient.repairWords({ container: "c", count: 4 });
  worker = await started();
  worker.reply(reply);
  await assert.rejects(asking, (error) => {
    assert.equal(error.code, "PACKAGE_MISMATCH");
    assert.match(error.message, /^The worker sent a message this page does not know \(/u);
    return true;
  });
  assert.equal(worker.messages.length, 1, `no answer to ${reply.question ?? reply.type}`);
  assert.equal(worker.terminated, true);
}
// A reply that the page cannot read, as from a faulty worker or one of another build, ends the job
// the same way, also after the worker said it was ready: nothing throws from the worker's event
// handler, the worker stops, and the slot is free for the next operation (AUD-016-API002).
for (
  const reply of [
    null,
    5,
    "result",
    {},
    { type: 3 },
    { type: "ready", buildId: 5 },
    { type: "error" },
    { type: "error", error: null },
    { type: "error", error: { code: "INTERNAL_ERROR" } },
    { type: "error", error: { code: "INTERNAL_ERROR", message: 3 } },
    { type: "error", error: { code: 3, message: "the worker failed" } },
  ]
) {
  const description = JSON.stringify(reply);
  const decrypting = client.decrypt({ container: "c", password: "p" });
  worker = await started();
  worker.reply({ type: "ready", buildId: BUILD_ID });
  assert.doesNotThrow(() => worker.reply(reply), `${description} throws from the event handler`);
  await assert.rejects(decrypting, (error) => {
    assert.equal(error.code, "PACKAGE_MISMATCH", description);
    assert.match(error.message, /^The worker sent a message this page does not know \(/u);
    return true;
  });
  assert.equal(worker.terminated, true, `${description} stops the worker`);
}
const afterMalformed = client.decrypt({ container: "c", password: "p" });
worker = await started();
worker.reply({ type: "result", result: { kind: "phrase" } });
assert.deepEqual(await afterMalformed, { kind: "phrase" }, "the slot is free again");

const passwordsClient = new MhfePasswords({ workerSource: "passwords worker", wasm });
const reviewing = passwordsClient.review({
  password: "secret words",
  passwordRepeat: "secret words",
});
worker = await started();
assert.equal(worker.messages[0].module, "passwords");
assert.equal(worker.messages[0].operation, "review");
assert.equal(worker.messages[0].repeated, true);
assert.equal(new TextDecoder().decode(worker.messages[0].password), "secret words");
worker.reply({ type: "result", result: { reading: "notThisShape" } });
assert.deepEqual(await reviewing, { reading: "notThisShape" });
// The check word takes no count, refused before any worker starts, as the WebAssembly refuses it
// and `mhfe password` refuses --check-word with --words (AUD-010). Without one, the class sends
// none.
const workersBeforeCount = StandInWorker.started.length;
for (const count of [7, 5, 0]) {
  await assert.rejects(passwordsClient.make({ kind: "checkWord", count }), {
    name: "TypeError",
    message:
      'count belongs only to the kinds "words" and "characters": "checkWord" always gives five '
      + "words and their check word.",
  });
}
assert.equal(StandInWorker.started.length, workersBeforeCount, "no worker was started");
const makingCheckWord = passwordsClient.make({ kind: "checkWord" });
worker = await started();
assert.deepEqual(fieldsOf(worker.messages[0], ["operation", "kind", "count"]), {
  operation: "make",
  kind: "checkWord",
  count: undefined,
});
worker.reply({ type: "result", result: { checkWord: true } });
assert.deepEqual(await makingCheckWord, { checkWord: true });

const walletClient = new MhfeWallet({ workerSource: "wallet worker", wasm });
// A phrase goes to the wallet's worker as bytes, transferred with the passphrase, so that the
// worker and the WebAssembly wipe it (AUD-010).
for (
  const [method, operation] of [
    ["fingerprint", "fingerprint"],
    ["walletCheck", "walletCheck"],
  ]
) {
  const asked = walletClient[method]({ phrase: PHRASE, passphrase: "TREZOR" });
  worker = await started(({ operation: sent }) => sent === operation);
  assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE, method);
  assert.equal(new TextDecoder().decode(worker.messages[0].passphrase), "TREZOR", method);
  assert.deepEqual(
    worker.transfers[0].map(({ byteLength }) => byteLength),
    [PHRASE.length, "TREZOR".length],
    `${method}: the phrase and the passphrase are transferred`,
  );
  worker.reply({ type: "result", result: "73c5da0a" });
  assert.equal(await asked, "73c5da0a");
}
// A passphrase of another type is a TypeError before the phrase is copied; one with a lone
// surrogate leaves no copy of the phrase behind.
const phraseCopies = [];
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === PHRASE) phraseCopies.push(bytes);
    return bytes;
  }
};
await assert.rejects(walletClient.fingerprint({ phrase: PHRASE, passphrase: 5 }), {
  name: "TypeError",
  message: "passphrase must be a string or a Uint8Array.",
});
assert.equal(phraseCopies.length, 0, "the phrase was not copied");
await assert.rejects(walletClient.walletCheck({ phrase: PHRASE, passphrase: "a\uD800" }), {
  code: "INVALID_PASSWORD_TEXT",
});
globalThis.TextEncoder = RealTextEncoder;
assert.equal(phraseCopies.length, 1);
assert.ok(
  phraseCopies[0].every((byte) => byte === 0),
  "the phrase's copy is wiped",
);
await assert.rejects(
  walletClient.drawPhrase({ passphrase: "p", passphraseRepeat: "p" }),
  TypeError,
);
await assert.rejects(
  walletClient.drawPhrase({ passphrase: "p", passphraseRepeat: "q", walletCheck: true }),
  { code: "PASSPHRASES_DIFFER", message: LIBRARY_MESSAGES.PASSPHRASES_DIFFER },
);
await assert.rejects(walletClient.drawPhrase({ walletCheck: true }), {
  code: "WALLET_CHECK_NEEDS_PASSPHRASE",
  message: LIBRARY_MESSAGES.WALLET_CHECK_NEEDS_PASSPHRASE,
});
StandInWorker.started.length = 0;
const draws = [];
const drawing = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 3,
  onProgress: ({ draws: count }) => draws.push(count),
});
await started();
await new Promise((resolve) => setTimeout(resolve, 0));
const drawWorkers = StandInWorker.started.filter((each) => !each.selfCheck);
assert.equal(drawWorkers.length, 3, "a checked phrase is drawn on several workers");
assert.ok(drawWorkers.every((each) => each.messages[0].module === "wallet"));
drawWorkers[0].reply({ type: "draws", value: 1024 });
drawWorkers[1].reply({ type: "draws", value: 1024 });
drawWorkers[2].reply({ type: "result", result: { phrase: "found", words: 24 } });
assert.deepEqual(await drawing, { phrase: "found", words: 24, workers: 3 });
assert.deepEqual(draws, [1024, 2048]);
assert.ok(
  drawWorkers.every((each) => each.terminated),
  "the other workers stop",
);
// A chosen word reaches the worker as a secret of its own, which its job wipes; its place, 0 for
// anywhere, and the words never to use as they are. One worker draws a phrase without the check.
const wishedDraw = walletClient.drawPhrase({
  chosen: [{ word: "zoo", position: "anywhere" }],
  neverUse: ["abandon"],
});
const wishWorker = await started((message) => message.operation === "drawPhrase");
assert.equal(new TextDecoder().decode(wishWorker.messages[0].chosenWords), "zoo");
assert.deepEqual(Array.from(wishWorker.messages[0].places), [0]);
assert.equal(wishWorker.messages[0].neverUse, "abandon");
wishWorker.reply({ type: "result", result: { phrase: "found", words: 24 } });
assert.deepEqual(await wishedDraw, { phrase: "found", words: 24, workers: 1 });
for (
  const chosen of [
    [{ word: "zoo", position: 0 }],
    [{ word: "zoo", position: "first" }],
    [{ position: 1 }],
    "zoo",
  ]
) {
  await assert.rejects(walletClient.drawPhrase({ chosen }), TypeError, JSON.stringify(chosen));
}
await assert.rejects(walletClient.drawPhrase({ neverUse: "abandon" }), TypeError);
await assert.rejects(walletClient.describeDraw({ walletCheck: "yes" }), TypeError);
const describing = walletClient.describeDraw({ chosen: [{ word: "zoo", position: 24 }] });
const describeWorker = await started((message) => message.operation === "describeDraw");
assert.equal(new TextDecoder().decode(describeWorker.messages[0].chosenWords), "zoo");
assert.deepEqual(Array.from(describeWorker.messages[0].places), [24]);
describeWorker.reply({ type: "result", result: { randomness: "ample" } });
assert.deepEqual(await describing, { randomness: "ample" });
// A line for a hint reaches the worker as a secret of its own, with the module's list.
for (
  const [client, operation] of [
    [walletClient, "wordHints"],
    [passwordsClient, "wordHints"],
  ]
) {
  const hinting = client.wordHints({ typed: "abandon ab" });
  const hintWorker = await started((message) => message.operation === operation);
  assert.equal(new TextDecoder().decode(hintWorker.messages[0].typed), "abandon ab");
  hintWorker.reply({ type: "result", result: { hint: "words" } });
  assert.deepEqual(await hinting, { hint: "words" });
}
await assert.rejects(walletClient.wordHints({ typed: 5 }), TypeError);
const cancelledDraw = walletClient.drawPhrase();
walletClient.cancel();
await assert.rejects(cancelledDraw, (error) => error instanceof MhfeCancelledError);
// A refused repetition leaves no copy of the first entry behind: one of a wrong type is refused
// before any copy, and one that is not valid text after the first entry was copied, which is
// then wiped.
const firstCopies = [];
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSWORD || text === TEST_PASSPHRASE) firstCopies.push(bytes);
    return bytes;
  }
};
await assert.rejects(
  passwordsClient.review({ password: TEST_PASSWORD, passwordRepeat: 5 }),
  TypeError,
);
assert.equal(firstCopies.length, 0, "a repetition of a wrong type is refused before any copy");
await assert.rejects(
  passwordsClient.review({ password: TEST_PASSWORD, passwordRepeat: "\uD800" }),
  { code: "INVALID_PASSWORD_TEXT" },
);
await assert.rejects(
  walletClient.drawPhrase({
    passphrase: TEST_PASSPHRASE,
    passphraseRepeat: "\uD800",
    walletCheck: true,
  }),
  { code: "INVALID_PASSWORD_TEXT" },
);
globalThis.TextEncoder = RealTextEncoder;
assert.equal(firstCopies.length, 2);
assert.ok(
  firstCopies.every((bytes) => bytes.every((byte) => byte === 0)),
  "the first entry's copy is wiped when its repetition is refused",
);

// A count of workers out of range is refused before the passphrase is copied, and a worker that
// cannot be started leaves none of this class's copies behind, stops the workers started and frees
// the drawing for the next (AUD-012-SEC001).
const drawCopies = [];
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSPHRASE) drawCopies.push(bytes);
    return bytes;
  }
};
for (const workers of [2 ** 32, 257, 0, 1.5]) {
  await assert.rejects(
    walletClient.drawPhrase({
      passphrase: TEST_PASSPHRASE,
      passphraseRepeat: TEST_PASSPHRASE,
      walletCheck: true,
      workers,
    }),
    { name: "TypeError", message: "workers must be a whole number from 1 to 256." },
  );
}
assert.equal(drawCopies.length, 0, "a refused count copies no passphrase");
// The type of walletCheck and the count of workers are checked whatever the passphrase, before
// any worker starts (AUD-015-API001).
StandInWorker.started.length = 0;
for (
  const [options, message] of [
    [{ walletCheck: "yes" }, "walletCheck must be true or false."],
    [{ walletCheck: 1 }, "walletCheck must be true or false."],
    [{ workers: 0 }, "workers must be a whole number from 1 to 256."],
    [{ workers: "many" }, "workers must be a whole number from 1 to 256."],
    [
      {
        passphrase: TEST_PASSPHRASE,
        passphraseRepeat: TEST_PASSPHRASE,
        walletCheck: false,
        workers: -1,
      },
      "workers must be a whole number from 1 to 256.",
    ],
  ]
) {
  await assert.rejects(walletClient.drawPhrase(options), { name: "TypeError", message });
}
assert.equal(StandInWorker.started.length, 0, "a refused draw starts no worker");
// A secret given as null is not one left out: only undefined takes a method's empty default, and
// null is a TypeError, as any other type, before any copy or worker (AUD-016-API003).
const notSecret = (name) => ({
  name: "TypeError",
  message: `${name} must be a string or a Uint8Array.`,
});
for (
  const [call, expected] of [
    [() => passwordsClient.review({ password: "", passwordRepeat: null }), "repeated password"],
    [() => passwordsClient.review({ password: null }), "password"],
    [() => walletClient.walletCheck({ phrase: PHRASE, passphrase: null }), "passphrase"],
    [() => walletClient.fingerprint({ phrase: PHRASE, passphrase: null }), "passphrase"],
    [
      () =>
        walletClient.drawPhrase({ passphrase: "x", passphraseRepeat: null, walletCheck: false }),
      "repeated passphrase",
    ],
    [() => walletClient.drawPhrase({ passphrase: null, walletCheck: false }), "passphrase"],
    [() => walletClient.drawPhrase({ passphraseRepeat: null }), "repeated passphrase"],
  ]
) {
  await assert.rejects(call(), notSecret(expected));
}
assert.equal(StandInWorker.started.length, 0, "a secret of a wrong type starts no worker");
// Left out, a repetition is none and a passphrase is empty, for the library to judge.
const reviewedOnce = passwordsClient.review({ password: "p" });
worker = await started((message) => message.operation === "review");
assert.deepEqual(
  [worker.messages[0].repeated, worker.messages[0].passwordRepeat.length],
  [false, 0],
);
worker.reply({ type: "result", result: { reading: "notThisShape" } });
await reviewedOnce;
const checkedWithout = walletClient.walletCheck({ phrase: PHRASE });
worker = await started((message) => message.operation === "walletCheck");
assert.equal(worker.messages[0].passphrase.length, 0);
worker.reply({
  type: "error",
  error: { code: "WALLET_CHECK_NEEDS_PASSPHRASE", message: "the library refuses it" },
});
await assert.rejects(checkedWithout, { code: "WALLET_CHECK_NEEDS_PASSPHRASE" });
const RealSlice = Uint8Array.prototype.slice;
const passphraseBytes = new TextDecoder();
let passphraseSlices = 0;
Uint8Array.prototype.slice = function(...range) {
  if (passphraseBytes.decode(this) === TEST_PASSPHRASE) {
    passphraseSlices += 1;
    // The third copy, the second worker's passphrase, cannot be made.
    if (passphraseSlices === 3) throw new RangeError("no memory for the copy");
  }
  return RealSlice.apply(this, range);
};
StandInWorker.started.length = 0;
const brokenDraw = walletClient.drawPhrase({
  passphrase: TEST_PASSPHRASE,
  passphraseRepeat: TEST_PASSPHRASE,
  walletCheck: true,
  workers: 2,
});
await assert.rejects(brokenDraw, { name: "RangeError" });
Uint8Array.prototype.slice = RealSlice;
assert.equal(passphraseSlices, 3, "the first worker had its copies before the third failed");
globalThis.TextEncoder = RealTextEncoder;
assert.equal(drawCopies.length, 2, "the passphrase and its repetition were encoded");
assert.ok(
  drawCopies.every((bytes) => bytes.every((byte) => byte === 0)),
  "this class's copies are wiped when a worker cannot be started",
);
await new Promise((resolve) => setTimeout(resolve, 0));
assert.ok(
  StandInWorker.started.filter((each) => !each.selfCheck).every((each) => each.terminated),
  "the worker started is stopped",
);
// Nor when the empty repetition of a drawing cannot be made, before the passphrase is copied.
const RealUint8Array = globalThis.Uint8Array;
let emptyRefused = false;
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSPHRASE) drawCopies.push(bytes);
    return bytes;
  }
};
drawCopies.length = 0;
globalThis.Uint8Array = new Proxy(RealUint8Array, {
  construct(target, args, newTarget) {
    if (!emptyRefused && args.length === 1 && args[0] === 0) {
      emptyRefused = true;
      throw new RangeError("no memory for the empty repetition");
    }
    return Reflect.construct(target, args, newTarget);
  },
});
const emptyDraw = walletClient.drawPhrase({ passphrase: TEST_PASSPHRASE, walletCheck: false });
await assert.rejects(emptyDraw, { name: "RangeError" });
globalThis.Uint8Array = RealUint8Array;
globalThis.TextEncoder = RealTextEncoder;
assert.ok(emptyRefused, "the empty repetition was refused");
assert.ok(
  drawCopies.every((bytes) => bytes.every((byte) => byte === 0)),
  "no copy of the passphrase is left when the empty repetition cannot be made",
);
const afterBroken = walletClient.drawPhrase();
await started();
await new Promise((resolve) => setTimeout(resolve, 0));
StandInWorker.started.at(-1).reply({ type: "result", result: { phrase: "next", words: 24 } });
assert.deepEqual(await afterBroken, { phrase: "next", words: 24, workers: 1 });

// A progress callback whose promise rejects stops every drawing worker; here the second has not
// loaded the WebAssembly yet.
StandInWorker.started.length = 0;
StandInWorker.loads = false;
const failingDraw = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 2,
  onProgress: () => Promise.reject(new Error("the page failed")),
});
await started();
await new Promise((resolve) => setTimeout(resolve, 0));
const failingWorkers = StandInWorker.started.filter((each) => !each.selfCheck);
failingWorkers[0].reply({ type: "draws", value: 1024 });
await assert.rejects(failingDraw, { code: "CALLBACK_FAILED" });
// A worker that has not yet said it loaded the WebAssembly stops once it has: Firefox crashes the
// page when a worker is terminated while it loads it, as when every worker of a draw failed at
// once (reported by wallet-tools, 2026-10-08).
assert.ok(failingWorkers[0].terminated, "the worker that reported stops at once");
assert.ok(!failingWorkers[1].terminated, "a worker still loading is not terminated");
failingWorkers[1].reply({ type: "ready", buildId: BUILD_ID });
assert.ok(failingWorkers[1].terminated, "it stops as soon as it has loaded");
StandInWorker.loads = true;
console.log("The repair, passwords and wallet classes pass their checks with a stand-in worker.");
