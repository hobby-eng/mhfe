// Part 4 of the checks of the browser package, continued: the quick modules' classes, MhfeRepair,
// MhfePasswords and MhfeWallet, against the stand-in worker, each call in a worker of its own,
// terminated afterwards: what they send, the replies they refuse, the wallet's drawing workers,
// and their copies of secrets, which they wipe.
import assert from "node:assert/strict";

import { PHRASE } from "../public-test-data.mjs";
import { fieldsOf, nextTurn } from "./expect.mjs";
import { BUILD_ID } from "./package.mjs";
import { wasm } from "./page-classes.mjs";
import { RealTextEncoder, StandInWorker, encoderKeeping, started } from "./stand-in-worker.mjs";
import { CHECK_WORD_TAKES_NO_COUNT, TEST_PASSPHRASE, TEST_PASSWORD } from "./test-values.mjs";

/**
 * The repair, passwords and wallet classes pass their checks with a stand-in worker; gives the
 * wallet's class, whose slot part 4b uses again.
 */
export async function checkModuleClasses(classes, client, libraryMessages) {
  const { MhfeRepair, MhfePasswords, MhfeWallet, MhfeCancelledError } = classes;
  await checkRepairClass(new MhfeRepair({ workerSource: "repair worker", wasm }), client);
  const passwordsClient = new MhfePasswords({ workerSource: "passwords worker", wasm });
  await checkPasswordsClass(passwordsClient);
  const walletClient = new MhfeWallet({ workerSource: "wallet worker", wasm });
  await checkWalletPhrases(walletClient, libraryMessages);
  await checkWalletDraws(walletClient);
  await checkHintsAndCancel(walletClient, passwordsClient, MhfeCancelledError);
  await checkFirstEntryCopies(walletClient, passwordsClient);
  await checkDrawCopies(walletClient, passwordsClient);
  await checkFailingProgress(walletClient);
  console.log("The repair, passwords and wallet classes pass their checks with a stand-in worker.");
  return walletClient;
}

/** The repair class, and replies the page does not know or cannot read. */
async function checkRepairClass(repairClient, client) {
  let worker;
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
  // no page code: it ends the job as a fault of the package, and no answer is sent
  // (AUD-015-SEC007).
  for (const reply of [
    { type: "valueOf", value: null },
    { type: "constructor", value: null },
    { type: "__proto__", value: null },
    { type: "notAKnownType", value: null },
    { type: "ask", question: "toString", value: null },
    { type: "ask", question: "notAKnownQuestion", value: null },
  ]) {
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
  // A reply that the page cannot read, as from a faulty worker or one of another build, ends the
  // job the same way, also after the worker said it was ready: nothing throws from the worker's
  // event handler, the worker stops, and the slot is free for the next operation (AUD-016-API002).
  for (const reply of [
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
  ]) {
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
}

/** The passwords class: a review, and the check word, which takes no count. */
async function checkPasswordsClass(passwordsClient) {
  let worker;
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
      message: `${CHECK_WORD_TAKES_NO_COUNT}.`,
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
}

/** A phrase goes to the wallet's worker as bytes, and a refused passphrase leaves no copy. */
async function checkWalletPhrases(walletClient, libraryMessages) {
  let worker;
  // A phrase goes to the wallet's worker as bytes, transferred with the passphrase, so that the
  // worker and the WebAssembly wipe it (AUD-010).
  for (const [method, operation] of [
    ["fingerprint", "fingerprint"],
    ["walletCheck", "walletCheck"],
  ]) {
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
  globalThis.TextEncoder = encoderKeeping([PHRASE], phraseCopies);
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
    { code: "PASSPHRASES_DIFFER", message: libraryMessages.PASSPHRASES_DIFFER },
  );
  await assert.rejects(walletClient.drawPhrase({ walletCheck: true }), {
    code: "WALLET_CHECK_NEEDS_PASSPHRASE",
    message: libraryMessages.WALLET_CHECK_NEEDS_PASSPHRASE,
  });
}

/** A checked phrase is drawn on several workers; a chosen word reaches the worker as a secret. */
async function checkWalletDraws(walletClient) {
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
  await nextTurn();
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
  for (const chosen of [
    [{ word: "zoo", position: 0 }],
    [{ word: "zoo", position: "first" }],
    [{ position: 1 }],
    "zoo",
  ]) {
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
}

/** A line for a hint reaches the worker as a secret of its own; a draw can be cancelled. */
async function checkHintsAndCancel(walletClient, passwordsClient, MhfeCancelledError) {
  // A line for a hint reaches the worker as a secret of its own, with the module's list.
  for (const [client, operation] of [
    [walletClient, "wordHints"],
    [passwordsClient, "wordHints"],
  ]) {
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
}

/**
 * A refused repetition leaves no copy of the first entry behind: one of a wrong type is refused
 * before any copy, and one that is not valid text after the first entry was copied, which is
 * then wiped.
 */
async function checkFirstEntryCopies(walletClient, passwordsClient) {
  const firstCopies = [];
  globalThis.TextEncoder = encoderKeeping([TEST_PASSWORD, TEST_PASSPHRASE], firstCopies);
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
}

/**
 * A count of workers out of range is refused before the passphrase is copied, and a worker that
 * cannot be started leaves none of this class's copies behind, stops the workers started and frees
 * the drawing for the next (AUD-012-SEC001).
 */
async function checkDrawCopies(walletClient, passwordsClient) {
  const drawCopies = [];
  globalThis.TextEncoder = encoderKeeping([TEST_PASSPHRASE], drawCopies);
  await checkDrawOptionsRefused(walletClient, drawCopies);
  await checkSecretsGivenAsNull(walletClient, passwordsClient);
  await checkUncopiablePassphrase(walletClient);
  globalThis.TextEncoder = RealTextEncoder;
  assert.equal(drawCopies.length, 2, "the passphrase and its repetition were encoded");
  assert.ok(
    drawCopies.every((bytes) => bytes.every((byte) => byte === 0)),
    "this class's copies are wiped when a worker cannot be started",
  );
  await nextTurn();
  assert.ok(
    StandInWorker.started.filter((each) => !each.selfCheck).every((each) => each.terminated),
    "the worker started is stopped",
  );
  await checkUnmadeEmptyRepetition(walletClient, drawCopies);
}

/** A count of workers, or a walletCheck, of the wrong kind is refused before any worker starts. */
async function checkDrawOptionsRefused(walletClient, drawCopies) {
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
  for (const [options, message] of [
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
  ]) {
    await assert.rejects(walletClient.drawPhrase(options), { name: "TypeError", message });
  }
  assert.equal(StandInWorker.started.length, 0, "a refused draw starts no worker");
}

/** A secret given as null, or left out, and what the library is given then. */
async function checkSecretsGivenAsNull(walletClient, passwordsClient) {
  let worker;
  // A secret given as null is not one left out: only undefined takes a method's empty default, and
  // null is a TypeError, as any other type, before any copy or worker (AUD-016-API003).
  const notSecret = (name) => ({
    name: "TypeError",
    message: `${name} must be a string or a Uint8Array.`,
  });
  for (const [call, expected] of [
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
  ]) {
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
}

/** The second worker's copy of the passphrase cannot be made: the first worker had its copies. */
async function checkUncopiablePassphrase(walletClient) {
  // %TypedArray%.prototype, which holds the slice() of every typed array.
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const passphraseBytes = new TextDecoder();
  let passphraseSlices = 0;
  Uint8Array.prototype.slice = function (...range) {
    if (passphraseBytes.decode(this) === TEST_PASSPHRASE) {
      passphraseSlices += 1;
      // The third copy, the second worker's passphrase, cannot be made.
      if (passphraseSlices === 3) throw new RangeError("no memory for the copy");
    }
    return typedArrayPrototype.slice.apply(this, range);
  };
  StandInWorker.started.length = 0;
  const brokenDraw = walletClient.drawPhrase({
    passphrase: TEST_PASSPHRASE,
    passphraseRepeat: TEST_PASSPHRASE,
    walletCheck: true,
    workers: 2,
  });
  await assert.rejects(brokenDraw, { name: "RangeError" });
  // The inherited slice() again.
  delete Uint8Array.prototype.slice;
  assert.equal(passphraseSlices, 3, "the first worker had its copies before the third failed");
}

/** Nor when the empty repetition of a drawing cannot be made, before the passphrase is copied. */
async function checkUnmadeEmptyRepetition(walletClient, drawCopies) {
  const RealUint8Array = globalThis.Uint8Array;
  let emptyRefused = false;
  globalThis.TextEncoder = encoderKeeping([TEST_PASSPHRASE], drawCopies);
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
  await nextTurn();
  StandInWorker.started.at(-1).reply({ type: "result", result: { phrase: "next", words: 24 } });
  assert.deepEqual(await afterBroken, { phrase: "next", words: 24, workers: 1 });
}

/**
 * A progress callback whose promise rejects stops every drawing worker; here the second has not
 * loaded the WebAssembly yet.
 */
async function checkFailingProgress(walletClient) {
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
  await nextTurn();
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
}
