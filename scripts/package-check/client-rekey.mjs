// Part 4 of the checks of the browser package, continued: the core client's rekey, which asks the
// page in the middle, through its owner callback and onConfirmAgain, and sends the answers back
// to the worker.
import assert from "node:assert/strict";

import { clientCalls } from "./client-refusals.mjs";
import { fieldsOf, nextTurn } from "./expect.mjs";
import { started } from "./stand-in-worker.mjs";
import { PHRASE_TREZOR_FINGERPRINT, REKEY_PASSPHRASE_ONLY_WITH_REFERENCE } from "./test-values.mjs";

/** The check the stand-in worker shows the owner: the length stated where another was found. */
const shownToOwner = {
  phrase: "p",
  words: 12,
  statedWords: 15,
  fingerprintWithoutPassphrase: "00000000",
};
// The owner's yes goes back with the passphrase for the new container's rehearsal, empty here.
const OWNER_YES = { type: "answer", value: { confirmed: true, passphrase: new Uint8Array(0) } };
/** A refusal that allows another confirmation, with the lengths the owner may compare. */
const lengthDiffers = { code: "LENGTH_DIFFERS", message: "the check finds 12", ownerLengths: [15] };

/** The rekey's questions to the page, its answers, and what ends it. */
export async function checkRekeyCallbacks(client, MhfeError) {
  await checkOwnerAsked(client);
  await checkConfirmAgain(client, MhfeError);
  await checkConfirmAgainRefused(client);
  await checkTrapAndPassphrases(client);
}

/**
 * A rekey asks the owner in the middle and sends the answer back. The callback gets the check as
 * the worker gives it, with the length stated where the built-in check found another.
 */
async function checkOwnerAsked(client) {
  let worker;
  const ownerChecks = [];
  const rekeying = client.rekey({
    container: "c",
    words: 15,
    password: "old",
    newPassword: "new",
    newPasswordRepeat: "new",
    confirmation: {
      owner: (check) => {
        ownerChecks.push(check);
        return check.words === 12;
      },
    },
    walletHasPassphrase: true,
  });
  worker = await started();
  assert.equal(worker.messages[0].confirmKind, "owner");
  assert.equal(
    worker.messages[0].walletHasPassphrase,
    true,
    "the page's answer goes to the worker",
  );
  worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
  await nextTurn();
  assert.deepEqual(ownerChecks, [shownToOwner]);
  assert.deepEqual(worker.messages[1], OWNER_YES);
  worker.reply({ type: "result", result: { container: "n" } });
  assert.deepEqual(await rekeying, { container: "n" });
  // The owner's yes with the wallet's passphrase, for the new container's rehearsal, reaches the
  // worker as a yes with the passphrase as bytes; any other answer is a no.
  for (const [answer, confirmed, passphrase] of [
    [{ passphrase: "TREZOR" }, true, "TREZOR"],
    [1, false, ""],
    [{}, false, ""],
  ]) {
    const answered = client.rekey({
      container: "c",
      words: 15,
      password: "old",
      newPassword: "new",
      newPasswordRepeat: "new",
      confirmation: { owner: () => answer },
      walletHasPassphrase: true,
    });
    worker = await started();
    worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
    await nextTurn();
    const { value } = worker.messages[1];
    assert.deepEqual(
      [value.confirmed, new TextDecoder().decode(value.passphrase)],
      [confirmed, passphrase],
      `the owner's answer ${JSON.stringify(answer)}`,
    );
    worker.reply({ type: "result", result: { container: "n" } });
    await answered;
  }
  // A passphrase answered as null is refused as any passphrase that is not text or bytes, never
  // taken for an empty one (AUD-016-API003): the callback's answer fails, with that as the cause.
  const answeredNull = client.rekey({
    container: "c",
    words: 15,
    password: "old",
    newPassword: "new",
    newPasswordRepeat: "new",
    confirmation: { owner: () => ({ passphrase: null }) },
    walletHasPassphrase: true,
  });
  worker = await started();
  worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
  await assert.rejects(
    answeredNull,
    (error) =>
      error.code === "CALLBACK_FAILED" &&
      error.cause instanceof TypeError &&
      error.cause.message === "passphrase must be a string or a Uint8Array.",
  );
}

/**
 * After a refusal that allows another confirmation the worker asks the page (AUD-017-UI002): the
 * page gets the refusal as an MhfeError with the owner's lengths, and its answer goes back with
 * its passphrase as bytes, or with the length the owner compares; the owner callback of the
 * answer is the one asked then. Without onConfirmAgain the worker is told not to ask.
 */
async function checkConfirmAgain(client, MhfeError) {
  const { rekeyWith } = clientCalls(client);
  let worker;
  const confirmAgainCalls = [];
  const answers = [
    { fingerprint: PHRASE_TREZOR_FINGERPRINT, passphrase: "TREZOR" },
    { owner: (check) => confirmAgainCalls.push(["owner", check]) > 0 },
  ];
  const confirmingAgain = rekeyWith({
    words: 15,
    confirmation: { builtInCheck: true },
    walletHasPassphrase: true,
    onConfirmAgain: (refusal) => {
      confirmAgainCalls.push(["refusal", refusal]);
      return answers.shift();
    },
  });
  worker = await started();
  assert.equal(worker.messages[0].confirmsAgain, true);
  worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
  await nextTurn();
  const [, firstRefusal] = confirmAgainCalls[0];
  assert.ok(firstRefusal.error instanceof MhfeError);
  assert.deepEqual(
    [firstRefusal.error.code, firstRefusal.error.message, firstRefusal.ownerLengths],
    ["LENGTH_DIFFERS", "The check finds 12", [15]],
  );
  assert.deepEqual(
    fieldsOf(worker.messages[1].value, ["confirmKind", "reference", "coin", "path", "words"]),
    {
      confirmKind: "fingerprint",
      reference: PHRASE_TREZOR_FINGERPRINT,
      coin: "",
      path: "",
      words: 0,
    },
  );
  assert.equal(new TextDecoder().decode(worker.messages[1].value.passphrase), "TREZOR");
  worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
  await nextTurn();
  assert.deepEqual(fieldsOf(worker.messages[2].value, ["confirmKind", "words"]), {
    confirmKind: "owner",
    words: 15,
  });
  worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
  await nextTurn();
  assert.deepEqual(confirmAgainCalls.at(-1), ["owner", shownToOwner]);
  assert.deepEqual(worker.messages[3], OWNER_YES);
  worker.reply({ type: "result", result: { container: "n" } });
  assert.deepEqual(await confirmingAgain, { container: "n" });
  const notAsking = rekeyWith({ confirmation: { builtInCheck: true }, walletHasPassphrase: false });
  worker = await started();
  assert.equal(worker.messages[0].confirmsAgain, false);
  worker.reply({ type: "result", result: { container: "n" } });
  await notAsking;
}

/**
 * A null answer ends the rekey with the refusal, as the worker throws it; an answer the client
 * refuses stops the rekey with CALLBACK_FAILED, its TypeError as the cause.
 */
async function checkConfirmAgainRefused(client) {
  const { rekeyWith } = clientCalls(client);
  let worker;
  const stopsAgain = rekeyWith({
    confirmation: { builtInCheck: true },
    walletHasPassphrase: false,
    onConfirmAgain: () => null,
  });
  worker = await started();
  worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
  await nextTurn();
  assert.deepEqual(worker.messages[1], { type: "answer", value: null });
  worker.reply({ type: "error", error: { code: "LENGTH_DIFFERS", message: "the check finds 12" } });
  await assert.rejects(stopsAgain, { code: "LENGTH_DIFFERS" });
  for (const { answer, ownerLengths, message } of [
    {
      answer: { owner: () => true, words: 12 },
      ownerLengths: [15],
      message: "words must name the reading the owner compares: 15.",
    },
    {
      answer: { owner: () => true },
      ownerLengths: [],
      message: "the owner cannot confirm this phrase: give an address or the fingerprint.",
    },
    {
      answer: { owner: () => true },
      ownerLengths: [12, 21],
      message: "words must name the reading the owner compares: 12 or 21.",
    },
    {
      answer: { fingerprint: "00000000", words: 15 },
      ownerLengths: [15],
      message: "words belongs only to the owner's confirmation.",
    },
    {
      answer: { owner: () => true, passphrase: "TREZOR" },
      ownerLengths: [15],
      message: REKEY_PASSPHRASE_ONLY_WITH_REFERENCE,
    },
    {
      answer: { walletCheck: true },
      ownerLengths: [15],
      message: "a rekey is confirmed by an address or a fingerprint, not by the wallet check.",
    },
  ]) {
    const refused = rekeyWith({
      confirmation: { builtInCheck: true },
      walletHasPassphrase: false,
      onConfirmAgain: () => answer,
    });
    worker = await started();
    worker.reply({
      type: "ask",
      question: "confirmAgain",
      value: { ...lengthDiffers, ownerLengths },
    });
    await assert.rejects(
      refused,
      (error) =>
        error.code === "CALLBACK_FAILED" &&
        error.cause instanceof TypeError &&
        error.cause.message === message,
      message,
    );
    assert.equal(worker.terminated, true, `${message}: the worker stops`);
  }
}

/** A trap in the worker's session, and the passphrase a reference or the built-in check takes. */
async function checkTrapAndPassphrases(client) {
  const { rekeyWith } = clientCalls(client);
  let worker;
  // A trap in the worker's session reaches the page as INTERNAL_ERROR "The WebAssembly stopped",
  // and the worker, whose instance cannot be called again, is terminated (AUD-023-API002).
  const trappedRekey = rekeyWith({
    confirmation: { builtInCheck: true },
    walletHasPassphrase: false,
  });
  worker = await started();
  worker.reply({
    type: "error",
    error: { code: "INTERNAL_ERROR", message: "the WebAssembly stopped" },
  });
  await assert.rejects(trappedRekey, {
    code: "INTERNAL_ERROR",
    message: "The WebAssembly stopped",
  });
  assert.equal(worker.terminated, true, "the worker of a trapped session is terminated");
  // Whether a left-out answer is enough is the core's to judge, from the reference's passphrase:
  // the client sends it as it is, undefined, with the passphrase as bytes.
  const byFingerprint = rekeyWith({
    confirmation: { fingerprint: PHRASE_TREZOR_FINGERPRINT },
    passphrase: "TREZOR",
  });
  worker = await started();
  assert.deepEqual(
    fieldsOf(worker.messages[0], ["confirmKind", "reference", "walletHasPassphrase"]),
    {
      confirmKind: "fingerprint",
      reference: PHRASE_TREZOR_FINGERPRINT,
      walletHasPassphrase: undefined,
    },
  );
  assert.equal(new TextDecoder().decode(worker.messages[0].passphrase), "TREZOR");
  worker.reply({ type: "result", result: { container: "n" } });
  assert.deepEqual(await byFingerprint, { container: "n" });
  // An empty passphrase is none, so the built-in check takes it.
  const emptyPassphrase = rekeyWith({
    confirmation: { builtInCheck: true },
    passphrase: "",
    walletHasPassphrase: false,
  });
  worker = await started();
  assert.deepEqual(fieldsOf(worker.messages[0], ["confirmKind", "walletHasPassphrase"]), {
    confirmKind: "builtInCheck",
    walletHasPassphrase: false,
  });
  assert.equal(worker.messages[0].passphrase.length, 0);
  worker.reply({ type: "result", result: { container: "n" } });
  assert.deepEqual(await emptyPassphrase, { container: "n" });
}
