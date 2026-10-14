// Public argument and progress contracts of the page-side classes (AUD-024-API002/004/005).
import assert from "node:assert/strict";

import { sources, wasm } from "./page-classes.mjs";
import { StandInWorker, started } from "./stand-in-worker.mjs";
import { NO_LENGTH_EVIDENCE } from "./test-values.mjs";

/** A malformed search or callback reference names only the forms that operation accepts. */
export async function checkReferenceRefusals(client) {
  const before = StandInWorker.started.length;
  for (const reference of [
    undefined,
    {},
    { builtInCheck: false },
    { words: 12 },
    { address: "a", coin: "bitcoin", fingerprint: "00000000" },
  ]) {
    await assert.rejects(client.searchDecoy({ container: "c ?", reference }), {
      name: "TypeError",
      message: "reference must be exactly one of { address, coin, path? } or { fingerprint }.",
    });
    await assert.rejects(client.searchWallet({ container: "c ?", password: "p", reference }), {
      name: "TypeError",
      message:
        "reference must be exactly one of { address, coin, path? }, { fingerprint }, " +
        "{ walletCheck: true } or { builtInCheck: true }.",
    });
  }
  assert.equal(StandInWorker.started.length, before, "malformed references start no worker");
  await assert.rejects(
    client.searchDecoy({ container: "c ?", reference: { builtInCheck: true } }),
    {
      name: "TypeError",
      message: "reference must be exactly one of { address, coin, path? } or { fingerprint }.",
    },
  );
  await assert.rejects(
    client.check({
      container: "c",
      password: "p",
      reference: { words: 12 },
      passphrase: "TREZOR",
    }),
    {
      name: "TypeError",
      message: "passphrase belongs only to an address, a fingerprint or the wallet check.",
    },
  );
  for (const answer of [
    {},
    { builtInCheck: true },
    { fingerprint: "00000000", address: "a", coin: "bitcoin" },
  ]) {
    const pending = client.check({
      container: "c",
      password: "p",
      reference: { words: 0 },
      onNoLength: () => answer,
    });
    const worker = await started();
    worker.reply({ type: "ask", question: "noLength", value: NO_LENGTH_EVIDENCE });
    await assert.rejects(pending, {
      name: "TypeError",
      message:
        "onNoLength must be exactly one of { words: 12 | 15 | 18 | 21 }, " +
        "{ address, coin, path? } or { fingerprint }.",
    });
    assert.equal(worker.terminated, true, "a refused answer stops the worker");
  }
  const unused = client.check({
    container: "c",
    password: "p",
    reference: { words: 0 },
    onNoLength: () => ({ words: 12, passphrase: "TREZOR" }),
  });
  const worker = await started();
  worker.reply({ type: "ask", question: "noLength", value: NO_LENGTH_EVIDENCE });
  await assert.rejects(unused, {
    name: "TypeError",
    message: "passphrase belongs only to an address, a fingerprint or the wallet check.",
  });
}

/** Rightly typed numbers get coded refusals; type mistakes remain TypeErrors. */
export async function checkNumericRefusals(wallet, passwords, client) {
  for (const workers of [-1, 0, 257, 2 ** 32]) {
    await assert.rejects(wallet.drawPhrase({ workers }), { code: "INVALID_REQUEST" });
  }
  for (const workers of ["2", 1.5, null]) {
    await assert.rejects(wallet.drawPhrase({ workers }), TypeError);
  }
  await assert.rejects(wallet.describeDraw({ chosen: [{ word: "zoo", position: 0 }] }), {
    code: "INVALID_WORD_WISH",
  });
  for (const repair of [-1, 0, 2 ** 32]) {
    await assert.rejects(passwords.strength({ password: "p", passwordRepair: { repair } }), {
      code: "PASSWORD_REPAIR_NOT_OFFERED",
    });
  }
  for (const scanGap of [-1, 0, 2 ** 32]) {
    const pending = client.searchDecoy({
      container: "c ?",
      reference: { fingerprint: "00000000" },
      scanGap,
    });
    const worker = await started();
    assert.equal(worker.messages[0].scanGap, scanGap, "the library owns search gap limits");
    worker.reply({ type: "result", result: { found: false } });
    assert.deepEqual(await pending, { found: false });
  }
}

/** Every full-check row is reported in order, including a failure on the page itself. */
export async function checkPageProgress({ MhfeClient, MhfeRepair, MhfePasswords, MhfeWallet }) {
  for (const Class of [MhfeClient, MhfeRepair, MhfePasswords, MhfeWallet]) {
    const client = new Class({ ...sources, wasm: new Uint8Array(wasm) });
    const events = [];
    const report = await client.fullCheck({ onProgress: (event) => events.push(event) });
    assert.deepEqual(
      events.map(({ id, running, outcome, detail }) => ({ id, running, outcome, detail })),
      report.components.flatMap(({ id, outcome, detail }) => [
        { id, running: true, outcome: undefined, detail: undefined },
        { id, running: false, outcome, detail },
      ]),
    );
  }
  const pageError = new Error("page progress failed");
  await assert.rejects(
    new MhfeRepair(sources).fullCheck({
      onProgress: async () => {
        throw pageError;
      },
    }),
    { code: "CALLBACK_FAILED", cause: pageError },
  );
  const previous = globalThis.TextEncoder;
  try {
    delete globalThis.TextEncoder;
    const events = [];
    const report = await new MhfeRepair(sources).fullCheck({
      onProgress: (event) => events.push(event),
    });
    assert.equal(report.passed, false);
    assert.deepEqual(
      events.filter(({ running }) => !running),
      report.components.map((part) => ({ ...part, running: false })),
    );
    assert.equal(events[0].id, "browser-features");
  } finally {
    globalThis.TextEncoder = previous;
  }
}
