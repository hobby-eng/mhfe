// AUD-014: bounded state checks against the current browser runtime and wallet class.
// A controlled Worker replaces browser execution; no cryptography or MHFE WASM runs here.
import assert from "node:assert/strict";
import { setImmediate as nextTurn } from "node:timers/promises";
import { MhfeWallet, runtime, sourceHashes, wasmBytes } from "./browser-sources.mjs";

const { BUILD_ID, CompiledModule, MhfeCancelledError, PackageCheck, WorkerJob } = runtime;

const part = (outcome = "passed") => ({
  id: "word-wishes",
  label: "Chosen word of a new phrase",
  outcome,
  ...(outcome === "failed" ? { detail: "synthetic damaged known answer" } : {}),
});
const report = (tier = "startup", outcome = "passed") => ({
  version: "audit-only",
  tier,
  passed: outcome === "passed",
  ids: ["word-wishes"],
  components: [part(outcome)],
});

class ControlledWorker {
  static started = [];
  static selfCheckOutcome = "passed";

  constructor(url) {
    this.url = url;
    this.messages = [];
    this.terminated = false;
    this.terminations = 0;
    ControlledWorker.started.push(this);
  }

  postMessage(message, transfer = []) {
    this.messages.push(structuredClone(message, { transfer }));
    if (message.operation === "selfCheck") {
      queueMicrotask(() => {
        this.reply({ type: "ready", buildId: BUILD_ID });
        this.reply({
          type: "result",
          result: report(message.tier, ControlledWorker.selfCheckOutcome),
        });
      });
    }
  }

  reply(data) {
    // Deliver even after termination to model a reply already queued on the page.
    this.onmessage?.({ data });
  }

  fail() {
    this.onerror?.({ preventDefault() {}, message: "synthetic worker failure" });
  }

  terminate() {
    this.terminated = true;
    this.terminations += 1;
  }
}

const realWorker = globalThis.Worker;
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const deadlines = new Set();
globalThis.Worker = ControlledWorker;
// Keep the exact runtime duration but drive its callback explicitly, without waiting a minute.
globalThis.setTimeout = (callback, delay, ...args) => {
  if (delay !== 60_000) return realSetTimeout(callback, delay, ...args);
  const deadline = { callback };
  deadlines.add(deadline);
  return deadline;
};
globalThis.clearTimeout = (handle) => {
  if (!deadlines.delete(handle)) realClearTimeout(handle);
};

const cases = [];
async function checked(name, check) {
  await check();
  cases.push(name);
  console.log(`PASS ${name}`);
}

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await nextTurn();
  }
  throw new Error("The controlled worker did not start within 50 event-loop turns.");
}

async function pendingJob() {
  const before = ControlledWorker.started.length;
  let ends = 0;
  const job = new WorkerJob(["audit-only worker"], {}, () => (ends += 1));
  const chosenWords = new TextEncoder().encode("happy");
  const done = job.run(
    { module: "wallet", operation: "drawPhrase", chosenWords },
    [chosenWords.buffer],
    new CompiledModule(wasmBytes(), "audit-only"),
  );
  await waitFor(() => ControlledWorker.started.length > before);
  assert.equal(chosenWords.byteLength, 0, "the request buffer is transferred out of the page");
  return { job, done, worker: ControlledWorker.started.at(-1), ends: () => ends };
}

async function freshWallet() {
  ControlledWorker.selfCheckOutcome = "passed";
  const wallet = new MhfeWallet({ workerSource: "audit-only worker", wasm: wasmBytes() });
  assert.equal((await wallet.startupCheck()).passed, true);
  return wallet;
}

async function pendingDraw(wallet, onProgress) {
  const before = ControlledWorker.started.length;
  const callerBytes = new TextEncoder().encode("public audit passphrase");
  const done = wallet.drawPhrase({
    passphrase: callerBytes,
    passphraseRepeat: "public audit passphrase",
    walletCheck: true,
    workers: 2,
    chosen: [{ word: "happy", position: 1 }],
    neverUse: ["abandon"],
    onProgress,
  });
  await waitFor(() => ControlledWorker.started.length === before + 2);
  assert.equal(new TextDecoder().decode(callerBytes), "public audit passphrase");
  const workers = ControlledWorker.started.slice(before);
  for (const worker of workers) {
    const message = worker.messages[0];
    assert.equal(new TextDecoder().decode(message.chosenWords), "happy");
    assert.deepEqual(message.places, [1]);
    assert.equal(message.neverUse, "abandon");
  }
  return { done, workers };
}

try {
  for (const reply of [
    { type: "ready", buildId: BUILD_ID },
    { type: "result", result: { phrase: "synthetic late result" } },
    { type: "error", error: { code: "RANDOM_FAILED", message: "synthetic" } },
    { type: "draws", value: 1024 },
  ]) {
    await checked(`cancel while loading, then first ${reply.type}`, async () => {
      const { job, done, worker, ends } = await pendingJob();
      const rejected = assert.rejects(done, MhfeCancelledError);
      job.stop(new MhfeCancelledError());
      await rejected;
      assert.equal(ends(), 1);
      assert.equal(worker.terminated, false);
      worker.reply(reply);
      assert.equal(worker.terminated, true);
      assert.equal(worker.terminations, 1);
      worker.reply({ type: "result", result: { phrase: "synthetic late result" } });
      assert.equal(worker.terminations, 1, "late replies do not terminate twice or settle again");
    });
  }

  await checked("cancel while loading, then worker error", async () => {
    const { job, done, worker } = await pendingJob();
    const rejected = assert.rejects(done, MhfeCancelledError);
    job.stop(new MhfeCancelledError());
    await rejected;
    worker.fail();
    assert.equal(worker.terminated, true);
    assert.equal(worker.terminations, 1);
  });

  await checked("cancel while loading, then deadline", async () => {
    const { job, done, worker } = await pendingJob();
    const rejected = assert.rejects(done, MhfeCancelledError);
    job.stop(new MhfeCancelledError());
    await rejected;
    assert.equal(deadlines.size, 1);
    [...deadlines][0].callback();
    assert.equal(worker.terminated, true);
  });

  await checked("cancel a loaded worker terminates immediately", async () => {
    const { job, done, worker } = await pendingJob();
    worker.reply({ type: "ready", buildId: BUILD_ID });
    const rejected = assert.rejects(done, MhfeCancelledError);
    job.stop(new MhfeCancelledError());
    await rejected;
    assert.equal(worker.terminated, true);
    assert.equal(deadlines.size, 0);
  });

  await checked("first result settles draw, stops loaded and loading workers", async () => {
    const wallet = await freshWallet();
    const { done, workers } = await pendingDraw(wallet);
    workers[0].reply({ type: "result", result: { phrase: "synthetic winner", words: 24 } });
    assert.deepEqual(await done, { phrase: "synthetic winner", words: 24, workers: 2 });
    assert.equal(workers[0].terminated, true);
    assert.equal(workers[1].terminated, false);
    workers[1].reply({ type: "result", result: { phrase: "synthetic late loser", words: 24 } });
    assert.equal(workers[1].terminated, true);
  });

  await checked("first error settles draw and releases its slot", async () => {
    const wallet = await freshWallet();
    const { done, workers } = await pendingDraw(wallet);
    const rejected = assert.rejects(done, { code: "RANDOM_FAILED" });
    workers[0].reply({ type: "error", error: { code: "RANDOM_FAILED", message: "synthetic" } });
    await rejected;
    assert.equal(workers[0].terminated, true);
    assert.equal(workers[1].terminated, false);
    workers[1].reply({ type: "ready", buildId: BUILD_ID });
    assert.equal(workers[1].terminated, true);
    const before = ControlledWorker.started.length;
    const next = wallet.drawPhrase();
    await waitFor(() => ControlledWorker.started.length === before + 1);
    ControlledWorker.started.at(-1).reply({ type: "result", result: { words: 24 } });
    assert.deepEqual(await next, { words: 24, workers: 1 });
  });

  await checked("draw cancel ignores late result and progress", async () => {
    const wallet = await freshWallet();
    const progress = [];
    const { done, workers } = await pendingDraw(wallet, (event) => progress.push(event));
    const rejected = assert.rejects(done, MhfeCancelledError);
    wallet.cancel();
    await rejected;
    workers[0].reply({ type: "result", result: { phrase: "synthetic late result" } });
    workers[1].reply({ type: "draws", value: 1024 });
    assert.deepEqual(progress, []);
    assert.ok(workers.every((worker) => worker.terminated));
  });

  await checked("WordWishes startup failure prevents drawing", async () => {
    ControlledWorker.selfCheckOutcome = "failed";
    const before = ControlledWorker.started.length;
    const wallet = new MhfeWallet({ workerSource: "audit-only worker", wasm: wasmBytes() });
    await assert.rejects(wallet.drawPhrase(), (error) => {
      assert.equal(error.code, "SELF_CHECK_FAILED");
      assert.equal(error.report.components.at(-1).id, "word-wishes");
      return true;
    });
    assert.equal(ControlledWorker.started.length, before + 1, "only the self-check worker starts");
    await assert.rejects(wallet.drawPhrase(), { code: "SELF_CHECK_FAILED" });
    assert.equal(ControlledWorker.started.length, before + 1);
  });

  await checked("WordWishes full failure prevents subsequent drawing", async () => {
    const wallet = await freshWallet();
    ControlledWorker.selfCheckOutcome = "failed";
    assert.equal((await wallet.fullCheck()).passed, false);
    const before = ControlledWorker.started.length;
    await assert.rejects(wallet.drawPhrase(), { code: "SELF_CHECK_FAILED" });
    assert.equal(ControlledWorker.started.length, before);
  });

  // Diagnostic only: isolate the existing shared gate from MHFE WASM and report the race outcome.
  const gate = new PackageCheck({
    wasm: new CompiledModule(wasmBytes(), "audit-only"),
    classFile: "wallet/wallet.js",
    classBuildId: BUILD_ID,
    secrets: true,
  });
  let passStartup;
  const startup = new Promise((resolve) => (passStartup = resolve));
  gate.startup("startup", () => startup);
  const waiting = gate.require(() => assert.fail("startup was already started"));
  const failed = await gate.full([{ run: async () => report("full", "failed") }]);
  assert.equal(failed.passed, false);
  passStartup(report());
  const race = await waiting.then(
    () => "waiting operation was permitted after a failed full check",
    (error) => `waiting operation was refused: ${error.code}`,
  );
  console.log(`DIAGNOSTIC ${race}`);
  await assert.rejects(
    gate.require(() => assert.fail("closed gate starts no check")),
    {
      code: "SELF_CHECK_FAILED",
    },
  );
  assert.equal(deadlines.size, 0, "every controlled worker deadline is cleared");
  console.log(
    JSON.stringify({
      cases: cases.length,
      race,
      sources: sourceHashes,
      limitations:
        "Controlled worker; no real Firefox, MHFE WASM, heap erasure, or phrase arithmetic.",
    }),
  );
} finally {
  globalThis.Worker = realWorker;
  globalThis.setTimeout = realSetTimeout;
  globalThis.clearTimeout = realClearTimeout;
  deadlines.clear();
}
