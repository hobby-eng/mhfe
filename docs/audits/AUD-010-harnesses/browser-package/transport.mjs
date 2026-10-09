// AUD-010 browser-package probe of the worker transport and the asynchronous state of the classes
// (CHECK-SEC-002, CHECK-API-002), with the AUD-009 reproductions API001, API002 and SEC001 turned
// into regressions. The page side is the production source web/ loaded as ES modules with a
// stand-in Worker; the worker side is dist/runtime/worker.js run in this process with the
// package's real WebAssembly. No Argon2 runs. Synthetic secrets only. Exits non-zero when a check
// fails.
//
//   node docs/audits/AUD-010-harnesses/browser-package/transport.mjs
import { resolveObjectURL } from "node:buffer";
import {
  Checks,
  StandInWorker,
  distBuildId,
  emptyWasm,
  inProcessWorker,
  loadPackage,
  packageModule,
  standInSources,
  tick,
} from "./lib.mjs";

const checks = new Checks("AUD-010 browser-package: worker transport and async state");
const originalWorker = globalThis.Worker;
globalThis.Worker = StandInWorker;
const unhandled = [];
process.on("unhandledRejection", (error) => unhandled.push(error));

const pkg = await loadPackage("web");
const { WorkerJob, OperationSlot, CompiledModule, MhfeError, secretBuffers } = pkg.runtime;
const { MhfeClient } = pkg.core;
const { MhfePasswords } = pkg.passwords;
const { MhfeWallet } = pkg.wallet;
const { MhfeRepair } = pkg.repair;
const compiled = () => new CompiledModule(emptyWasm(), "wasm");
const settleState = (promise) => {
  const state = { settled: false, value: undefined, error: undefined };
  promise.then(
    (value) => Object.assign(state, { settled: true, value }),
    (error) => Object.assign(state, { settled: true, error }),
  );
  return state;
};
const synthetic = () => Uint8Array.of(0x73, 0x79, 0x6e, 0x74, 0x68); // "synth"

// --- Part 1: WorkerJob, the transport of one operation -------------------------------------
{
  StandInWorker.reset();
  const password = synthetic();
  const message = { module: "repair", operation: "parameters", password };
  const job = new WorkerJob(["worker text"], {});
  const state = settleState(job.run(message, secretBuffers(message), compiled()));
  const worker = await StandInWorker.operation();
  checks.ok(
    worker.messages[0].compiled instanceof WebAssembly.Module,
    "the worker gets the compiled module",
  );
  checks.ok(password.byteLength === 0, "the page's copy of a secret is transferred (detached)");
  const url = worker.url;
  checks.ok(resolveObjectURL(url) !== undefined, "the worker comes from a Blob URL");
  worker.reply({ type: "ready", buildId: "development" });
  worker.reply({ type: "result", result: { answer: 1 } });
  await tick();
  checks.ok(state.settled && state.value?.answer === 1, "a result after the handshake resolves");
  checks.ok(worker.terminated, "the worker is terminated when the result arrives");
  checks.ok(resolveObjectURL(url) === undefined, "the Blob URL is revoked");
  // Late and duplicate replies after the end change nothing.
  worker.terminated = false; // let the stand-in deliver as a browser may for a queued message
  worker.reply({ type: "result", result: { answer: 2 } });
  worker.reply({ type: "error", error: { code: "INTERNAL_ERROR", message: "late" } });
  worker.reply({ type: "progress", value: { round: 1 } });
  await tick();
  checks.ok(state.value.answer === 1 && job.ended, "late and duplicate replies are ignored");
}

{
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {});
  const state = settleState(job.run({ module: "repair", operation: "parameters" }, [], compiled()));
  const worker = await StandInWorker.operation();
  worker.reply({ type: "ready", buildId: "0123456789abcdef" });
  worker.reply({ type: "result", result: "from another build" });
  await tick();
  checks.ok(
    state.error?.code === "PACKAGE_MISMATCH" && worker.terminated,
    "a worker of another build is refused at the handshake and terminated",
    `${state.error?.code}`,
  );
}

{
  // A worker that answers without the build handshake (none of this build does; the published
  // v0.5.0 worker had no handshake and fails on the new request instead).
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {});
  const state = settleState(job.run({ module: "repair", operation: "parameters" }, [], compiled()));
  const worker = await StandInWorker.operation();
  worker.reply({ type: "result", result: "no handshake" });
  await tick();
  checks.note(
    `a result before any "ready" ${state.value === "no handshake" ? "is accepted" : "is refused"}` +
      " (the page does not require the handshake before a reply)",
  );
}

{
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {});
  const state = settleState(job.run({ module: "repair", operation: "parameters" }, [], compiled()));
  const worker = await StandInWorker.operation();
  let prevented = false;
  worker.onerror({ message: "synthetic worker error", preventDefault: () => (prevented = true) });
  await tick();
  checks.ok(
    state.error?.code === "WORKER_FAILED" && worker.terminated && prevented,
    "a worker error rejects with WORKER_FAILED and ends the worker",
  );
}

{
  // The start limit: a worker that never says ready ends after a minute, with fake time.
  StandInWorker.reset();
  const realSetTimeout = globalThis.setTimeout;
  let startLimit = null;
  globalThis.setTimeout = (callback, delay, ...rest) => {
    if (delay === 60_000) {
      startLimit = callback;
      return realSetTimeout(() => {}, 0);
    }
    return realSetTimeout(callback, delay, ...rest);
  };
  const password = synthetic();
  const message = { module: "passwords", operation: "review", password };
  const job = new WorkerJob(["worker text"], {});
  // As every class sends a secret: its buffer in the transfer list.
  const state = settleState(job.run(message, secretBuffers(message), compiled()));
  const worker = await StandInWorker.operation();
  globalThis.setTimeout = realSetTimeout;
  checks.ok(typeof startLimit === "function", "the start limit is one minute");
  startLimit?.();
  await tick();
  checks.ok(
    state.error?.code === "WORKER_FAILED" && worker.terminated,
    "a worker that never says ready rejects with WORKER_FAILED and is terminated",
  );
  checks.ok(password.byteLength === 0, "the page kept no copy of the secret it transferred");
  // A copy sent without a transfer stays with the page once the worker has it; every class
  // transfers its secrets (secretBuffers), so this records the design, not a defect.
  StandInWorker.reset();
  globalThis.setTimeout = (callback, delay, ...rest) =>
    delay === 60_000 ? realSetTimeout(() => {}, 0) : realSetTimeout(callback, delay, ...rest);
  const kept = synthetic();
  const keptJob = new WorkerJob(["worker text"], {});
  keptJob.run({ password: kept }, [], compiled()).catch(() => {});
  await StandInWorker.operation();
  globalThis.setTimeout = realSetTimeout;
  keptJob.stop(new MhfeError("CANCELLED", "synthetic stop"));
  checks.note(
    `a secret sent without a transfer is ${kept.every((b) => b === 0) ? "wiped" : "not wiped"} when the job stops after the send (WorkerJob wipes only before the worker owns the request)`,
  );
}

// --- Part 2: AUD-009-API001, a Blob, Blob URL or Worker the browser refuses -----------------
for (const [label, sabotage, restore] of [
  [
    "URL.createObjectURL throws",
    () => {
      const original = URL.createObjectURL;
      URL.createObjectURL = () => {
        throw new Error("synthetic Blob URL refusal");
      };
      return () => (URL.createObjectURL = original);
    },
  ],
  [
    "new Worker throws",
    () => {
      StandInWorker.refuse = new Error("synthetic worker refusal");
      return () => (StandInWorker.refuse = null);
    },
  ],
  [
    "new Blob throws",
    () => {
      const original = globalThis.Blob;
      globalThis.Blob = class {
        constructor() {
          throw new Error("synthetic Blob refusal");
        }
      };
      return () => (globalThis.Blob = original);
    },
  ],
]) {
  StandInWorker.reset();
  const undo = sabotage();
  try {
    const slot = new OperationSlot();
    const password = synthetic();
    const message = { module: "core", operation: "decrypt", password };
    const job = slot.job(["worker text"], {});
    const state = settleState(job.run(message, secretBuffers(message), compiled()));
    for (let i = 0; i < 5; i += 1) await tick();
    checks.ok(
      state.settled && state.error?.code === "WORKER_FAILED",
      `API001: ${label}: rejects with WORKER_FAILED`,
    );
    checks.ok(job.ended, `API001: ${label}: the job has ended`);
    checks.ok(
      password.every((byte) => byte === 0),
      `API001: ${label}: the page's secret copy is wiped`,
    );
    let busy = false;
    try {
      slot.requireIdle();
    } catch {
      busy = true;
    }
    checks.ok(!busy, `API001: ${label}: the operation slot is free again`);
  } finally {
    undo();
  }
}

{
  // WebAssembly that does not compile: WORKER_FAILED, no worker, the copy wiped.
  StandInWorker.reset();
  const password = synthetic();
  const job = new WorkerJob(["worker text"], {});
  const state = settleState(
    job.run({ password }, [], new CompiledModule(Uint8Array.of(1, 2, 3), "wasm")),
  );
  for (let i = 0; i < 5; i += 1) await tick();
  checks.ok(
    state.error?.code === "WORKER_FAILED" &&
      StandInWorker.instances.length === 0 &&
      password.every((byte) => byte === 0),
    "a WebAssembly that does not compile rejects with WORKER_FAILED before any worker, copy wiped",
  );
}

// --- Part 3: callbacks of the page ----------------------------------------------------------
{
  StandInWorker.reset();
  const cause = new Error("synthetic progress failure");
  const job = new WorkerJob(["worker text"], {
    progress: () => {
      throw cause;
    },
  });
  const state = settleState(job.run({}, [], compiled()));
  const worker = await StandInWorker.operation();
  worker.reply({ type: "ready", buildId: "development" });
  worker.reply({ type: "progress", value: { round: 1 } });
  await tick();
  checks.ok(
    state.error?.code === "CALLBACK_FAILED" && state.error.cause === cause && worker.terminated,
    "a progress callback that throws stops the job with CALLBACK_FAILED, cause kept",
  );
}

{
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {
    progress: () => Promise.reject(new Error("synthetic async failure")),
  });
  const state = settleState(job.run({}, [], compiled()));
  const worker = await StandInWorker.operation();
  worker.reply({ type: "ready", buildId: "development" });
  worker.reply({ type: "progress", value: { round: 1 } });
  await tick();
  await tick();
  checks.ok(
    state.error?.code === "CALLBACK_FAILED" && worker.terminated,
    "a progress callback whose promise rejects stops the job with CALLBACK_FAILED",
  );
}

{
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {
    ownerCheck: async () => true,
  });
  const state = settleState(job.run({}, [], compiled()));
  const worker = await StandInWorker.operation();
  worker.reply({ type: "ready", buildId: "development" });
  worker.reply({ type: "ask", question: "ownerCheck", value: { words: 12 } });
  await tick();
  await tick();
  checks.ok(
    worker.messages.at(-1)?.type === "answer" && worker.messages.at(-1)?.value === true,
    "an ask is answered with the page's awaited answer",
  );
  worker.reply({ type: "ask", question: "unknownQuestion", value: null });
  await tick();
  await tick();
  checks.ok(
    state.error?.code === "CALLBACK_FAILED" && worker.terminated,
    "a question without a handler stops the job with CALLBACK_FAILED",
  );
}

// --- Part 4: AUD-009-API002, the drawing's asynchronous progress failure --------------------
{
  StandInWorker.reset();
  const wallet = new MhfeWallet(standInSources());
  const drawing = settleState(
    wallet.drawPhrase({
      passphrase: "synthetic passphrase",
      passphraseRepeat: "synthetic passphrase",
      walletCheck: true,
      workers: 3,
      onProgress: async () => {
        throw new Error("synthetic callback failure");
      },
    }),
  );
  for (
    let i = 0;
    i < 20 && StandInWorker.instances.filter((w) => !w.isSelfCheck).length < 3;
    i += 1
  ) {
    await tick();
  }
  const drawers = StandInWorker.instances.filter((w) => !w.isSelfCheck);
  checks.ok(drawers.length === 3, "a checked phrase is drawn on the 3 workers asked for");
  for (const worker of drawers) worker.reply({ type: "ready", buildId: "development" });
  drawers[0].reply({ type: "draws", value: 1024 });
  for (let i = 0; i < 5; i += 1) await tick();
  checks.ok(
    drawing.error?.code === "CALLBACK_FAILED",
    "API002: an onProgress whose promise rejects rejects the drawing with CALLBACK_FAILED",
    `${drawing.error?.code}`,
  );
  checks.ok(
    drawers.every((worker) => worker.terminated),
    "API002: every drawing worker ends",
  );
  checks.ok(
    !unhandled.some((error) => error?.message === "synthetic callback failure"),
    "API002: the page's rejection is not left unhandled",
  );
  // The passphrase copies each worker got are the worker's; the page kept none.
  const late = settleState(wallet.drawPhrase({ passphrase: "", walletCheck: false }));
  const next = await StandInWorker.operation(
    (m) => m.operation === "drawPhrase" && !drawers.some((w) => w.messages[0] === m),
  );
  checks.ok(next !== undefined, "a new drawing starts after one stopped (not BUSY)");
  wallet.cancel();
  await tick();
  checks.ok(late.error?.code === "CANCELLED", "cancel() stops a drawing with CANCELLED");
}

// --- Part 5: AUD-009-SEC001, a refused repetition wipes the first copy ----------------------
{
  StandInWorker.reset();
  const originalEncode = TextEncoder.prototype.encode;
  const encoded = [];
  TextEncoder.prototype.encode = function (text) {
    const result = originalEncode.call(this, text);
    encoded.push(result);
    return result;
  };
  const allWiped = () => encoded.every((bytes) => bytes.every((byte) => byte === 0));
  try {
    const passwords = new MhfePasswords(standInSources());
    await passwords.startupCheck();
    encoded.length = 0;
    await checks.rejects(
      passwords.review({ password: "synthetic-test", passwordRepeat: 23 }),
      TypeError,
      "SEC001: review with a repetition that is not text",
    );
    checks.ok(encoded.length > 0 && allWiped(), "SEC001: review wipes the password's copy");
    encoded.length = 0;
    await checks.rejects(
      passwords.review({ password: "synthetic-test", passwordRepeat: "a\uD800" }),
      "INVALID_PASSWORD_TEXT",
      "SEC001: review with a repetition holding a lone surrogate",
    );
    checks.ok(encoded.length > 0 && allWiped(), "SEC001: review wipes the password's copy again");

    const wallet = new MhfeWallet(standInSources());
    await wallet.startupCheck();
    encoded.length = 0;
    await checks.rejects(
      wallet.drawPhrase({ passphrase: "synthetic-test", passphraseRepeat: 23, walletCheck: false }),
      TypeError,
      "SEC001: drawPhrase with a repetition that is not text",
    );
    checks.ok(encoded.length > 0 && allWiped(), "SEC001: drawPhrase wipes the passphrase's copy");

    // The core's staged copies: a passphrase of the wrong type after the password was copied.
    const client = new MhfeClient(standInSources());
    await client.startupCheck({ argon2: false });
    encoded.length = 0;
    await checks.rejects(
      client.check({
        container: "synthetic container",
        password: "synthetic-test",
        reference: { fingerprint: "00000000" },
        passphrase: 5,
      }),
      TypeError,
      "core check with a passphrase that is not text",
    );
    checks.ok(encoded.length > 0 && allWiped(), "the core wipes the password copied before it");
    encoded.length = 0;
    await checks.rejects(
      client.rekey({
        container: "synthetic container",
        words: 24,
        password: "synthetic-old",
        otherWalletsMoved: true,
        newPassword: "synthetic-new",
        newPasswordRepeat: "synthetic-new",
        confirmation: { fingerprint: "00000000" },
        passphrase: "a\uD800",
      }),
      "INVALID_PASSWORD_TEXT",
      "rekey with a passphrase holding a lone surrogate",
    );
    checks.ok(encoded.length > 0 && allWiped(), "rekey wipes every copy made before the refusal");
  } finally {
    TextEncoder.prototype.encode = originalEncode;
  }
}

// --- Part 6: the long-operation slot, cancel and close -------------------------------------
{
  StandInWorker.reset();
  const client = new MhfeClient(standInSources());
  const first = settleState(
    client.decrypt({ container: "synthetic container", password: "synthetic-test" }),
  );
  await tick();
  await checks.rejects(
    client.decrypt({ container: "synthetic container", password: "synthetic-test" }),
    "BUSY",
    "a second long operation while one waits for the startup check",
  );
  const worker = await StandInWorker.operation((m) => m.operation === "decrypt");
  checks.ok(
    worker.messages[0].password instanceof Uint8Array && worker.messages[0].argon2Script === null,
    "the operation starts after its startup check, with the password as bytes",
  );
  worker.reply({ type: "ready", buildId: "development" });
  client.cancel();
  await tick();
  checks.ok(
    first.error?.code === "CANCELLED" && worker.terminated,
    "cancel() during an operation rejects with CANCELLED and terminates the worker",
  );
  worker.terminated = false;
  worker.reply({ type: "result", result: { kind: "phrase" } });
  await tick();
  checks.ok(first.error?.code === "CANCELLED", "a result after cancel() is ignored");
  const again = settleState(
    client.decrypt({ container: "synthetic container", password: "synthetic-test" }),
  );
  const second = await StandInWorker.operation(
    (m) => m.operation === "decrypt" && m !== worker.messages[0],
  );
  checks.ok(second !== worker, "the slot is free after a cancel");
  client.cancel();
  await tick();
  checks.ok(again.error?.code === "CANCELLED", "cancel() of the second operation");
}

{
  // cancel() while the operation waits for its startup check: nothing secret is copied.
  StandInWorker.reset();
  StandInWorker.respond = () => {}; // the check never answers
  const client = new MhfeClient(standInSources());
  const originalEncode = TextEncoder.prototype.encode;
  let encodes = 0;
  TextEncoder.prototype.encode = function (text) {
    encodes += 1;
    return originalEncode.call(this, text);
  };
  try {
    const waiting = settleState(
      client.decrypt({ container: "synthetic container", password: "synthetic-test" }),
    );
    await tick();
    const before = encodes;
    client.cancel();
    await tick();
    checks.ok(
      waiting.error?.code === "CANCELLED" && encodes === before,
      "cancel() during the startup check rejects with CANCELLED before any secret is copied",
    );
  } finally {
    TextEncoder.prototype.encode = originalEncode;
  }
}

{
  // A failed startup report closes the class for good; nothing reaches an operation worker.
  StandInWorker.reset();
  StandInWorker.respond = (worker, message) => {
    worker.reply({ type: "ready", buildId: "development" });
    worker.reply({
      type: "result",
      result: {
        version: "0.5.0",
        tier: message.tier,
        passed: false,
        ids: ["repair-words"],
        components: [
          { id: "repair-words", label: "Repair words", outcome: "failed", detail: "card 1 of 1" },
        ],
      },
    });
  };
  const repair = new MhfeRepair(standInSources());
  const first = await repair.repairWords({ container: "x", count: 4 }).catch((e) => e);
  const second = await repair.repairPlate({ plate: "x", card: "y" }).catch((e) => e);
  checks.ok(
    first.code === "SELF_CHECK_FAILED" && first.report?.passed === false,
    "a failed startup part rejects with SELF_CHECK_FAILED and the report",
  );
  checks.ok(second.code === "SELF_CHECK_FAILED", "the class stays closed for later calls");
  checks.ok(
    StandInWorker.instances.filter((w) => !w.isSelfCheck).length === 0 &&
      StandInWorker.instances.length === 1,
    "one startup check ran and no operation worker started",
  );
}

{
  // PACKAGE_MISMATCH and WORKER_FAILED at the startup check are not kept: the next call checks again.
  StandInWorker.reset();
  StandInWorker.buildId = "0123456789abcdef";
  const passwords = new MhfePasswords(standInSources());
  const first = await passwords.strength({ password: "synthetic" }).catch((e) => e);
  StandInWorker.buildId = "development";
  const secondCall = settleState(passwords.strength({ password: "synthetic" }));
  const operation = await StandInWorker.operation((m) => m.operation === "strength");
  operation.reply({ type: "ready", buildId: "development" });
  operation.reply({ type: "result", result: { bits: 1, weak: true } });
  await tick();
  checks.ok(
    first.code === "PACKAGE_MISMATCH" && secondCall.value?.bits === 1,
    "PACKAGE_MISMATCH at the check is not kept; the next call checks again and runs",
  );
}

{
  // Concurrent first calls share one startup check.
  StandInWorker.reset();
  const repair = new MhfeRepair(standInSources());
  const calls = [
    repair.parameters(),
    repair.repairWords({ container: "x", count: 4 }),
    repair.repairPlate({ plate: "x", card: "y" }),
  ];
  for (const call of calls) call.catch(() => {});
  for (let i = 0; i < 5; i += 1) await tick();
  checks.ok(
    StandInWorker.instances.filter((w) => w.isSelfCheck).length === 1,
    "concurrent first calls of a class run one startup check",
  );
  for (const worker of StandInWorker.instances) worker.terminate();
}

{
  // Hidden wallets: BUSY, SESSION_CLOSED, close() while waiting and during an open.
  StandInWorker.reset();
  const client = new MhfeClient(standInSources());
  const sessionPromise = client.openHiddenWallets({
    container: "synthetic container",
    mainPassphrase: "",
  });
  const worker = await StandInWorker.operation((m) => m.operation === "hiddenWallets");
  worker.reply({ type: "ready", buildId: "development" });
  worker.reply({ type: "ask", question: "ready", value: null });
  const session = await sessionPromise;
  const opening = settleState(
    session.open({ password: "synthetic-one", passwordRepeat: "synthetic-one" }),
  );
  await tick();
  const answer = worker.messages.at(-1);
  checks.ok(
    answer.type === "answer" && answer.value.password instanceof Uint8Array,
    "open() sends the password to the waiting session as bytes",
  );
  await checks.rejects(
    session.open({ password: "synthetic-two", passwordRepeat: "synthetic-two" }),
    "BUSY",
    "a second open() while one runs",
  );
  const closing = session.close();
  await tick();
  checks.ok(
    opening.error?.code === "CANCELLED" && worker.terminated,
    "close() during an open() stops the worker and rejects that open() with CANCELLED",
  );
  await closing;
  await checks.rejects(
    session.open({ password: "synthetic-three", passwordRepeat: "synthetic-three" }),
    "SESSION_CLOSED",
    "open() after close()",
  );
  checks.ok(session.close() === closing, "every close() returns the same promise");
}

{
  // A failed full check closes the class too; cancel() does not reach a full check.
  StandInWorker.reset();
  StandInWorker.respond = (worker, message) => {
    if (worker.messages.length !== 1) return;
    worker.reply({ type: "ready", buildId: "development" });
    const failed = message.tier === "full";
    worker.reply({
      type: "result",
      result: {
        version: "0.5.0",
        tier: message.tier,
        passed: !failed,
        ids: ["bip39-words"],
        components: [
          failed
            ? { id: "bip39-words", label: "BIP39 words", outcome: "failed", detail: "word 1 of 1" }
            : { id: "bip39-words", label: "BIP39 words", outcome: "passed" },
        ],
      },
    });
  };
  const repair = new MhfeRepair(standInSources());
  await repair.startupCheck();
  const full = await repair.fullCheck();
  const after = await repair.repairWords({ container: "x", count: 4 }).catch((e) => e);
  checks.ok(
    full.passed === false && after.code === "SELF_CHECK_FAILED",
    "a failed full check closes the class for later calls",
  );
  // selfTest() does not wait for the startup check, but holds the slot.
  StandInWorker.reset();
  StandInWorker.respond = () => {};
  const client = new MhfeClient(standInSources());
  const selfTest = settleState(client.selfTest());
  const selfTestWorker = await StandInWorker.operation((m) => m.operation === "selfTest");
  checks.ok(
    StandInWorker.instances.filter((w) => w.isSelfCheck).length === 0,
    "selfTest() starts without a startup check",
  );
  await checks.rejects(
    client.decrypt({ container: "x", password: "synthetic-test" }),
    "BUSY",
    "a long operation while selfTest() runs",
  );
  client.cancel();
  await tick();
  checks.ok(
    selfTest.error?.code === "CANCELLED" && selfTestWorker.terminated,
    "cancel() stops selfTest()",
  );
  // A WebAssembly that fails to compile once is not compiled again (the promise is kept).
  const broken = new CompiledModule(Uint8Array.of(0, 97, 115, 109, 9, 9, 9, 9), "wasm");
  const firstTry = broken.get();
  firstTry.catch(() => {});
  checks.note(
    `CompiledModule.get() after a failed compilation ${broken.get() === firstTry ? "returns the same rejected promise (no retry)" : "compiles again"}`,
  );
}

// --- Part 7: the worker side, dist/runtime/worker.js with the real WebAssembly ---------------
{
  const module = packageModule();
  const build = distBuildId();
  const send = async (message) => inProcessWorker().send({ compiled: module, ...message });

  const unknown = await send({ module: "repair", operation: "noSuchOperation" });
  checks.ok(
    unknown[0]?.type === "ready" && unknown[0].buildId === build,
    "the worker says ready with its build before it serves",
  );
  checks.ok(
    unknown.at(-1)?.type === "error" && unknown.at(-1).error.code === "INVALID_REQUEST",
    "an unknown operation is refused with INVALID_REQUEST",
  );
  const noModule = await send({ module: "noSuchModule", operation: "parameters" });
  checks.ok(noModule.at(-1)?.error?.code === "INVALID_REQUEST", "an unknown module is refused");
  const missing = await send({});
  checks.ok(
    missing.at(-1)?.error?.code === "INVALID_REQUEST",
    "a request without module and operation is refused",
  );

  // Names inherited from Object.prototype must not count as operations.
  for (const [moduleName, operation] of [
    ["core", "constructor"],
    ["repair", "toString"],
    ["__proto__", "constructor"],
    ["constructor", "keys"],
  ]) {
    const password = synthetic();
    const posted = await send({ module: moduleName, operation, password });
    const last = posted.at(-1);
    const echoed = last?.type === "result" && last.result?.password !== undefined;
    checks.ok(
      last?.type === "error" && last.error.code === "INVALID_REQUEST",
      `the inherited name ${moduleName}.${operation} is refused as an operation`,
      `the worker answered ${JSON.stringify(last?.type)}${
        last?.type === "result"
          ? `, result ${echoed ? "echoing the request with its secret bytes" : JSON.stringify(last.result)}`
          : ` ${last?.error?.code}`
      }`,
    );
  }

  const noCompiled = await inProcessWorker().send({ module: "repair", operation: "parameters" });
  checks.ok(
    noCompiled.length === 1 && noCompiled[0].type === "error",
    "a first message without the compiled WebAssembly is refused before ready",
    JSON.stringify(noCompiled),
  );

  const stray = inProcessWorker();
  const strayPosted = await stray.send({ type: "answer", value: "nobody asked" });
  checks.ok(strayPosted.length === 0, "an answer nobody asked for is ignored");

  // The worker wipes its copies of the secrets after an operation, also after an error.
  const password = new TextEncoder().encode("synthetic password");
  const repeat = new TextEncoder().encode("synthetic password");
  const reviewed = await send({
    module: "passwords",
    operation: "review",
    password,
    passwordRepeat: repeat,
    repeated: true,
  });
  checks.ok(reviewed.at(-1)?.type === "result", "a review through the worker resolves");
  checks.ok(
    password.every((b) => b === 0) && repeat.every((b) => b === 0),
    "the worker wipes its copies after the operation",
  );
  const bad = new TextEncoder().encode("synthetic\tpassword");
  const refused = await send({
    module: "passwords",
    operation: "review",
    password: bad,
    passwordRepeat: new Uint8Array(0),
    repeated: false,
  });
  checks.ok(
    refused.at(-1)?.error?.code === "CONTROL_CHARACTER_IN_PASSWORD" && bad.every((b) => b === 0),
    "the worker wipes its copies after an error too",
  );
  // The worker's PACKAGE_MISMATCH for a WebAssembly of another build, as the page shows it.
  const otherBuild = await inProcessWorker().send({
    module: "repair",
    operation: "parameters",
    compiled: new WebAssembly.Module(emptyWasm()),
  });
  StandInWorker.reset();
  const job = new WorkerJob(["worker text"], {});
  const shown = settleState(job.run({}, [], compiled()));
  const standIn = await StandInWorker.operation();
  standIn.reply(otherBuild.at(-1));
  await tick();
  checks.ok(
    otherBuild.at(-1)?.error?.code === "PACKAGE_MISMATCH" &&
      shown.error?.message.startsWith("runtime/mhfe.wasm is of build"),
    "PACKAGE_MISMATCH names the file runtime/mhfe.wasm as it is spelled in the package",
    `the page's message: "${shown.error?.message}"`,
  );
  const extra = await send({ module: "repair", operation: "parameters", unexpected: "field" });
  checks.note(
    `a request with an unexpected property is ${extra.at(-1)?.type === "result" ? "served (the property is ignored)" : "refused"}`,
  );
}

globalThis.Worker = originalWorker;
checks.finish();
// The stand-in timers and promises are done; leave without waiting for anything else.
setTimeout(() => process.exit(), 50);
