// AUD-017 R3 (carried over from AUD-015 R3) dynamic probe of the browser package's page-side classes in dist/, with a stand-in
// worker in this process (no WebAssembly operation runs; the stand-in answers the self-checks with
// a passed synthetic report unless a probe says otherwise). Read-only: it imports dist/ files as
// data URLs and changes nothing on disk.
//
//   node docs/audits/AUD-017-harnesses/r3-browser/api-probes.mjs
//
// "CHECK" lines compare a documented contract and count towards the exit code (1 when any fails);
// "INFO" lines record behaviour for the report without judging it. Public test data only.
import { readFileSync } from "node:fs";
import { resolveObjectURL } from "node:buffer";
import { join } from "node:path";

const root = new URL("../../../../", import.meta.url).pathname;
const read = (path) => readFileSync(join(root, path));
const runtimeText = read("dist/runtime/runtime.js").toString();
const runtimeUrl = `data:text/javascript;base64,${Buffer.from(runtimeText).toString("base64")}`;
const importClass = (path) => {
  const text = read(path).toString().replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`);
  return import(`data:text/javascript;base64,${Buffer.from(text).toString("base64")}`);
};
const runtime = await import(runtimeUrl);
const { BUILD_ID, MhfeError } = runtime;
const { MhfeClient } = await importClass("dist/core/client.js");
const { MhfeRepair } = await importClass("dist/repair/repair.js");
const { MhfePasswords } = await importClass("dist/passwords/passwords.js");
const { MhfeWallet } = await importClass("dist/wallet/wallet.js");

/** The BIP39 test phrase of the published vectors (public). */
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/** The smallest valid WebAssembly module: the classes compile it; the stand-in ignores it. */
const MINIMAL_WASM = [0, 97, 115, 109, 1, 0, 0, 0];
/** The core limits the client compares with its own (web/client.js requireSameLimits). */
const CORE_PARAMETERS = {
  maxPim: 1023,
  maxMemoryLevel: 21,
  highestBrowserMemoryLevel: 0,
  wordCounts: [12, 15, 18, 21, 24],
  builtInCheckWordCounts: [12, 15, 18, 21],
  repairWordCounts: [2, 4, 6, 8],
  decoyScanGap: 20,
};
/** The request fields the page treats as secrets (dist/runtime/runtime.js SECRET_FIELDS). */
const SECRET_FIELDS = JSON.parse(
  `[${/const SECRET_FIELDS = \[([^\]]*)\]/u.exec(runtimeText)[1].replace(/,\s*$/u, "")}]`,
);

let failures = 0;
function check(name, ok, evidence) {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} CHECK ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
}
function info(name, evidence) {
  console.log(`INFO ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
}
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
async function settle(promise) {
  try {
    return { resolved: await promise };
  } catch (error) {
    return { rejected: { name: error?.name, code: error?.code, message: error?.message } };
  }
}

/** A passed synthetic self-check report, as a worker returns it. */
function passedReport(message) {
  const report = {
    version: "0.5.1",
    tier: message.tier,
    passed: true,
    ids: ["stand-in-part"],
    components: [{ id: "stand-in-part", label: "Stand-in part", outcome: "passed" }],
  };
  return message.module === "core" && message.operation === "selfCheck"
    ? { ...report, parameters: CORE_PARAMETERS }
    : report;
}
function failedReport(message) {
  return {
    ...passedReport(message),
    passed: false,
    components: [
      { id: "stand-in-part", label: "Stand-in part", outcome: "failed", detail: "case 1 differs" },
    ],
  };
}

/**
 * The stand-in worker. It records every message with its transfer list, says it is ready unless
 * `hold` is set, answers self-checks by `checkReply`, and other operations by `serve`, or leaves
 * them to the probe.
 */
class StandInWorker {
  static all = [];
  static hold = false;
  static checkReply = (message) => ({ type: "result", result: passedReport(message) });
  static serve = null;
  constructor(url) {
    this.url = url;
    this.script = resolveObjectURL(url);
    this.messages = [];
    this.transferChecks = [];
    this.terminated = false;
    StandInWorker.all.push(this);
  }
  postMessage(message, transfer = []) {
    // Which secret fields of this message are not in its transfer list (would stay with the page).
    const holder = message?.type === "answer" ? message.value : message;
    const notTransferred = SECRET_FIELDS.filter(
      (field) =>
        holder?.[field] instanceof Uint8Array && !transfer.includes(holder[field].buffer),
    );
    const cloned = structuredClone(message, { transfer });
    this.transferChecks.push({
      operation: this.messages[0]?.operation ?? message.operation,
      kind: message?.type ?? "request",
      notTransferred,
      pageCopiesLeft: SECRET_FIELDS.filter((field) => holder?.[field]?.byteLength > 0),
    });
    this.messages.push(cloned);
    if (this.messages.length === 1) setTimeout(() => this.#start(cloned), 0);
    else setTimeout(() => StandInWorker.serve?.(cloned, this), 0);
  }
  #start(message) {
    if (StandInWorker.hold || this.terminated) return;
    this.reply({ type: "ready", buildId: BUILD_ID });
    if (["selfCheck", "selfCheckArgon2"].includes(message.operation)) {
      this.selfCheck = true;
      const reply = StandInWorker.checkReply(message, this);
      if (reply !== undefined) this.reply(reply);
    } else {
      StandInWorker.serve?.(message, this);
    }
  }
  reply(data) {
    if (!this.terminated) this.onmessage?.({ data });
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = StandInWorker;
const operationWorkers = () => StandInWorker.all.filter((worker) => !worker.selfCheck);
const lastOperationWorker = () => operationWorkers().at(-1);
const wasmBytes = () => new Uint8Array(MINIMAL_WASM);
const parts = () => ({ workerSource: "stand-in worker", wasm: wasmBytes() });
const coreParts = () => ({
  ...parts(),
  argon2Threaded: "threaded",
  argon2SingleThreaded: "single-threaded",
});

/** Serves operations: answers the core's questions and gives a result. */
function serveAll(message, worker) {
  if (message.type === "answer") {
    const first = worker.messages[0];
    if (first.operation === "hiddenWallets") {
      if (message.value?.close === true) {
        worker.reply({ type: "result", result: { closed: true } });
      } else {
        worker.reply({
          type: "ask",
          question: "opened",
          value: { phrase: "stand-in", words: 24, fingerprintWithoutPassphrase: "00000000" },
        });
      }
      return;
    }
    worker.reply({ type: "result", result: { answered: true } });
    return;
  }
  if (message.operation === "check" && message.asksLength) {
    worker.reply({ type: "ask", question: "noLength", value: null });
    return;
  }
  if (message.operation === "hiddenWallets") {
    worker.reply({ type: "ask", question: "ready", value: null });
    return;
  }
  worker.reply({ type: "result", result: { operation: message.operation } });
}

// ---------------------------------------------------------------------------------------------
// P1: every secret field of every request and answer is transferred, so no copy stays in the page.
StandInWorker.serve = serveAll;
{
  const client = new MhfeClient(coreParts());
  const passwords = new MhfePasswords(parts());
  const wallet = new MhfeWallet(parts());
  StandInWorker.all.length = 0;
  const calls = [
    ["client.readPhrase", () => client.readPhrase(PHRASE)],
    [
      "client.encrypt",
      () => client.encrypt({ phrase: PHRASE, password: "p w", passwordRepeat: "p w" }),
    ],
    ["client.decrypt", () => client.decrypt({ container: PHRASE, password: "p w" })],
    [
      "client.check+noLength",
      () =>
        client.check({
          container: PHRASE,
          password: "p w",
          reference: { words: 0 },
          passphrase: "first passphrase",
          onNoLength: () => ({ fingerprint: "73c5da0a", passphrase: "second passphrase" }),
        }),
    ],
    [
      "client.searchDecoy",
      () =>
        client.searchDecoy({
          container: PHRASE,
          reference: { fingerprint: "73c5da0a" },
          passphrase: "x",
        }),
    ],
    [
      "client.searchWallet",
      () =>
        client.searchWallet({
          container: PHRASE,
          password: "p w",
          reference: { fingerprint: "73c5da0a" },
          passphrase: "x",
        }),
    ],
    [
      "client.rekey",
      () =>
        client.rekey({
          container: PHRASE,
          password: "p w",
          newPassword: "n w",
          newPasswordRepeat: "n w",
          confirmation: { fingerprint: "73c5da0a" },
          passphrase: "x",
        }),
    ],
    [
      "client.openHiddenWallets+open+close",
      async () => {
        const session = await client.openHiddenWallets({
          container: PHRASE,
          mainPassphrase: "main",
        });
        await session.open({ password: "h w", passwordRepeat: "h w" });
        await session.close();
      },
    ],
    ["passwords.review", () => passwords.review({ password: "a b", passwordRepeat: "a b" })],
    ["passwords.strength", () => passwords.strength({ password: "a b" })],
    ["passwords.make", () => passwords.make({ kind: "words", dice: "11111 22222" })],
    ["passwords.wordHints", () => passwords.wordHints({ typed: "aba" })],
    ["wallet.walletCheck", () => wallet.walletCheck({ phrase: PHRASE, passphrase: "x" })],
    ["wallet.fingerprint", () => wallet.fingerprint({ phrase: PHRASE, passphrase: "x" })],
    ["wallet.wordHints", () => wallet.wordHints({ typed: "aba" })],
    [
      "wallet.describeDraw",
      () => wallet.describeDraw({ chosen: [{ word: "zoo", position: 1 }], walletCheck: false }),
    ],
    [
      "wallet.drawPhrase(2 workers)",
      () =>
        wallet.drawPhrase({
          passphrase: "x",
          passphraseRepeat: "x",
          walletCheck: true,
          workers: 2,
          chosen: [{ word: "zoo", position: 1 }],
        }),
    ],
  ];
  const outcomes = {};
  for (const [name, call] of calls) {
    const before = StandInWorker.all.length;
    const outcome = await settle(call());
    await tick();
    const workers = StandInWorker.all.slice(before).filter((worker) => !worker.selfCheck);
    outcomes[name] = {
      outcome: outcome.rejected ?? "resolved",
      notTransferred: workers.flatMap((worker) =>
        worker.transferChecks.filter((each) => each.notTransferred.length > 0),
      ),
      pageCopiesLeft: workers.flatMap((worker) =>
        worker.transferChecks.filter((each) => each.pageCopiesLeft.length > 0),
      ),
    };
  }
  const leaks = Object.entries(outcomes).filter(
    ([, { notTransferred, pageCopiesLeft }]) =>
      notTransferred.length > 0 || pageCopiesLeft.length > 0,
  );
  const rejected = Object.entries(outcomes).filter(([, { outcome }]) => outcome !== "resolved");
  check("P1a every secret-bearing call reached its stand-in worker", rejected.length === 0, {
    rejected,
  });
  check(
    "P1b every secret field of every request and answer is transferred, none left in the page",
    leaks.length === 0,
    { leaks },
  );
}

// ---------------------------------------------------------------------------------------------
// P2: runtime types outside the declarations of MhfeWallet.drawPhrase (wallet.d.ts: walletCheck
// is a boolean; workers is 1 to 256). describeDraw refuses walletCheck "yes" with a TypeError.
{
  const wallet = new MhfeWallet(parts());
  await wallet.startupCheck();
  const cases = [
    ["walletCheck: 'yes', no passphrase", { walletCheck: "yes" }],
    ["walletCheck: 1, no passphrase", { walletCheck: 1 }],
    ["workers: 0, no passphrase", { workers: 0 }],
    ["workers: 'many', no passphrase", { workers: "many" }],
    ["workers: 1e9, no passphrase", { workers: 1e9 }],
    [
      "workers: -1, passphrase, walletCheck false",
      { passphrase: "x", passphraseRepeat: "x", walletCheck: false, workers: -1 },
    ],
  ];
  const results = {};
  for (const [name, options] of cases) {
    const before = StandInWorker.all.length;
    const outcome = await settle(wallet.drawPhrase(options));
    const sent = StandInWorker.all
      .slice(before)
      .filter((worker) => !worker.selfCheck)
      .map((worker) => ({
        operation: worker.messages[0]?.operation,
        walletCheck: worker.messages[0]?.walletCheck,
      }));
    results[name] = { outcome: outcome.rejected ?? "resolved", sent };
  }
  const accepted = Object.entries(results).filter(([, { outcome }]) => outcome === "resolved");
  check(
    "P2 drawPhrase refuses a walletCheck that is not a boolean and workers outside 1..256 (TypeError)",
    accepted.length === 0,
    results,
  );
  const describeDraw = await settle(wallet.describeDraw({ walletCheck: "yes" }));
  info("P2 describeDraw({ walletCheck: 'yes' }) for comparison", describeDraw);
  const nullPassphrase = {
    walletCheck: await settle(wallet.walletCheck({ phrase: PHRASE, passphrase: null })),
    fingerprint: await settle(wallet.fingerprint({ phrase: PHRASE, passphrase: null })),
  };
  info("P2 passphrase: null in walletCheck() and fingerprint()", nullPassphrase);
}

// ---------------------------------------------------------------------------------------------
// P3: worker replies whose type is a name inherited from Object.prototype. The worker side refuses
// such names as operations (operationOf, AUD-010-API002); the page dispatches replies by
// `handlers[reply.type]` and questions by `handlers[question]`.
{
  StandInWorker.serve = null;
  const repair = new MhfeRepair(parts());
  await repair.startupCheck();
  const results = {};
  for (const type of ["notAKnownType", "valueOf", "hasOwnProperty", "__proto__", "constructor"]) {
    const pending = settle(repair.inspectContainer({ container: PHRASE }));
    await tick();
    await tick();
    const worker = lastOperationWorker();
    worker.reply({ type, value: null });
    worker.reply({ type: "result", result: { reading: "container" } });
    results[`reply type ${type}`] = (await pending).rejected ?? "resolved";
  }
  for (const question of ["notAKnownQuestion", "toString", "valueOf"]) {
    const pending = settle(repair.inspectContainer({ container: PHRASE }));
    await tick();
    await tick();
    const worker = lastOperationWorker();
    worker.reply({ type: "ask", question, value: null });
    await tick();
    const answered = worker.messages.slice(1).map((message) => message.value);
    worker.reply({ type: "result", result: { reading: "container" } });
    results[`ask ${question}`] = {
      outcome: (await pending).rejected ?? "resolved",
      answerSent: answered,
    };
  }
  // Each inherited name must behave as the unknown name of its kind: an unknown reply type is
  // ignored, and an unknown question ends the job without any answer being sent.
  const baseline = (name) =>
    name.startsWith("ask ") ? results["ask notAKnownQuestion"] : results["reply type notAKnownType"];
  const inheritedTreatedAsCallbacks = Object.entries(results).filter(
    ([name, outcome]) =>
      /valueOf|hasOwnProperty|__proto__|toString/u.test(name) &&
      JSON.stringify(outcome).replaceAll(/valueOf|hasOwnProperty|__proto__|toString/gu, "X") !==
        JSON.stringify(baseline(name)).replaceAll(/notAKnownQuestion|notAKnownType/gu, "X"),
  );
  check(
    "P3 a reply or question named after an Object.prototype member is handled like any unknown name",
    inheritedTreatedAsCallbacks.length === 0,
    results,
  );
  StandInWorker.serve = serveAll;
}

// ---------------------------------------------------------------------------------------------
// P4: the self-check gate (AUD-014-SEC001 regression): an operation that waits for a startup
// check rejects when a concurrent full check fails first, for the ModuleWorker classes and for
// the core's slot.
for (const [name, make, operate] of [
  ["MhfeWallet.fingerprint", () => new MhfeWallet(parts()), (c) => c.fingerprint({ phrase: PHRASE })],
  [
    "MhfeClient.decrypt",
    () => new MhfeClient(coreParts()),
    (c) => c.decrypt({ container: PHRASE, password: "p w" }),
  ],
]) {
  const held = [];
  StandInWorker.checkReply = (message, worker) => {
    if (message.tier === "startup") {
      held.push({ message, worker });
      return undefined;
    }
    return { type: "result", result: failedReport(message) };
  };
  const subject = make();
  const before = operationWorkers().length;
  const pending = settle(operate(subject));
  await tick();
  await tick();
  const full = await settle(subject.fullCheck());
  for (const { message, worker } of held) {
    worker.reply({ type: "result", result: passedReport(message) });
  }
  const outcome = await pending;
  await tick();
  check(`P4 ${name} waiting for its startup check rejects after a failed fullCheck()`, outcome.rejected?.code === "SELF_CHECK_FAILED" && operationWorkers().length === before, {
    fullCheckPassed: full.resolved?.passed,
    outcome,
    operationWorkersStarted: operationWorkers().length - before,
  });
  StandInWorker.checkReply = (message) => ({ type: "result", result: passedReport(message) });
}

// ---------------------------------------------------------------------------------------------
// P5: what a failed fullCheck() leaves: an operation already running, and startupCheck() asked
// again afterwards. Recorded as behaviour; the contract only speaks of methods called afterwards.
{
  StandInWorker.serve = null;
  const wallet = new MhfeWallet(parts());
  await wallet.startupCheck();
  const running = settle(wallet.fingerprint({ phrase: PHRASE }));
  await tick();
  await tick();
  const worker = lastOperationWorker();
  StandInWorker.checkReply = (message) => ({ type: "result", result: failedReport(message) });
  const full = await settle(wallet.fullCheck());
  worker.reply({ type: "result", result: "00000000" });
  const inFlight = await running;
  const startupAgain = await settle(wallet.startupCheck());
  const afterwards = await settle(wallet.fingerprint({ phrase: PHRASE }));
  info("P5 failed fullCheck(): in-flight operation, startupCheck() again, a later operation", {
    fullCheckPassed: full.resolved?.passed,
    inFlight,
    startupCheckAgain: startupAgain.resolved?.passed ?? startupAgain.rejected,
    laterOperation: afterwards.rejected?.code ?? afterwards,
  });
  StandInWorker.checkReply = (message) => ({ type: "result", result: passedReport(message) });
  StandInWorker.serve = serveAll;
}

// ---------------------------------------------------------------------------------------------
// P6: cancel() while the operation's worker still loads the WebAssembly (deferred termination):
// the promise rejects at once, the slot is free at once, the worker stays until it says it is
// ready, then stops, and its late result is ignored.
{
  StandInWorker.serve = null;
  const client = new MhfeClient(coreParts());
  await client.startupCheck({ argon2: false });
  StandInWorker.hold = true;
  const first = settle(client.decrypt({ container: PHRASE, password: "p w" }));
  await tick();
  await tick();
  const loading = lastOperationWorker();
  client.cancel();
  const cancelled = await first;
  const terminatedAtCancel = loading.terminated;
  const second = settle(client.decrypt({ container: PHRASE, password: "p w" }));
  await tick();
  await tick();
  const secondWorker = lastOperationWorker();
  const aliveTogether = !loading.terminated && !secondWorker.terminated;
  StandInWorker.hold = false;
  loading.onmessage({ data: { type: "ready", buildId: BUILD_ID } });
  const terminatedOnReady = loading.terminated;
  loading.onmessage({ data: { type: "result", result: { late: true } } });
  secondWorker.reply({ type: "ready", buildId: BUILD_ID });
  secondWorker.reply({ type: "result", result: { second: true } });
  const secondOutcome = await second;
  check(
    "P6 a cancelled loading worker stops when it loads and its late result is ignored",
    cancelled.rejected?.code === "CANCELLED" &&
      terminatedOnReady &&
      JSON.stringify(secondOutcome.resolved) === JSON.stringify({ second: true }),
    { cancelled, terminatedAtCancel, terminatedOnReady, secondOutcome },
  );
  info("P6 a new long operation may start while the cancelled one's worker still loads", {
    aliveTogether,
    secretsLeftInPageAfterTransfer: loading.transferChecks[0].pageCopiesLeft,
  });
  StandInWorker.serve = serveAll;
}

// ---------------------------------------------------------------------------------------------
// P7 (AUD-017, new in 0.5.1): decrypt() takes `passphrase`. It is a secret: transferred, never
// left in the page, wiped when the job ends before the worker owns it, and refused by type.
{
  StandInWorker.serve = serveAll;
  const client = new MhfeClient(coreParts());
  await client.startupCheck({ argon2: false });
  const before = StandInWorker.all.length;
  const outcome = await settle(
    client.decrypt({ container: PHRASE, password: "p w", passphrase: "TREZOR" }),
  );
  const sent = StandInWorker.all.slice(before).filter((worker) => !worker.selfCheck);
  const request = sent[0]?.messages[0];
  check(
    "P7a decrypt sends passphrase as transferred bytes, none left in the page",
    outcome.resolved !== undefined &&
      request?.passphrase instanceof Uint8Array &&
      new TextDecoder().decode(request.passphrase) === "TREZOR" &&
      sent[0].transferChecks.every(
        (each) => each.notTransferred.length === 0 && each.pageCopiesLeft.length === 0,
      ),
    { outcome, transferChecks: sent[0]?.transferChecks },
  );
  // Cancelled while the worker loads: the request with the passphrase was transferred already.
  StandInWorker.hold = true;
  const bytes = new TextEncoder().encode("TREZOR");
  const pending = settle(client.decrypt({ container: PHRASE, password: "p w", passphrase: bytes }));
  await tick();
  await tick();
  client.cancel();
  const cancelled = await pending;
  StandInWorker.hold = false;
  check(
    "P7b a passphrase given as bytes is copied, the caller's buffer kept, and a cancel rejects",
    cancelled.rejected?.code === "CANCELLED" && new TextDecoder().decode(bytes) === "TREZOR",
    { cancelled, callerBytes: Array.from(bytes) },
  );
  const wrongTypes = {};
  for (const [name, value] of [
    ["null", null],
    ["number", 7],
    ["object", { text: "TREZOR" }],
  ]) {
    wrongTypes[name] = await settle(
      client.decrypt({ container: PHRASE, password: "p w", passphrase: value }),
    );
  }
  check(
    "P7c decrypt refuses a passphrase that is not a string or bytes (TypeError), message without it",
    Object.values(wrongTypes).every(
      (each) => each.rejected?.name === "TypeError" && !/TREZOR/u.test(each.rejected.message),
    ),
    wrongTypes,
  );
}

// ---------------------------------------------------------------------------------------------
// P8 (AUD-017): worker replies out of protocol order. A worker that answers "result" without
// "ready" first skips the page's build comparison (#started); a duplicate result, an error after
// a result, and an answer the page never asked for must change nothing.
{
  StandInWorker.serve = null;
  const repair = new MhfeRepair(parts());
  await repair.startupCheck();
  StandInWorker.hold = true;
  const pending = settle(repair.inspectContainer({ container: PHRASE }));
  await tick();
  await tick();
  const worker = lastOperationWorker();
  StandInWorker.hold = false;
  worker.onmessage({ data: { type: "result", result: { reading: "no ready first" } } });
  const noReady = await pending;
  info("P8 a result before ready: resolves without the build comparison (stand-in worker only)", noReady);

  const second = settle(repair.inspectContainer({ container: PHRASE }));
  await tick();
  await tick();
  const w2 = lastOperationWorker();
  w2.reply({ type: "result", result: { first: true } });
  w2.onmessage({ data: { type: "result", result: { second: true } } });
  w2.onmessage({ data: { type: "error", error: { code: "INTERNAL_ERROR", message: "late" } } });
  const dup = await second;
  check(
    "P8 a duplicate result and a late error after the first result change nothing",
    JSON.stringify(dup.resolved) === JSON.stringify({ first: true }) && w2.terminated,
    { dup, terminated: w2.terminated },
  );
  StandInWorker.serve = serveAll;
}

console.log(`\n${failures === 0 ? "every CHECK passed" : `${failures} CHECK(s) failed`}`);
process.exit(failures === 0 ? 0 : 1);
