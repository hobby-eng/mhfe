// AUD-016: bounded adversarial probes of the current web/ sources, with a synthetic worker.
// No generated package, Argon2, real browser, or private data is used. The source imports are
// resolved in memory because the production build arranges them in separate package folders.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const runtimeText = read("web/runtime.js");
const dataUrl = (text) => `data:text/javascript;base64,${Buffer.from(text).toString("base64")}`;
const runtimeUrl = dataUrl(runtimeText);
const runtime = await import(runtimeUrl);
const load = async (path) =>
  import(dataUrl(read(path).replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`)));
const { MhfeClient } = await load("web/client.js");
const { MhfeWallet } = await load("web/wallet.js");
const { MhfePasswords } = await load("web/passwords.js");
const { MhfeRepair } = await load("web/repair.js");
const { WorkerJob, CompiledModule, MhfeCancelledError, encodeSecret } = runtime;

const MINIMAL_WASM = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const parts = () => ({ workerSource: "synthetic public-data worker", wasm: MINIMAL_WASM });
const coreParts = () => ({
  ...parts(),
  argon2Threaded: "synthetic threaded source",
  argon2SingleThreaded: "synthetic single-threaded source",
});
const CORE_PARAMETERS = {
  maxPim: 1023,
  maxMemoryLevel: 21,
  highestBrowserMemoryLevel: 0,
  wordCounts: [12, 15, 18, 21, 24],
  builtInCheckWordCounts: [12, 15, 18, 21],
  repairWordCounts: [2, 4, 6, 8],
  decoyScanGap: 20,
};
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
let failures = 0;
const check = (label, passed, detail) => {
  failures += Number(!passed);
  console.log(`${passed ? "PASS" : "FAIL"} ${label}: ${JSON.stringify(detail)}`);
};
function watch(promise) {
  const result = { state: "pending" };
  promise.then(
    (value) => Object.assign(result, { state: "resolved", value }),
    (error) =>
      Object.assign(result, {
        state: "rejected",
        name: error.name,
        code: error.code,
        message: error.message,
      }),
  );
  return result;
}

class FakeWorker {
  static all = [];
  static serve = null;
  constructor() {
    this.messages = [];
    this.thrown = [];
    this.terminated = false;
    FakeWorker.all.push(this);
  }
  postMessage(message, transfer = []) {
    const copied = structuredClone(message, { transfer });
    this.messages.push(copied);
    if (FakeWorker.serve !== null) setTimeout(() => FakeWorker.serve(copied, this), 0);
  }
  reply(data) {
    if (this.terminated) return;
    try {
      this.onmessage?.({ data });
    } catch (error) {
      // A real browser reports this as an uncaught page-handler exception. Retain it while
      // keeping the probe itself alive long enough to inspect and cancel the pending job.
      this.thrown.push({ name: error.name, message: error.message });
    }
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = FakeWorker;

console.log(
  `SOURCE runtime.js ${createHash("sha256").update(runtimeText).digest("hex")}; public data only`,
);

// A known message type must also have a valid envelope. An invalid envelope must settle the
// job as a protocol error, instead of throwing from onmessage and leaving it running forever.
for (const [label, reply] of [
  ["null reply", null],
  ["error without payload", { type: "error" }],
  ["error with non-text message", { type: "error", error: { code: "INTERNAL_ERROR", message: 3 } }],
]) {
  const job = new WorkerJob(["synthetic"]);
  const result = watch(job.run({}, [], new CompiledModule(MINIMAL_WASM, "wasm")));
  await tick();
  const worker = FakeWorker.all.at(-1);
  worker.reply({ type: "ready", buildId: runtime.BUILD_ID });
  worker.reply(reply);
  await tick();
  check(label, result.state === "rejected" && worker.thrown.length === 0, {
    result,
    uncaughtPageExceptions: worker.thrown,
    ended: job.ended,
    terminated: worker.terminated,
  });
  job.stop(new MhfeCancelledError());
}

for (const name of ["constructor", "toString", "valueOf", "__proto__", "hasOwnProperty"]) {
  const job = new WorkerJob(["synthetic"]);
  const result = watch(job.run({}, [], new CompiledModule(MINIMAL_WASM, "wasm")));
  await tick();
  FakeWorker.all.at(-1).reply({ type: name });
  await tick();
  check(`AUD-015-SEC007 inherited news ${name}`, result.code === "PACKAGE_MISMATCH", result);
  const asked = new WorkerJob(["synthetic"]);
  const answer = watch(asked.run({}, [], new CompiledModule(MINIMAL_WASM, "wasm")));
  await tick();
  FakeWorker.all.at(-1).reply({ type: "ask", question: name, value: null });
  await tick();
  check(`AUD-015-SEC007 inherited question ${name}`, answer.code === "PACKAGE_MISMATCH", answer);
}

FakeWorker.serve = (message, worker) => {
  worker.reply({ type: "ready", buildId: runtime.BUILD_ID });
  if (message.operation === "selfCheck") {
    const report = {
      version: "synthetic",
      tier: message.tier,
      passed: true,
      ids: ["synthetic-part"],
      components: [{ id: "synthetic-part", label: "Synthetic part", outcome: "passed" }],
    };
    if (message.module === "core") report.parameters = CORE_PARAMETERS;
    worker.reply({ type: "result", result: report });
  } else worker.reply({ type: "result", result: { accepted: true } });
};

for (const [label, call] of [
  [
    "review null repetition",
    () => new MhfePasswords(parts()).review({ password: "", passwordRepeat: null }),
  ],
  [
    "walletCheck null passphrase",
    () => new MhfeWallet(parts()).walletCheck({ phrase: PHRASE, passphrase: null }),
  ],
  [
    "draw null repetition",
    () =>
      new MhfeWallet(parts()).drawPhrase({
        passphrase: "public",
        passphraseRepeat: null,
        walletCheck: false,
      }),
  ],
]) {
  const result = watch(call());
  for (let i = 0; i < 5 && result.state === "pending"; i += 1) await tick();
  check(`wrongly typed ${label} refuses with TypeError`, result.name === "TypeError", result);
}

for (const [label, options] of [
  ["string walletCheck", { walletCheck: "true" }],
  ["number walletCheck", { walletCheck: 1 }],
  ["zero workers", { workers: 0 }],
  ["text workers", { workers: "many" }],
  ["huge workers", { workers: 1e9 }],
]) {
  const result = watch(new MhfeWallet(parts()).drawPhrase(options));
  await tick();
  check(`AUD-015-API001 ${label}`, result.name === "TypeError", result);
}

// Caller bytes must be preserved even when a later argument fails. Buffer.slice aliases its
// original allocation; encodeSecret must make a plain new Uint8Array, as its contract says.
const caller = Buffer.from("synthetic public password");
const saved = Buffer.from(caller);
const copied = encodeSecret(caller, "password");
copied.fill(0);
check("caller Buffer ownership", caller.equals(saved) && copied.buffer !== caller.buffer, {
  callerUnchanged: caller.equals(saved),
  differentBuffer: copied.buffer !== caller.buffer,
});
const badReview = watch(
  new MhfePasswords(parts()).review({ password: caller, passwordRepeat: {} }),
);
for (let i = 0; i < 5 && badReview.state === "pending"; i += 1) await tick();
check(
  "caller byte ownership on refused repetition",
  badReview.name === "TypeError" && caller.equals(saved),
  badReview,
);

// Reusing a fresh class after cancellation during its startup wait must not be BUSY forever.
const client = new MhfeClient(coreParts());
const initial = watch(client.decrypt({ container: PHRASE, password: "public" }));
client.cancel();
await tick();
check("cancel during initialization", initial.code === "CANCELLED", initial);
const retried = watch(client.decrypt({ container: PHRASE, password: "public" }));
for (let i = 0; i < 6 && retried.state === "pending"; i += 1) await tick();
check("reuse after cancelled initialization", retried.state === "resolved", retried);

// The independent repair module constructs and runs without either Argon2 source.
const repaired = watch(new MhfeRepair(parts()).inspectContainer({ container: PHRASE }));
for (let i = 0; i < 5 && repaired.state === "pending"; i += 1) await tick();
check("independent repair surface", repaired.state === "resolved", repaired);

for (const worker of FakeWorker.all) worker.terminate();
console.log(`Checks complete: ${failures} failed assertions.`);
process.exitCode = failures === 0 ? 0 : 1;
