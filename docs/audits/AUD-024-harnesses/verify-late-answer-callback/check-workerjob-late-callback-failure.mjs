// AUD-024 verifier probe (review only): drives web/runtime.js's WorkerJob at b6fca69 directly, with
// a stand-in Worker that sends "ready" and then either news ("progress") or a question ("ask").
// The page handler ends the job (as cancel() does, through job.stop) and then fails. No WebAssembly,
// no Argon2, no secrets. Prints how the job settled and which rejections Node saw as unhandled.
// Exits 0 when every late failure is reported (unhandled rejection or uncaught exception), 1 when
// one disappears, 2 when the control (an async news rejection) is not reported.
import { fileURLToPath } from "node:url";

// Run from the repository root.
const root = new URL(`file://${process.cwd()}/`);
const runtimeUrl = new URL("web/runtime.js", root);

const unhandled = [];
process.on("unhandledRejection", (reason) => unhandled.push(String(reason?.message ?? reason)));
const uncaught = [];
process.on("uncaughtException", (error) => uncaught.push(String(error?.message ?? error)));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let script = null;
class StandInWorker {
  constructor() {
    this.terminated = false;
    this.received = [];
    StandInWorker.last = this;
    setTimeout(() => this.#emit({ type: "ready", buildId: "development" }), 0);
    setTimeout(() => this.#emit(script), 1);
  }
  #emit(data) {
    if (!this.terminated) this.onmessage?.({ data });
  }
  postMessage(message) {
    this.received.push(message?.type ?? "request");
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = StandInWorker;
URL.createObjectURL = () => "blob:stand-in";
URL.revokeObjectURL = () => {};

const { WorkerJob, MhfeCancelledError, MhfeError } = await import(runtimeUrl.href);
console.log(`runtime: ${fileURLToPath(runtimeUrl).replace(/^\/home\/[^/]+/u, "/home/user")}`);
const wasm = { get: async () => "stand-in module" };

async function run(label, message, handlers, jobRef) {
  unhandled.length = 0;
  uncaught.length = 0;
  script = message;
  const job = new WorkerJob(["// stand-in"], handlers);
  jobRef.job = job;
  let outcome;
  try {
    outcome = `resolved ${JSON.stringify(await job.run({ type: "start" }, [], wasm))}`;
  } catch (error) {
    outcome = `rejected ${error?.name} ${error?.code}`;
  }
  await sleep(50);
  const seen = [...unhandled, ...uncaught];
  console.log(
    `${label}: ${outcome}; unhandled rejections: ${JSON.stringify(unhandled)}; uncaught: ${JSON.stringify(uncaught)}`,
  );
  return seen;
}

const cancelled = () => new MhfeCancelledError("CANCELLED", "The operation was cancelled.");
// Make sure MhfeCancelledError is constructible as used; fall back to MhfeError.
let makeCancel = cancelled;
try {
  cancelled();
} catch {
  makeCancel = () => new MhfeError("CANCELLED", "The operation was cancelled.");
}

// 1. News: an async onProgress-like handler that ends the job and then rejects.
const ref1 = {};
const news = await run(
  "news (progress), async, fails after the job ended",
  { type: "progress", value: { stage: "x" } },
  {
    progress: async () => {
      ref1.job.stop(makeCancel());
      await sleep(5);
      throw new Error("news handler failed after end");
    },
  },
  ref1,
);

// 1b. News: a synchronous onProgress-like handler that ends the job and then throws.
const ref1b = {};
const newsSync = await run(
  "news (progress), sync throw after the job ended",
  { type: "progress", value: { stage: "x" } },
  {
    progress: () => {
      ref1b.job.stop(makeCancel());
      throw new Error("sync news handler failed after end");
    },
  },
  ref1b,
);

// 2. Question: an async ask handler that ends the job and then rejects.
const ref2 = {};
const askAsync = await run(
  "ask (ownerCheck), async, fails after the job ended",
  { type: "ask", question: "ownerCheck", value: {} },
  {
    ownerCheck: async () => {
      ref2.job.stop(makeCancel());
      await sleep(5);
      throw new Error("ask handler failed after end");
    },
  },
  ref2,
);

// 3. Question: a synchronous ask handler that ends the job and then throws.
const ref3 = {};
const askSync = await run(
  "ask (noLength), sync throw after the job ended",
  { type: "ask", question: "noLength", value: {} },
  {
    noLength: () => {
      ref3.job.stop(makeCancel());
      throw new Error("sync ask handler failed after end");
    },
  },
  ref3,
);

// 4. Control: an ask handler that fails while the job runs is reported as CALLBACK_FAILED.
const ref4 = {};
await run(
  "ask (confirmAgain), fails while the job runs",
  { type: "ask", question: "confirmAgain", value: {} },
  {
    confirmAgain: async () => {
      throw new Error("ask handler failed while running");
    },
  },
  ref4,
);

const reported = (seen, text) => seen.includes(text);
const checks = [
  ["control: async news failure after the end stays unhandled", reported(news, "news handler failed after end")],
  ["sync news failure after the end is not swallowed", reported(newsSync, "sync news handler failed after end")],
  ["async ask failure after the end is not swallowed", reported(askAsync, "ask handler failed after end")],
  ["sync ask failure after the end is not swallowed", reported(askSync, "sync ask handler failed after end")],
];
for (const [label, ok] of checks) console.log(`${ok ? "ok  " : "FAIL"} ${label}`);
// Exit 2 when the control fails (the probe itself is broken), 1 when a late failure disappears.
process.exit(!checks[0][1] ? 2 : checks.every(([, ok]) => ok) ? 0 : 1);
