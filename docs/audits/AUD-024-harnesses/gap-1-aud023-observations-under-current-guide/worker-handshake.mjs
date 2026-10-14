// AUD-024 harness: does WorkerJob (web/runtime.js) act on a worker's messages before the worker's
// "ready" has shown its build? Its doc comment says a handler is called only after it. A fake
// Worker stands in for the browser's; no package worker or WebAssembly runs. Exits 1 when a result
// or news without a ready reach the page.
//
//   node --no-warnings docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/worker-handshake.mjs
import { BUILD_ID, WorkerJob } from "../../../../web/runtime.js";

let script = [];
class FakeWorker {
  constructor() {
    this.onmessage = null;
    this.onerror = null;
    this.requests = 0;
  }
  postMessage() {
    // Only the request is answered; answers to a question get no reply.
    if (this.requests++ > 0) return;
    for (const reply of script) setTimeout(() => this.onmessage?.({ data: reply }), 0);
  }
  terminate() {}
}
globalThis.Worker = FakeWorker;
const wasm = { get: async () => ({}) };

async function run(name, replies, handlers = {}) {
  script = replies;
  const job = new WorkerJob(["/* no script */"], handlers);
  const outcome = await Promise.race([
    job.run({ module: "core", operation: "x" }, [], wasm).then(
      (result) => `resolved with ${JSON.stringify(result)}`,
      (error) => `rejected ${error.code}`,
    ),
    new Promise((resolve) => setTimeout(() => resolve("still waiting after 200 ms"), 200)),
  ]);
  console.log(`${name}: ${outcome}`);
  job.stop(null);
  return outcome;
}

console.log(`runtime build ${BUILD_ID}`);
const unchecked = await run("a result, no ready", [{ type: "result", result: "unchecked" }]);
const heard = [];
await run("news then a result, no ready", [
  { type: "progress", value: { round: 1 } },
  { type: "result", result: "unchecked" },
], { progress: (value) => heard.push(value) });
console.log(`  the page's progress handler ran ${heard.length} time(s) without a ready`);
await run("control: ready of another build, then a result", [
  { type: "ready", buildId: "another-build" },
  { type: "result", result: "unchecked" },
]);
await run("control: ready of this build, then a result", [
  { type: "ready", buildId: BUILD_ID },
  { type: "result", result: "checked" },
]);
const failed = unchecked.startsWith("resolved") || heard.length > 0;
console.log(
  failed
    ? "FAIL: the page takes a worker's result and news before its ready"
    : "PASS: nothing reaches the page before the worker's ready",
);
process.exit(failed ? 1 : 0);
