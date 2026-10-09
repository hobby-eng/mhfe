// AUD-014 regression: a failed full check must refuse a draw already awaiting startup.
// The controlled scheduling reproduces a full result delivered before the startup result.
import assert from "node:assert/strict";
import { setTimeout as pause } from "node:timers/promises";
import {
  MhfeWallet,
  readBytes,
  runtime,
  sha256,
  source,
  sourceHashes,
  wasmBytes,
} from "./browser-sources.mjs";

const mode = process.argv[2] ?? "--controlled";
assert.ok(["--controlled", "--wasm"].includes(mode), "mode is --controlled or --wasm");
assert.ok(process.argv.length <= 3, "no other arguments are accepted");
const { BUILD_ID } = runtime;
const actualWasm = mode === "--wasm";
const glue = actualWasm ? source("target/wasm-bindgen/mhfe.js") : null;
const bytes = actualWasm ? readBytes("dist/runtime/mhfe.wasm") : wasmBytes();
const artifacts = actualWasm
  ? {
      "dist/runtime/mhfe.wasm": sha256(bytes),
      "target/wasm-bindgen/mhfe.js": sha256(glue),
      relationship: "existing baseline artifact, not rebuilt by this harness",
    }
  : null;

const draws = [];
let startupWorker;
const fakeReport = (tier) => ({
  tier,
  version: "audit-only",
  passed: tier === "startup",
  ids: ["word-wishes"],
  components: [
    {
      id: "word-wishes",
      label: "Chosen word of a new phrase",
      outcome: tier === "startup" ? "passed" : "failed",
      ...(tier === "full" ? { detail: "synthetic damaged known answer" } : {}),
    },
  ],
});

class ScheduledWorker {
  postMessage(message, transfer = []) {
    const request = structuredClone(message, { transfer });
    if (request.operation === "drawPhrase") {
      draws.push({
        operation: request.operation,
        chosen: new TextDecoder().decode(request.chosenWords),
      });
      // No phrase is generated: refuse this observed dispatch and let the pending call settle.
      queueMicrotask(() => {
        this.reply({ type: "ready", buildId: BUILD_ID });
        this.reply({
          type: "error",
          error: { code: "CANCELLED", message: "audit probe refused the dispatched draw" },
        });
      });
      return;
    }
    assert.equal(request.operation, "selfCheck", "only self-checks run before the gate");
    this.reply({ type: "ready", buildId: BUILD_ID });
    if (actualWasm) {
      // This is the same wasm-bindgen init and Rust wallet binding the package worker calls.
      const binding = new Function(`${glue}\nreturn mhfe;`)();
      binding.initSync({ module: request.compiled });
      const random = {
        fill: (buffer) =>
          request.tier === "full" ? buffer.fill(0x2a) : crypto.getRandomValues(buffer),
      };
      this.report = JSON.parse(
        binding.selfCheckWallet(
          request.tier,
          request.skip,
          random,
          (id, label) => this.reply({ type: "componentStart", value: { id, label } }),
          (json) => this.reply({ type: "component", value: JSON.parse(json) }),
        ),
      );
      assert.ok(this.report.components.some(({ id }) => id === "word-wishes"));
    } else {
      this.report = fakeReport(request.tier);
    }
    if (request.tier === "startup") {
      assert.equal(this.report.passed, true, "the startup known answers pass");
      startupWorker = this;
    } else {
      assert.equal(this.report.passed, false, "the full report is a real gate failure");
      if (actualWasm) {
        assert.equal(
          this.report.components.find(({ outcome }) => outcome === "failed").id,
          "random-source",
          "only the live source used by the full wallet check fails",
        );
      }
      queueMicrotask(() => this.reply({ type: "result", result: this.report }));
    }
  }

  reply(data) {
    this.onmessage?.({ data });
  }

  terminate() {}
}

async function waitForStartup() {
  // The baseline MHFE artifact is larger than the empty module: compilation can outlast many
  // immediate event-loop turns, so use a bounded wall-clock deadline instead.
  const deadline = performance.now() + 5_000;
  while (performance.now() < deadline) {
    if (startupWorker !== undefined) return;
    await pause(10);
  }
  throw new Error(
    `Startup was not requested within five seconds (${mode}, WASM SHA-256 ${sha256(bytes)}).`,
  );
}

const realWorker = globalThis.Worker;
globalThis.Worker = ScheduledWorker;
try {
  const wallet = new MhfeWallet({ workerSource: "audit-only scheduled worker", wasm: bytes });
  const pending = wallet
    .drawPhrase({ chosen: [{ word: "happy", position: 1 }], neverUse: ["abandon"] })
    .then(
      () => ({ resolved: true }),
      (error) => ({ resolved: false, code: error.code }),
    );
  await waitForStartup();
  const failed = await wallet.fullCheck();
  assert.equal(failed.passed, false);
  startupWorker.reply({ type: "result", result: startupWorker.report });
  const outcome = await pending;
  console.log(
    JSON.stringify({
      mode,
      startupPassed: startupWorker.report.passed,
      fullPassed: failed.passed,
      failedPart: failed.components.find(({ outcome }) => outcome === "failed").id,
      dispatchedDraws: draws,
      pendingOutcome: outcome,
      sources: sourceHashes,
      artifacts,
      limitations: "Controlled delivery order; no real browser, Argon2, or phrase drawing.",
    }),
  );
  assert.equal(
    draws.length,
    0,
    "a failed full check must prevent a waiting draw from being dispatched",
  );
  assert.deepEqual(outcome, { resolved: false, code: "SELF_CHECK_FAILED" });
  console.log("PASS a failed full check refuses an already waiting draw");
} finally {
  globalThis.Worker = realWorker;
}
