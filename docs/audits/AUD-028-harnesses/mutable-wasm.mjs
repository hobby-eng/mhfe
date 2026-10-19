// AUD-028: real class, worker script, glue and WASM over a deterministic Worker edge adapter.
import assert from "node:assert/strict";
import { resolveObjectURL } from "node:buffer";
import { readFileSync } from "node:fs";
import { MhfeRepair } from "../../../dist/repair/repair.js";
import { damagedCopies } from "../../../scripts/rust-strings.mjs";

class WorkerAdapter {
  #self;
  #loaded;
  #stopped = false;

  constructor(url) {
    this.#self = {
      crypto: globalThis.crypto,
      crossOriginIsolated: false,
      postMessage: (value) => {
        if (!this.#stopped) this.onmessage({ data: structuredClone(value) });
      },
    };
    this.#loaded = resolveObjectURL(url)
      .text()
      .then((text) => {
        // The input is the exact package worker supplied by this audit, never external code.
        new Function("self", text)(this.#self);
      });
  }

  postMessage(message, transfer = []) {
    const data = structuredClone(message, { transfer });
    this.#loaded
      .then(() => this.#self.onmessage({ data }))
      .catch((error) => {
        if (!this.#stopped) this.onerror?.({ message: String(error) });
      });
  }

  terminate() {
    this.#stopped = true;
  }
}

const savedWorker = globalThis.Worker;
globalThis.Worker = WorkerAdapter;
try {
  const workerSource = readFileSync("dist/runtime/worker.js", "utf8");
  const bytes = new Uint8Array(readFileSync("dist/runtime/mhfe.wasm"));
  const { container } = JSON.parse(readFileSync("tests/fixtures/suite3-vectors/zero-12.json"));
  const healthy = new MhfeRepair({ workerSource, wasm: bytes });
  assert.equal((await healthy.startupCheck()).passed, true);
  const card = (await healthy.repairWords({ container, count: 4 })).words;
  const before = await healthy.repairContainer({ container, card });
  bytes.set(damagedCopies(bytes, "Bitcoin seed"));
  const reused = new MhfeRepair({ workerSource, wasm: bytes });
  const reusedReport = await reused.startupCheck();
  const fresh = new MhfeRepair({ workerSource, wasm: bytes.slice() });
  const freshReport = await fresh.startupCheck();
  assert.equal(freshReport.passed, false, "damage must fail with independent cache identity");
  let after = null;
  if (reusedReport.passed) after = await reused.repairContainer({ container, card });
  else
    await assert.rejects(reused.repairContainer({ container, card }), {
      code: "SELF_CHECK_FAILED",
    });
  const originalAfterMutation = await healthy.repairContainer({ container, card });
  assert.equal(originalAfterMutation.containerFingerprint, before.containerFingerprint);
  console.log(
    JSON.stringify({
      reusedStartupPassed: reusedReport.passed,
      freshStartupPassed: freshReport.passed,
      healthyFingerprint: before.containerFingerprint,
      reusedFingerprint: after?.containerFingerprint ?? null,
      originalCompiledModuleStillHealthy: true,
    }),
  );
  assert.equal(reusedReport.passed, false, "changed bytes must not inherit old passed checks");
  console.log("PASS: changed WASM bytes cannot reuse another compiled module's results");
} finally {
  if (savedWorker === undefined) delete globalThis.Worker;
  else globalThis.Worker = savedWorker;
}
