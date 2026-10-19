// AUD-028 regression: a completed failed component must outlive later operational failure.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PackageCheck, BUILD_ID } from "../../../dist/runtime/runtime.js";

const originalWorker = globalThis.Worker;
// Worker is an edge dependency; no actual worker or Argon2 is needed for this state transition.
globalThis.Worker = class WorkerCapability {};
try {
  const bytes = new Uint8Array(readFileSync("dist/runtime/mhfe.wasm"));
  const compiled = await WebAssembly.compile(bytes);
  const gate = new PackageCheck({
    wasm: { source: bytes, get: async () => compiled },
    classFile: "AUD028-public-probe",
    classBuildId: BUILD_ID,
    secrets: false,
  });
  const failed = {
    id: "argon2",
    label: "Argon2id",
    outcome: "failed",
    detail: "public synthetic wrong-answer case",
  };
  const workerFailure = Object.assign(new Error("public synthetic transport failure"), {
    code: "WORKER_FAILED",
  });
  await assert.rejects(
    gate.full([
      {
        run: async (_skip, handlers) => {
          await handlers.component(failed);
          return {
            version: "0.6.1",
            tier: "full",
            passed: false,
            ids: [failed.id],
            components: [failed],
          };
        },
      },
      {
        run: async () => {
          throw workerFailure;
        },
      },
    ]),
    { code: "WORKER_FAILED" },
  );
  const pass = { version: "0.6.1", tier: "startup", passed: true, ids: [], components: [] };
  await assert.rejects(
    gate.require(() => gate.startup("default", async () => pass)),
    { code: "SELF_CHECK_FAILED" },
  );
  console.log("PASS: completed failed component keeps the class closed after WORKER_FAILED");
} finally {
  if (originalWorker === undefined) delete globalThis.Worker;
  else globalThis.Worker = originalWorker;
}
