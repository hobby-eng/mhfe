// Malformed worker reports must not open actual class operations or populate shared passes.
import assert from "node:assert/strict";
import { bindings } from "./package.mjs";
import { wasm } from "./page-classes.mjs";
import { StandInWorker, servedByTheWebAssembly, started } from "./stand-in-worker.mjs";

/** Actual repair class dispatch over real startup checks, with only the final envelope damaged. */
export async function checkStartupReportBoundaries({ MhfeRepair }) {
  const saved = StandInWorker.serveCheck;
  try {
    for (const damage of [
      (report) => ({ ...report, components: [] }),
      (report) => ({ ...report, components: report.components.slice(1) }),
      (report) => ({ ...report, ids: [] }),
      (report) => ({ ...report, ids: undefined }),
      (report) => ({ ...report, tier: "full" }),
      (report) => ({ ...report, passed: false }),
      (report) => ({ ...report, ids: [...report.ids, "unreported"] }),
      (report) => ({ ...report, ids: [...report.ids, report.ids[0]] }),
      (report) => ({ ...report, components: [...report.components, report.components[0]] }),
    ]) {
      const compiled = await WebAssembly.compile(wasm);
      const before = StandInWorker.started.length;
      StandInWorker.serveCheck = (message, worker) =>
        damage(servedByTheWebAssembly(message, worker));
      const client = new MhfeRepair({ workerSource: "public report control", wasm: compiled });
      await assert.rejects(client.inspectContainer({ container: "synthetic" }), {
        code: "PACKAGE_MISMATCH",
      });
      assert.ok(
        StandInWorker.started.slice(before).every((worker) => worker.selfCheck),
        "no class operation request may follow an incomplete startup report",
      );
      StandInWorker.serveCheck = servedByTheWebAssembly;
      const retry = new MhfeRepair({ workerSource: "public report control", wasm: compiled });
      assert.equal((await retry.startupCheck()).passed, true);
      assert.deepEqual(StandInWorker.checks.at(-1).messages[0].skip, [], "no partial cache");
      const reused = new MhfeRepair({ workerSource: "public report control", wasm: compiled });
      assert.equal((await reused.startupCheck()).passed, true);
      assert.ok(StandInWorker.checks.at(-1).messages[0].skip.length > 0, "verified cache reuse");
    }
    await checkCompletedRepair(MhfeRepair);
  } finally {
    StandInWorker.serveCheck = saved;
  }
  console.log("Incomplete final startup reports block actual class dispatch and cache writes.");
}

/** A complete positive report still permits an actual Rust inspection through class transport. */
async function checkCompletedRepair(MhfeRepair) {
  const client = new MhfeRepair({ workerSource: "public report control", wasm: wasm.slice() });
  const pending = client.inspectContainer({ container: "synthetic" });
  const worker = await started((message) => message.operation === "inspectContainer");
  const result = JSON.parse(bindings.inspectContainer(worker.messages[0].container));
  worker.reply({ type: "result", result });
  assert.deepEqual(await pending, result);
  assert.equal((await client.fullCheck()).passed, true);
}
