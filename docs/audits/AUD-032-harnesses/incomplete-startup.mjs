// AUD-032 candidate only: actual class gating with a spurious same-build final check report.
// Public data; no browser worker, recovery round or cryptographic parameter change.
import assert from "node:assert/strict";

import { BUILD_ID, VERSION } from "../../../scripts/package-check/package.mjs";
import { loadClasses, wasm } from "../../../scripts/package-check/page-classes.mjs";
import {
  StandInWorker,
  servedByTheWebAssembly,
} from "../../../scripts/package-check/stand-in-worker.mjs";

const actual = globalThis.Worker;
const firstWorker = StandInWorker.started.length;
const classes = await loadClasses();
const operationResult = { reading: "notAContainer", wordCount: 0, unreadable: [] };
class AutoOperationWorker extends StandInWorker {
  postMessage(message, transfer = []) {
    super.postMessage(message, transfer);
    if (message.operation === "inspectContainer") {
      setTimeout(() => {
        if (this.terminated) return;
        this.reply({ type: "ready", buildId: BUILD_ID });
        this.ready = true;
        this.reply({ type: "result", result: operationResult });
      }, 0);
    }
  }
}
const rows = [];
try {
  globalThis.Worker = AutoOperationWorker;
  StandInWorker.autoParameters = true;
  StandInWorker.serveCheck = servedByTheWebAssembly;
  const positive = new classes.MhfeRepair({
    workerSource: "public synthetic worker",
    wasm: new Uint8Array(wasm),
  });
  const complete = await positive.startupCheck();
  assert.equal(complete.passed, true);
  const library = complete.components.filter(
    ({ id }) => !["browser-features", "package-parts", "page-encoding"].includes(id),
  );
  assert.ok(library.length > 0);
  const ids = library.map(({ id }) => id);
  assert.deepEqual(await positive.inspectContainer({ container: "" }), operationResult);
  rows.push({ case: "complete actual published check", passed: true, libraryParts: ids });

  for (const [name, report] of [
    ["empty components without ids", { version: VERSION, components: [] }],
    ["empty components with all actual ids", { version: VERSION, components: [], ids }],
    [
      "first component with all actual ids",
      { version: VERSION, components: library.slice(0, 1), ids },
    ],
  ]) {
    StandInWorker.serveCheck = () => report;
    // A fresh byte array compiles to a distinct module: no known answer was cached for it.
    const owner = new classes.MhfeRepair({
      workerSource: "public synthetic worker",
      wasm: new Uint8Array(wasm),
    });
    const before = StandInWorker.started.length;
    let errorCode = null;
    let returned = false;
    try {
      await owner.inspectContainer({ container: "" });
      returned = true;
    } catch (error) {
      errorCode = error.code ?? error.name;
    }
    const requests = StandInWorker.started.slice(before).map(({ messages }) => messages[0]);
    const operationStarted = requests.some(({ operation }) => operation === "inspectContainer");
    assert.equal(requests.find(({ operation }) => operation === "selfCheck").skip.length, 0);
    const refusedBeforeOperation = !returned && !operationStarted;
    rows.push({ case: name, refusedBeforeOperation, returned, operationStarted, errorCode });
  }
} finally {
  globalThis.Worker = actual;
  StandInWorker.serveCheck = servedByTheWebAssembly;
  for (const worker of StandInWorker.started.slice(firstWorker)) worker.terminate();
}
console.log(JSON.stringify({ candidateOnly: true, rows }, null, 2));
assert.ok(
  rows.slice(1).every(({ refusedBeforeOperation }) => refusedBeforeOperation),
  "An incomplete fresh startup report must refuse before an actual operation starts",
);
