import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const startedAt = new Date().toISOString();
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const runtimeSource = readFileSync("web/runtime.js", "utf8");
const runtimeUrl = "data:text/javascript;base64," + Buffer.from(runtimeSource).toString("base64");
const runtime = await import(runtimeUrl);
const walletSource = readFileSync("web/wallet.js", "utf8");
const adapted = walletSource.replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl));
const { MhfeWallet } = await import(
  "data:text/javascript;base64," + Buffer.from(adapted).toString("base64")
);
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const originals = {
  ready: runtime.PackageCheck.prototype.require,
  start: runtime.ModuleWorker.prototype.start,
  encode: TextEncoder.prototype.encode,
  bytes: globalThis.Uint8Array,
  slice: Uint8Array.prototype.slice,
  array: globalThis.Array,
};
const fault = new Error("AUD013 synthetic allocation refusal");
const secret = "AUD013 public synthetic draw passphrase";
const results = [];
const lines = [];
const emit = (line) => {
  lines.push(line);
  console.log(line);
};

// Isolate unchanged public preparation from startup cryptography and browser scheduling.
runtime.PackageCheck.prototype.require = async () => {};
try {
  for (const scenario of [
    "invalid-worker-count",
    "repeat-encoding",
    "initial-empty-array",
    "draw-count-array",
    "first-worker-copy",
    "second-worker-repeat-copy",
    "second-worker-start",
  ]) {
    const copies = [];
    const jobs = [];
    let encodingCount = 0;
    let sliceCount = 0;
    let startCount = 0;
    let injecting = true;
    const wallet = new MhfeWallet({ workerSource: "AUD013 synthetic worker", wasm });
    TextEncoder.prototype.encode = function (text) {
      if (text === secret) {
        encodingCount += 1;
        if (injecting && scenario === "repeat-encoding" && encodingCount === 2) throw fault;
      }
      const bytes = originals.encode.call(this, text);
      if (text === secret) copies.push(bytes);
      return bytes;
    };
    globalThis.Uint8Array = new Proxy(originals.bytes, {
      construct(target, argumentsList, newTarget) {
        if (injecting && scenario === "initial-empty-array" && argumentsList[0] === 0) {
          throw fault;
        }
        return Reflect.construct(target, argumentsList, newTarget);
      },
    });
    globalThis.Array = new Proxy(originals.array, {
      construct(target, argumentsList, newTarget) {
        if (injecting && scenario === "draw-count-array" && argumentsList[0] === 2) throw fault;
        return Reflect.construct(target, argumentsList, newTarget);
      },
    });
    originals.bytes.prototype.slice = function (...args) {
      sliceCount += 1;
      if (
        injecting &&
        ((scenario === "first-worker-copy" && sliceCount === 1) ||
          (scenario === "second-worker-repeat-copy" && sliceCount === 4))
      ) {
        throw fault;
      }
      const bytes = originals.slice.apply(this, args);
      copies.push(bytes);
      return bytes;
    };
    runtime.ModuleWorker.prototype.start = function (message) {
      startCount += 1;
      if (injecting && scenario === "second-worker-start" && startCount === 2) throw fault;
      const job = {
        stopped: false,
        stop() {
          this.stopped = true;
          runtime.wipeSecrets(message);
        },
      };
      jobs.push(job);
      return {
        job,
        done: injecting
          ? new Promise(() => {})
          : Promise.resolve({ phrase: "AUD013 public synthetic result", words: 24 }),
      };
    };
    const options = {
      passphrase: secret,
      passphraseRepeat: secret,
      walletCheck: true,
      workers: scenario === "invalid-worker-count" ? 2 ** 32 : 2,
    };
    await assert.rejects(wallet.drawPhrase(options));
    const unwipedCopies = copies.filter((bytes) => bytes.some((byte) => byte !== 0)).length;
    assert.ok(
      jobs.every(({ stopped }) => stopped),
      `${scenario}: a partially started job survived`,
    );
    if (scenario !== "initial-empty-array") {
      assert.equal(unwipedCopies, 0, `${scenario}: guard control left an owned copy unwiped`);
    }
    if (scenario === "invalid-worker-count") assert.equal(copies.length, 0);
    const observedCopies = copies.length;
    injecting = false;
    const after = await wallet.drawPhrase();
    assert.equal(after.workers, 1, `${scenario}: the operation slot remained occupied`);
    results.push({ scenario, observedCopies, unwipedCopies, slotReusable: true });
    emit(
      `${unwipedCopies > 0 ? "REPRODUCED" : "PASS"}: ${scenario}; ` +
        `unwiped owned copies=${unwipedCopies}; stopped partial jobs; slot reusable`,
    );
    for (const bytes of copies) bytes.fill(0);
    wallet.cancel();
    globalThis.Uint8Array = originals.bytes;
    globalThis.Array = originals.array;
    originals.bytes.prototype.slice = originals.slice;
  }
} finally {
  runtime.PackageCheck.prototype.require = originals.ready;
  runtime.ModuleWorker.prototype.start = originals.start;
  TextEncoder.prototype.encode = originals.encode;
  globalThis.Uint8Array = originals.bytes;
  globalThis.Array = originals.array;
  originals.bytes.prototype.slice = originals.slice;
}

emit(
  JSON.stringify({
    node: process.version,
    walletSourceSha256: hash(walletSource),
    runtimeSourceSha256: hash(runtimeSource),
    results,
    limitation:
      "Synthetic bounded constructor/copy/start faults; no real OOM, browser memory exposure or egress demonstrated",
  }),
);
process.exitCode = results.some(({ unwipedCopies }) => unwipedCopies > 0) ? 1 : 0;
if (process.argv.includes("--evidence")) {
  const directory = "docs/audits/AUD-013-evidence";
  const label = "browser-draw-setup-corrected";
  const output = lines.join("\n") + "\n";
  mkdirSync(directory, { recursive: true });
  writeFileSync(`${directory}/${label}.log`, output);
  writeFileSync(
    `${directory}/${label}.command.json`,
    JSON.stringify(
      {
        command: [process.execPath, ...process.argv.slice(1)],
        cwd: process.cwd(),
        startedAt,
        endedAt: new Date().toISOString(),
        exitCode: process.exitCode,
        signal: null,
        failure: null,
        logSha256: hash(output),
        capture: "Harness-owned diagnostic stdout",
      },
      null,
      2,
    ) + "\n",
  );
}
