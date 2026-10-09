import assert from "node:assert/strict";
import { resolveObjectURL } from "node:buffer";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import vm from "node:vm";

// Public synthetic bytes only. A long marker avoids dlmalloc's free-list header obscuring it.
const workerSource = readFileSync("dist/runtime/worker.js", "utf8");
const wasmBytes = readFileSync("dist/runtime/mhfe.wasm");
const compiled = new WebAssembly.Module(wasmBytes);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const valid = (tag) => new TextEncoder().encode(`AUD013-${tag}-synthetic-public-`.repeat(12));
const invalid = (tag) => Uint8Array.of(0xff, ...valid(tag));
const pattern = (bytes) => bytes.slice(24, 80);
const results = [];
const startedAt = new Date().toISOString();
const lines = [];
const emit = (line) => {
  lines.push(line);
  console.log(line);
};

function countPattern(memory, expected) {
  const bytes = new Uint8Array(memory.buffer);
  let count = 0;
  for (let i = 0; i <= bytes.length - expected.length; i += 1) {
    if (bytes[i] !== expected[0]) continue;
    if (expected.every((byte, offset) => bytes[i + offset] === byte)) count += 1;
  }
  return count;
}

function environment(source = workerSource, postMessage = () => {}) {
  const context = vm.createContext({
    WebAssembly,
    Uint8Array,
    TextEncoder,
    TextDecoder,
    crypto: globalThis.crypto,
    console,
    self: { crypto: globalThis.crypto, postMessage },
    auditCompiled: compiled,
  });
  vm.runInContext(source, context, { filename: "dist/runtime/worker.js" });
  const bindings = vm.runInContext("mhfe", context);
  const memory = vm.runInContext("mhfe.initSync({ module: auditCompiled }).memory", context);
  return { context, bindings, memory };
}

function directCase(name, action, first, repeat, expectedResidual) {
  const { bindings, memory } = environment();
  const firstBefore = first.slice();
  const repeatBefore = repeat.slice();
  assert.equal(countPattern(memory, pattern(repeat)), 0, "Marker was already in fresh WASM");
  assert.throws(() => action(bindings, first, repeat), /INVALID_(?:PASSPHRASE|PASSWORD_UTF8):/u);
  assert.deepEqual(first, firstBefore, "The binding modified caller-owned first bytes");
  assert.deepEqual(repeat, repeatBefore, "The binding modified caller-owned repeat bytes");
  const residuals = countPattern(memory, pattern(repeat));
  if (!expectedResidual) assert.equal(residuals, 0, `${name}: cleanup control failed`);
  results.push({ name, expectedHealthyResiduals: 0, residuals, callerBytesPreserved: true });
  emit(`${residuals > 0 ? "REPRODUCED" : "PASS"}: ${name}; WASM marker copies=${residuals}`);
}

directCase(
  "draw-invalid-first-valid-repeat",
  (bindings, first, repeat) => bindings.drawPhrase(first, repeat, false, { fill() {} }, () => {}),
  invalid("direct-first"),
  valid("direct-repeat"),
  true,
);
directCase(
  "draw-valid-first-invalid-repeat-control",
  (bindings, first, repeat) => bindings.drawPhrase(first, repeat, false, { fill() {} }, () => {}),
  valid("control-first"),
  invalid("control-repeat"),
  false,
);
directCase(
  "review-invalid-first-valid-repeat-control",
  (bindings, first, repeat) => bindings.reviewPassword(first, repeat, true),
  invalid("review-first"),
  valid("review-repeat"),
  false,
);

// Execute the unchanged public class and real worker source in bounded VM workers. This isolates
// request transfer/cleanup from browser scheduling; it is not a real-browser acceptance run.
const realWorker = globalThis.Worker;
const workers = [];
globalThis.Worker = class {
  constructor(url) {
    this.terminated = false;
    this.messages = [];
    this.loaded = resolveObjectURL(url)
      .text()
      .then((source) => {
        this.worker = environment(source, (reply) => {
          queueMicrotask(() => {
            if (!this.terminated) this.onmessage?.({ data: reply });
          });
        });
      });
    workers.push(this);
  }

  postMessage(message, transfer = []) {
    const request = structuredClone(message, { transfer });
    this.messages.push(request);
    this.loaded
      .then(() => this.worker.context.self.onmessage({ data: request }))
      .catch((error) => this.onerror?.({ message: error.message, preventDefault() {} }));
  }

  terminate() {
    // Retain only for this diagnostic memory inspection. The production runtime calls terminate.
    this.terminated = true;
  }
};

try {
  const { MhfeWallet } = await import("../../../../dist/wallet/wallet.js");
  const wallet = new MhfeWallet({ workerSource, wasm: compiled });
  const startup = await wallet.startupCheck();
  assert.equal(startup.passed, true, "The public class startup check failed");
  const caller = invalid("public-equal-repeat");
  const callerBefore = caller.slice();
  const pending = wallet.drawPhrase({
    passphrase: caller,
    passphraseRepeat: caller,
    walletCheck: false,
  });
  await assert.rejects(pending, { code: "INVALID_PASSPHRASE" });
  await new Promise((resolve) => setImmediate(resolve));
  const drawWorker = workers.find((worker) =>
    worker.messages.some((message) => message.operation === "drawPhrase"),
  );
  assert.ok(drawWorker, "The public class refused the bytes before the worker");
  const request = drawWorker.messages.find((message) => message.operation === "drawPhrase");
  assert.ok(
    request.passphrase.every((byte) => byte === 0),
    "Worker JS first bytes were not wiped",
  );
  assert.ok(
    request.passphraseRepeat.every((byte) => byte === 0),
    "Worker JS repeat bytes were not wiped",
  );
  assert.deepEqual(caller, callerBefore, "The public class changed caller-owned bytes");
  assert.equal(
    drawWorker.terminated,
    true,
    "The public class did not terminate the refused worker",
  );
  const residuals = countPattern(drawWorker.worker.memory, pattern(caller));
  results.push({
    name: "public-draw-identical-invalid-bytes",
    startupPassed: true,
    expectedHealthyResiduals: 0,
    residuals,
    workerJsCopiesWiped: true,
    callerBytesPreserved: true,
    workerTerminated: true,
  });
  emit(
    `${residuals > 0 ? "REPRODUCED" : "PASS"}: public draw identical malformed bytes; ` +
      `WASM marker copies=${residuals}; ` +
      "worker JS wiped; caller preserved; refused worker terminated",
  );
} finally {
  globalThis.Worker = realWorker;
}

emit(
  JSON.stringify({
    node: process.version,
    wasmSha256: hash(wasmBytes),
    workerSha256: hash(workerSource),
    walletSourceSha256: hash(readFileSync("web/wallet.js")),
    walletBindingSha256: hash(readFileSync("src/wasm_api/wallet.rs")),
    results,
    limitation:
      "VM diagnostic retains terminated memory; no browser/OS erasure or disclosure claim",
  }),
);
// This regression harness fails while the demonstrated cleanup defect remains.
process.exitCode = results.some(({ residuals }) => residuals > 0) ? 1 : 0;
if (process.argv.includes("--evidence")) {
  const directory = "docs/audits/AUD-013-evidence";
  const label = "browser-draw-utf8-direct";
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
        capture: "Harness-owned diagnostic stdout; Node's module-type warning is in tool output",
      },
      null,
      2,
    ) + "\n",
  );
}
