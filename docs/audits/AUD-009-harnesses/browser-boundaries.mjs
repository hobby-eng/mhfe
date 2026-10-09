import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const runtimeUrl =
  "data:text/javascript;base64," +
  Buffer.from(readFileSync("web/runtime.js", "utf8")).toString("base64");
async function loadClass(path) {
  const source = readFileSync(path, "utf8").replaceAll(
    '"../runtime/runtime.js"',
    JSON.stringify(runtimeUrl),
  );
  return import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
}
const { MhfeWallet } = await loadClass("web/wallet.js");
const { MhfePasswords } = await loadClass("web/passwords.js");
const { WorkerJob, CompiledModule } = await import(runtimeUrl);
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const tick = () => new Promise((resolve) => setImmediate(resolve));
const unhandled = [];
const onUnhandled = (error) => unhandled.push(error.message);
process.on("unhandledRejection", onUnhandled);
const originalWorker = globalThis.Worker;
let fakeWorker;
globalThis.Worker = class {
  constructor() {
    fakeWorker = this;
  }
  postMessage() {}
  terminate() {
    this.terminated = true;
  }
};
try {
  const wallet = new MhfeWallet({ workerSource: "synthetic", wasm });
  let settled = false;
  const drawing = wallet
    .drawPhrase({
      onProgress: async () => {
        throw new Error("synthetic callback failure");
      },
    })
    .then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
  await tick();
  fakeWorker.onmessage({ data: { type: "draws", value: 1 } });
  await tick();
  assert.ok(unhandled.includes("synthetic callback failure"));
  assert.equal(settled, false);
  assert.notEqual(fakeWorker.terminated, true);
  wallet.cancel();
  await drawing;
  console.log("REPRODUCED API002: async callback failure does not stop drawing");

  const originalCreateObjectURL = URL.createObjectURL;
  const bytes = Uint8Array.of(17, 23);
  const job = new WorkerJob(["synthetic"]);
  let startupSettled = false;
  try {
    URL.createObjectURL = () => {
      throw new Error("synthetic Blob URL refusal");
    };
    job.run({ password: bytes }, [], new CompiledModule(wasm, "wasm")).then(
      () => {
        startupSettled = true;
      },
      () => {
        startupSettled = true;
      },
    );
    await tick();
    assert.ok(unhandled.includes("synthetic Blob URL refusal"));
    assert.equal(startupSettled, false);
    assert.equal(job.ended, false);
    assert.deepEqual([...bytes], [17, 23]);
    console.log("REPRODUCED API001: Blob URL failure strands promise and secret bytes");
  } finally {
    URL.createObjectURL = originalCreateObjectURL;
    job.stop(new Error("synthetic probe cleanup"));
    bytes.fill(0);
  }

  const originalEncode = TextEncoder.prototype.encode;
  const encoded = [];
  TextEncoder.prototype.encode = function (text) {
    const result = originalEncode.call(this, text);
    encoded.push(result);
    return result;
  };
  try {
    const passwords = new MhfePasswords({ workerSource: "synthetic", wasm });
    await assert.rejects(
      passwords.review({
        password: "synthetic-test",
        passwordRepeat: 23,
      }),
      TypeError,
    );
    assert.ok(encoded.at(-1).some((byte) => byte !== 0));
    await assert.rejects(
      wallet.drawPhrase({
        passphrase: "synthetic-test",
        passphraseRepeat: 23,
        walletCheck: false,
      }),
      TypeError,
    );
    assert.ok(encoded.at(-1).some((byte) => byte !== 0));
    console.log("REPRODUCED SEC001: invalid repetition leaves first copy unwiped");
  } finally {
    TextEncoder.prototype.encode = originalEncode;
    for (const buffer of encoded) buffer.fill(0);
  }

  for (const path of ["passwords", "repair", "wallet"]) {
    const module = await loadClass("web/" + path + ".js");
    assert.equal(module.MhfeError, undefined);
    if (path === "wallet") assert.equal(module.MhfeCancelledError, undefined);
  }
  console.log("REPRODUCED API003: declared error value exports are absent");
} finally {
  globalThis.Worker = originalWorker;
  process.removeListener("unhandledRejection", onUnhandled);
}
