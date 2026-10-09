import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const runtimeUrl = "data:text/javascript;base64," + Buffer.from(readFileSync("web/runtime.js", "utf8")).toString("base64");
const runtime = await import(runtimeUrl);
// This probe isolates request lifecycle from cryptography, which the coordinator checks separately.
runtime.PackageCheck.prototype.require = async () => {};
const source = readFileSync("web/client.js", "utf8").replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl));
const { MhfeClient } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const tick = () => new Promise((resolve) => setImmediate(resolve));
const originalWorker = globalThis.Worker;
const originalEncode = TextEncoder.prototype.encode;
let worker;
let failSend = false;
let failEncoding = false;
let copies = [];
globalThis.Worker = class {
  constructor() { worker = this; }
  postMessage(message, transfer) {
    if (message.type !== "answer") return;
    if (failSend) throw new Error("Synthetic send refusal");
    const received = structuredClone(message, { transfer });
    if (received.value.close) {
      this.emit({ type: "result", result: { closed: true } });
    } else {
      this.emit({ type: "ask", question: "opened", value: { words: 24 } });
    }
    runtime.wipeSecrets(received);
  }
  emit(data) { this.onmessage({ data }); }
  terminate() {}
};
TextEncoder.prototype.encode = function (text) {
  if (failEncoding && text === "synthetic-repeat") throw new Error("Synthetic allocation refusal");
  const bytes = originalEncode.call(this, text);
  if (text === "synthetic-password" || text === "synthetic-repeat") copies.push(bytes);
  return bytes;
};
async function session() {
  const client = new MhfeClient({ workerSource: "synthetic", wasm, argon2Threaded: "synthetic", argon2SingleThreaded: "synthetic" });
  const pending = client.openHiddenWallets({ container: "synthetic", mainPassphrase: "" });
  await tick();
  worker.emit({ type: "ready", buildId: "development" });
  worker.emit({ type: "ask", question: "ready", value: null });
  return { client, handle: await pending };
}
try {
  for (const allocation of [false, true]) {
    const { client, handle } = await session();
    copies = [];
    failEncoding = allocation;
    try {
      await assert.rejects(handle.open({ password: "synthetic-password", passwordRepeat: allocation ? "synthetic-repeat" : "\uD800" }));
      assert.equal(copies.length, 1);
      assert.ok(copies[0].every((byte) => byte === 0));
      console.log(`PASS: repetition ${allocation ? "allocation" : "surrogate"} refusal wipes the first copy`);
    } finally { failEncoding = false; client.cancel(); }
  }
  {
    const { client, handle } = await session();
    copies = [];
    failSend = true;
    try {
      await assert.rejects(handle.open({ password: "synthetic-password", passwordRepeat: "synthetic-password" }), { code: "WORKER_FAILED" });
      assert.equal(copies.length, 2);
      assert.ok(copies.every((bytes) => bytes.every((byte) => byte === 0)));
      console.log("PASS: send refusal wipes both package copies");
    } finally { failSend = false; client.cancel(); }
  }
  for (const caller of [new Uint8Array([11, 22, 33]), Buffer.from([11, 22, 33])]) {
    const { client, handle } = await session();
    try {
      await assert.rejects(handle.open({ password: caller, passwordRepeat: "\uD800" }), { code: "INVALID_PASSWORD_TEXT" });
      assert.deepEqual([...caller], [11, 22, 33]);
      console.log(`PASS: ${caller.constructor.name} caller buffer survives repetition refusal`);
      await handle.open({ password: caller, passwordRepeat: caller });
      assert.deepEqual([...caller], [11, 22, 33]);
      console.log(`PASS: ${caller.constructor.name} caller buffer survives successful transfer`);
      await handle.close();
    } finally { client.cancel(); }
  }
  console.log("PASS: all seven lifecycle cases");
} finally {
  for (const bytes of copies) if (bytes.byteLength > 0) bytes.fill(0);
  TextEncoder.prototype.encode = originalEncode;
  globalThis.Worker = originalWorker;
}
