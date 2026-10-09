import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const runtimeUrl = "data:text/javascript;base64," + Buffer.from(
  readFileSync("web/runtime.js", "utf8"),
).toString("base64");
const runtime = await import(runtimeUrl);
// Isolate request encoding from startup cryptography. The public class and its session run unchanged.
runtime.PackageCheck.prototype.require = async () => {};
async function loadClass(path) {
  const source = readFileSync(path, "utf8").replaceAll(
    '"../runtime/runtime.js"', JSON.stringify(runtimeUrl),
  );
  return import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
}
const { MhfeClient } = await loadClass("web/client.js");
const originalWorker = globalThis.Worker;
let worker;
globalThis.Worker = class {
  constructor() { worker = this; }
  postMessage() {}
  terminate() {}
};
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const client = new MhfeClient({
  workerSource: "synthetic", wasm,
  argon2Threaded: "synthetic", argon2SingleThreaded: "synthetic",
});
const encode = TextEncoder.prototype.encode;
let owned;
try {
  const opening = client.openHiddenWallets({ container: "synthetic", mainPassphrase: "" });
  await new Promise((resolve) => setImmediate(resolve));
  worker.onmessage({ data: { type: "ready", buildId: "development" } });
  worker.onmessage({ data: { type: "ask", question: "ready", value: null } });
  const session = await opening;
  TextEncoder.prototype.encode = function (text) {
    const bytes = encode.call(this, text);
    if (text === "synthetic-test") owned = bytes;
    return bytes;
  };
  await assert.rejects(
    session.open({ password: "synthetic-test", passwordRepeat: "\uD800" }),
    { code: "INVALID_PASSWORD_TEXT" },
  );
  assert.ok(owned instanceof Uint8Array, "The first password was encoded before refusal");
  assert.ok(owned.every((byte) => byte === 0), "The first password copy was not wiped on refusal");
  console.log("PASS: hidden-session repetition refusal wipes the first password copy");
} finally {
  owned?.fill(0);
  TextEncoder.prototype.encode = encode;
  client.cancel();
  globalThis.Worker = originalWorker;
}
