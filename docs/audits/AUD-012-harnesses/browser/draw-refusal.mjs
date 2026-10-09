import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const runtimeUrl = "data:text/javascript;base64," + Buffer.from(readFileSync("web/runtime.js", "utf8")).toString("base64");
const runtime = await import(runtimeUrl);
// Isolate public request preparation from startup cryptography; the draw method runs unchanged.
runtime.PackageCheck.prototype.require = async () => {};
const source = readFileSync("web/wallet.js", "utf8").replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl));
const { MhfeWallet } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const wallet = new MhfeWallet({ workerSource: "synthetic", wasm });
const originalEncode = TextEncoder.prototype.encode;
const copies = [];
TextEncoder.prototype.encode = function (text) {
  const bytes = originalEncode.call(this, text);
  if (text === "synthetic-password") copies.push(bytes);
  return bytes;
};
try {
  // 2^32 cannot be an Array length: this throws immediately without a large allocation.
  await assert.rejects(wallet.drawPhrase({
    passphrase: "synthetic-password", passphraseRepeat: "synthetic-password",
    walletCheck: true, workers: 2 ** 32,
  }));
  assert.equal(copies.length, 2, "Both package-owned passphrase copies must be observed");
  assert.ok(copies.every((bytes) => bytes.every((byte) => byte === 0)), "A refused drawing left package-owned passphrase copies unwiped");
  console.log("PASS: drawing setup refusal leaves no unwiped passphrase copy");
} finally {
  TextEncoder.prototype.encode = originalEncode;
  for (const bytes of copies) bytes.fill(0);
  wallet.cancel();
}
