// AUD-008: classify the observed real-WASM key marker without running Argon2 or a browser.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const workerSource = readFileSync("dist/mhfe-worker.js", "utf8");
const coreBytes = readFileSync("dist/mhfe_core_bg.wasm");
const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const publicPassword = new TextEncoder().encode("AUD008 independent public password marker 5742");
const publicKey = Uint8Array.from({ length: 32 }, (_, index) => (index * 37 + 19) & 255);
const cases = [];

for (const mode of ["engine-error", "cancel-round-2", "cancel-unverified", "success"]) {
  // A fresh real core per case excludes residue from an earlier operation. The JS engine only
  // writes a public marker; this harness never instantiates either Argon2 module.
  const context = vm.createContext({
    TextEncoder,
    TextDecoder,
    WebAssembly,
    console,
    coreBytes,
    self: { postMessage() {} },
  });
  vm.runInContext(workerSource, context, { filename: "dist/mhfe-worker.js" });
  const core = vm.runInContext("wasm_bindgen", context);
  const exports = vm.runInContext("wasm_bindgen.initSync({module:coreBytes})", context);
  const memory = exports.memory;
  const stackBefore = exports.__wbindgen_add_to_stack_pointer(0);
  const heapProbe = exports.__wbindgen_export(1, 1);
  exports.__wbindgen_export4(heapProbe, 1, 1);
  const markerOffsets = (bytes) => {
    const buffer = Buffer.from(memory.buffer);
    const marker = Buffer.from(bytes);
    const offsets = [];
    for (
      let offset = buffer.indexOf(marker);
      offset !== -1;
      offset = buffer.indexOf(marker, offset + 1)
    ) {
      offsets.push(offset);
    }
    return offsets;
  };
  assert.deepEqual(markerOffsets(publicKey), []);
  let calls = 0;
  let latestPassword;
  let latestKey;
  const pointers = [];
  const engine = {
    derive(password, salt, memoryKib, passes, key) {
      assert.equal(password.buffer, memory.buffer);
      assert.equal(salt.buffer, memory.buffer);
      assert.equal(key.buffer, memory.buffer);
      assert.equal(memoryKib, 2097152);
      assert.equal(passes, 12);
      calls++;
      latestPassword = password;
      latestKey = key;
      pointers.push({ password: password.byteOffset, salt: salt.byteOffset, key: key.byteOffset });
      key.set(publicKey);
      if (mode === "engine-error") throw new Error("synthetic independent engine failure");
    },
  };
  const action = () =>
    core.encrypt(
      phrase,
      publicPassword,
      0,
      0,
      false,
      engine,
      (round) => {
        if (mode === "cancel-round-2" && round === 2) throw new Error("stop");
      },
      () => {
        if (mode === "cancel-unverified") throw new Error("stop");
      },
    );
  if (mode === "success") {
    const result = JSON.parse(action());
    assert.equal(result.container.split(" ").length, 24);
    assert.equal(result.suiteId, "MHFE-BIP39-256-EXPERIMENTAL-3");
  } else {
    const code = mode === "engine-error" ? "ARGON2_FAILED" : "CANCELLED";
    assert.throws(action, (error) => error.message.startsWith(`${code}: `));
  }
  const stackAfter = exports.__wbindgen_add_to_stack_pointer(0);
  assert.equal(stackAfter, stackBefore);
  assert.ok(latestPassword.every((byte) => byte === 0));
  assert.deepEqual(markerOffsets(publicPassword), []);
  const keyOffsets = markerOffsets(publicKey);
  if (mode === "engine-error") assert.deepEqual(keyOffsets, []);
  else assert.ok(keyOffsets.length > 0, "retain the observed residual as evidence");
  cases.push({
    mode,
    deriveCalls: calls,
    stackBefore,
    stackAfter,
    sampledHeapAllocation: heapProbe,
    keyOffsets,
    keyOffsetsBelowRestoredStackPointer: keyOffsets.every((offset) => offset < stackAfter),
    latestKeyViewOffset: latestKey.byteOffset,
    latestKeyViewAllZero: latestKey.every((byte) => byte === 0),
    latestKeyViewContainsExactMarker: Buffer.from(latestKey).equals(Buffer.from(publicKey)),
    latestPasswordViewAllZero: true,
    passwordMarkerAbsent: true,
    pointerSamples: [pointers[0], pointers.at(-1)],
  });
}
console.log(
  JSON.stringify(
    {
      outcome: "observed documented compiler-copy limitation",
      artifactHashes: {
        "dist/mhfe-worker.js": hash(Buffer.from(workerSource)),
        "dist/mhfe_core_bg.wasm": hash(coreBytes),
      },
      cases,
      interpretation:
        "The callback key view wipes when derive throws before RoundValues returns. After derive returns successfully, that original view and another inactive stack location can retain the key pattern below the restored stack pointer. This is consistent with compiled RoundValues moves; it does not establish a missed Drop of the final source owner. The production client terminates the entire operation worker on result/error/cancel. Arbitrary memory-disclosure and physical erasure were not tested.",
    },
    null,
    2,
  ),
);
