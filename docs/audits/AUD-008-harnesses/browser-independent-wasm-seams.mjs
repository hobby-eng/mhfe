// AUD-008: real WASM glue/callback cleanup, with no Argon2 computation or browser launch.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = (path) => readFileSync(path);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sourcePaths = [
  "web/client.js",
  "web/client.d.ts",
  "web/mhfe-worker.js",
  "web/argon2-engine.js",
  "src/wasm_api.rs",
  "src/engine/browser.rs",
  "src/feistel.rs",
  "scripts/build-wasm.sh",
  "scripts/build-argon2-wasm.sh",
  "scripts/remove-network-code.mjs",
  "scripts/verify-browser-package.mjs",
  "scripts/verify-browsers.mjs",
  "docs/BROWSER-PACKAGE.md",
  "SECURITY.md",
];
const artifactPaths = [
  "dist/client.js",
  "dist/mhfe-worker.js",
  "dist/argon2-mt.js",
  "dist/argon2-st.js",
  "dist/mhfe_core_bg.wasm",
  "target/wasm-bindgen/mhfe_core.js",
];
const sourceHashes = Object.fromEntries(sourcePaths.map((path) => [path, hash(read(path))]));
const artifactHashes = Object.fromEntries(artifactPaths.map((path) => [path, hash(read(path))]));
const snapshot = JSON.parse(read("docs/audits/AUD-008-evidence/snapshot.json").toString());
for (const path of sourcePaths) assert.equal(sourceHashes[path], snapshot.mhfe.files[path], path);
assert.equal(artifactHashes["dist/client.js"], sourceHashes["web/client.js"]);
assert.deepEqual(
  read("dist/mhfe-worker.js"),
  Buffer.concat([
    read("target/wasm-bindgen/mhfe_core.js"),
    read("web/argon2-engine.js"),
    read("web/mhfe-worker.js"),
  ]),
);

// Loading the assembled worker checks the shipped glue, not a hand-written binding substitute.
globalThis.self = { postMessage() {} };
vm.runInThisContext(read("dist/mhfe-worker.js").toString(), { filename: "dist/mhfe-worker.js" });
const core = vm.runInThisContext("wasm_bindgen");
const memory = core.initSync({ module: read("dist/mhfe_core_bg.wasm") }).memory;
assert.equal(JSON.parse(core.suiteParameters()).apiVersion, 7);

const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const publicPassword = new TextEncoder().encode("AUD008 independent public password marker 5742");
const publicKey = Uint8Array.from({ length: 32 }, (_, index) => (index * 37 + 19) & 255);
const observations = [];
const expectCode = (code, action) =>
  assert.throws(action, (error) => error.message.startsWith(`${code}: `));
const assertAbsent = (bytes, label) => {
  assert.equal(Buffer.from(memory.buffer).indexOf(Buffer.from(bytes)), -1, label);
};

// A failed engine call must unwind Rust owners even after writing its output view.
let failedViews;
const failedEngine = {
  derive(password, salt, memoryKib, passes, key) {
    assert.equal(password.buffer, memory.buffer);
    assert.equal(salt.buffer, memory.buffer);
    assert.equal(key.buffer, memory.buffer);
    assert.equal(memoryKib, 2097152);
    assert.equal(passes, 12);
    assert.deepEqual([...password], [...publicPassword]);
    key.set(publicKey);
    failedViews = { password, salt, key };
    throw new Error("synthetic independent engine failure");
  },
};
expectCode("ARGON2_FAILED", () =>
  core.encrypt(
    phrase,
    publicPassword,
    0,
    0,
    false,
    failedEngine,
    () => {},
    () => {},
  ),
);
assert.ok(
  failedViews.password.every((byte) => byte === 0),
  "normalized password view is wiped",
);
assertAbsent(publicPassword, "no input/normalized password marker remains in WASM memory");
assertAbsent(publicKey, "no written key marker remains in WASM memory");
observations.push({
  case: "engine failure after writing live output view",
  errorCode: "ARGON2_FAILED",
  passwordViewWiped: true,
  passwordMarkerAbsent: true,
  keyMarkerAbsent: true,
  limits: "Marker absence in this returned operation is not a general memory-erasure proof.",
});

// A real Rust on_unverified callback failure occurs after twelve rounds, before verification.
let calls = 0;
let latestPassword;
let unverifiedContainer;
const syntheticEngine = {
  derive(password, salt, memoryKib, passes, key) {
    assert.equal(password.buffer, memory.buffer);
    assert.equal(salt.length, 16);
    assert.equal(key.length, 32);
    assert.equal(memoryKib, 2097152);
    assert.equal(passes, 12);
    latestPassword = password;
    calls++;
    key.set(publicKey);
  },
};
expectCode("CANCELLED", () =>
  core.encrypt(
    phrase,
    publicPassword,
    0,
    0,
    false,
    syntheticEngine,
    () => {},
    (container) => {
      unverifiedContainer = container;
      throw new Error("synthetic independent unverified callback failure");
    },
  ),
);
assert.equal(calls, 12, "verification did not run after the callback failure");
assert.equal(unverifiedContainer.split(" ").length, 24);
assert.ok(latestPassword.every((byte) => byte === 0));
assertAbsent(publicPassword, "password marker absent after on_unverified failure");
assertAbsent(publicKey, "key marker absent after on_unverified failure");
observations.push({
  case: "on_unverified failure after twelve real Rust rounds with synthetic keys",
  errorCode: "CANCELLED",
  deriveCalls: calls,
  containerWords: 24,
  verificationStarted: false,
  passwordViewWiped: true,
  passwordMarkerAbsent: true,
  keyMarkerAbsent: true,
});

// Direct binding failures must happen before invoking an engine. The public client adds type
// checks; these cases check the Rust numeric and text guards beneath the generated bindings.
const forbiddenEngine = {
  derive() {
    throw new Error("engine should not be called");
  },
};
for (const [pim, memoryLevel, code] of [
  [NaN, 0, "INVALID_PIM"],
  [2 ** 32, 0, "INVALID_PIM"],
  [0, Infinity, "INVALID_MEMORY_LEVEL"],
  [0, 1, "MEMORY_LEVEL_NOT_SUPPORTED_HERE"],
]) {
  expectCode(code, () =>
    core.encrypt(
      phrase,
      publicPassword,
      pim,
      memoryLevel,
      false,
      forbiddenEngine,
      () => {},
      () => {},
    ),
  );
  assertAbsent(publicPassword, `password marker absent after ${code}`);
}
observations.push({ case: "direct WASM numeric guards", cases: 4, passwordMarkerAbsent: true });

console.log(
  JSON.stringify(
    {
      outcome: "passed",
      groups: observations.length,
      reviewedCommit: snapshot.mhfe.commit,
      sourceHashes,
      artifactHashes,
      observations,
      limits:
        "Real shipped WASM/core callback glue; synthetic engine only, no Argon2 computation, no browser or CSP execution. Does not establish cryptographic outputs or physical memory erasure.",
    },
    null,
    2,
  ),
);
