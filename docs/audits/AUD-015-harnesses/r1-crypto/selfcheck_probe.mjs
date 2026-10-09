// AUD-015 R1: the core module's own self-check in the built package, full tier, in Node.js.
//
//   node selfcheck_probe.mjs
//
// Run from the repository root. The full tier replays all 27 published suite 3 and suite 4
// transcripts with their recorded round keys (no Argon2 at the suite's cost), the 63 suite 4
// refusals and the other parts; Argon2's own known answer runs at 1 MiB through the package's
// single-threaded Emscripten build. This is the implementation checking itself, complementary to
// oracle.py, which replays the same transcripts independently. Exits non-zero unless every part
// passes.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const read = (path) => readFileSync(path);
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const core = vm.runInThisContext("mhfe");
core.initSync({ module: read("dist/runtime/mhfe.wasm") });
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");
const engine = argon2Engine(await require("../../../../dist/core/argon2-st.js")());
const allowed = { derive: (password, salt, memoryKib, passes, key) => {
  assert.equal(`${memoryKib}/${passes}`, "1024/1", "only the 1 MiB known answer may run");
  engine.derive(password, salt, memoryKib, passes, key);
}, reserve: () => {} };
const report = JSON.parse(core.selfCheckCore("full", [], allowed, () => {}, () => {}));
for (const part of report.components) {
  console.log(`${part.id}: ${part.outcome} ${part.detail ?? ""}`);
}
console.log(`tier ${report.tier}, passed: ${report.passed}`);
assert.ok(report.components.length > 0);
assert.equal(report.passed, true);
