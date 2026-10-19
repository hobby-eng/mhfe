// AUD-026 raw WASM preflight probe. Public inputs; the external Argon2 fake never computes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import vm from "node:vm";

const root = resolve(process.argv[2] ?? ".");
vm.runInThisContext(readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8"));
const core = vm.runInThisContext("mhfe");
core.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
const bytes = (text) => new TextEncoder().encode(text);
const container = "abandon ".repeat(23) + "art";
const results = [];
for (const count of [0, 2, 3, 4, 6, 8]) {
  let engineCalls = 0;
  const engine = {
    derive() {
      engineCalls += 1;
      throw new Error("AUD026 external engine must not compute");
    },
    reserve() {
      throw new Error("AUD026 external engine must not reserve");
    },
  };
  const session = new core.RekeySession(
    container,
    12,
    bytes("old public password"),
    "",
    0,
    0,
    0,
    engine,
  );
  let accepted = false;
  let refusal = null;
  try {
    session.setNew(bytes("new public password"), bytes("new public password"), "", 0, 0, 0, count);
    accepted = true;
    if (count === 3) {
      try {
        session.recover("builtInCheck", "", "", "", bytes(""), false, () => {});
      } catch (error) {
        refusal = error.message;
      }
    }
  } catch (error) {
    refusal = error.message;
  } finally {
    session.free();
  }
  results.push({ repairWordCount: count, setNewAccepted: accepted, engineCalls, refusal });
}
console.log(JSON.stringify(results, null, 2));
assert(results.filter((row) => row.repairWordCount !== 3).every((row) => row.setNewAccepted));
const bad = results.find((row) => row.repairWordCount === 3);
process.exitCode = bad.setNewAccepted || bad.engineCalls !== 0 ? 1 : 0;
