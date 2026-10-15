// Static CORE review inventory and bounded witnesses; no production operation is executed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { rustProductionLines } from "../../../scripts/rust-code.mjs";

const root = new URL("../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const args = process.argv.slice(2);
if (args.length !== 1 || !["--inventory", "--self-test", "--check"].includes(args[0])) {
  console.error("usage: node docs/audits/AUD-025-harnesses/core-review.mjs --inventory|--self-test|--check");
  process.exit(2);
}

/** Public surface candidates; macros and documented exceptions still need manual review. */
function surface(source) {
  const lines = rustProductionLines(source.split("\n"));
  return {
    functions: lines.flatMap(([line, text]) => {
      const found = /^pub (?:const |async )?fn (\w+)/u.exec(text);
      return found ? [{ line, name: found[1] }] : [];
    }),
    fields: lines.flatMap(([line, text]) => {
      const found = /^\s+pub (\w+)\s*:/u.exec(text);
      return found ? [{ line, name: found[1] }] : [];
    }),
  };
}

/** Isolate the actual internal error definition, without evaluating the worker's operation table. */
function startupError(source) {
  const begin = source.indexOf("class Argon2StartError extends Error");
  const end = source.indexOf("\n}\n", begin);
  assert.ok(begin !== -1 && end > begin, "the actual startup error definition must be located");
  return vm.runInNewContext(
    source.slice(begin, end + 3) +
      '; const error = new Argon2StartError("threaded", "startFailed");' +
      '({ name: error.name, hasCode: "code" in error, code: error.code, message: error.message });',
  );
}

if (args[0] === "--self-test") {
  assert.equal(surface("pub fn raw() {}\n").functions.length, 1);
  assert.equal(surface("impl Owner {\n    pub fn owned() {}\n}\n").functions.length, 0);
  assert.equal(surface("pub struct Value {\n    pub data: usize,\n}\n").fields.length, 1);
  assert.equal(surface("pub struct Value {\n    data: usize,\n}\n").fields.length, 0);
  assert.equal(surface("#[cfg(test)]\nmod tests {\n pub fn fake() {}\n}\n").functions.length, 0);
  const definition = (code) =>
    "class Argon2StartError extends Error {\n constructor() {\n super();\n" + code + "\n }\n}\n";
  assert.equal(startupError(definition("this.code = 'INTERNAL_ERROR';")).hasCode, true);
  assert.equal(startupError(definition("this.message = 'INTERNAL_ERROR';")).hasCode, false);
  console.log("CORE inventory/witness positive and negative controls passed.");
} else if (args[0] === "--inventory") {
  const paths = execFileSync(
    "git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "src"],
    { cwd: root, encoding: "utf8" },
  ).split("\0").filter((path) => path.endsWith(".rs") && !path.startsWith("src/bin/"));
  const records = [...new Set(paths)].map((path) => ({ path, ...surface(read(path)) }));
  console.log(JSON.stringify(records, null, 2));
} else {
  let failed = 0;
  for (const path of ["src/repair.rs", "src/suite.rs", "src/word_hints.rs", "src/word_wishes.rs"]) {
    const fields = surface(read(path)).fields;
    if (fields.length > 0) {
      console.log(`CORE-02 ${path}: public writable fields remain: ${fields.map((x) => x.name).join(", ")}`);
      failed += 1;
    }
  }
  if (surface(read("src/check_word.rs")).functions.some((x) => x.name === "check_index")) {
    console.log("CORE-03 AUD-024-ARC023: check_index remains a public free calculation.");
    failed += 1;
  }
  const error = startupError(read("web/core-worker.js"));
  console.log(JSON.stringify({ actualStartupError: error }));
  if (!error.hasCode) {
    console.log("TS-06/CORE-23: Argon2StartError has a code prefix in message but no code property.");
    failed += 1;
  }
  process.exitCode = failed > 0 ? 1 : 0;
}
