import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { rustProductionLines } from "../../../scripts/rust-code.mjs";

const source = readFileSync("scripts/verify-module-boundaries.mjs", "utf8");
const end = source.indexOf("/** Read only Git-visible library sources");
assert(end > 0, "read the actual graph/finding helpers before their CLI boundary");
const helpers = source.slice(0, end).replace(/^import .*;$/gmu, "");
const cases = [
  ["use crate::engine::Engine;", true],
  ["use super::engine::Engine;", true],
  ["use super::Engine;", true],
  ["fn call() { super::engine::run(); }", true],
  ["fn independent() {}", false],
];
const mismatches = [];
for (const [repair, expected] of cases) {
  const files = {
    "src/lib.rs": "mod repair; mod engine; pub use engine::Engine;",
    "src/engine.rs": "pub struct Engine; pub fn run() {}",
    "src/repair.rs": repair,
  };
  const result = vm.runInNewContext(`${helpers}\nfindings(files).failed`, {
    files,
    assert,
    rustProductionLines,
  });
  if (result.length > 0 !== expected) mismatches.push(repair);
}
console.log(JSON.stringify({ cases: cases.length, mismatches }));
assert.equal(mismatches.length, 0, "root-relative paths must enforce the same boundary");
