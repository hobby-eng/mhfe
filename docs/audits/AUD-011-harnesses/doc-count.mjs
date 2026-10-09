import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// This is a witness of the documented inventory, not an independent execution of self-tests.
const api = readFileSync("docs/API.md", "utf8");
const sets = readFileSync("src/self_check/sets.rs", "utf8");
const actual = Number(sets.match(/const NATIVE_IDS: \[&str; (\d+)\]/)?.[1]);
const documented = Number(api.match(/native\(random\)[\s\S]*?(\d+) parts/)?.[1]);
assert.ok(Number.isInteger(actual) && actual > 0, "Native test inventory was not found");
assert.ok(Number.isInteger(documented) && documented > 0, "Documented count was not found");
console.log(JSON.stringify({ documented, actual }));
assert.equal(documented, actual, "Documented native component count is stale");
