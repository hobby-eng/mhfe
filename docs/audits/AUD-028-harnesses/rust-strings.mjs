import assert from "node:assert/strict";
import vm from "node:vm";
import { rustStrings } from "../../../scripts/rust-strings.mjs";

const cases = [
  ['const X: &str = "one";', ["one"]],
  ['/* " */', []],
  ['const X: &str = r#"a"b"#;', ['a"b']],
  ["const X: char = '\"';", []],
];
const failures = [];
for (const [source, expected] of cases) {
  try {
    const result = vm.runInNewContext(
      `(${rustStrings.toString()})(source)`,
      { source },
      { timeout: 100 },
    );
    assert.deepEqual(Array.from(result), expected);
  } catch (error) {
    failures.push({ source, diagnostic: String(error) });
  }
}
console.log(JSON.stringify({ cases: cases.length, failures }, null, 2));
assert.equal(failures.length, 0, "Rust literal extraction must finish correctly");
