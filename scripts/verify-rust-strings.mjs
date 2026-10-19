// Bound the actual public extractor in a worker: a broken scan cannot hang the fast gates.
import assert from "node:assert/strict";
import { isMainThread, parentPort, Worker } from "node:worker_threads";

import { scriptArguments } from "./gate-command-line.mjs";
import { rustStrings } from "./rust-strings.mjs";
import { RustSource } from "./rust-source.mjs";

const DEADLINE_MS = 2000;
// A broken literal loop is contained before its strings can exhaust the host's memory.
const WORKER_LIMITS = { maxOldGenerationSizeMb: 32, maxYoungGenerationSizeMb: 8, stackSizeMb: 2 };
// Literal expected text is independent of the extractor; null means a required refusal.
const cases = [
  ["empty", "", []],
  ["ordinary", 'const X: &str = "one";', ["one"]],
  ["block comment", '/* " */', []],
  ["raw interior quote", 'const X: &str = r#"a"b"#;', ['a"b']],
  ["character quote", "const X: char = '\"';", []],
  ["byte character quote", "const X: u8 = b'\"';", []],
  ["unicode character", "const X: char = '𐍈';", []],
  ["lifetimes", "fn f<'a>(x: &'a str) { let c = '\"'; let s = \"kept\"; }", ["kept"]],
  ["unicode escape", String.raw`"\u{1_F600_}"`, ["😀"]],
  ["escapes", String.raw`"\x41\r\n\t\0\\\'\""`, ["A\r\n\t\0\\'\""]],
  ["byte UTF-8", String.raw`b"Caf\xc3\xa9"`, ["Café"]],
  ["byte UTF-8 BOM", String.raw`b"\xef\xbb\xbfkeep"`, ["\ufeffkeep"]],
  ["C UTF-8 BOM", String.raw`c"\u{feff}keep"`, ["\ufeffkeep"]],
  ["raw byte", String.raw`br##"a\b"##`, [String.raw`a\b`]],
  ["C string", String.raw`c"Caf\u{e9}"`, ["Café"]],
  ["raw C string", String.raw`cr#"Café"#`, ["Café"]],
  ["CRLF normalization", '"first\r\nsecond"', ["first\nsecond"]],
  ["continuation", '"before\\\n \t after"', ["beforeafter"]],
  ["non-ASCII space", '"before\\\n \t\u00a0after"', ["before\u00a0after"]],
  ["line comment", '// "ignored"\n"kept"', ["kept"]],
  ["unterminated string", '"missing', null],
  ["escaped end", '"tail\\', null],
  ["unterminated raw", 'r##"missing"#', null],
  ["unterminated nested comment", "/* /* */", null],
  ["unknown escape", String.raw`"\q"`, null],
  ["surrogate", String.raw`"\u{d800}"`, null],
  ["oversized scalar", String.raw`"\u{110000}"`, null],
  ["bad hex", String.raw`"\xGG"`, null],
  ["non-ASCII str byte", String.raw`"\xff"`, null],
  ["byte unicode escape", String.raw`b"\u{41}"`, null],
  ["non-UTF-8 byte text", String.raw`b"\xff"`, null],
  ["non-UTF-8 C text", String.raw`c"\xff"`, null],
  ["C interior NUL", String.raw`c"\0"`, null],
  ["bare raw CR", 'r"a\rb"', null],
  ["too many raw hashes", "r" + "#".repeat(256) + '"body"' + "#".repeat(256), null],
];
// Every supported raw delimiter length, including quoted contents when a hash separates them.
for (let count = 0; count <= 255; count += 1) {
  const hashes = "#".repeat(count);
  const text = count === 0 ? String.raw`a\b` : 'a"b';
  cases.push([`raw delimiter ${count}`, `r${hashes}"${text}"${hashes}`, [text]]);
}
for (let depth = 1; depth <= 8; depth += 1) {
  cases.push([
    `nested comment ${depth}`,
    "/* ".repeat(depth) + '"ignored"' + " */".repeat(depth) + ' "kept"',
    ["kept"],
  ]);
}

if (!isMainThread) {
  const failed = [];
  for (const [label, source, expected] of cases) {
    try {
      if (expected === null) assert.throws(() => rustStrings(source));
      else {
        assert.deepEqual(rustStrings(source), expected);
        const reader = new RustSource(source);
        const code = reader.code();
        assert.equal(code.length, source.length, "code blanking retains UTF-16 offsets");
        assert.equal(code.split("\n").length, source.split("\n").length);
        let previous = 0;
        for (const span of reader.spans()) {
          assert.ok(span.from >= previous && span.end > span.from && span.end <= source.length);
          if (span.kind !== "lifetime") assert.equal(code.slice(span.from, span.end).trim(), "");
          previous = span.end;
        }
      }
    } catch {
      failed.push(label);
    }
    parentPort.postMessage({ completed: label });
  }
  parentPort.postMessage({ failed });
} else {
  scriptArguments("usage: node scripts/verify-rust-strings.mjs");
  const worker = new Worker(new URL(import.meta.url), { resourceLimits: WORKER_LIMITS });
  let completed = 0;
  let failures;
  try {
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        void worker.terminate();
        reject(new Error(`Rust literal scan exceeded its deadline after ${completed} cases.`));
      }, DEADLINE_MS);
      worker.on("message", (message) => {
        if (Object.hasOwn(message, "completed")) completed += 1;
        else failures = message.failed;
      });
      worker.once("error", reject);
      worker.once("exit", (code) => {
        clearTimeout(deadline);
        if (code === 0) resolve();
        else reject(new Error(`Rust literal worker exited ${code}.`));
      });
    });
    assert.equal(completed, cases.length);
    assert.deepEqual(failures, [], "actual extractor must match every literal/refusal oracle");
    console.log(`All ${completed} Rust literal controls passed within the worker deadline.`);
  } finally {
    await worker.terminate();
  }
}
