// ARC013/ARC014: independent modules own typed failures; arbitrary message payloads cannot be
// hidden by renaming a root error variant. Runtime code/message/privacy controls complement this
// structural check. This scans current sources, not the frozen AUD-024 baseline evidence.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { reported, runGate } from "./gate-command-line.mjs";
import { rustProductionLines, rustScopeDelta } from "./rust-code.mjs";
import { rustStrings } from "./rust-strings.mjs";

// Leaf operations must not import the aggregate of unrelated modules (RUST-04). High-level
// orchestration (rekey, rehearsal, search, operations) legitimately aggregates their errors.
const LEAVES = new Set([
  "password",
  "phrase",
  "repair",
  "wallet",
  "random",
  "engine",
  "suite",
  "new_password",
  "check_word",
  "eff",
  "self_check",
  "word_hints",
  "word_wishes",
  "wallet_check",
  "mhfe",
  "bip39_seed",
]);

/** The structural failures in one library file, with its original line numbers. */
function typedErrors(path, source) {
  const findings = [];
  const lines = rustProductionLines(source.split("\n"));
  const errorOwner = path.endsWith("/error.rs") || path === "src/error.rs";
  const leaf = LEAVES.has(path.slice(4).split(/[/.]/u)[0]);
  let declaration = null;
  let depth = 0;
  let parentheses = 0;
  for (const [number, code] of lines) {
    const start = /\b(?:enum|struct|type)\s+(\w+)/u.exec(code);
    if (
      start !== null &&
      (errorOwner || /(?:Error|Failure|Issue|Reason|FailureDetail)$/u.test(start[1]))
    ) {
      declaration = { name: start[1], depth, parentheses, opened: false };
    }
    if (declaration !== null) {
      const freeText = /\b(?:String|str|Cow|JsValue|Value|dyn)\b/u.test(code);
      // ComponentCheck labels are static program identifiers, never a caller's error reason.
      const label =
        declaration.name === "SelfCheckError" && /^\s*component: &'static str,/u.test(code);
      if (freeText && !label) findings.push(`${path}:${number}: CORE-23 free-text error payload`);
    }
    if (leaf && /\bMhfeError\b/u.test(code)) {
      findings.push(`${path}:${number}: RUST-04 leaf depends on the aggregate MhfeError`);
    }
    const delta = rustScopeDelta(code);
    depth += delta.braces;
    parentheses += delta.parentheses;
    if (declaration !== null) {
      declaration.opened ||= /[({]/u.test(code);
      if (
        depth <= declaration.depth &&
        parentheses <= declaration.parentheses &&
        (declaration.opened || code.trim().endsWith(";"))
      )
        declaration = null;
    }
  }
  return findings;
}

/** Binding-owned code prefixes would duplicate an error owner's message vocabulary. */
function bindingMessages(path, source, codes) {
  if (!path.startsWith("src/wasm_api")) return [];
  return rustStrings(source).flatMap((value) => {
    const code = /^([A-Z0-9_]+):/u.exec(value)?.[1];
    return codes.has(code) ? [`${path}: CORE-23 binding writes a library code prefix ${code}`] : [];
  });
}

/** Current tracked and new Rust sources, without generated build output. */
function check() {
  const files = execFileSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "src"],
    { encoding: "utf8" },
  )
    .split("\0")
    .filter((path) => path.endsWith(".rs") && !path.startsWith("src/bin/"));
  const codeSource = readFileSync("src/error_code.rs", "utf8");
  const codes = new Set([...codeSource.matchAll(/=>\s*"([A-Z0-9_]+)"/gu)].map((match) => match[1]));
  assert.equal(
    codes.size,
    52,
    "the documented stable vocabulary must be read before checking bindings",
  );
  const found = [...new Set(files)].flatMap((path) => {
    const source = readFileSync(path, "utf8");
    return [...typedErrors(path, source), ...bindingMessages(path, source, codes)];
  });
  return reported(
    found,
    (count) => `${count} error-contract failures`,
    "Typed error contracts passed.",
  );
}

/** Negative controls include a renamed variant and a payload after a test-only enum variant. */
function selfTest() {
  const sample = (body) => typedErrors("src/wallet/error.rs", body);
  assert.deepEqual(sample("enum WalletError { Bad(PathIssue), Cancelled }"), []);
  assert.equal(sample("enum WalletError { Renamed(String) }").length, 1);
  assert.equal(sample("struct Renamed { detail: std::string::String }").length, 1);
  assert.equal(sample("struct Renamed(\nString,\n);").length, 1);
  assert.equal(sample("type Hidden = String;").length, 1);
  assert.equal(sample("enum WalletError { Bad(&'static str) }").length, 1);
  assert.equal(sample("enum WalletError { Bad(Box<dyn std::error::Error>) }").length, 1);
  assert.deepEqual(sample('// String {\n#[cfg(test)]\nmod tests { const X: &str = r#"}"#; }'), []);
  const afterTest = "enum WalletError {\n#[cfg(test)]\nFake(String),\nReal(String),\n}";
  assert.equal(
    sample(afterTest).length,
    1,
    "a test-only variant cannot hide a later production field",
  );
  assert.equal(typedErrors("src/phrase.rs", "fn x() -> MhfeError { todo!() }").length, 1);
  assert.equal(typedErrors("src/rekey.rs", "fn x() -> MhfeError { todo!() }").length, 0);
  assert.equal(
    bindingMessages(
      "src/wasm_api/core.rs",
      'format!("ARGON2_FAILED: {reason}")',
      new Set(["ARGON2_FAILED"]),
    ).length,
    1,
  );
  console.log("Typed error contract controls passed.");
}

runGate("usage: node scripts/verify-error-contracts.mjs [--self-test]", { check, selfTest });
