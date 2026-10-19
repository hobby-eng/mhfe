// ARC022: check every production library edge, including acyclic paths and grouped imports.
// Error identity/type references and known-answer/self-check hooks are separate boundaries.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { reported, runGate } from "./gate-command-line.mjs";
import { rustProductionLines } from "./rust-code.mjs";

const CORE = new Set(["mhfe", "feistel", "engine", "wallet", "rehearsal", "container"]);
const PARTS = [
  "repair",
  "check_word",
  "password",
  "new_password",
  "strength",
  "word_hints",
  "wallet_check",
  "word_wishes",
  "phrase",
  "memory",
  "packing",
  "bip39_seed",
];
const CHECKS = new Set(["self_check", "self_test", "validation_fixtures"]);

/** Preserve line numbers while removing test-only code, comments and literal contents. */
function production(source) {
  const lines = source.split("\n");
  const code = Array.from({ length: lines.length }, () => "");
  for (const [number, line] of rustProductionLines(lines)) code[number - 1] = line;
  return code.join("\n");
}

/** Names and owning top-level modules of the root's explicit public reexports. */
function rootExports(lib) {
  const exports = new Map();
  for (const match of lib.matchAll(/\bpub use (\w+)::(\{[^;]+\}|[^;]+);/gu)) {
    const names = match[2].replace(/^\{|\}$/gu, "").split(",");
    for (const entry of names) {
      const [original, alias] = entry.trim().split(/\s+as\s+/u);
      if (original) exports.set(alias ?? original, match[1]);
    }
  }
  return exports;
}

/** Top-level comma-separated Rust use entries, keeping nested brace groups together. */
function useEntries(text) {
  const entries = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "{") depth += 1;
    else if (text[index] === "}") depth -= 1;
    else if (text[index] === "," && depth === 0) {
      entries.push(text.slice(start, index));
      start = index + 1;
    }
  }
  entries.push(text.slice(start));
  return entries.filter((entry) => entry.trim() !== "");
}

/** Expand grouped imports to paths before classifying error-only references. */
function usePaths(text, prefix = "") {
  return useEntries(text).flatMap((entry) => {
    const part = entry.trim();
    const brace = part.indexOf("{");
    if (brace === -1) return [prefix + part.split(/\s+as\s+/u)[0]];
    return usePaths(part.slice(brace + 1, part.lastIndexOf("}")), prefix + part.slice(0, brace));
  });
}

/** Resolve one explicit crate path, without treating an error cause as executable core code. */
function targetOf(path, modules, exports) {
  const names = path.split("::").map((name) => name.trim());
  if (names.some((name) => name.endsWith("Error") || /^Error(?:Code|Identity)$/u.test(name)))
    return null;
  const target = modules.has(names[0]) ? names[0] : exports.get(names[0]);
  return target === undefined || CHECKS.has(target) || target === "error" ? null : target;
}

/** Explicit internal paths resolved at their file/inline-module scope, not expression blocks. */
function rootedReferences(file, code) {
  const references = [];
  const expressions = code.replace(/\buse\s+([^;]+);/gu, (whole, imports, index) => {
    for (const path of usePaths(imports)) references.push({ path, index });
    return whole.replace(/[^\n]/gu, " ");
  });
  for (const match of expressions.matchAll(/\b(?:crate|super|self)\s*::\s*\w+(?:\s*::\s*\w+)*/gu))
    references.push({ path: match[0], index: match.index });
  references.sort((left, right) => left.index - right.index);
  const scopes = [...code.matchAll(/\bmod\s+(\w+)\s*\{|[{}]/gu)];
  const parents = [];
  let module = file
    .replace(/^src\//u, "")
    .replace(/\.rs$/u, "")
    .split("/");
  if (module.at(-1) === "mod" || module.at(-1) === "lib") module.pop();
  let nextScope = 0;
  return references.map(({ path, index }) => {
    while (nextScope < scopes.length && scopes[nextScope].index < index) {
      const token = scopes[nextScope++];
      if (token[0] === "}") {
        const parent = parents.pop();
        if (parent === undefined) throw new Error(`${file}: unbalanced module scope`);
        module = parent;
      } else {
        parents.push(module);
        if (token[1] !== undefined) module = [...module, token[1]];
      }
    }
    const names = path.split("::").map((name) => name.trim());
    const explicit = ["crate", "self", "super"].includes(names[0]);
    // An unprefixed use starts at the crate root/extern prelude; self/super use this module.
    const root = names[0] === "self" || names[0] === "super" ? [...module] : [];
    if (names[0] === "crate" || names[0] === "self") names.shift();
    while (names[0] === "super") {
      names.shift();
      if (root.pop() === undefined) throw new Error(`${file}: path above the crate root`);
    }
    return { path: [...root, ...names].join("::"), index, explicit };
  });
}

/** All edges, with source evidence, rather than only edges already known to be cyclic. */
function graphOf(files) {
  assert.ok(
    Object.hasOwn(files, "src/lib.rs"),
    "module graph requires src/lib.rs in the repository root",
  );
  const lib = production(files["src/lib.rs"]);
  const modules = new Set([...lib.matchAll(/\bmod\s+(\w+)\s*;/gu)].map((match) => match[1]));
  const exports = rootExports(lib);
  const graph = new Map();
  const evidence = new Map();
  for (const [file, source] of Object.entries(files)) {
    const owner = /^src\/(\w+)(?:\.rs|\/)/u.exec(file)?.[1];
    if (
      !modules.has(owner) ||
      CHECKS.has(owner) ||
      owner === "error" ||
      owner === "wasm_api" ||
      file.includes("known_answers") ||
      /\/(?:tests|test_support)\.rs$/u.test(file)
    )
      continue;
    const code = production(source);
    const add = (path, index, explicit) => {
      const first = path.split("::")[0];
      if (path.includes("*") && (explicit || modules.has(first) || exports.has(first)))
        throw new Error(`${file}: wildcard crate imports cannot prove a boundary`);
      const target = targetOf(path, modules, exports);
      if (target === null || target === owner) return;
      if (!graph.has(owner)) graph.set(owner, new Set());
      graph.get(owner).add(target);
      const number = code.slice(0, index).split("\n").length;
      evidence.set(`${owner}->${target}`, `${file}:${number}`);
    };
    // Imports are expanded before error-only classification; expressions use the same resolver.
    for (const { path, index, explicit } of rootedReferences(file, code))
      add(path, index, explicit);
  }
  return { graph, evidence };
}

/** Reachable executable modules; all paths are considered, whether cyclic or acyclic. */
function reachable(graph, start) {
  const seen = new Set();
  const pending = [start];
  while (pending.length > 0) {
    for (const next of graph.get(pending.pop()) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        pending.push(next);
      }
    }
  }
  return seen;
}

/** The independent parts cannot reach the cipher/core; an engine cannot reach its front end. */
function findings(files) {
  const { graph, evidence } = graphOf(files);
  const failed = PARTS.flatMap((part) => {
    const reached = [...reachable(graph, part)]
      .filter((name) => CORE.has(name))
      .sort((left, right) => (left < right ? -1 : Number(left > right)));
    return reached.length === 0
      ? []
      : [`CORE-04 ${part} reaches executable core: ${reached.join(", ")}`];
  });
  if (reachable(graph, "engine").has("wasm_api")) failed.push("CORE-04 engine reaches wasm_api");
  return { failed, evidence };
}

/** Read only Git-visible library sources; a missing or wrong working directory fails closed. */
function check() {
  const paths = execFileSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "src"],
    { encoding: "utf8" },
  )
    .split("\0")
    .filter((path) => path.endsWith(".rs"));
  const files = Object.fromEntries(
    [...new Set(paths)].map((path) => [path, readFileSync(path, "utf8")]),
  );
  const { failed, evidence } = findings(files);
  if (failed.length > 0)
    for (const [edge, location] of evidence) console.error(`${edge} (${location})`);
  return reported(
    failed,
    (count) => `${count} module boundary failures`,
    "No independent part reaches executable core; engine has no frontend dependency.",
  );
}

/** These controls distinguish acyclic paths, grouped imports, error types, tests and real calls. */
function selfTest() {
  const lib =
    "mod repair; mod phrase; mod memory; mod engine; mod wasm_api; mod wallet; mod suite; mod mhfe;\n" +
    "pub use mhfe::Mhfe; pub use suite::{WordCount, FormatError}; pub use engine::EngineError;";
  const fixture = (files) => ({ "src/lib.rs": lib, ...files });
  assert.deepEqual(findings(fixture({ "src/repair.rs": "use crate::WordCount;" })).failed, []);
  assert.equal(findings(fixture({ "src/repair.rs": "use crate::{Mhfe};" })).failed.length, 1);
  assert.equal(
    findings(
      fixture({
        "src/repair.rs": "use crate::{phrase};",
        "src/phrase.rs": "crate::engine::run();",
      }),
    ).failed.length,
    2,
  );
  assert.deepEqual(
    findings(fixture({ "src/repair.rs": "use crate::engine::{EngineError};" })).failed,
    [],
  );
  assert.equal(
    findings(fixture({ "src/repair/error.rs": "crate::engine::run();" })).failed.length,
    1,
  );
  assert.equal(findings(fixture({ "src/engine.rs": "crate::wasm_api::text();" })).failed.length, 1);
  assert.equal(
    findings(fixture({ "src/memory.rs": "crate::engine::ffi::lock();" })).failed.length,
    1,
  );
  assert.equal(
    findings(fixture({ "src/repair.rs": "use crate::{engine::{EngineError, run}};" })).failed
      .length,
    1,
  );
  assert.deepEqual(
    findings(fixture({ "src/repair.rs": "#[cfg(test)]\nmod tests { crate::engine::run(); }" }))
      .failed,
    [],
  );
  assert.deepEqual(
    findings(fixture({ "src/repair/known_answers.rs": "crate::engine::run();" })).failed,
    [],
  );
  for (const source of [
    "use crate::*;",
    "use {crate::*};",
    "use {super::*};",
    "mod nested { use {super::super::*}; }",
  ]) {
    assert.throws(() => findings(fixture({ "src/repair.rs": source })), /wildcard/u);
  }
  assert.throws(
    () =>
      findings({
        "src/lib.rs": "mod repair; mod engine; mod bridge { pub use crate::engine::Engine; }",
        "src/repair.rs": "use {crate::bridge::*};",
      }),
    /wildcard/u,
  );
  for (const path of ["crate::engine", "super::engine", "super::Engine"]) {
    const files = {
      "src/lib.rs": "mod repair; mod engine; pub use engine::Engine;",
      "src/repair.rs": `use ${path};`,
    };
    assert.equal(findings(files).failed.length, 1, `same root edge through ${path}`);
  }
  for (const [file, source, expected] of [
    ["src/repair.rs", "fn call() { super::engine::run(); }", 1],
    ["src/repair.rs", "mod nested { use super::super::engine::run; }", 1],
    ["src/repair/inner.rs", "use super::super::{engine::{EngineError, run}};", 1],
    ["src/repair/inner.rs", "use super::super::{Engine as CoreEngine};", 1],
    ["src/repair/inner.rs", "super::super::engine::run();", 1],
    ["src/repair.rs", "mod nested { super::super::engine::run(); }", 1],
    ["src/repair.rs", "use self::local; mod local {}", 0],
    ["src/repair/inner.rs", "use super::local;", 0],
    ["src/repair.rs", "mod nested { use super::local; }", 0],
    ["src/repair.rs", "fn independent() { let super_name = 1; }", 0],
    ["src/repair.rs", "use super::engine::EngineError;", 0],
    ["src/repair.rs", "use external::prelude::*;", 0],
    ["src/repair.rs", "use {external::prelude::*, super::engine::Engine};", 1],
  ]) {
    assert.equal(
      findings({
        "src/lib.rs": "mod repair; mod engine; pub use engine::Engine;",
        [file]: source,
      }).failed.length,
      expected,
      `relative boundary in ${file}: ${source}`,
    );
  }
  assert.throws(
    () => findings(fixture({ "src/repair.rs": "use super::super::engine;" })),
    /above the crate root/u,
  );
  assert.throws(() => findings({}), /requires src\/lib.rs/u);
  console.log("Module boundary controls passed, including acyclic and transitive violations.");
}

runGate("usage: node scripts/verify-module-boundaries.mjs [--self-test]", { check, selfTest });
