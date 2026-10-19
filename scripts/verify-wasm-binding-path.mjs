// Observe the real shell wrapper without compiling or binding; Cargo owns target-directory rules.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { scriptArguments } from "./gate-command-line.mjs";

scriptArguments("usage: node scripts/verify-wasm-binding-path.mjs");
const root = fileURLToPath(new URL("../", import.meta.url));
const parent = existsSync(resolve(root, "../AGENTS.md"))
  ? resolve(root, "../tmp/wasm-binding-controls")
  : resolve(root, "target/check-controls");
mkdirSync(parent, { recursive: true });
const temporary = mkdtempSync(join(parent, "binding-"));
const realCargo = execFileSync("sh", ["-c", "command -v cargo"], { encoding: "utf8" }).trim();
const version = /^expected_bindgen="([^"]+)"$/mu.exec(
  readFileSync(join(root, "scripts/bind-wasm.sh"), "utf8"),
)?.[1];
assert.ok(version, "binding wrapper must state its pinned tool version");
const metadataArgs = ["metadata", "--locked", "--no-deps", "--format-version", "1"];

// The observer refuses unknown commands and never dispatches any compiler request.
const observer = `#!${process.execPath}
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { basename } from "node:path";
const name = basename(process.argv[1]);
const args = process.argv.slice(2);
appendFileSync(process.env.BINDING_RECORD, JSON.stringify({ name, args }) + "\\n");
if (name === "wasm-bindgen") {
  if (args.length === 1 && args[0] === "--version") console.log(process.env.BINDING_VERSION);
  else process.exit(77);
} else if (JSON.stringify(args) === process.env.BINDING_METADATA_ARGS) {
  if (process.env.BINDING_FAIL === "metadata") process.exit(42);
  const result = spawnSync(process.env.BINDING_CARGO, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
} else if (args[0] === "rustc") {
  if (process.env.BINDING_FAIL === "rustc") process.exit(43);
} else process.exit(99);
`;

try {
  const shims = join(temporary, "commands");
  mkdirSync(shims);
  for (const name of ["cargo", "wasm-bindgen"]) {
    writeFileSync(join(shims, name), observer, { mode: 0o700 });
  }
  const clean = { ...process.env };
  for (const key of [
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
  ])
    delete clean[key];
  const cases = [
    {},
    { CARGO_BUILD_TARGET_DIR: join(temporary, "configured target") },
    { CARGO_TARGET_DIR: join(temporary, "explicit target") },
    {
      CARGO_BUILD_TARGET_DIR: join(temporary, "ignored target"),
      CARGO_TARGET_DIR: join(temporary, "winning target"),
    },
    { CARGO_TARGET_DIR: "target/relative-binding-control" },
    { CARGO_TARGET_DIR: join(temporary, "target ending in a newline\n") },
    { BINDING_FAIL: "metadata" },
    { BINDING_FAIL: "rustc" },
  ];
  for (const [number, additions] of cases.entries()) {
    const originalEnv = { ...clean, ...additions };
    const expected = JSON.parse(
      execFileSync(realCargo, metadataArgs, { cwd: root, env: originalEnv, encoding: "utf8" }),
    ).target_directory;
    const record = join(temporary, `calls-${number}.jsonl`);
    const result = spawnSync("bash", ["scripts/bind-wasm.sh", "wasm", join(temporary, "output")], {
      cwd: root,
      env: {
        ...originalEnv,
        PATH: shims + delimiter + process.env.PATH,
        BINDING_CARGO: realCargo,
        BINDING_RECORD: record,
        BINDING_VERSION: version,
        BINDING_METADATA_ARGS: JSON.stringify(metadataArgs),
      },
      encoding: "utf8",
      timeout: 15000,
      maxBuffer: 1024 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(
      result.status,
      // The shared Node metadata CLI propagates a failed child as its own exit 1.
      additions.BINDING_FAIL === "metadata" ? 1 : additions.BINDING_FAIL === "rustc" ? 43 : 77,
    );
    const calls = readFileSync(record, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const builds = calls.filter((call) => call.name === "cargo" && call.args[0] === "rustc");
    const bindings = calls.filter(
      (call) => call.name === "wasm-bindgen" && call.args[0] !== "--version",
    );
    assert.equal(builds.length, additions.BINDING_FAIL === "metadata" ? 0 : 1);
    if (additions.BINDING_FAIL) assert.equal(bindings.length, 0, "failed Cargo must stop binding");
    else {
      assert.equal(bindings.length, 1);
      assert.equal(
        resolve(root, bindings[0].args[0]),
        join(expected, "wasm32-unknown-unknown/release/mhfe.wasm"),
      );
      assert.ok(builds[0].args.includes("--locked"));
    }
  }
  console.log(
    `All ${cases.length} binding-path controls passed; no compiler or binder was dispatched.`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
