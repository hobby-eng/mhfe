// Reproduce a synthetic signal consumed by Rust, and bind the public probe's actual bytes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const scratch = resolve(root, "../tmp");
const target = resolve(process.argv[2] ?? "");
assert(process.platform === "linux" && process.arch === "x64", "Linux x64 control only");
assert(target.startsWith(`${scratch}${sep}`), "give an output path under workspace tmp/");
assert(!existsSync(target), "preserve the old executable; choose a fresh output path");
mkdirSync(dirname(target), { recursive: true });
const source = resolve(here, "signal.rs");
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const sourceSha256 = sha(source);
const expectedVersion = readFileSync(resolve(root, "rust-toolchain.toml"), "utf8").match(
  /^channel = "([^"]+)"$/m,
)?.[1];
assert(expectedVersion, "the repository must pin its Rust toolchain");
const compiler = spawnSync("rustc", ["-vV"], {
  cwd: root,
  encoding: "utf8",
  timeout: 10_000,
  maxBuffer: 1024 * 1024,
});
assert.ifError(compiler.error);
assert.equal(compiler.status, 0, compiler.stderr);
assert(compiler.stdout.startsWith(`rustc ${expectedVersion} `), "activate the pinned Rust");
const compile = spawnSync("rustc", ["--edition=2024", source, "-o", target], {
  cwd: root,
  encoding: "utf8",
  timeout: 45_000,
  maxBuffer: 1024 * 1024,
});
assert.ifError(compile.error);
assert.equal(compile.status, 0, compile.stderr);
const executableSha256 = sha(target);
const result = spawnSync(target, [], {
  encoding: "utf8",
  timeout: 10_000,
  maxBuffer: 1024 * 1024,
});
assert.ifError(result.error);
assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
assert.equal(sha(source), sourceSha256, "source changed during the check");
assert.equal(sha(target), executableSha256, "executable changed during the check");
process.stdout.write(result.stdout);
process.stdout.write(
  `${JSON.stringify({ sourceSha256, executableSha256, compilerVersion: compiler.stdout.trim() })}\n`,
);
