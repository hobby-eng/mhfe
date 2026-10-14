// Checks that Python's checker entry points refuse disabled assertions before optional imports
// or test work, even when they receive a modified public vector. No Argon2 call is run.
//
//   node scripts/verify-python-checks.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
if (process.argv.length !== 2) {
  console.error("usage: node scripts/verify-python-checks.mjs");
  process.exit(2);
}

const scripts = [
  "independent-suite3.py",
  "independent-suite4.py",
  "verify-hidden-input.py",
  "verify-hidden-input-windows.py",
];
const scratch = existsSync(resolve(root, "../AGENTS.md"))
  ? resolve(root, "../tmp/aud024")
  : resolve(root, "target/check-controls");
mkdirSync(scratch, { recursive: true });
const temporary = mkdtempSync(resolve(scratch, "python-check-controls-"));
try {
  const fixture = JSON.parse(
    readFileSync(resolve(root, "tests/fixtures/suite3-vectors/zero-12.json")),
  );
  fixture.container = "deliberately changed public test value";
  const path = resolve(temporary, "changed-vector.json");
  writeFileSync(path, JSON.stringify(fixture));
  let refusal;
  let count = 0;
  for (const script of scripts) {
    for (const mode of ["-O", "-OO", "environment"]) {
      const result = spawnSync(
        "python3",
        [
          ...(mode === "environment" ? [] : [mode]),
          resolve(root, "scripts", script),
          ...(script.startsWith("independent") ? ["vector", "--trust-argon2-keys", path] : []),
        ],
        {
          cwd: root,
          encoding: "utf8",
          timeout: 10000,
          env: { ...process.env, PYTHONOPTIMIZE: mode === "environment" ? "1" : "" },
        },
      );
      if (
        result.error !== undefined ||
        result.status !== 1 ||
        result.stdout !== "" ||
        !result.stderr.startsWith("Python optimization disables assertions;")
      ) {
        throw new Error(
          `${script}/${mode}: unsafe or unexplained result: ${JSON.stringify(result)}`,
        );
      }
      refusal ??= result.stderr;
      if (result.stderr !== refusal) throw new Error(`${script}: the deliberate copy differs`);
      count += 1;
    }
  }
  console.log(
    `All ${count} optimized checker entry points refuse before test work; refusals agree.`,
  );
} finally {
  rmSync(temporary, { recursive: true });
}
