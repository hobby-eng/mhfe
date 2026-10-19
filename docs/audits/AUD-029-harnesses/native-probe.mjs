// Compile a public Rust regression probe against the actual Cargo-emitted MHFE library.
// Run: node docs/audits/AUD-029-harnesses/native-probe.mjs phrase-raw-boundary|hint-debug-boundary
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

class NativeProbe {
  run(name) {
    assert.ok(["phrase-raw-boundary", "hint-debug-boundary"].includes(name), "Unknown probe");
    const root = process.cwd();
    const probe = join(dirname(fileURLToPath(import.meta.url)), `${name}.rs`);
    const cargo = spawnSync("cargo", ["build", "--locked", "--lib", "--message-format=json"], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    process.stderr.write(cargo.stderr ?? "");
    assert.equal(cargo.error, undefined);
    assert.equal(cargo.status, 0, "Cargo build failed");
    const artifacts = cargo.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .filter(
        (entry) =>
          entry.reason === "compiler-artifact" &&
          resolve(entry.manifest_path) === join(root, "Cargo.toml") &&
          entry.target.kind.includes("rlib") &&
          !entry.profile.test,
      )
      .flatMap((entry) => entry.filenames.filter((path) => path.endsWith(".rlib")));
    assert.equal(artifacts.length, 1, "Expected exactly one own non-test library receipt");
    const library = artifacts[0];
    for (const path of [library, probe]) {
      console.log(`${createHash("sha256").update(readFileSync(path)).digest("hex")}  ${path}`);
    }
    const outputDirectory = join(root, "target", "aud029-probes");
    mkdirSync(outputDirectory, { recursive: true });
    const output = join(outputDirectory, `${name}${process.platform === "win32" ? ".exe" : ""}`);
    const compilation = spawnSync(
      "rustc",
      [
        "--edition=2021",
        probe,
        "--extern",
        `mhfe=${library}`,
        "-L",
        `dependency=${join(dirname(library), "deps")}`,
        "-o",
        output,
      ],
      { stdio: "inherit" },
    );
    assert.equal(compilation.error, undefined);
    assert.equal(compilation.status, 0, "Probe compilation failed");
    const result = spawnSync(output, [], { stdio: "inherit" });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    process.exitCode = result.status ?? 1;
  }
}

new NativeProbe().run(process.argv[2]);
