// Cargo's public JSON outputs, read by thin shell wrappers without embedded Python programs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { cargoMetadata } from "./cargo-paths.mjs";
import { runGate } from "./gate-command-line.mjs";

const USAGE =
  "usage: node scripts/cargo-output.mjs target-directory|version|test-binary|--self-test";
const MANIFEST = fileURLToPath(new URL("../Cargo.toml", import.meta.url));
// Cargo reports a library target's crate types as its kind, including an explicit `rlib`.
// https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages
const LIBRARY_KINDS = new Set(["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"]);

function testBinary(input) {
  const messages = input
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
  const binaries = messages
    .filter(
      (message) =>
        message.reason === "compiler-artifact" &&
        message.manifest_path === MANIFEST &&
        message.profile?.test === true &&
        typeof message.executable === "string" &&
        message.executable.trim() !== "" &&
        message.target.kind.some((kind) => LIBRARY_KINDS.has(kind)),
    )
    .map((message) => message.executable);
  if (binaries.length !== 1)
    throw new Error(`Expected one library test executable, found ${binaries.length}.`);
  return binaries[0];
}

function metadataValue(operation) {
  const metadata = cargoMetadata();
  if (operation === "target-directory") return metadata.target_directory;
  const ownPackage = metadata.packages.find((entry) => entry.manifest_path === MANIFEST);
  if (!ownPackage) throw new Error("Cargo did not report the package of this checkout.");
  return ownPackage.version;
}

function selfTest() {
  const artifact = {
    reason: "compiler-artifact",
    manifest_path: MANIFEST,
    profile: { test: true },
    target: { kind: ["rlib"] },
    executable: "/synthetic/target/debug/deps/mhfe-test",
  };
  const stream = (...messages) => messages.map((message) => JSON.stringify(message)).join("\n");
  for (const kind of ["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"]) {
    assert.equal(
      testBinary(
        stream(
          { reason: "build-finished", success: true },
          {
            ...artifact,
            target: { kind: [kind] },
          },
        ),
      ),
      "/synthetic/target/debug/deps/mhfe-test",
    );
  }
  const ignored = [
    { ...artifact, manifest_path: "/synthetic/dependency/Cargo.toml" },
    { ...artifact, profile: { test: false } },
    { ...artifact, profile: {} },
    ...["bin", "example", "test", "bench", "custom-build", "unknown"].map((kind) => ({
      ...artifact,
      target: { kind: [kind] },
    })),
    ...[null, "", " ", undefined].map((executable) => ({ ...artifact, executable })),
  ];
  for (const message of ignored) {
    assert.throws(() => testBinary(stream(message)), /found 0/);
    assert.equal(testBinary(stream(message, artifact)), "/synthetic/target/debug/deps/mhfe-test");
  }
  assert.throws(() => testBinary("\n \n"), /found 0/);
  assert.throws(() => testBinary(stream(artifact, artifact)), /found 2/);
  assert.throws(() => testBinary(stream(artifact) + "\ninvalid JSON"), SyntaxError);
  console.log("Cargo test executable selection controls passed.");
}

runGate(USAGE, {
  selfTest,
  modes: Object.fromEntries(
    ["target-directory", "version", "test-binary"].map((operation) => [
      operation,
      () => {
        const value =
          operation === "test-binary"
            ? testBinary(readFileSync(0, "utf8"))
            : metadataValue(operation);
        process.stdout.write(`${value}\n`);
        return true;
      },
    ]),
  ),
});
