// Cargo's public JSON outputs, read by thin shell wrappers without embedded Python programs.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { cargoMetadata } from "./cargo-paths.mjs";
import { scriptArguments } from "./gate-command-line.mjs";

const USAGE = "usage: node scripts/cargo-output.mjs target-directory|version|test-binary";
const { positionals } = scriptArguments(USAGE, { operands: 1 });
if (
  positionals.length !== 1 ||
  !["target-directory", "version", "test-binary"].includes(positionals[0])
) {
  console.error(USAGE);
  process.exit(2);
}
const [operation] = positionals;
if (operation === "test-binary") {
  const messages = readFileSync(0, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
  const binaries = messages
    .filter(
      (message) =>
        message.reason === "compiler-artifact" &&
        message.executable &&
        message.target.kind.includes("lib"),
    )
    .map((message) => message.executable);
  if (binaries.length !== 1)
    throw new Error(`Expected one library test executable, found ${binaries.length}.`);
  process.stdout.write(`${binaries[0]}\n`);
} else {
  const metadata = cargoMetadata();
  if (operation === "target-directory") process.stdout.write(`${metadata.target_directory}\n`);
  else {
    const manifest = fileURLToPath(new URL("../Cargo.toml", import.meta.url));
    const ownPackage = metadata.packages.find((entry) => entry.manifest_path === manifest);
    if (!ownPackage) throw new Error("Cargo did not report the package of this checkout.");
    process.stdout.write(`${ownPackage.version}\n`);
  }
}
