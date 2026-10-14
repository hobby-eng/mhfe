// Cargo owns the target directory, including CARGO_TARGET_DIR and workspace configuration.
import { execFileSync } from "node:child_process";
import { join } from "node:path";

/** Metadata of the current checkout, without loading or resolving dependencies. */
export function cargoMetadata() {
  return JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
}

/** The executable Cargo produces for a native binary of the current platform. */
export function nativeBinary(name, profile = "debug") {
  return join(
    cargoMetadata().target_directory,
    profile,
    name + (process.platform === "win32" ? ".exe" : ""),
  );
}
