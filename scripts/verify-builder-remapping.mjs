// Exercise the actual release guard, including Cargo's distinction between unset and empty flags.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { scriptArguments } from "./gate-command-line.mjs";

scriptArguments("usage: node scripts/verify-builder-remapping.mjs");
const root = fileURLToPath(new URL("../", import.meta.url));
const guard = fileURLToPath(new URL("../packaging/remap-builder-paths.sh", import.meta.url));
const clean = { ...process.env };
delete clean.RUSTFLAGS;
delete clean.CARGO_ENCODED_RUSTFLAGS;
clean.CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS = "--cfg remap_probe";
const cases = [
  [{}, 0],
  [{ RUSTFLAGS: "" }, 1],
  [{ CARGO_ENCODED_RUSTFLAGS: "" }, 1],
  [{ RUSTFLAGS: "--cfg witness" }, 1],
  [{ CARGO_ENCODED_RUSTFLAGS: "--cfg\u001fwitness" }, 1],
  [{ RUSTFLAGS: "", CARGO_ENCODED_RUSTFLAGS: "" }, 1],
];

for (const shell of ["sh", "bash"]) {
  for (const [additions, status] of cases) {
    const probe = spawnSync(
      shell,
      [
        "-c",
        `
      . "$1"
      remap_builder_paths "$2" || exit $?
      first="$CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS"
      remap_builder_paths "$2" || exit $?
      [ "$first" = "$CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS" ] || exit 3
      printf '%s' "$first"
    `,
        "remap-check",
        guard,
        root.replace(/\/$/u, ""),
      ],
      {
        cwd: root,
        env: { ...clean, ...additions },
        encoding: "utf8",
        timeout: 5000,
        maxBuffer: 1024 * 1024,
      },
    );
    if (probe.error) throw probe.error;
    assert.equal(probe.status, status, `CORE-24: ${shell} overriding flag presence refusal`);
    if (status === 0) {
      assert.ok(
        probe.stdout.startsWith("--cfg remap_probe --remap-path-prefix="),
        "CORE-24: keep existing per-target flags and append remapping",
      );
      assert.equal(
        probe.stdout.split("=mhfe").length,
        2,
        "CORE-24: repeated calls add the repository mapping once",
      );
    } else {
      assert.match(probe.stderr, /unset it for a release build/u);
    }
  }
}
console.log(
  "CORE-24: all 12 shell remapping controls passed; unset, empty, precedence and idempotence.",
);
