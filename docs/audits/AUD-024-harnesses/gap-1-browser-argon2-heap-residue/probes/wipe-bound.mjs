// AUD-024 gap-1-browser-argon2-heap-residue: the measure of scripts/package-check/argon2-faults.mjs
// checkArgon2Wipe (non-zero bytes added to a fresh build's heap by the core's 1 MiB Argon2 self-check,
// bound WIPED_RESIDUE_BYTES = 16 KiB), applied to both builds; the package check applies it to the
// single-threaded build only. Shows whether the bound would tell the threaded residue apart.
//   node wipe-bound.mjs <repository root>
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.argv[2] ?? process.cwd();
const pkg = await import(pathToFileURL(join(ROOT, "scripts/package-check/package.mjs")).href);
const nonZero = (heap) => heap.reduce((count, byte) => count + (byte === 0 ? 0 : 1), 0);
const result = {};
for (const build of ["single-threaded", "threaded"]) {
  const fresh = await pkg.builds[build]();
  const before = nonZero(fresh.HEAPU8);
  const report = JSON.parse(
    pkg.bindings.selfCheckArgon2("startup", [], pkg.argon2Engine(fresh), pkg.noop, pkg.noop),
  );
  const residue = nonZero(fresh.HEAPU8) - before;
  result[build] = { passed: report.passed, residueBytes: residue, below16KiB: residue < 16 * 1024 };
}
console.log(JSON.stringify(result));
process.exit(0);
