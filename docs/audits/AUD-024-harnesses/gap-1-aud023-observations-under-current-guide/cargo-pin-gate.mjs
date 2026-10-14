// AUD-024 harness: the CORE-25 check of Cargo.toml in scripts/verify-code-rules.mjs, run on
// manifests that are not exact crates.io pins. The function is read from the script as it is.
// Exits 1 when such a manifest passes.
//
//   node docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/cargo-pin-gate.mjs
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../../../../scripts/verify-code-rules.mjs", import.meta.url), "utf8");
const start = source.indexOf("function cargoFindings(text) {");
const end = source.indexOf("/** TOOL-05: pnpm-lock.yaml present");
if (start < 0 || end < 0) throw new Error("cargoFindings not found in verify-code-rules.mjs");
const finding = (rule, path, line, message) => ({ rule, path, line, message });
// oxlint-disable-next-line typescript/no-implied-eval -- the gate's own function text
const cargoFindings = new Function("finding", `${source.slice(start, end)}\nreturn cargoFindings;`)(finding);
const cases = [
  ["control: a range requirement in [dependencies]", '[dependencies]\nfoo = "1.2"\n', true],
  ["a range requirement in a [dependencies.foo] table", '[dependencies.foo]\nversion = "1.2"\n'],
  ["a git source without a version in a [dependencies.foo] table", '[dependencies.foo]\ngit = "https://example.invalid/foo"\n'],
  ["a wildcard in a [target.'cfg(unix)'.dependencies.foo] table", "[target.'cfg(unix)'.dependencies.foo]\nversion = \"*\"\n"],
  ["an exact version from a git repository", '[dependencies]\nfoo = { git = "https://example.invalid/foo", version = "=1.0.0" }\n'],
  ["an exact version from another registry", '[dependencies]\nfoo = { version = "=1.0.0", registry = "other" }\n'],
];
let missed = 0;
for (const [what, manifest, control] of cases) {
  const found = cargoFindings(manifest);
  console.log(`${found.length === 0 ? "passes " : "refused"} ${what}: ${JSON.stringify(manifest)}`);
  if (!control && found.length === 0) missed += 1;
}
console.log(
  missed > 0
    ? `FAIL: ${missed} of ${cases.length - 1} manifests that are not exact crates.io pins pass CORE-25`
    : "PASS: every such manifest is refused",
);
process.exit(missed > 0 ? 1 : 0);
