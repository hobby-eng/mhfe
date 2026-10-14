// AUD-024, role guide-tooling-js: does scripts/verify-pinned-versions.mjs see every copy of the
// vendored Argon2 commit and of the wasm-bindgen version? It claims that "every copy of a pinned
// version or provenance value" equals its source (its header, AGENTS.md "Pinned versions").
//
// The harness extracts the committed tree (git archive HEAD) into a scratch folder, runs the gate
// there unchanged, then once for each changed copy: two copies in THIRD_PARTY_NOTICES.md that the
// gate's list leaves out, and, as controls, two copies it lists. A copy whose change the gate
// passes is one it does not keep in step. Writes only into the scratch folder it is given.
//
//   node docs/audits/AUD-024-harnesses/guide-tooling-js/pinned-copies.mjs <scratch folder>
//
// Exit 0 when the gate refuses every changed copy; exit 1 when it passes one.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [scratchArg] = process.argv.slice(2);
if (scratchArg === undefined) {
  console.error("usage: node pinned-copies.mjs <scratch folder>");
  process.exit(2);
}
const repo = process.cwd();
const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
const tree = resolve(scratchArg, "pinned-copies-tree");
rmSync(tree, { recursive: true, force: true });
mkdirSync(tree, { recursive: true });
execFileSync("sh", ["-c", `git archive HEAD | tar -x -C "${tree}"`], { cwd: repo });
console.log(`commit ${head} extracted`);

const ARGON2 = "f57e61e19229e23c4445b85494dbf7c07de721cb";
const OTHER_ARGON2 = "0123456789abcdef0123456789abcdef01234567";
/** [description, file, text found, text it becomes, whether the gate must refuse it]. */
const cases = [
  ["THIRD_PARTY_NOTICES.md: the Argon2 commit", "THIRD_PARTY_NOTICES.md", `\`${ARGON2}\``, `\`${OTHER_ARGON2}\``],
  [
    "THIRD_PARTY_NOTICES.md: the wasm-bindgen command-line tool's version",
    "THIRD_PARTY_NOTICES.md",
    "wasm-bindgen command-line tool 0.2.129",
    "wasm-bindgen command-line tool 0.2.130",
  ],
  [
    "THIRD_PARTY_NOTICES.md: the wasm-bindgen-cli-support version of the glue's notice",
    "THIRD_PARTY_NOTICES.md",
    "`wasm-bindgen-cli-support` 0.2.129",
    "`wasm-bindgen-cli-support` 0.2.130",
  ],
  ["control, a listed copy: src/vectors.rs: the Argon2 commit", "src/vectors.rs", ARGON2, OTHER_ARGON2],
  [
    "control, a listed copy: docs/DEVELOPMENT.md: the wasm-bindgen version",
    "docs/DEVELOPMENT.md",
    "wasm-bindgen command-line tool 0.2.129",
    "wasm-bindgen command-line tool 0.2.130",
  ],
];

const gate = () =>
  spawnSync(process.execPath, ["scripts/verify-pinned-versions.mjs"], { cwd: tree, encoding: "utf8" });
const unchanged = gate();
console.log(`unchanged tree: exit ${unchanged.status}: ${unchanged.stdout.trim()}`);
let failed = unchanged.status !== 0;
for (const [description, file, from, to] of cases) {
  const path = join(tree, file);
  const original = readFileSync(path, "utf8");
  if (original.split(from).length !== 2) throw new Error(`${file}: "${from}" is not there once`);
  writeFileSync(path, original.replace(from, to));
  const run = gate();
  writeFileSync(path, original);
  const refused = run.status !== 0;
  const said = `${run.stdout}${run.stderr}`.trim().split("\n")[0];
  console.log(`${refused ? "ok  " : "FAIL"} ${description} changed: gate exit ${run.status}: ${said}`);
  if (!refused) failed = true;
}
console.log(failed ? "The gate passes a changed copy of a pinned value." : "The gate refuses every changed copy.");
process.exit(failed ? 1 : 0);
