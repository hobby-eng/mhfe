// AUD-024, role guide-tooling-js: does the type check of the browser package (pnpm run
// check:types: tsc -p web/tsconfig.json) check the classes against their declarations? TS-13 of
// the coding guide says "`tsc --checkJs` checks it against its `.d.ts` files", AGENTS.md says
// "`tsc --checkJs` of `web/*.js` against `web/*.d.ts`", and scripts/check-fast.sh runs it as the
// check of "the browser package's plain JavaScript against its declarations".
//
// The harness copies web/ into a scratch folder and runs the repository's own tsc
// (node_modules/.bin/tsc) on the copy: unchanged, then with one change at a time to client.js or
// client.d.ts that makes the class differ from its declaration, and, as a control, one type error
// inside client.js. A change the check passes is one it does not see. Writes only into the scratch
// folder it is given; needs `pnpm install --frozen-lockfile` done (node_modules/.bin/tsc).
//
//   node docs/audits/AUD-024-harnesses/guide-tooling-js/tsc-declarations.mjs <scratch folder>
//
// Exit 0 when tsc refuses every change; exit 1 when it passes one.
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const [scratchArg] = process.argv.slice(2);
if (scratchArg === undefined) {
  console.error("usage: node tsc-declarations.mjs <scratch folder>");
  process.exit(2);
}
const repo = process.cwd();
const tsc = join(repo, "node_modules/.bin/tsc");
const web = resolve(scratchArg, "tsc-declarations/web");
rmSync(web, { recursive: true, force: true });
cpSync(join(repo, "web"), web, { recursive: true });

/** [description, file, text found, text it becomes, whether the check must refuse it]. */
const cases = [
  [
    "client.js loses its keepOldContainer() method, which client.d.ts declares",
    "client.js",
    "  async keepOldContainer({ pim = 0, memoryLevel = 0 } = {}) {",
    "  async keepOldContainerRenamed({ pim = 0, memoryLevel = 0 } = {}) {",
  ],
  [
    "client.js's mode() returns a number, where client.d.ts declares MhfeMode",
    "client.js",
    "    return globalThis.crossOriginIsolated === true ? FAST_MODE : STANDARD_MODE;",
    "    return globalThis.crossOriginIsolated === true ? 1 : 0;",
  ],
  [
    "client.d.ts declares a method that client.js does not have",
    "client.d.ts",
    "  cancel(): void;",
    "  cancel(): void;\n  declaredOnly(): Promise<number>;",
  ],
  [
    "control: a call inside client.js with an argument of the wrong type",
    "client.js",
    '    return this.#quick({ operation: "keepOldContainer", pim, memoryLevel });',
    '    requireText(42 + 1, 7);\n    return this.#quick({ operation: "keepOldContainer", pim, memoryLevel });',
  ],
];

const check = () =>
  spawnSync(tsc, ["-p", join(web, "tsconfig.json")], { cwd: repo, encoding: "utf8" });
const unchanged = check();
console.log(`unchanged copy: tsc exit ${unchanged.status}`);
let failed = unchanged.status !== 0;
for (const [description, file, from, to] of cases) {
  const path = join(web, file);
  const original = readFileSync(path, "utf8");
  if (original.split(from).length !== 2) throw new Error(`${file}: the text is not there once: ${from}`);
  writeFileSync(path, original.replace(from, to));
  const run = check();
  writeFileSync(path, original);
  const refused = run.status !== 0;
  const said = `${run.stdout}${run.stderr}`.trim().split("\n")[0]?.replaceAll(web, "<web>") ?? "";
  console.log(`${refused ? "ok  " : "FAIL"} ${description}: tsc exit ${run.status}${said ? `: ${said}` : ""}`);
  if (!refused) failed = true;
}
console.log(
  failed
    ? "The type check passes a class that differs from its declaration."
    : "The type check refuses every difference.",
);
process.exit(failed ? 1 : 0);
