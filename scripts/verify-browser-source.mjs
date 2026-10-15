// Source assembly preserves module scope and refuses incomplete or conflicting wiring.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { browserSource, joinSources } from "./browser-source.mjs";
import { scriptArguments } from "./gate-command-line.mjs";

scriptArguments("usage: node scripts/verify-browser-source.mjs", { operands: 0 });

/** Assemble only the synthetic modules of one control, never another project tree. */
function control(files) {
  return joinSources(new URL("file:///control/entry.js"), (path) => {
    const source = files[path.pathname.slice("/control/".length)];
    if (source === undefined) throw new Error(`Missing control source: ${path.pathname}`);
    return source;
  });
}

const source = control({
  "entry.js": 'export { answer } from "./answer.js";\n',
  "answer.js": 'import { value } from "./value.js";\nexport function answer() { return value; }\n',
  "value.js": "export const value = 42;\n",
});
assert.ok(source.includes("export function answer()"));
assert.ok(source.includes("const value = 42;"));
assert.ok(!source.includes("export const value"));
assert.ok(!source.includes("import {"));

const typedSource = control({
  "entry.js":
    '/** @import { Value } from "./runtime-parts/value.js" */\nexport { Value } from "./runtime-parts/value.js";\n',
  "runtime-parts/value.js": "export class Value {}\n",
});
assert.ok(typedSource.includes("export class Value {}"));
assert.ok(
  !typedSource.includes("@import"),
  "local source types are declarations in the joined file",
);
assert.ok(!typedSource.includes("./runtime-parts/"));
const sourceTypes = control({
  "entry.js":
    '// @ts-check\n/**\n * @import { Options } from "./types/source-only.d.ts"\n */\n/** @typedef {Options} InternalOptions */\nexport const value = 42;\n',
});
assert.ok(sourceTypes.includes("export const value = 42;"));
assert.ok(!sourceTypes.includes("@import") && !sourceTypes.includes("@typedef"));
assert.ok(!sourceTypes.includes("@ts-check"));

for (const [files, refusal] of [
  [
    { "entry.js": 'export { missing } from "./value.js";\n', "value.js": "const value = 42;\n" },
    /Missing browser source import/u,
  ],
  [
    {
      "entry.js": 'import { value } from "./value.js";\nconst value = 1;\n',
      "value.js": "export const value = 2;\n",
    },
    /Duplicate browser source binding/u,
  ],
  [
    {
      "entry.js": 'export { value } from "./value.js";\n',
      "value.js": 'import { value } from "./entry.js";\nexport const other = 0;\n',
    },
    /import cycle/u,
  ],
  [
    { "entry.js": 'import { value } from "https://example.invalid/source.js";\n' },
    /unsupported source import/u,
  ],
  [
    { "entry.js": 'import * as value from "./value.js";\n' },
    /outside the source assembly grammar/u,
  ],
  [
    { "entry.js": 'import { value } from "../runtime/runtime.js";\nconst value = 1;\n' },
    /Duplicate browser source binding/u,
  ],
  [
    { "entry.js": 'export { value } from "../runtime/runtime.js";\nexport const value = 1;\n' },
    /Duplicate browser source export/u,
  ],
]) {
  assert.throws(() => control(files), refusal);
}

for (const name of ["runtime", "client"]) {
  const text = browserSource(name);
  assert.ok(!/oxlint-disable\s+max-lines/u.test(text));
  assert.ok(!/from "\.\/(?:runtime-parts|client-parts)\//u.test(text));
  assert.ok(!text.includes("@import"), "only source modules carry type-only import paths");
}

const runtime = await import(
  `data:text/javascript;base64,${Buffer.from(browserSource("runtime")).toString("base64")}`
);
const protocol = await import(
  `data:text/javascript;base64,${Buffer.from(
    joinSources(new URL("../web/runtime-parts/protocol.js", import.meta.url), (path) =>
      readFileSync(path, "utf8"),
    ),
  ).toString("base64")}`
);
const report = { passed: false, components: [] };
const cause = new Error("synthetic cause");
const error = new runtime.MhfeError("SELF_CHECK_FAILED", "Synthetic refusal", { report, cause });
assert.equal(error.code, "SELF_CHECK_FAILED");
assert.equal(error.report, report);
assert.equal(error.cause, cause);
assert.throws(() => {
  error.code = "INTERNAL_ERROR";
}, TypeError);
assert.throws(() => {
  error.report = undefined;
}, TypeError);
assert.equal(error.code, "SELF_CHECK_FAILED");
assert.equal(error.report, report);

// The worker has no module exports. Evaluate its actual definition without starting an operation;
// the public worker requests separately exercise backend failure sanitization in package-check.
const worker = readFileSync(new URL("../web/core-worker.js", import.meta.url), "utf8");
const errorStart = worker.indexOf("class Argon2StartError extends Error");
const errorEnd = worker.indexOf("\n}\n", errorStart);
assert.ok(errorStart >= 0 && errorEnd > errorStart, "the actual startup error is present");
const StartupError = vm.runInNewContext(
  `${worker.slice(errorStart, errorEnd + 3)}\nArgon2StartError;`,
);
for (const issue of ["startFailed", "notIsolated"]) {
  const failure = new StartupError("threaded", issue);
  assert.equal(failure.code, "INTERNAL_ERROR");
  assert.equal(failure.message, `INTERNAL_ERROR: ${failure.detail}`);
  assert.equal(Reflect.set(failure, "code", "UNKNOWN"), false);
  assert.equal(failure.code, "INTERNAL_ERROR");
}

for (const round of [-1.5, -1, 0, 0.5, 13, Number.MAX_SAFE_INTEGER + 1]) {
  assert.throws(
    () =>
      protocol.checkedPageHandler(() => {}, "progress", { stage: "recover", round, rounds: 12 }),
    { code: "PACKAGE_MISMATCH" },
  );
}
for (const stage of ["recover", "encrypt", "check", "compare"]) {
  for (const rounds of [12, 24, 36]) {
    for (const round of [1, rounds]) {
      const progress = { stage, round, rounds };
      let received;
      protocol.checkedPageHandler(
        (value) => {
          received = value;
        },
        "progress",
        progress,
      )();
      assert.equal(received, progress);
    }
  }
}
let search;
const initialSearch = { stage: "search", candidate: 0, candidates: 2 };
protocol.checkedPageHandler(
  (value) => {
    search = value;
  },
  "progress",
  initialSearch,
)();
assert.equal(search, initialSearch, "search may start before the first candidate");
console.log("Browser source assembly and its refusal controls passed.");
