// AUD-013: production checker, unchanged, linked to bounded virtual source files.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import vm from "node:vm";

const checkerPath = new URL("../../../../scripts/verify-no-copies.mjs", import.meta.url);
const startedAt = new Date().toISOString();
const evidenceLabel = process.argv[2];
if (evidenceLabel !== undefined && !/^[a-z0-9-]+$/.test(evidenceLabel)) {
  throw new Error("An evidence label contains only lowercase letters, digits and hyphens.");
}
const checker = readFileSync(checkerPath, "utf8");
const virtualRoot = "/virtual/mhfe";
const exited = Symbol("exit");

async function check(files, args = []) {
  const lines = [];
  let status = 0;
  const context = vm.createContext({
    URL,
    console: { log: (text) => lines.push(text), error: (text) => lines.push(text) },
    process: {
      argv: ["node", "verify-no-copies.mjs", ...args],
      exit: (code) => {
        status = code;
        throw exited;
      },
    },
  });
  const filesystem = {
    readdirSync: (directory) =>
      Object.keys(files)
        .filter((file) => path.dirname(path.join(virtualRoot, file)) === directory)
        .map((file) => ({ name: path.basename(file), isDirectory: () => false })),
    readFileSync: (file) => {
      const found = files[path.relative(virtualRoot, file)];
      assert.notEqual(found, undefined, `unexpected read ${file}`);
      return found;
    },
  };
  const modules = new Map();
  for (const [name, exports] of [
    ["node:fs", filesystem],
    ["node:path", path],
    ["node:url", url],
  ]) {
    modules.set(
      name,
      new vm.SyntheticModule(
        Object.keys(exports),
        function () {
          for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
        },
        { context },
      ),
    );
  }
  const source = new vm.SourceTextModule(checker, {
    context,
    initializeImportMeta: (meta) => {
      meta.url = "file:///virtual/mhfe/scripts/verify-no-copies.mjs";
    },
  });
  await source.link((name) => {
    assert.ok(modules.has(name), `unexpected import ${name}`);
    return modules.get(name);
  });
  try {
    await source.evaluate();
  } catch (error) {
    if (error !== exited) throw error;
  }
  return { status, output: lines.join("\n") };
}

// Twelve statements and one long expression exceed the default 50-token threshold.
const body = Array.from({ length: 12 }, (_, i) => `total = total * 7 + from + ${i};`).join("\n");
const expression = Array.from({ length: 30 }, (_, i) => `from * ${i}`).join(" + ");
const ordinary = (name) => `function ${name}(from) { let total = 0;\n${body}\nreturn total; }`;
const reports = [];
const cases = [
  ["ordinary-positive", { "web/a.js": ordinary("a"), "web/b.js": ordinary("b") }, 1],
  [
    "exported-from-positive",
    {
      "web/a.js": `export function a(from) { let total = 0;\n${body}\nreturn total; }`,
      "web/b.js": `export class B { b(from) { let total = 0;\n${body}\nreturn total; } }`,
    },
    1,
  ],
  [
    "asi-import-active-body",
    {
      "web/a.js": `import "./dependency.js"\nexport function a(from) { return ${expression}; }`,
      "web/b.js": `import "./dependency.js"\nexport function b(from) { return ${expression}; }`,
    },
    1,
  ],
  [
    "noncomment-marker",
    {
      "web/a.js": `const explanation = "deliberate copy";\n${ordinary("a")}`,
      "web/b.js": ordinary("b"),
    },
    1,
  ],
  [
    "semicolon-import-active-body-control",
    {
      "web/a.js": `import "./dependency.js";\nexport function a(from) { return ${expression}; }`,
      "web/b.js": `import "./dependency.js";\nexport function b(from) { return ${expression}; }`,
    },
    1,
  ],
  [
    "asi-reexport-active-body",
    {
      "web/a.js": `export * from "./dependency.js"\nexport function a(from) { return ${expression}; }`,
      "web/b.js": `export * from "./dependency.js"\nexport function b(from) { return ${expression}; }`,
    },
    1,
  ],
  [
    "marked-first-unmarked-pair",
    {
      "web/a.js": `// deliberate copy: a synthetic independently valid exception.\n${ordinary("a")}`,
      "web/b.js": ordinary("b"),
      "web/c.js": ordinary("c"),
    },
    1,
  ],
  [
    "legitimate-marked-pair",
    {
      "web/a.js": `// deliberate copy: a synthetic independently valid exception.\n${ordinary("a")}`,
      "web/b.js": ordinary("b"),
    },
    0,
  ],
  [
    "unmarked-first-marked-last-control",
    {
      "web/a.js": ordinary("a"),
      "web/b.js": ordinary("b"),
      "web/c.js": `// deliberate copy: a synthetic independently valid exception.\n${ordinary("c")}`,
    },
    1,
  ],
];
for (const [label, files, expected] of cases) {
  // Confirm fixtures are syntactically valid ESM, independently of checker tokenization.
  for (const text of Object.values(files)) new vm.SourceTextModule(text);
  const result = await check(files);
  reports.push({ label, expected, ...result, passed: result.status === expected });
}
for (const value of ["NaN", "Infinity", "0", "-1", "1", "1.5", "9007199254740993"]) {
  const result = await check({}, ["--tokens", value]);
  reports.push({ label: `invalid-${value}`, expected: 2, ...result, passed: result.status === 2 });
}
const selfTest = await check({}, ["--self-test"]);
reports.push({
  label: "production-self-test",
  expected: 0,
  ...selfTest,
  passed: selfTest.status === 0,
});
const result = {
  checkerSha256: createHash("sha256").update(checker).digest("hex"),
  results: reports,
};
const passed = reports.every((report) => report.passed);
const output = JSON.stringify(result, null, 2) + "\n";
console.log(output.trimEnd());
if (!passed) console.error("Production clone checker missed a required control.");
process.exitCode = passed ? 0 : 1;
if (evidenceLabel !== undefined) {
  // Record in this process: spawning a recorder can lose stdout in restricted hosts.
  const directory = new URL("../../AUD-013-evidence/", import.meta.url);
  mkdirSync(directory, { recursive: true });
  const log = output + (passed ? "" : "Production clone checker missed a required control.\n");
  writeFileSync(new URL(`${evidenceLabel}.log`, directory), log);
  const metadata = {
    command: [process.execPath, ...process.execArgv, ...process.argv.slice(1)],
    cwd: process.cwd(),
    startedAt,
    endedAt: new Date().toISOString(),
    exitCode: process.exitCode,
    signal: null,
    failure: null,
    logSha256: createHash("sha256").update(log).digest("hex"),
    selfRecorded: true,
    checkerSha256: result.checkerSha256,
    harnessSha256: createHash("sha256")
      .update(readFileSync(import.meta.filename))
      .digest("hex"),
    logScope: "Probe JSON and its failure message; Node experimental warnings are not retained.",
  };
  writeFileSync(
    new URL(`${evidenceLabel}.command.json`, directory),
    JSON.stringify(metadata, null, 2) + "\n",
  );
}
