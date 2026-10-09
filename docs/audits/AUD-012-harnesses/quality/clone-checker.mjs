// Audit-only public synthetic inputs; the production checker executes unchanged in a VM.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("../../../..", import.meta.url)));
const scriptURL = new URL("scripts/verify-no-copies.mjs", `file://${root}/`).href;
const original = fs.readFileSync(new URL(scriptURL), "utf8");
const source = original.replace(/^import .*;\n/gm, "").replaceAll("import.meta.url", "scriptURL");
const statements = Array.from({ length: 12 }, (_, index) => `result += input * ${index + 1};`).join(" ");
const ordinary = `function sample(input) { let result = input; ${statements} return result; }`;
const exported = `export function sample(from) { const result = ${Array.from({ length: 30 }, (_, index) => `from * ${index + 1}`).join(" + ")}; return result; }`;

function probe(body, { marked = false, args = [], ending = "js" } = {}) {
  const fixture = {
    [`web/a.${ending}`]: (marked ? "// deliberate copy: binding cannot import\n" : "") + body,
    [`web/b.${ending}`]: body,
  };
  const output = [];
  let status = 0;
  const exit = new Error("synthetic process exit");
  const context = {
    scriptURL,
    URL,
    join: path.join,
    relative: path.relative,
    resolve: path.resolve,
    fileURLToPath,
    readdirSync(directory) {
      return Object.keys(fixture)
        .filter((file) => path.dirname(path.join(root, file)) === directory)
        .map((file) => ({ name: path.basename(file), isDirectory: () => false }));
    },
    readFileSync: (file) => fixture[path.relative(root, file)],
    console: { log: (text) => output.push(text), error: (text) => output.push(text) },
    process: {
      argv: ["node", "script", ...args],
      exit(code) {
        status = code;
        throw exit;
      },
    },
  };
  try {
    vm.runInNewContext(source, context);
  } catch (error) {
    if (error !== exit) throw error;
  }
  return { status, output };
}

const control = probe(ordinary);
assert.equal(control.status, 1, "positive control: ordinary duplicate must be reported");
const checks = {
  exportedFunctionWithFrom: probe(exported),
  invalidThreshold: probe(ordinary, { args: ["--tokens", "NaN"] }),
  oneSidedExemption: probe(ordinary, { marked: true }),
};
console.log(JSON.stringify({ control, checks }, null, 2));
// One-sided exemptions are documented observations, not part of the strict acceptance test.
assert.equal(checks.exportedFunctionWithFrom.status, 1, "exported active code must not be dropped as an import");
assert.notEqual(checks.invalidThreshold.status, 0, "invalid threshold must be refused");
