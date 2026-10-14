// The rules of the coding guide that the other gates cannot see (the gate `code-rules` of the
// workspace's code-core.instructions.md): each finding names its rule ID, the file and the line.
//
//   CORE-15  at most 800 lines in a Rust, Python or shell file; a Rust file's #[cfg(test)] module
//            and the generated files of GENERATED are left out, and a comment "long: <reason>" on
//            the first line (after a #! line) exempts a file. TypeScript and JavaScript are left
//            to the lint gate (oxlint's max-lines).
//   CORE-25  every dependency pinned exactly: "1.2.3" in package.json, "=1.2.3" in Cargo.toml.
//   TOOL-02  a shell script sets -euo pipefail before its first command, or says why not in a
//            header comment "no set -euo pipefail: <reason>" (a file that is only sourced).
//   TOOL-03  every Python package of a requirements file comes with its --hash.
//   TOOL-05  pnpm through package.json's packageManager, and pnpm-lock.yaml the only lockfile.
//   TS-05    no `private` keyword in TypeScript: #private fields.
//   TS-06    an error class's name ends in Error.
//   TS-08    no `enum` in TypeScript.
//   TS-09    kebab-case names for JavaScript and TypeScript files.
//   TS-11    a /** ... */ comment on every export of a library module (web/).
//   TS-12    a reason after "--" in every lint exception.
//   WEB-01   no on…= handler in markup.
//
// Audit records (docs/audits/), vendored code (vendor/), test vectors (tests/fixtures/) and build
// output are not read: they keep the bytes they were written with.
//
//   node scripts/verify-code-rules.mjs              the repository
//   node scripts/verify-code-rules.mjs --self-test  the checks against controls they must decide

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
/** CORE-15's limit for a file. */
const MAX_FILE_LINES = 800;
/** Folders never read: build output, tools, records and upstream bytes. */
const SKIPPED = [
  ".git",
  "node_modules",
  "target",
  "dist",
  "canonical-output",
  "docs/audits",
  "vendor",
  "tests/fixtures",
];
/** Generated files, long by nature, which CORE-15 lists by name. */
const GENERATED = new Set(["src/mhfe/published_rounds.rs", "src/bin/mhfe/cell_widths.rs"]);
/** The files whose length this gate counts: the lint gate counts JavaScript and TypeScript. */
const LENGTH_COUNTED = /\.(?:rs|py|sh)$/u;
const SCRIPT = /\.(?:js|mjs|ts)$/u;
/** The library modules of the browser package, whose exports need a doc comment (TS-11). */
const LIBRARY_MODULE = /^web\/[^/]+\.(?:js|d\.ts)$/u;
/** The files this gate reads; others (images, data) are only listed. */
const READ = /\.(?:rs|py|sh|js|mjs|ts|html|txt|json|toml)$/u;
const LOCKFILES_OF_OTHERS = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lockb"];

/** The usage, said with a refused command line. */
const USAGE = "usage: node scripts/verify-code-rules.mjs [--self-test]";

/** Every file of the repository this gate reads, by its path from the root. */
function repositoryFiles(directory = "") {
  return readdirSync(join(root, directory), { withFileTypes: true }).flatMap((entry) => {
    const path = directory === "" ? entry.name : `${directory}/${entry.name}`;
    if (SKIPPED.some((skipped) => path === skipped || path.startsWith(`${skipped}-`))) return [];
    if (entry.isDirectory()) return entry.name === "__pycache__" ? [] : repositoryFiles(path);
    return READ.test(entry.name) ? [path] : [];
  });
}

/** A finding: the rule, where it is and what to do. */
function finding(rule, path, line, message) {
  return `${rule} ${path}${line > 0 ? `:${line}` : ""}: ${message}`;
}

/** The lines of a Rust file without its `#[cfg(test)]` module, the part CORE-15 counts. */
function rustLinesWithoutTests(lines) {
  const start = lines.findIndex(
    (line, index) =>
      line.startsWith("#[cfg(test)]") &&
      /^(?:pub(?:\(crate\))? )?mod \w+ \{/u.test(lines[index + 1] ?? ""),
  );
  if (start === -1) return lines.length;
  const end = lines.findIndex((line, index) => index > start + 1 && line === "}");
  return end === -1 ? start : lines.length - (end - start + 1);
}

/** The first line after a #! line, where a file's exemption comment stands. */
function headLine(lines) {
  return lines[0]?.startsWith("#!") ? (lines[1] ?? "") : (lines[0] ?? "");
}

/** CORE-15: the length of a Rust, Python or shell file. */
function lengthFindings(path, lines) {
  if (!LENGTH_COUNTED.test(path) || GENERATED.has(path)) return [];
  if (/^\s*(?:\/\/|#)\s*long: \S/u.test(headLine(lines))) return [];
  const counted = path.endsWith(".rs") ? rustLinesWithoutTests(lines) : lines.length;
  if (counted <= MAX_FILE_LINES) return [];
  const what = path.endsWith(".rs") ? "lines without its test module" : "lines";
  return [
    finding(
      "CORE-15",
      path,
      0,
      `${counted} ${what}, at most ${MAX_FILE_LINES}: split it, or write "long: <reason>" on its first line`,
    ),
  ];
}

/** TOOL-02: `set -euo pipefail` before the first command of a shell script. */
function shellFindings(path, lines) {
  if (!path.endsWith(".sh")) return [];
  for (const line of lines) {
    if (/^#\s*no set -euo pipefail: \S/u.test(line)) return [];
    if (line === "" || line.startsWith("#")) continue;
    if (line === "set -euo pipefail") return [];
    break;
  }
  return [
    finding(
      "TOOL-02",
      path,
      0,
      'set -euo pipefail before its first command, or a header comment "no set -euo pipefail: <reason>"',
    ),
  ];
}

/** TOOL-03: every requirement of a pip requirements file with its hash. */
function requirementsFindings(path, text) {
  if (!/requirements[^/]*\.txt$/u.test(path)) return [];
  const requirements = text
    .replace(/\\\n/gu, " ")
    .split("\n")
    .map((line, index) => ({ line: line.replace(/#.*$/u, "").trim(), number: index + 1 }))
    .filter(({ line }) => line !== "" && !line.startsWith("-"));
  return requirements
    .filter(({ line }) => !/--hash=sha256:[0-9a-f]{64}/u.test(line))
    .map(({ line, number }) =>
      finding("TOOL-03", path, number, `${line.split(" ")[0]} without --hash=sha256:…`),
    );
}

/** TS-09: kebab-case JavaScript and TypeScript file names. */
function fileNameFindings(path) {
  if (!SCRIPT.test(path)) return [];
  const name = path.slice(path.lastIndexOf("/") + 1);
  if (/^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.d)?\.(?:js|mjs|ts)$/u.test(name)) return [];
  return [finding("TS-09", path, 0, "the file name is not kebab-case")];
}

/** The line numbers (from 1) of the lines of `lines` that match `pattern`. */
function matchingLines(lines, pattern) {
  return lines.flatMap((line, index) => (pattern.test(line) ? [index + 1] : []));
}

/** TS-06, TS-05, TS-08 and TS-12 in a JavaScript or TypeScript file. */
function scriptFindings(path, lines) {
  if (!SCRIPT.test(path)) return [];
  const found = [];
  for (const [index, line] of lines.entries()) {
    const errorClass = /\bclass\s+(\w+)\s+extends\s+(\w*Error)\b/u.exec(line);
    if (errorClass !== null && !errorClass[1].endsWith("Error")) {
      found.push(
        finding("TS-06", path, index + 1, `the error class ${errorClass[1]} ends in Error`),
      );
    }
    const exception = /(?:oxlint|eslint)-(?:disable|enable)(?:-next-line|-line)?\b(.*)/u.exec(line);
    if (exception !== null && !/\s--\s+\S/u.test(exception[1])) {
      found.push(finding("TS-12", path, index + 1, 'a lint exception without "-- <reason>"'));
    }
  }
  if (path.endsWith(".ts")) {
    const enums = matchingLines(lines, /^\s*(?:export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+\w/u);
    const privates = matchingLines(
      lines,
      /^\s*(?:(?:public|protected|static|readonly|abstract|declare)\s+)*private\s+/u,
    );
    for (const line of enums)
      found.push(finding("TS-08", path, line, "an enum: a union of literals"));
    for (const line of privates)
      found.push(finding("TS-05", path, line, "private: a #private field"));
  }
  return found;
}

/** Whether the code before line `index` ends with a /** ... *\/ comment. */
function hasDocComment(lines, index) {
  let above = index - 1;
  while (above >= 0 && lines[above].trim() === "") above -= 1;
  if (above < 0 || !lines[above].trimEnd().endsWith("*/")) return false;
  while (above >= 0 && !lines[above].includes("/*")) above -= 1;
  return above >= 0 && lines[above].includes("/**");
}

/** TS-11: a doc comment on every export of a library module, re-export lists aside. */
function docCommentFindings(path, lines) {
  if (!LIBRARY_MODULE.test(path)) return [];
  return lines.flatMap((line, index) => {
    if (!/^export\s+(?!\{|\*|type\s*\{)/u.test(line) || hasDocComment(lines, index)) return [];
    const name = /^export\s+(?:declare\s+)?(?:default\s+)?(?:async\s+)?\w+\s+(\w+)/u.exec(line);
    return [finding("TS-11", path, index + 1, `${name?.[1] ?? "an export"} has no /** */ comment`)];
  });
}

/** WEB-01: no inline handler such as onclick= in markup, in a page or in a script's template. */
function markupFindings(path, lines) {
  if (!/\.(?:html|js|mjs)$/u.test(path)) return [];
  return matchingLines(lines, /<[a-zA-Z][^<>]*\son[a-z]+\s*=/u).map((line) =>
    finding("WEB-01", path, line, "an on…= handler in markup: use addEventListener"),
  );
}

/** Every finding of one file. */
function fileFindings(path, text) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return [
    ...lengthFindings(path, lines),
    ...shellFindings(path, lines),
    ...requirementsFindings(path, text),
    ...fileNameFindings(path),
    ...scriptFindings(path, lines),
    ...docCommentFindings(path, lines),
    ...markupFindings(path, lines),
  ];
}

/** CORE-25 and TOOL-05 in package.json: exact versions and pnpm through packageManager. */
function packageFindings(text) {
  const manifest = JSON.parse(text);
  const found = [];
  for (const group of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    for (const [name, version] of Object.entries(manifest[group] ?? {})) {
      if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(String(version))) {
        found.push(
          finding(
            "CORE-25",
            "package.json",
            0,
            `${name} ${String(version)} is not one exact version`,
          ),
        );
      }
    }
  }
  if (!/^pnpm@\d+\.\d+\.\d+$/u.test(String(manifest.packageManager))) {
    found.push(finding("TOOL-05", "package.json", 0, 'packageManager names no exact "pnpm@x.y.z"'));
  }
  return found;
}

/** CORE-25 in Cargo.toml: every dependency's version "=x.y.z". */
function cargoFindings(text) {
  let inDependencies = false;
  return text.split("\n").flatMap((line, index) => {
    const section = /^\[(.+)\]\s*$/u.exec(line);
    if (section !== null) {
      inDependencies = /(?:^|\.)(?:dev-|build-)?dependencies$/u.test(section[1]);
      return [];
    }
    const dependency = /^([\w-]+)\s*=\s*(.*)$/u.exec(line);
    if (!inDependencies || dependency === null) return [];
    const version = /^"([^"]*)"|version\s*=\s*"([^"]*)"/u.exec(dependency[2]);
    const value = version?.[1] ?? version?.[2];
    if (value !== undefined && /^=\d+\.\d+\.\d+/u.test(value)) return [];
    return [
      finding("CORE-25", "Cargo.toml", index + 1, `${dependency[1]} is not pinned as "=x.y.z"`),
    ];
  });
}

/** TOOL-05: pnpm-lock.yaml present, and no lockfile of another package manager. */
function lockfileFindings(exists) {
  const found = LOCKFILES_OF_OTHERS.filter(exists).map((name) =>
    finding("TOOL-05", name, 0, "a lockfile of another package manager: pnpm-lock.yaml only"),
  );
  if (!exists("pnpm-lock.yaml")) found.push(finding("TOOL-05", "pnpm-lock.yaml", 0, "missing"));
  return found;
}

/** Every finding of the repository at `root`. */
function repositoryFindings() {
  const read = (path) => readFileSync(join(root, path), "utf8");
  const files = repositoryFiles();
  return [
    ...files.flatMap((path) => fileFindings(path, read(path))),
    ...packageFindings(read("package.json")),
    ...cargoFindings(read("Cargo.toml")),
    ...lockfileFindings((name) => existsSync(join(root, name))),
  ];
}

/**
 * The controls of the file checks: a path, its text, and the rule it must break, or null. The
 * texts that break a rule are joined from two parts, so that this file does not break it.
 */
function fileControls() {
  const lines = (count, line) => Array.from({ length: count }, () => line).join("\n");
  const rustTests = `${lines(799, "fn a() {}")}\n#[cfg(test)]\nmod tests {\n${lines(20, "    fn b() {}")}\n}\n`;
  return [
    ["src/long.rs", `${lines(801, "fn a() {}")}\n`, "CORE-15"],
    ["src/tested.rs", rustTests, null],
    ["src/exempt.rs", `// long: one table read whole\n${lines(900, "fn a() {}")}\n`, null],
    ["src/mhfe/published_rounds.rs", `${lines(900, "x")}\n`, null],
    ["scripts/long.py", `${lines(801, "x = 1")}\n`, "CORE-15"],
    ["scripts/a.sh", "#!/usr/bin/env bash\n# What it does.\nset -euo pipefail\nls\n", null],
    ["scripts/b.sh", "#!/usr/bin/env bash\nls\nset -euo pipefail\n", "TOOL-02"],
    [
      "scripts/c.sh",
      "# no set -euo pipefail: sourced into scripts that set it.\nf() { :; }\n",
      null,
    ],
    ["scripts/r-requirements.txt", "a==1.0 \\\n    --hash=sha256:" + "0".repeat(64) + "\n", null],
    ["scripts/s-requirements.txt", "# pins\na==1.0\n", "TOOL-03"],
    ["scripts/BadName.mjs", "export const a = 1;\n", "TS-09"],
    ["scripts/a.mjs", "class Refusal extends Mhfe" + "Error {}\n", "TS-06"],
    ["scripts/b.mjs", "class RefusalError extends MhfeError {}\n", null],
    ["scripts/c.mjs", "// oxlint-" + "disable-next-line max-lines-per-function\n", "TS-12"],
    ["scripts/d.mjs", "// oxlint-disable-next-line max-lines-per-function -- a table\n", null],
    ["web/a.d.ts", "/** Kinds. */\nexport enum Kind { A }\n", "TS-08"],
    ["web/b.d.ts", "/** A class. */\nexport class A {\n  private b: number;\n}\n", "TS-05"],
    ["web/c.js", "export function f() {}\n", "TS-11"],
    [
      "web/d.js",
      '/**\n * A function.\n */\nexport function f() {}\nexport { g } from "./g.js";\n',
      null,
    ],
    ["scripts/e.mjs", "const page = `<button on" + 'click="go()">`;\n', "WEB-01"],
    ["scripts/f.mjs", 'const page = `<button id="go">`;\n', null],
  ];
}

/** The checks against controls they must decide right, and a refused command line. */
function selfTest() {
  for (const [path, text, rule] of fileControls()) {
    const rules = fileFindings(path, text).map((found) => found.split(" ")[0]);
    const decided = rule === null ? rules.length === 0 : rules.length === 1 && rules[0] === rule;
    if (!decided) throw new Error(`self-test: ${path} gives ${JSON.stringify(rules)}, not ${rule}`);
  }
  const repository = [
    [packageFindings('{"packageManager":"pnpm@12.8.1","devDependencies":{"a":"1.2.3"}}'), 0],
    [packageFindings('{"packageManager":"npm@11.0.0","devDependencies":{"a":"^1.2.3"}}'), 2],
    [
      cargoFindings('[dependencies]\na = "=1.0.0"\nb = { version = "=2.0.0", features = ["c"] }\n'),
      0,
    ],
    [cargoFindings("[target.'cfg(unix)'.dependencies]\na = \"1.0\"\n[features]\nb = []\n"), 1],
    [lockfileFindings((name) => name === "pnpm-lock.yaml"), 0],
    [lockfileFindings((name) => name === "package-lock.json"), 2],
  ];
  for (const [index, [found, expected]] of repository.entries()) {
    if (found.length !== expected) {
      throw new Error(`self-test: repository control ${index + 1} gives ${JSON.stringify(found)}`);
    }
  }
  const controls = fileControls().length + repository.length;
  console.log(`The code rules decide all ${controls} of their controls right.`);
}

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--self-test") {
  selfTest();
} else if (args.length === 0) {
  const found = repositoryFindings();
  for (const line of found) console.error(line);
  if (found.length > 0) {
    console.error(
      `${found.length} breaks of the coding guide (see the top of scripts/verify-code-rules.mjs).`,
    );
    process.exit(1);
  }
  console.log("The repository keeps the coding guide's rules that code-rules checks.");
} else {
  console.error(USAGE);
  process.exit(2);
}
