// The rules of the coding guide that the other gates cannot see (the gate `code-rules` of the
// workspace's code-core.instructions.md): each finding names its rule ID, the file and the line.
//
//   CORE-15  at most 800 lines in a Rust, Python or shell file; a Rust file's #[cfg(test)] module
//            and the generated files of GENERATED are left out, and a comment "long: <reason>" on
//            the first line (after a #! line) exempts a file. TypeScript and JavaScript are left
//            to the lint gate (oxlint's max-lines).
//   CORE-25  every dependency pinned exactly: "1.2.3" in package.json, "=1.2.3" in Cargo.toml.
//   CORE-02/03 externally public library records have private fields and operations belong to
//            owner types; wasm-bindgen exports and executable front ends are adapters.
//   RUST-05  no assert!, assert_eq!, assert_ne!, unreachable!, todo! or unimplemented! in Rust code
//            outside its tests and const blocks, which clippy's panic lints do not see: a
//            refusal, or the documented exception of an expect (AUD-024-API016).
//   TOOL-02  a shell script sets -euo pipefail before its first command, or says why not in a
//            header comment "no set -euo pipefail: <reason>" (a file that is only sourced).
//   TOOL-03  every Python package of a requirements file comes with its --hash.
//   TOOL-04  Python code at most 99 columns, comment-only lines and docstrings at most 72,
//            the owner's agreed PEP 8 widths (AUD-024-ARC037).
//   TOOL-05  pnpm through package.json's packageManager, and pnpm-lock.yaml the only lockfile.
//   TS-05    no `private` keyword in TypeScript: #private fields.
//   TS-06    an error class's name ends in Error.
//   TS-08    no `enum` in TypeScript.
//   TS-09    kebab-case names for JavaScript and TypeScript files.
//   TS-11    a /** ... */ comment on every export of a library module (web/).
//   TS-12    a reason after "--" in every lint exception.
//   WEB-01   no on…= handler in markup.
//
// It reads the files Git would commit: tracked and new files, not what .gitignore or
// .git/info/exclude leave out (build output, tools, other working trees). Audit records
// (docs/audits/), vendored code (vendor/) and test vectors (tests/fixtures/) are not read either:
// they keep the bytes they were written with.
//
//   node scripts/verify-code-rules.mjs              the repository
//   node scripts/verify-code-rules.mjs --self-test  the checks against controls they must decide

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reported, runGate } from "./gate-command-line.mjs";
import { rustProductionLines, rustRunTimeLines } from "./rust-code.mjs";

/** Public Rust library ownership, including inline modules and multiline impl headers. */
function libraryOwners(path, source) {
  if (
    !path.startsWith("src/") ||
    !path.endsWith(".rs") ||
    path.startsWith("src/bin/") ||
    path.startsWith("src/wasm_api")
  )
    return [];
  const findings = [];
  const scopes = [];
  let pending = null;
  // Rust permits visibility on items and record fields only. Recognize item/modifier keywords
  // instead of parsing tuple fields through generic bounds, function arrows and const expressions.
  const itemStarts = new Set([
    "fn",
    "const",
    "async",
    "unsafe",
    "safe",
    "extern",
    "struct",
    "enum",
    "union",
    "type",
    "trait",
    "mod",
    "use",
    "static",
    "macro",
    "default",
  ]);
  const lines = rustProductionLines(source.split("\n"));
  const joined = lines.map(([, code]) => code).join("\n");
  let offset = 0;
  for (const [line, code] of lines) {
    for (const token of code.matchAll(/[A-Za-z_]\w*|[{}();<>,]/gu)) {
      const word = token[0];
      if (word === "pub") {
        const after = joined.slice(offset + token.index + word.length).trimStart();
        const nextWord = /^[A-Za-z_]\w*/u.exec(after)?.[0];
        const restricted = /^\(\s*(?:(?:crate|self|super)\s*\)|in\b)/u.test(after);
        const macroOperand = after.startsWith(",");
        const inRecord = pending === "struct" || scopes.at(-1) === "struct";
        if (!restricted && !macroOperand && (inRecord || !itemStarts.has(nextWord))) {
          findings.push(`CORE-02 ${path}:${line}: a public record exposes writable fields`);
        }
      }
      if (
        word === "pub" &&
        /^pub\s+(?:(?:const|async|unsafe|extern)\s+)*fn\s+[A-Za-z_]/u.test(
          code.slice(token.index),
        ) &&
        !scopes.includes("impl") &&
        !scopes.includes("trait")
      )
        findings.push(`CORE-03 ${path}:${line}: a public operation has no owner type`);
      if (["impl", "trait", "fn", "struct", "enum", "mod"].includes(word) && pending === null) {
        pending = word;
      } else if (word === "{") {
        scopes.push(pending);
        pending = null;
      } else if (word === "}") {
        scopes.pop();
        pending = null;
      } else if (word === ";") pending = null;
    }
    offset += code.length + 1;
  }
  return findings;
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
/** CORE-15's limit for a file. */
const MAX_FILE_LINES = 800;
/** Folders Git commits that this gate does not read: records and upstream bytes. */
const SKIPPED = ["docs/audits/", "vendor/", "tests/fixtures/"];
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
function repositoryFiles() {
  const listed = execFileSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: root, encoding: "utf8" },
  );
  return listed
    .split("\0")
    .filter((path) => READ.test(path) && !SKIPPED.some((skipped) => path.startsWith(skipped)))
    .filter((path) => existsSync(join(root, path)));
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
    // A diagnostic string mentioning a directive is not an actual lint exception.
    const exception =
      /(?:\/\/|\/\*|^\s*\*)\s*(?:oxlint|eslint)-(?:disable|enable)(?:-next-line|-line)?\b(.*)/u.exec(
        line,
      );
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

/**
 * CORE-19/20: adjacent JSDoc blocks, except type declarations, and a Rust doc's one-line
 * summary joined to a new sentence. This catches the recurring misplaced-comment pattern; it
 * cannot decide whether a comment's meaning fits its item. Genuine new Rust paragraphs use a
 * blank /// line, so that they are distinct from a sentence accidentally moved onto an item.
 */
function joinedDocFindings(path, lines) {
  const found = [];
  if (path.endsWith(".rs")) {
    for (let i = 0; i < lines.length - 1; i += 1) {
      const first = /^\s*\/\/\/\s*(.*)$/u.exec(lines[i]);
      if (first === null || (i > 0 && /^\s*\/\/\//u.test(lines[i - 1]))) continue;
      const next = /^\s*\/\/\/\s*([A-Z].*)$/u.exec(lines[i + 1]);
      if (first[1].endsWith(".") && !first[1].startsWith("-") && next !== null) {
        found.push(finding("CORE-19", path, i + 1, "joined doc paragraphs: review the item's doc"));
      }
    }
  } else if (/\.[cm]?[jt]s$/u.test(path)) {
    let previous;
    for (let i = 0; i < lines.length; i += 1) {
      if (!/^\s*\/\*\*/u.test(lines[i])) continue;
      const start = i;
      while (i < lines.length - 1 && !lines[i].includes("*/")) i += 1;
      const block = lines.slice(start, i + 1).join("\n");
      const typedef = /@(?:typedef|import|callback)\b/u.test(block);
      if (
        previous !== undefined &&
        lines.slice(previous.end + 1, start).every((line) => line.trim() === "") &&
        !previous.typedef &&
        !typedef
      ) {
        found.push(finding("CORE-19", path, start + 1, "adjacent doc blocks: review their items"));
      }
      previous =
        lines[i].slice(lines[i].indexOf("*/") + 2).trim() === "" ? { end: i, typedef } : undefined;
    }
  }
  return found;
}

/** WEB-01: no inline handler such as onclick= in markup, in a page or in a script's template. */
function markupFindings(path, lines) {
  if (!/\.(?:html|js|mjs)$/u.test(path)) return [];
  return matchingLines(lines, /<[a-zA-Z][^<>]*\son[a-z]+\s*=/u).map((line) =>
    finding("WEB-01", path, line, "an on…= handler in markup: use addEventListener"),
  );
}

/** A macro that panics at run time, which clippy's lints do not report. */
const PANICKING_MACRO = /(?<![\w:])(?:assert|assert_eq|assert_ne|unreachable|todo|unimplemented)!/u;

/** RUST-05: a panicking macro in the run-time code of a Rust file that is not a test module. */
function panicFindings(path, lines, testModules) {
  if (!/^src\/.*\.rs$/u.test(path) || testModules.has(path)) return [];
  return rustRunTimeLines(lines)
    .filter(([, code]) => PANICKING_MACRO.test(code))
    .map(([line]) =>
      finding("RUST-05", path, line, "a panicking macro outside tests: refuse with an error"),
    );
}

/** The Rust files that hold a module declared `#[cfg(test)] mod name;`, from every file's text. */
function testModuleFiles(texts) {
  const files = new Set();
  for (const [path, text] of texts) {
    if (!path.endsWith(".rs")) continue;
    const folder = /(?:^|\/)(?:lib|main|mod)\.rs$/u.test(path)
      ? path.replace(/[^/]+$/u, "")
      : path.replace(/\.rs$/u, "/");
    for (const match of text.matchAll(/#\[cfg\(test\)\]\s*(?:pub(?:\(crate\))? )?mod (\w+);/gu)) {
      files.add(`${folder}${match[1]}.rs`);
    }
  }
  return files;
}

/** Every finding of one file. */
function fileFindings(path, text, testModules = new Set()) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return [
    ...lengthFindings(path, lines),
    ...shellFindings(path, lines),
    ...requirementsFindings(path, text),
    ...fileNameFindings(path),
    ...scriptFindings(path, lines),
    ...docCommentFindings(path, lines),
    ...joinedDocFindings(path, lines),
    ...markupFindings(path, lines),
    ...panicFindings(path, lines, testModules),
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
  // Cargo's table, quoted and dotted keys are TOML syntax, not line patterns (AUD-024-BLD010).
  const dependencies = JSON.parse(
    execFileSync("python3", [join(root, "scripts/cargo-dependencies.py")], {
      input: text,
      encoding: "utf8",
    }),
  );
  const exact = /^=\d+\.\d+\.\d+(?:-[\dA-Za-z.-]+)?(?:\+[\dA-Za-z.-]+)?$/u;
  return dependencies
    .filter(({ version }) => typeof version !== "string" || !exact.test(version))
    .map(({ name, section }) =>
      finding("CORE-25", "Cargo.toml", 0, `${section}.${name} is not pinned as "=x.y.z"`),
    );
}

/** Every Cargo spelling of a dependency must preserve the exact-version rule. */
function cargoControls() {
  const declarations = [
    '[dependencies.foo]\nversion = "VERSION"',
    "[target.'cfg(unix)'.dependencies.foo]\nversion = \"VERSION\"",
    '[dev-dependencies.foo]\nversion = "VERSION"',
    '[build-dependencies.foo]\nversion = "VERSION"',
    '[dependencies]\n  foo = "VERSION"',
    '[dependencies]\n"foo" = "VERSION"',
    '[dependencies]\nfoo.version = "VERSION"',
    '[dependencies] # runtime\nfoo = "VERSION"',
  ];
  return declarations
    .flatMap((text) => [
      [cargoFindings(text.replace("VERSION", "^1.2")), 1],
      [cargoFindings(text.replace("VERSION", "=1.2.3")), 0],
    ])
    .concat([[cargoFindings('[dependencies.foo]\ngit = "https://example.invalid/foo"'), 1]]);
}

/** TOOL-05: pnpm-lock.yaml present, and no lockfile of another package manager. */
function lockfileFindings(exists) {
  const found = LOCKFILES_OF_OTHERS.filter(exists).map((name) =>
    finding("TOOL-05", name, 0, "a lockfile of another package manager: pnpm-lock.yaml only"),
  );
  if (!exists("pnpm-lock.yaml")) found.push(finding("TOOL-05", "pnpm-lock.yaml", 0, "missing"));
  return found;
}

/** TOOL-04: Python's own AST identifies docstrings, including nested ones. */
function pythonFindings(texts) {
  const sources = Object.fromEntries([...texts].filter(([path]) => path.endsWith(".py")));
  return JSON.parse(
    execFileSync("python3", [join(root, "scripts/python-style.py")], {
      cwd: root,
      input: JSON.stringify(sources),
      encoding: "utf8",
    }),
  );
}

/** Boundary, nesting and string-literal controls for the Python width check. */
function pythonControls() {
  const code = (width) => `value = "${"x".repeat(width - 10)}"\n`;
  const comment = (width) => `# ${"x".repeat(width - 2)}\n`;
  const doc = (width) => `def f():\n    """\n    ${"x".repeat(width - 4)}\n    """\n`;
  return [
    [code(99), 0],
    [code(100), 1],
    [comment(72), 0],
    [comment(73), 1],
    [doc(72), 0],
    [doc(73), 1],
    [`value = "${"#".repeat(80)}"\n`, 0],
    [`value = """\n${"x".repeat(99)}\n"""\n`, 0],
    [`class C:\n    """\n    ${"x".repeat(69)}\n    """\n`, 1],
  ];
}

/** Every finding of the repository at `root`. */
function repositoryFindings() {
  const read = (path) => readFileSync(join(root, path), "utf8");
  const texts = new Map(repositoryFiles().map((path) => [path, read(path)]));
  const testModules = testModuleFiles(texts);
  return [
    ...[...texts].flatMap(([path, text]) => [
      ...fileFindings(path, text, testModules),
      ...(testModules.has(path) ? [] : libraryOwners(path, text)),
    ]),
    ...pythonFindings(texts),
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
    ["scripts/directive-text.mjs", 'const text = "oxlint-disable max-lines";\n', null],
    ["scripts/inline.mjs", "f(); // oxlint-" + "disable-line no-alert\n", "TS-12"],
    ["scripts/block.mjs", "/*\n * oxlint-" + "disable no-alert\n */\n", "TS-12"],
    ["web/a.d.ts", "/** Kinds. */\nexport enum Kind { A }\n", "TS-08"],
    ["web/b.d.ts", "/** A class. */\nexport class A {\n  private b: number;\n}\n", "TS-05"],
    ["web/c.js", "export function f() {}\n", "TS-11"],
    ["web/joined.js", "/** One item. */\n/** Another item. */\nfunction f() {}\n", "CORE-19"],
    ["web/typedef.js", "/** @typedef {string} Name */\n/** The item. */\nfunction f() {}\n", null],
    [
      "web/import.js",
      "/** @import {Name} from './a.js' */\n/** The item. */\nconst a = 1;\n",
      null,
    ],
    ["web/inline.js", "/** @type {string} */ let a;\n/** @type {string} */ let b;\n", null],
    [
      "web/separate.js",
      "/** One item. */\nfunction f() {}\n/** Another. */\nfunction g() {}\n",
      null,
    ],
    ["src/joined.rs", "/// One item.\n/// Another item.\nfn f() {}\n", "CORE-19"],
    ["src/paragraph.rs", "/// The item.\n///\n/// Its details.\nfn f() {}\n", null],
    ["src/wrapped.rs", "/// The item and its\n/// Wrapped description.\nfn f() {}\n", null],
    [
      "web/d.js",
      '/**\n * A function.\n */\nexport function f() {}\nexport { g } from "./g.js";\n',
      null,
    ],
    ["scripts/e.mjs", "const page = `<button on" + 'click="go()">`;\n', "WEB-01"],
    ["scripts/f.mjs", 'const page = `<button id="go">`;\n', null],
    ["src/g.rs", "fn f(n: u8) {\n    asse" + "rt!(n > 0);\n}\n", "RUST-05"],
    ["src/h.rs", "fn f() {\n    unreach" + "able!();\n}\n", "RUST-05"],
    [
      "src/i.rs",
      "const _: () = {\n    assert!(1 > 0);\n};\nfn f() {\n    debug_assert!(true);\n}\n" +
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(1, 1);\n    }\n}\n",
      null,
    ],
    [
      "src/j.rs",
      "const fn h() {\n    assert!(true);\n}\n#[cfg(all(test, unix))]\n/// Doc.\nfn t() {\n" +
        '    assert!(true);\n}\nfn f() {\n    let a = ["//"]; // assert!(false)\n}\n',
      null,
    ],
    ["src/k.rs", 'fn f() {\n    let a = ["//"];\n    todo' + "!();\n}\n", "RUST-05"],
    [
      "src/literal-brace.rs",
      '#[cfg(test)]\nmod tests {\n let s = "}";\n assert!(true);\n}\n',
      null,
    ],
    [
      "src/after-tests.rs",
      '#[cfg(test)]\nmod tests {\n let s = "}";\n}\nfn f() { assert!(false); }\n',
      "RUST-05",
    ],
    ["src/raw-literal.rs", 'fn f() { let s = r##"{ assert!(false); }"##; }\n', null],
    ["src/character-brace.rs", "#[cfg(test)]\nmod tests { let c = '}'; assert!(true); }\n", null],
    ["src/block-comment.rs", "/* nested /* } */ } */\nfn f() { assert!(false); }\n", "RUST-05"],
  ];
}

/** The checks against controls they must decide right, and a refused command line. */
function selfTest() {
  const ownerControls = [
    ["pub fn raw() {}", 1],
    ["pub const fn raw() -> u8 { 0 }", 1],
    ["pub struct Owner {\n pub value: u8,\n}", 1],
    ["pub struct Owner(pub u8);", 1],
    ["pub struct Owner(\n pub u8,\n);", 1],
    ["pub struct Owner { pub value: u8 }", 1],
    ['pub extern "C" fn raw() {}', 1],
    ['impl Owner { pub extern "C" fn owned() {} }', 0],
    ["pub struct Owner(\n u8,\n);", 0],
    ["pub struct Owner<T: Fn()>(pub T);", 1],
    ["pub struct Owner<T: Fn()>(T);", 0],
    ["pub struct Owner<T: Fn() -> (u8, u8)>(pub T);", 1],
    ["pub struct Owner<T: Fn() -> (u8, u8)>(T);", 0],
    ["pub struct Owner<const N: usize = { 1 }>(pub [u8; N]);", 1],
    ["pub struct Owner<const N: usize = { 1 }>([u8; N]);", 0],
    ["pub struct Owner(\n pub\n u8,\n);", 1],
    ["pub struct Owner(pub(crate) u8);", 0],
    ["define_coins! { pub, Bitcoin = 0 => Rules::new() }", 0],
    ["pub struct Owner(pub (u8, u8));", 1],
    ["pub struct Owner((u8, u8));", 0],
    ["pub struct Owner(pub *const u8);", 1],
    ["pub struct Owner(*const u8);", 0],
    ["pub struct Owner(pub fn());", 1],
    ["pub struct Owner(fn());", 0],
    ["pub struct Owner(u8);\nimpl Owner { pub fn get(&self) -> u8 { self.0 } }", 0],
    ["impl<T>\n Owner<T> { pub fn get(&self) {} }\npub fn raw() {}", 1],
    ["pub mod nested { pub fn raw() {} }", 1],
    ["#[cfg(test)]\nmod tests { pub fn fixture() {} }", 0],
    ['const TEXT: &str = "pub fn fake() {}";\nfn private() {}', 0],
    ["pub struct Owner { value: u8 }\nimpl Owner { pub fn read(&self) {} }", 0],
  ];
  for (const [source, count] of ownerControls) {
    const found = libraryOwners("src/control.rs", source);
    if (found.length !== count) throw new Error(`owner control: ${JSON.stringify(found)}`);
  }
  for (const path of ["src/bin/mhfe/main.rs", "src/wasm_api/core.rs", "tests/control.rs"]) {
    if (libraryOwners(path, "pub fn adapter() {}").length !== 0) {
      throw new Error(`owner control: adapter scope ${path}`);
    }
  }
  for (const [index, [text, expected]] of pythonControls().entries()) {
    const found = pythonFindings(new Map([[`control-${index}.py`, text]]));
    if (found.length !== expected || found.some((issue) => !issue.startsWith("TOOL-04 "))) {
      throw new Error(`self-test: Python width control ${index + 1}: ${JSON.stringify(found)}`);
    }
  }
  for (const [path, text, rule] of fileControls()) {
    const rules = fileFindings(path, text).map((found) => found.split(" ")[0]);
    const decided = rule === null ? rules.length === 0 : rules.length === 1 && rules[0] === rule;
    if (!decided) throw new Error(`self-test: ${path} gives ${JSON.stringify(rules)}, not ${rule}`);
  }
  const repository = [
    ...cargoControls(),
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
  const controls = fileControls().length + repository.length + pythonControls().length;
  console.log(`The code rules decide all ${controls} of their controls right.`);
}

runGate(USAGE, {
  selfTest,
  check: () =>
    reported(
      repositoryFindings(),
      (count) =>
        `${count} breaks of the coding guide (see the top of scripts/verify-code-rules.mjs).`,
      "The repository keeps the coding guide's rules that code-rules checks.",
    ),
});
