// AUD-010 probe (docs-build-release): the error codes of the library, the browser declarations and
// the documents agree. Exits 1 on any disagreement.
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/error-codes.mjs
//
// - Every code of MhfeError::code() (src/error.rs) is in the table of docs/API.md and in
//   MhfeErrorCode (web/runtime.d.ts), and the API.md table lists no other code.
// - Every MhfeErrorCode member is raised somewhere: by the Rust library or in a web/ script.
// - Every code-like name in backticks in the user documents and the release notes is a known code
//   or one of the reviewed non-code names below.
import { readFileSync, readdirSync } from "node:fs";

const read = (path) => readFileSync(path, "utf8");
const errorRs = read("src/error.rs");
const codeFn = errorRs.slice(errorRs.indexOf("fn code("));
const rustCodes = new Set(
  [...codeFn.slice(0, codeFn.indexOf("\n    }\n")).matchAll(/"([A-Z][A-Z0-9_]+)"/gu)].map(
    (m) => m[1],
  ),
);
const declarations = read("web/runtime.d.ts");
// The union up to its closing semicolon, read without its doc comments, which hold semicolons.
const union = declarations
  .slice(declarations.indexOf("export type MhfeErrorCode"))
  .replace(/\/\*[\s\S]*?\*\//gu, "");
const declared = new Set(
  [...union.slice(0, union.indexOf(";")).matchAll(/\|\s*"([A-Z][A-Z0-9_]+)"/gu)].map((m) => m[1]),
);
const api = read("docs/API.md");
const errorsSection = api.slice(api.indexOf("### Errors"), api.indexOf("## Browser package"));
const apiTable = new Set(
  [...errorsSection.matchAll(/^\| `([A-Z][A-Z0-9_]+)`/gmu)].map((match) => match[1]),
);
const webSources = readdirSync("web")
  .filter((name) => name.endsWith(".js"))
  .map((name) => read(`web/${name}`))
  .join("\n");
const raisedInWeb = new Set(
  [...webSources.matchAll(/"([A-Z][A-Z0-9_]{3,})"/gu)].map((match) => match[1]),
);

const problems = [];
for (const code of rustCodes) {
  if (!apiTable.has(code)) problems.push(`${code}: in src/error.rs, not in the API.md table`);
  if (!declared.has(code)) problems.push(`${code}: in src/error.rs, not in MhfeErrorCode`);
}
for (const code of apiTable) {
  if (!rustCodes.has(code)) problems.push(`${code}: in the API.md table, not in src/error.rs`);
}
for (const code of declared) {
  if (!rustCodes.has(code) && !raisedInWeb.has(code)) {
    problems.push(`${code}: declared in MhfeErrorCode, raised nowhere`);
  }
}

// Names in backticks that are not error codes, reviewed by hand: constants, markers, files.
const NOT_CODES = new Set([
  "BUILD_ID",
  "ARGON2_THREADED_BUILD_ID",
  "ARGON2_SINGLE_THREADED_BUILD_ID",
  "SHA256SUMS",
  "MHFE",
  "REDUCED_COST_MARKER",
  // Named in the release notes as removed in 0.5.0.
  "PROCESSOR_NOT_SUPPORTED",
  // Files, kernel and C names, a wallet brand, and constants of the library (docs/API.md).
  "LICENSE",
  "HEAD",
  "RLIMIT_CORE",
  "PR_SET_DUMPABLE",
  "MADV_DONTDUMP",
  "TREZOR",
  "BUILT_IN_CHECK_WORD_COUNTS",
  "WORD_COUNTS",
  "PUBLIC_INPUTS",
  "NEGATIVE_INPUTS",
  "SAME_LENGTH_INPUTS",
  "SAME_LENGTH_NEGATIVE_INPUTS",
]);
const known = new Set([...rustCodes, ...declared]);
const DOCUMENTS = [
  "README.md",
  "SECURITY.md",
  "docs/API.md",
  "docs/BROWSER-PACKAGE.md",
  "docs/releases/v0.5.0.md",
];
for (const path of DOCUMENTS) {
  for (const [index, line] of read(path).split("\n").entries()) {
    for (const match of line.matchAll(/`([A-Z][A-Z0-9_]{3,})`/gu)) {
      const name = match[1];
      if (!known.has(name) && !NOT_CODES.has(name)) {
        problems.push(`${path}:${index + 1}: \`${name}\` is no known error code`);
      }
    }
  }
}

console.log(
  `src/error.rs: ${rustCodes.size} codes; API.md table: ${apiTable.size}; MhfeErrorCode: ${declared.size}.`,
);
for (const problem of problems) console.log(`FAIL ${problem}`);
if (problems.length > 0) process.exit(1);
console.log("PASS: error codes agree.");
