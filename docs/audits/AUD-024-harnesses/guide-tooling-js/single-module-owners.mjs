// AUD-024, role guide-tooling-js: does scripts/verify-single-modules.mjs look for the vectors of
// every part outside a module's set? Its header says each module built alone is "scanned for the
// vectors of the parts outside its set"; the texts it looks for come only from the files of its
// OWNERS table and from the suite 3 validation fixture (formatsVectors).
//
// The harness lists the files whose vectors the library's self-checks read (every known_answers
// file under src/, the generated table src/mhfe/published_rounds.rs, and the fixtures that
// src/validation_fixtures.rs builds in), reads the gate's OWNERS table from its source, and names
// each file the gate does not read with the vector texts (by the gate's own isVectorText) that
// occur in no file it reads: texts the gate can never find in a module, whatever it carries.
// Reads only; no build.
//
//   node docs/audits/AUD-024-harnesses/guide-tooling-js/single-module-owners.mjs
//
// Exit 0 when the gate reads every such file; exit 1 when it misses one with vectors of its own.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const repo = process.cwd();
const { isVectorText, rustStrings } = await import(
  pathToFileURL(join(repo, "scripts/rust-strings.mjs")).href
);
const read = (path) => readFileSync(join(repo, path), "utf8");

const gateText = read("scripts/verify-single-modules.mjs");
const owners = new Set([...gateText.matchAll(/^ {2}"(src\/[^"]+\.rs)": \[/gmu)].map((m) => m[1]));
console.log(`the gate's OWNERS table reads ${owners.size} files`);

/** Every file under `directory`, by its path from the repository root. */
const filesUnder = (directory) =>
  readdirSync(join(repo, directory), { recursive: true }).map((name) => `${directory}/${name}`);
const knownAnswerFiles = filesUnder("src").filter((path) =>
  /(?:^|\/)known_answers(?:\.rs|\/[^/]+\.rs)$/u.test(path),
);
const fixtures = [
  ...read("src/validation_fixtures.rs").matchAll(/include_str!\("\.\.\/(tests\/fixtures\/[^"]+)"\)/gu),
].map((m) => m[1]);
const sources = [...knownAnswerFiles, "src/mhfe/published_rounds.rs", ...fixtures].sort();

/** The vector texts of a Rust file or a JSON fixture, as the gate tells them. */
function vectorTexts(path) {
  if (path.endsWith(".rs")) return rustStrings(read(path)).filter(isVectorText);
  const strings = (value) =>
    typeof value === "string"
      ? [value]
      : typeof value === "object" && value !== null
        ? Object.values(value).flatMap(strings)
        : [];
  return strings(JSON.parse(read(path))).filter(isVectorText);
}

// Everything the gate reads: its OWNERS files and the suite 3 fixture of formatsVectors.
const readByGate = new Set(
  [...owners, "tests/fixtures/validation-cases.json"].flatMap((path) => vectorTexts(path)),
);
let failed = false;
for (const path of sources) {
  if (owners.has(path) || path === "tests/fixtures/validation-cases.json") {
    console.log(`ok   ${path}: read by the gate`);
    continue;
  }
  const own = [...new Set(vectorTexts(path))].filter((text) => !readByGate.has(text));
  if (own.length === 0) {
    console.log(`ok   ${path}: not read, but has no vector text of its own`);
    continue;
  }
  failed = true;
  const examples = own.slice(0, 2).map((text) => JSON.stringify(text.slice(0, 64)));
  console.log(
    `FAIL ${path}: not read by the gate; ${own.length} vector texts no file it reads holds, ` +
      `such as ${examples.join(" and ")}`,
  );
}
console.log(
  failed
    ? "A module built alone could carry these vectors and pass the gate."
    : "The gate reads every file whose vectors a self-check holds.",
);
process.exit(failed ? 1 : 0);
