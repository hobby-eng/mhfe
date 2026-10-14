// AUD-024 verifier probe (review only, no build): does scripts/verify-single-modules.mjs look,
// in a module built alone, for the vector texts of every core-only source the browser-core build
// compiles in? Uses the gate's own OWNERS, COINCIDENCES, formatsVectors and foreignVectors, sliced
// from its source and evaluated here, and the four single-module WebAssembly files the baseline
// run of the gate built at b6fca69 (target/single-modules/<module>/mhfe_bg.wasm, read only).
//
//   node docs/audits/AUD-024-harnesses/verify-single-module-owners/naive-fix-coincidences.mjs
//
// Exit 1 when a core-only source has vector texts that core's WebAssembly carries and that the
// gate never looks for in another module; exit 0 otherwise.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const repo = process.cwd();
const { isVectorText, rustStrings } = await import(
  pathToFileURL(join(repo, "scripts/rust-strings.mjs")).href
);
const read = (path) => readFileSync(join(repo, path));

// The gate's own code, lines "const OWNERS" to the comment before build(): OWNERS, COINCIDENCES,
// formatsVectors and foreignVectors, unchanged.
const gate = read("scripts/verify-single-modules.mjs").toString();
const from = gate.indexOf("const OWNERS = {");
const to = gate.indexOf("/**\n * Builds and binds");
if (from === -1 || to === -1) throw new Error("the gate's source has another shape");
const gateCode = gate.slice(from, to);
const { OWNERS, COINCIDENCES, foreignVectors } = new Function(
  "read",
  "isVectorText",
  "rustStrings",
  `${gateCode}\nreturn { OWNERS, COINCIDENCES, foreignVectors };`,
)(read, isVectorText, rustStrings);
console.log(`gate code evaluated: OWNERS names ${Object.keys(OWNERS).length} files`);

const wasmText = (module) =>
  read(`target/single-modules/${module}/mhfe_bg.wasm`).toString("latin1");
const wasm = Object.fromEntries(
  ["core", "repair", "passwords", "wallet"].map((m) => [m, wasmText(m)]),
);

/** Strings of a JSON value. */
const strings = (value) =>
  typeof value === "string"
    ? [value]
    : typeof value === "object" && value !== null
      ? Object.values(value).flatMap(strings)
      : [];

/** Core-only sources compiled into a browser-core build that OWNERS does not name. */
const SOURCES = [
  ["src/engine/known_answers.rs", "src/engine.rs:76-81 (browser-core)"],
  ["src/mhfe/published_rounds.rs", "src/mhfe.rs:23-24 (browser-core)"],
  ["tests/fixtures/suite4-vectors/validation-cases.json", "src/validation_fixtures.rs:26-28 SUITE_4"],
  ["tests/fixtures/suite3-vectors/zero-12.json", "src/self_test.rs:23 SUITE_3_VECTOR (lib.rs:56)"],
  [
    "tests/fixtures/suite4-vectors/same-length-zero-12.json",
    "src/self_test.rs:24-25 SUITE_4_VECTOR (lib.rs:56)",
  ],
];
for (const [path] of SOURCES) {
  if (Object.hasOwn(OWNERS, path)) console.log(`note: OWNERS names ${path}`);
}

/** Vector texts of a source, filtered as foreignVectors filters (runs of 3+ characters). */
function vectorTexts(path) {
  const all = path.endsWith(".rs")
    ? rustStrings(read(path).toString())
    : strings(JSON.parse(read(path).toString()));
  return [
    ...new Set(
      all.filter((t) => isVectorText(t) && new Set(t).size > 2 && !COINCIDENCES.has(t)),
    ),
  ];
}

/** Texts a module holds for its own parts, as foreignVectors computes `own`. */
function ownTexts(module) {
  return Object.entries(OWNERS)
    .filter(([, owners]) => owners.includes(module))
    .flatMap(([path]) => rustStrings(read(path).toString()).filter(isVectorText));
}

let gap = false;
for (const module of ["repair", "passwords", "wallet"]) {
  const looked = new Set(foreignVectors(module));
  const own = ownTexts(module);
  console.log(`\n== ${module}: the gate looks for ${looked.size} foreign texts`);
  for (const [path, how] of SOURCES) {
    const texts = vectorTexts(path);
    const missed = texts.filter((t) => !looked.has(t) && !own.some((mine) => mine.includes(t)));
    const inCore = missed.filter((t) => wasm.core.includes(t));
    const inModule = missed.filter((t) => wasm[module].includes(t));
    if (inCore.length > 0) gap = true;
    console.log(
      `${path} [${how}]: ${texts.length} vector texts, ${missed.length} never looked for, ` +
        `${inCore.length} of those carried by core's WebAssembly, ${inModule.length} by ${module}'s today`,
    );
    if (inCore.length > 0) console.log(`   e.g. core carries ${JSON.stringify(inCore[0].slice(0, 72))}`);
    if (inModule.length > 0) console.log(`   ${module} carries ${JSON.stringify(inModule.slice(0, 3))}`);
  }
}

// Control: the gate's own carried-vector test (lines 149-154) on the passwords WebAssembly with a
// core-only text appended. A text of an OWNERS file is found; a text of each unread source is not.
const carried = (module, text) => foreignVectors(module).filter((f) => text.includes(f));
const base = wasm.passwords;
console.log(`\n== control on passwords: today carried=${JSON.stringify(carried("passwords", base))}`);
const ownersText = [...new Set(foreignVectors("passwords"))].find(
  (t) => !base.includes(t) && rustStrings(read("src/mhfe/known_answers.rs").toString()).includes(t),
);
console.log(
  `OWNERS text (src/mhfe/known_answers.rs) appended: carried=${carried("passwords", base + ownersText).length} (gate fails)`,
);
for (const [path] of SOURCES) {
  const looked = new Set(foreignVectors("passwords"));
  const sample = vectorTexts(path).find((t) => wasm.core.includes(t) && !looked.has(t) && !base.includes(t));
  if (!sample) {
    console.log(`${path}: no core-carried text to append`);
    continue;
  }
  const found = carried("passwords", base + sample).length;
  console.log(
    `${path} text ${JSON.stringify(sample.slice(0, 48))} appended: carried=${found} (${found === 0 ? "gate passes" : "gate fails"})`,
  );
}
console.log(
  gap
    ? "\nRESULT: the gate cannot fail for core-only vector texts that core's WebAssembly carries."
    : "\nRESULT: no gap.",
);
process.exit(gap ? 1 : 0);
