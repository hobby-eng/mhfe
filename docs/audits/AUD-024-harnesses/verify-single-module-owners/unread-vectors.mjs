// AUD-024 verifier harness (review only, no build): does scripts/verify-single-modules.mjs look,
// in each module built alone, for the vector texts of every source a browser-core or
// browser-repair build compiles in? It evaluates the gate's own OWNERS, COINCIDENCES,
// formatsVectors and foreignVectors, sliced unchanged from the gate's source, and reads the four
// single-module WebAssembly files the gate itself built at this commit
// (target/single-modules/<module>/mhfe_bg.wasm, read only).
//
// For each source the OWNERS table does not name, and each module outside the source's owners, it
// counts the vector texts (the gate's isVectorText, runs of 3 or more characters, no COINCIDENCE)
// that the gate never looks for in that module and that the owner's WebAssembly carries while that
// module's does not: texts a loosened cfg gate would bring into the module unseen. A control then
// appends one such text to the passwords WebAssembly and applies the gate's own carried-vector test
// (scripts/verify-single-modules.mjs:149-154), next to a text of an OWNERS file that it must find.
//
//   node docs/audits/AUD-024-harnesses/verify-single-module-owners/unread-vectors.mjs
//
// Exit 1 when such texts exist (the gap is present); exit 0 when the gate looks for all of them.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const repo = process.cwd();
const { isVectorText, rustStrings } = await import(
  pathToFileURL(join(repo, "scripts/rust-strings.mjs")).href
);
const read = (path) => readFileSync(join(repo, path));

const gate = read("scripts/verify-single-modules.mjs").toString();
const from = gate.indexOf("const OWNERS = {");
const to = gate.indexOf("/**\n * Builds and binds");
if (from === -1 || to === -1) throw new Error("the gate's source has another shape");
const { OWNERS, COINCIDENCES, foreignVectors } = new Function(
  "read",
  "isVectorText",
  "rustStrings",
  `${gate.slice(from, to)}\nreturn { OWNERS, COINCIDENCES, foreignVectors };`,
)(read, isVectorText, rustStrings);
console.log(`the gate's own code: OWNERS names ${Object.keys(OWNERS).length} files`);

const MODULES = ["core", "repair", "passwords", "wallet"];
const wasm = Object.fromEntries(
  MODULES.map((m) => [m, read(`target/single-modules/${m}/mhfe_bg.wasm`).toString("latin1")]),
);

const strings = (value) =>
  typeof value === "string"
    ? [value]
    : typeof value === "object" && value !== null
      ? Object.values(value).flatMap(strings)
      : [];

/** Sources compiled into browser builds that OWNERS does not name: path, owners, where built in. */
const SOURCES = [
  ["src/engine/known_answers.rs", ["core"], "src/engine.rs:77-81 (browser-core)"],
  ["src/mhfe/published_rounds.rs", ["core"], "src/mhfe.rs:23-24 (browser-core)"],
  [
    "tests/fixtures/suite4-vectors/validation-cases.json",
    ["core"],
    "src/validation_fixtures.rs:26-28 SUITE_4 (browser-core)",
  ],
  [
    "tests/fixtures/suite3-vectors/zero-12.json",
    ["core"],
    "src/self_test.rs:23 SUITE_3_VECTOR; src/lib.rs:56-57 (browser-core)",
  ],
  [
    "tests/fixtures/suite4-vectors/same-length-zero-12.json",
    ["core"],
    "src/self_test.rs:24-25 SUITE_4_VECTOR; src/lib.rs:56-57 (browser-core)",
  ],
  [
    "src/self_check.rs",
    ["core", "repair"],
    "src/self_check.rs:462-469 ZERO_12_CONTAINER (browser-core, browser-repair)",
  ],
];

function vectorTexts(path) {
  const all = path.endsWith(".rs")
    ? rustStrings(read(path).toString())
    : strings(JSON.parse(read(path).toString()));
  return [
    ...new Set(all.filter((t) => isVectorText(t) && new Set(t).size > 2 && !COINCIDENCES.has(t))),
  ];
}

let gap = false;
for (const [path, owners, how] of SOURCES) {
  if (Object.hasOwn(OWNERS, path)) {
    console.log(`ok   ${path}: named by OWNERS`);
    continue;
  }
  const texts = vectorTexts(path);
  console.log(`${path} [${how}]: ${texts.length} vector texts`);
  for (const module of MODULES.filter((m) => !owners.includes(m))) {
    const looked = new Set(foreignVectors(module));
    const unseen = texts.filter(
      (t) =>
        !looked.has(t) && owners.some((o) => wasm[o].includes(t)) && !wasm[module].includes(t),
    );
    const notInWasm = texts.filter((t) => !owners.some((o) => wasm[o].includes(t))).length;
    if (unseen.length > 0) gap = true;
    console.log(
      `   ${unseen.length > 0 ? "GAP " : "ok  "}${module}: ${unseen.length} texts carried by ` +
        `${owners.join("/")} and never looked for${unseen.length ? `, such as ${JSON.stringify(unseen[0].slice(0, 60))}` : ""}` +
        ` (${notInWasm} texts of the source are in no owner's WebAssembly as text)`,
    );
  }
}

const carried = (module, text) => foreignVectors(module).filter((f) => text.includes(f));
const base = wasm.passwords;
console.log(`\ncontrol, passwords WebAssembly as built: carried ${carried("passwords", base).length}`);
const ownersText = foreignVectors("passwords").find(
  (t) => !base.includes(t) && rustStrings(read("src/mhfe/known_answers.rs").toString()).includes(t),
);
console.log(
  `   + a text of src/mhfe/known_answers.rs (OWNERS): carried ${carried("passwords", base + ownersText).length} -> gate fails`,
);
const looked = new Set(foreignVectors("passwords"));
for (const [path, owners] of SOURCES) {
  const sample = vectorTexts(path).find(
    (t) => owners.some((o) => wasm[o].includes(t)) && !looked.has(t) && !base.includes(t),
  );
  if (!sample) continue;
  const found = carried("passwords", base + sample).length;
  console.log(
    `   + ${JSON.stringify(sample.slice(0, 40))} of ${path}: carried ${found} -> ${found ? "gate fails" : "gate passes"}`,
  );
}
console.log(
  gap
    ? "\nGAP: a module built alone could carry these vector texts and pass the gate."
    : "\nThe gate looks for every vector text of these sources.",
);
process.exit(gap ? 1 : 0);
