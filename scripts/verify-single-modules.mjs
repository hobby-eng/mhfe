// Each module of the browser package built alone, as another program may take one part without
// the rest (Cargo.toml's features browser-core, browser-repair, browser-passwords and
// browser-wallet): linked and bound with wasm-bindgen, scanned for the vectors of the parts outside
// its set, and run, its startup self-check passing and failing on a damaged vector
// (AUD-023-BLD011). scripts/check.sh runs it after the package's own checks.
//
//   node scripts/verify-single-modules.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";

import { PHRASE, SELF_CHECK_PARTS } from "./public-test-data.mjs";
import { isVectorText, rustStrings } from "./rust-strings.mjs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const target = process.env.CARGO_TARGET_DIR ?? new URL("target", root).pathname;

/**
 * The known-answers files and the modules whose set holds their parts (src/self_check/sets.rs).
 * A vector of a file that no part of a module's set reads must not be in that module.
 */
const OWNERS = {
  "src/mhfe/known_answers.rs": ["core"],
  "src/container/known_answers.rs": ["core"],
  "src/operation/known_answers.rs": ["core"],
  "src/search/known_answers.rs": ["core"],
  "src/hidden/known_answers.rs": ["core"],
  "src/rekey/known_answers.rs": ["core"],
  "src/rehearsal/known_answers.rs": ["core"],
  "src/password/known_answers.rs": ["core", "passwords"],
  "src/check_word/known_answers.rs": ["core", "passwords"],
  "src/new_password/known_answers.rs": ["passwords"],
  "src/strength/known_answers.rs": ["passwords"],
  "src/word_hints/known_answers.rs": ["passwords", "wallet"],
  "src/word_wishes/known_answers.rs": ["wallet"],
  "src/wallet_check/known_answers.rs": ["core", "wallet"],
  "src/phrase/known_answers.rs": ["core", "repair", "wallet"],
  "src/repair/known_answers.rs": ["core", "repair"],
  "src/wallet/known_answers.rs": ["core", "repair", "wallet"],
};

/** Texts that a module holds for its own reason, which a foreign part's vector happens to be. */
const COINCIDENCES = new Map([
  [
    "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "the generator's 57 characters, part of the Base58 alphabet of addresses",
  ],
]);

/** The vectors of the suite 3 validation fixture outside its passwords, which only core reads. */
function formatsVectors() {
  const fixture = JSON.parse(read("tests/fixtures/validation-cases.json").toString());
  const strings = (value) =>
    typeof value === "string"
      ? [value]
      : typeof value === "object" && value !== null
        ? Object.values(value).flatMap(strings)
        : [];
  const { passwords, ...others } = fixture;
  const ofPasswords = new Set(strings(passwords));
  return strings(others).filter((text) => isVectorText(text) && !ofPasswords.has(text));
}

/**
 * The vectors each module must not carry: those of the other parts, less its own and those that
 * are part of one of its own, such as the twelve words "abandon" that begin its phrases.
 */
function foreignVectors(module) {
  const vectorsOf = (path) => rustStrings(read(path).toString()).filter(isVectorText);
  const own = new Set();
  const foreign = new Set();
  for (const [path, owners] of Object.entries(OWNERS)) {
    for (const text of vectorsOf(path)) (owners.includes(module) ? own : foreign).add(text);
  }
  if (module !== "core") for (const text of formatsVectors()) foreign.add(text);
  const ownTexts = [...own];
  // A run of one or two characters, such as all-zero entropy, says nothing of where it came from.
  return [...foreign].filter(
    (text) =>
      new Set(text).size > 2 &&
      !COINCIDENCES.has(text) &&
      !ownTexts.some((mine) => mine.includes(text)),
  );
}

/** Builds and binds `module` alone, and returns its wasm-bindgen glue and WebAssembly. */
function build(module) {
  execFileSync(
    "cargo",
    [
      "rustc",
      "--locked",
      "--release",
      "--lib",
      "--target",
      "wasm32-unknown-unknown",
      "--no-default-features",
      "--features",
      `browser-${module}`,
      "--crate-type",
      "cdylib",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const out = new URL(`target/single-modules/${module}/`, root);
  mkdirSync(out, { recursive: true });
  execFileSync(
    "wasm-bindgen",
    [
      `${target}/wasm32-unknown-unknown/release/mhfe.wasm`,
      "--target",
      "no-modules",
      "--no-modules-global",
      "mhfe",
      "--no-typescript",
      "--out-dir",
      out.pathname,
      "--out-name",
      "mhfe",
    ],
    { cwd: root, stdio: "inherit" },
  );
  return {
    glue: readFileSync(new URL("mhfe.js", out)).toString(),
    wasm: readFileSync(new URL("mhfe_bg.wasm", out)),
  };
}

/** The WebAssembly with the last byte of every copy of `text` changed. */
function damaged(wasm, text) {
  const bytes = Buffer.from(wasm);
  const needle = Buffer.from(text);
  let copies = 0;
  for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) {
    bytes[at + needle.length - 1] ^= 1;
    copies += 1;
  }
  assert.ok(copies > 0, `the WebAssembly holds ${text}`);
  return bytes;
}

const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
const noop = () => {};
/** Each module's startup self-check binding, and a vector of its set that a damage must find. */
const MODULES = {
  repair: {
    check: (mhfe) => mhfe.selfCheckRepair("startup", [], noop, noop),
    vector: "shaft pupil patient jewel",
  },
  passwords: {
    check: (mhfe) => mhfe.selfCheckPasswords("startup", [], random, noop, noop),
    vector: "abacus abdomen abdominal abide abiding aids",
    // The password cases of the suite 3 fixture, and none of the formats check's (AUD-023-BLD009).
    holds: ["too-long-ascii", "nfkd-expansion-crosses-limit"],
    lacks: [
      "verifier_serialization",
      "pim-and-memory-level",
      "031425364758697a8b9cadbecfe0f102a23d99f2cc2b11f42045500d5073b112",
    ],
  },
  wallet: {
    check: (mhfe) => mhfe.selfCheckWallet("startup", [], random, noop, noop),
    vector: PHRASE,
  },
  core: {
    check: (mhfe) => mhfe.selfCheckCore("startup", [], undefined, noop, noop),
    vector: "shaft pupil patient jewel",
  },
};

for (const [module, { check, vector, holds = [], lacks = [] }] of Object.entries(MODULES)) {
  const { glue, wasm } = build(module);
  const run = (bytes) => {
    const mhfe = new Function(`${glue}\nreturn mhfe;`)();
    mhfe.initSync({ module: new WebAssembly.Module(bytes) });
    return JSON.parse(check(mhfe));
  };
  const report = run(wasm);
  assert.deepEqual(report.ids, SELF_CHECK_PARTS[module], `${module}: the parts of its set`);
  assert.ok(
    report.components.every(({ outcome }) => outcome !== "failed"),
    `${module}: its startup self-check passes`,
  );
  assert.equal(run(damaged(wasm, vector)).passed, false, `${module}: a damaged vector fails`);
  const text = wasm.toString("latin1");
  for (const marker of holds) assert.ok(text.includes(marker), `${module}: it holds ${marker}`);
  for (const marker of lacks) assert.ok(!text.includes(marker), `${module}: it holds ${marker}`);
  const carried = foreignVectors(module).filter((foreign) => text.includes(foreign));
  assert.deepEqual(carried, [], `${module}: it carries vectors of parts outside its set`);
  console.log(
    `The ${module} module alone passes its startup self-check and carries no other part.`,
  );
}
