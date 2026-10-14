// Each module of the browser package built alone, as another program may take one part without
// the rest (Cargo.toml's features browser-core, browser-repair, browser-passwords and
// browser-wallet): linked and bound with wasm-bindgen, scanned for the vectors of the parts outside
// its set, and run, its startup self-check passing and failing on a damaged vector
// (AUD-023-BLD011). scripts/check.sh runs it after the package's own checks.
//
//   node scripts/verify-single-modules.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";

import { PHRASE, SELF_CHECK_PARTS } from "./public-test-data.mjs";
import { damagedCopies, isVectorText, rustStrings } from "./rust-strings.mjs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));

/**
 * The known-answers files and the modules whose set holds their parts (src/self_check/sets.rs).
 * A vector of a file that no part of a module's set reads must not be in that module.
 */
const OWNERS = {
  "src/mhfe/known_answers.rs": ["core"],
  "src/mhfe/known_answers/published.rs": ["core"],
  "src/mhfe/published_rounds.rs": ["core"],
  "src/engine/known_answers.rs": ["core"],
  "src/self_check.rs": ["core", "repair"],
  "tests/fixtures/suite4-vectors/validation-cases.json": ["core"],
  "tests/fixtures/suite3-vectors/zero-12.json": ["core"],
  "tests/fixtures/suite4-vectors/same-length-zero-12.json": ["core"],
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
  "src/wallet/known_answers/addresses.rs": ["core", "wallet"],
};

/** Literals shared by several checks, now held once outside their known-answer modules. */
const SHARED_INPUTS = {
  "src/vectors/inputs.rs": {
    ZERO_12: ["core", "repair", "wallet"],
    ZERO_24: ["core", "repair", "wallet"],
    UNICODE_PASSWORD: ["core", "repair", "passwords", "wallet"],
    UNICODE_PASSWORD_NFKD: ["core", "passwords"],
  },
  "src/eff.rs": { EFF_LIST_SHA256: ["core", "passwords"] },
};

/** Read exact Rust literals by symbol; a missing or changed declaration needs review. */
function sharedVectors() {
  return Object.entries(SHARED_INPUTS).flatMap(([path, symbols]) => {
    const literals = new Map(
      [
        ...read(path)
          .toString()
          .matchAll(/\bconst\s+(\w+)\s*:\s*&str\s*=\s*("(?:\\.|[^"\\])*")/gsu),
      ].map((match) => [match[1], rustStrings(match[2])[0]]),
    );
    return Object.entries(symbols).map(([name, owners]) => {
      assert.ok(literals.has(name), `${path}: no shared literal ${name}`);
      return { text: literals.get(name), owners };
    });
  });
}

/** Texts that a module holds for its own reason, which a foreign part's vector happens to be. */
const COINCIDENCES = new Map([
  ["0123456789abcdef", "the common hexadecimal alphabet"],
  ["0102030405060708", "the common ascending-byte table"],
  [
    "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "the generator's 57 characters, part of the Base58 alphabet of addresses",
  ],
]);

/** Text values of a fixture, leaving ownership decisions to its caller. */
function fixtureStrings(value) {
  if (typeof value === "string") return [value];
  return typeof value === "object" && value !== null
    ? Object.values(value).flatMap(fixtureStrings)
    : [];
}

/** Strings and compile-time hex constants, including tags stored as bytes rather than text. */
function vectorsOf(path) {
  const source = read(path).toString();
  const texts = path.endsWith(".json") ? fixtureStrings(JSON.parse(source)) : rustStrings(source);
  const hexes = compiledHexes(source);
  return [...new Set([...texts.filter(isVectorText), ...hexes])];
}

/** Only hex() constants become bytes at compile time; JSON hex fields stay text in the binary. */
function compiledHexes(source) {
  return [...source.matchAll(/\bhex\(\s*"([\da-fA-F]{16,})"\s*\)/gu)].map((match) => match[1]);
}
const COMPILED_HEX = new Set(
  Object.keys(OWNERS)
    .filter((path) => path.endsWith(".rs"))
    .flatMap((path) => compiledHexes(read(path).toString())),
);

/** The vectors of the suite 3 validation fixture outside its passwords, which only core reads. */
function formatsVectors() {
  const fixture = JSON.parse(read("tests/fixtures/validation-cases.json").toString());
  const { passwords, ...others } = fixture;
  const ofPasswords = new Set(fixtureStrings(passwords));
  return fixtureStrings(others).filter((text) => isVectorText(text) && !ofPasswords.has(text));
}

/**
 * The vectors each module must not carry: those of the other parts, less its own and those that
 * are part of one of its own, such as the twelve words "abandon" that begin its phrases.
 */
function foreignVectors(module) {
  const own = new Set();
  const foreign = new Set();
  for (const [path, owners] of Object.entries(OWNERS)) {
    for (const text of vectorsOf(path)) (owners.includes(module) ? own : foreign).add(text);
  }
  for (const { text, owners } of sharedVectors()) {
    if (isVectorText(text)) (owners.includes(module) ? own : foreign).add(text);
  }
  if (module === "passwords") {
    const { passwords } = JSON.parse(read("tests/fixtures/validation-cases.json").toString());
    for (const text of fixtureStrings(passwords)) own.add(text);
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

/** The same foreign values in their textual and compiled hexadecimal byte forms. */
function carriedVectors(module, bytes) {
  return foreignVectors(module).filter(
    (text) =>
      bytes.includes(Buffer.from(text)) ||
      (COMPILED_HEX.has(text) && bytes.includes(Buffer.from(text, "hex"))),
  );
}

/** Every known-answer source, generated table and runtime fixture has an explicit owner. */
function checkOwnershipInventory() {
  const walk = (folder) =>
    readdirSync(new URL(folder, root), { withFileTypes: true }).flatMap((entry) => {
      const path = `${folder}${entry.name}`;
      return entry.isDirectory() ? walk(`${path}/`) : path.endsWith(".rs") ? [path] : [];
    });
  for (const path of walk("src/").filter((name) => !name.startsWith("src/bin/"))) {
    const source = read(path).toString();
    if (
      path.includes("/known_answers") ||
      /Generated by/u.test(source.split("\n").slice(0, 8).join("\n"))
    ) {
      assert.ok(Object.hasOwn(OWNERS, path), `${path}: no vector owner`);
    }
    // These two modules are native/test-only; other unit-test sections are not browser inputs.
    if (["src/test_support.rs", "src/vectors.rs"].includes(path)) continue;
    const runtime = source.split("#[cfg(test)]")[0];
    for (const [, fixture] of runtime.matchAll(
      /include_str!\(\s*"([^"]*tests\/fixtures\/[^"]+)"/gu,
    )) {
      const resolved = new URL(fixture, new URL(path, root)).pathname;
      const name = resolved.slice(root.pathname.length);
      assert.ok(
        name === "tests/fixtures/validation-cases.json" || Object.hasOwn(OWNERS, name),
        `${name}: no fixture owner`,
      );
    }
  }
}

/** Each new vector source is detectable as text, and each compiled tag is detectable as bytes. */
function selfTest() {
  checkOwnershipInventory();
  const shared = sharedVectors();
  assert.ok(shared.length > 0, "shared-input ownership is not empty");
  for (const { text, owners } of shared) {
    if (!isVectorText(text)) continue;
    for (const module of ["core", "repair", "passwords", "wallet"]) {
      if (owners.includes(module)) continue;
      assert.ok(
        carriedVectors(module, Buffer.from(text)).includes(text),
        `${module}: a shared foreign literal is still detectable`,
      );
    }
  }
  for (const path of [
    "src/mhfe/published_rounds.rs",
    "src/engine/known_answers.rs",
    "src/self_check.rs",
    "tests/fixtures/suite4-vectors/validation-cases.json",
    "tests/fixtures/suite3-vectors/zero-12.json",
    "tests/fixtures/suite4-vectors/same-length-zero-12.json",
  ]) {
    const foreign = new Set(foreignVectors("passwords"));
    const vector = vectorsOf(path).find((text) => foreign.has(text));
    assert.ok(vector, `${path}: has a foreign control`);
    assert.ok(
      carriedVectors("passwords", Buffer.from(vector)).includes(vector),
      `${path}: found as text`,
    );
    const hex = vectorsOf(path).find((text) => foreign.has(text) && COMPILED_HEX.has(text));
    if (hex !== undefined)
      assert.ok(
        carriedVectors("passwords", Buffer.from(hex, "hex")).includes(hex),
        `${path}: found as bytes`,
      );
  }
  assert.deepEqual(carriedVectors("passwords", Buffer.from("0123456789abcdef")), []);
  console.log("The vector ownership and foreign text/byte controls pass.");
}

/**
 * Builds and binds `module` alone, as the package's build does (scripts/bind-wasm.sh), and returns
 * its wasm-bindgen glue and WebAssembly.
 */
function build(module) {
  const out = new URL(`target/single-modules/${module}/`, root);
  execFileSync("scripts/bind-wasm.sh", [`browser-${module}`, out.pathname], {
    cwd: root,
    stdio: "inherit",
  });
  return {
    glue: readFileSync(new URL("mhfe.js", out)).toString(),
    wasm: readFileSync(new URL("mhfe_bg.wasm", out)),
  };
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

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--self-test") {
  selfTest();
  process.exit(0);
}
if (args.length !== 0) {
  console.error("Usage: node scripts/verify-single-modules.mjs [--self-test]");
  process.exit(2);
}
checkOwnershipInventory();
for (const [module, { check, vector, holds = [], lacks = [] }] of Object.entries(MODULES)) {
  const { glue, wasm } = build(module);
  const run = (bytes) => {
    // The module's own wasm-bindgen glue, which this script just built, as a worker loads it.
    // oxlint-disable-next-line typescript/no-implied-eval -- the glue is a classic script to run
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
  assert.equal(run(damagedCopies(wasm, vector)).passed, false, `${module}: a damaged vector fails`);
  const text = wasm.toString("latin1");
  // Each message says what failed: a marker it should hold that is missing, or one it holds.
  for (const marker of holds) assert.ok(text.includes(marker), `${module}: it lacks ${marker}`);
  for (const marker of lacks) assert.ok(!text.includes(marker), `${module}: it holds ${marker}`);
  const carried = carriedVectors(module, wasm);
  assert.deepEqual(carried, [], `${module}: it carries vectors of parts outside its set`);
  console.log(
    `The ${module} module alone passes its startup self-check and carries no other part.`,
  );
}
