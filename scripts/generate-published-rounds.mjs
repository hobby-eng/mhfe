// Writes src/mhfe/published_rounds.rs from the published vectors in tests/fixtures.
//
//   node scripts/generate-published-rounds.mjs            writes the file
//   node scripts/generate-published-rounds.mjs --check    writes nothing and fails when the file
//                                                         differs from what the fixtures give
//
// The self-checks replay every published vector through the library with the round keys the vector
// records (src/mhfe/known_answers.rs), so they need each vector's inputs, container, recovery and
// the salt and Argon2id key of each of its twelve rounds. This script copies exactly those values;
// it computes nothing. The output is deterministic: the same fixtures give the same bytes. The unit
// test published_round_table_equals_the_fixtures compares every value with the fixtures again.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const OUTPUT = join(root, "src", "mhfe", "published_rounds.rs");
/** The folders of tests/fixtures with published vectors, and whether each is a same-length suite. */
const SUITES = [
  { folder: "suite3-vectors", sameLength: false },
  { folder: "suite4-vectors", sameLength: true },
];
/**
 * The vectors of the startup check: every phrase length's packing in either suite, both settings,
 * a non-ASCII password, the repair words and the ambiguous reading. The others run in the full
 * self-test only.
 */
const STARTUP = [
  "zero-12",
  "nonzero-15",
  "zero-24",
  "ambiguous-12-21",
  "unicode-password",
  "zero-12-pim-1-memory-level-1",
  "same-length-zero-12",
  "same-length-unicode-password",
  "same-length-zero-18",
  "same-length-nonzero-21",
];
/** Rounds of every MHFE encryption, fixed by the specification. */
const ROUNDS = 12;
/** The usage, said with a refused command line. */
const USAGE = "usage: node scripts/generate-published-rounds.mjs [--check]";
/** Printable ASCII, from the space to the tilde, which the Rust literals keep as it is. */
const PRINTABLE_FIRST = 0x20;
const PRINTABLE_LAST = 0x7e;

/** A Rust string literal that keeps the source ASCII: every other character is escaped. */
function rustText(text) {
  let out = "";
  for (const character of text) {
    const code = character.codePointAt(0);
    if (character === '"' || character === "\\") out += `\\${character}`;
    else if (code >= PRINTABLE_FIRST && code <= PRINTABLE_LAST) out += character;
    else out += `\\u{${code.toString(16)}}`;
  }
  return `"${out}"`;
}

/** A Rust byte string literal of the bytes `hexText` gives, printable ASCII kept. */
function rustBytes(hexText) {
  // Buffer.from(…, "hex") would stop silently at the first character that is not hex.
  if (!/^(?:[0-9a-fA-F]{2})*$/u.test(hexText)) throw new Error(`not hex: ${hexText}`);
  let out = "";
  for (const byte of Buffer.from(hexText, "hex")) {
    const character = String.fromCharCode(byte);
    if (character === '"' || character === "\\") out += `\\${character}`;
    else if (byte >= PRINTABLE_FIRST && byte <= PRINTABLE_LAST) out += character;
    else out += `\\x${byte.toString(16).padStart(2, "0")}`;
  }
  return `b"${out}"`;
}

/** Every published vector of both suites, in file-name order within each suite. */
function vectors() {
  return SUITES.flatMap(({ folder, sameLength }) => {
    const directory = join(root, "tests", "fixtures", folder);
    return readdirSync(directory)
      .filter((name) => name.endsWith(".json"))
      .sort()
      .map((name) => JSON.parse(readFileSync(join(directory, name), "utf8")))
      .filter(
        // The negative cases and the verification records hold no inputs.
        (vector) =>
          typeof vector === "object" &&
          vector !== null &&
          !Array.isArray(vector) &&
          Object.hasOwn(vector, "inputs"),
      )
      .map((vector) => ({ vector, sameLength }));
  });
}

/** The readings of a vector's recovery: a list in suite 3, a single reading in suite 4. */
function readings(vector, sameLength) {
  return sameLength ? [vector.recovery] : vector.recovery;
}

/** The salt and Argon2id key of each of the vector's rounds, as hex. */
function rounds(vector) {
  const encryption = vector.encryption.rounds;
  if (encryption.length !== ROUNDS) throw new Error(`${vector.name}: ${encryption.length} rounds`);
  return encryption.map((entry) => ({ salt: entry.salt_hex, key: entry.argon2_key_hex }));
}

/** The text of src/mhfe/published_rounds.rs. */
function render() {
  const published = vectors();
  const names = new Set(published.map(({ vector }) => vector.name));
  const missing = STARTUP.filter((name) => !names.has(name));
  if (missing.length > 0) throw new Error(`startup vectors not found: ${missing.join(", ")}`);
  const lines = [
    "//! The published MHFE vectors as the self-checks replay them: inputs, container, recovery and",
    "//! the salt and Argon2id key of every round. Generated by scripts/generate-published-rounds.mjs",
    "//! from tests/fixtures/suite3-vectors and tests/fixtures/suite4-vectors (the specification's",
    "//! vectors/suite3 and vectors/suite4); do not edit. The unit test",
    "//! published_round_table_equals_the_fixtures compares every value with the fixtures.",
    "",
    "use super::known_answers::{PublishedReading, PublishedRound, PublishedVector};",
    "use crate::self_check::hex;",
    "",
    `pub(super) static PUBLISHED: [PublishedVector; ${published.length}] = [`,
  ];
  for (const { vector, sameLength } of published) {
    const { inputs } = vector;
    lines.push(
      "    PublishedVector {",
      `        name: ${rustText(vector.name)},`,
      `        same_length: ${sameLength},`,
      `        startup: ${STARTUP.includes(vector.name)},`,
      `        phrase: ${rustText(inputs.phrase)},`,
      `        password: ${rustText(inputs.password)},`,
      `        password_nfkd: ${rustBytes(inputs.password_nfkd_utf8_hex)},`,
      `        pim: ${inputs.pim},`,
      `        memory_level: ${inputs.memory_level},`,
      `        container: ${rustText(vector.container)},`,
      "        recovery: &[",
    );
    for (const { words, verified, phrase } of readings(vector, sameLength)) {
      lines.push(
        "            PublishedReading {",
        `                words: ${words},`,
        `                verified: ${verified ? "true" : "false"},`,
        `                phrase: ${rustText(phrase)},`,
        "            },",
      );
    }
    lines.push("        ],", "        rounds: [");
    for (const { salt, key } of rounds(vector)) {
      lines.push(
        "            PublishedRound {",
        `                salt: hex("${salt}"),`,
        `                key: hex("${key}"),`,
        "            },",
      );
    }
    lines.push("        ],", "    },");
  }
  lines.push("];", "");
  return lines.join("\n");
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  console.error(USAGE);
  process.exit(2);
}
const text = render();
if (args.length === 0) {
  writeFileSync(OUTPUT, text, "utf8");
} else if (readFileSync(OUTPUT, "utf8") !== text) {
  console.error(`${relative(root, OUTPUT)} differs from the fixtures; regenerate it`);
  process.exit(1);
}
