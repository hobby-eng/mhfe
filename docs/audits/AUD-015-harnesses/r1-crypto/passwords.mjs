// AUD-015 R1: the MHFE password rule of the library against ICU's Unicode 17 data.
//
//   node passwords.mjs <password-probe binary> <spec suite3/validation-cases.json>
//
// The oracle is Node.js's ICU (process.versions.unicode must be 17.0): General_Category Cc and
// Cn through \p{Cc} and \p{Cn}, and String.prototype.normalize("NFKD"). The rule, from the
// specification's "Password encoding": a password with a Cc character, U+2028 or U+2029 is
// refused; one with a Cn code point (unassigned, noncharacters included) is refused; otherwise
// P_enc = UTF8(NFKD(P)) and it must have 1 to 1024 bytes. Three parts:
//   1. every Unicode scalar value as a one-character password ("password-probe all");
//   2. 20,000 random strings of assigned characters weighted towards combining marks, so that
//      canonical reordering across characters is exercised, plus the length boundaries;
//   3. the specification's password validation cases, with their recorded bytes.
// Exits non-zero on the first disagreement. Public, synthetic data only.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const [probe, validationPath] = process.argv.slice(2);
assert.equal(process.versions.unicode, "17.0", "the oracle must use Unicode 17.0 data");

const LIMIT = 1024;
const forbidden = (text) => /[\p{Cc}\u2028\u2029]/u.test(text);
const unassigned = (text) => /\p{Cn}/u.test(text);
function expected(text) {
  if (forbidden(text)) return "err:CONTROL_CHARACTER_IN_PASSWORD";
  if (unassigned(text)) return "err:UNASSIGNED_CHARACTER";
  const bytes = Buffer.from(text.normalize("NFKD"), "utf8");
  if (bytes.length === 0) return "err:EMPTY_PASSWORD";
  if (bytes.length > LIMIT) return "err:PASSWORD_TOO_LONG";
  return `ok:${bytes.toString("hex")}`;
}

function run(mode, input) {
  const result = spawnSync(probe, [mode], { input, maxBuffer: 1 << 30, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.split("\n").filter(Boolean);
}

// 1. Every scalar value.
let counts = { ok: 0, control: 0, unassigned: 0 };
const all = run("all", "");
assert.equal(all.length, 0x110000 - 0x800, "one line per scalar value");
for (const line of all) {
  const [hex, result] = line.split(" ");
  const text = String.fromCodePoint(parseInt(hex, 16));
  const want = expected(text);
  if (result !== want) {
    console.log(`FAIL U+${hex.toUpperCase()}: library ${result}, ICU ${want}`);
    process.exit(1);
  }
  if (want.startsWith("ok:")) counts.ok += 1;
  else if (want.includes("CONTROL")) counts.control += 1;
  else counts.unassigned += 1;
}

// 2. Random strings and boundaries.
let seed = 0x2545f491;
const next = (bound) => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed % bound;
};
const assigned = [];
const marks = [];
for (let cp = 0; cp <= 0x10ffff; cp += 1) {
  if (cp >= 0xd800 && cp <= 0xdfff) continue;
  const text = String.fromCodePoint(cp);
  if (forbidden(text) || unassigned(text)) continue;
  assigned.push(cp);
  if (/\p{M}/u.test(text)) marks.push(cp);
}
// The empty password first: an empty last line would be dropped by the line reader.
const strings = [""];
for (let i = 0; i < 20000; i += 1) {
  const length = 1 + next(12);
  let text = "";
  for (let j = 0; j < length; j += 1) {
    const pool = next(2) === 0 ? marks : assigned;
    text += String.fromCodePoint(pool[next(pool.length)]);
  }
  strings.push(text);
}
// Boundaries: 1024 and 1025 bytes, an NFKD expansion across the limit (U+FDFA: 3 -> 33 bytes),
// a contraction from more than 1024 input bytes (U+FB01: 3 -> 2 bytes), and the empty password.
strings.push("a".repeat(1024), "a".repeat(1025), "\uFDFA".repeat(31), "\uFDFA".repeat(32));
strings.push("\uFB01".repeat(512), "\uFB01".repeat(513), "a".repeat(1023) + "\u00E9");
const lines = run("lines", strings.map((s) => Buffer.from(s, "utf8").toString("hex")).join("\n"));
assert.equal(lines.length, strings.length);
strings.forEach((text, i) => {
  const want = expected(text);
  const got = lines[i].slice(lines[i].indexOf(" ") + 1);
  if (got !== want) {
    console.log(`FAIL string ${i} ${JSON.stringify(text)}: library ${got}, ICU ${want}`);
    process.exit(1);
  }
});

// 3. The specification's password validation cases.
const validation = JSON.parse(readFileSync(validationPath, "utf8"));
const cases = validation.passwords;
const inputOf = (c) => (c.repeat_utf8_hex ? c.repeat_utf8_hex.repeat(c.count) : c.input_utf8_hex);
const caseLines = run("lines", cases.map(inputOf).join("\n"));
assert.equal(caseLines.length, cases.length);
cases.forEach((c, i) => {
  const got = caseLines[i].slice(caseLines[i].indexOf(" ") + 1);
  let ok;
  if (c.expected_error) ok = got === `err:${c.expected_error}`;
  else if (c.expected_nfkd_utf8_hex !== undefined) ok = got === `ok:${c.expected_nfkd_utf8_hex}`;
  else ok = got.startsWith("ok:") && (got.length - 3) / 2 === c.expected_nfkd_bytes;
  if (!ok) {
    console.log(`FAIL spec case ${c.id}: library ${got.slice(0, 80)}`);
    process.exit(1);
  }
});

// The checks can fail: a forbidden, an unassigned and a too-long password are refused.
assert.equal(expected("a\tb"), "err:CONTROL_CHARACTER_IN_PASSWORD");
assert.equal(expected("\uFDD0"), "err:UNASSIGNED_CHARACTER");
assert.equal(expected("a".repeat(1025)), "err:PASSWORD_TOO_LONG");
console.log(
  `PASS passwords: ${all.length} scalar values (${counts.ok} accepted, ${counts.control} ` +
    `control/separator, ${counts.unassigned} unassigned), ${strings.length} strings and ` +
    `${cases.length} specification cases agree with ICU ${process.versions.icu} ` +
    `(Unicode ${process.versions.unicode})`,
);
