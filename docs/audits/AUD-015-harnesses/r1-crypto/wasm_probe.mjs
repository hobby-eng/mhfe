// AUD-015 R1: the browser core of the built package at a reduced Argon2 cost.
//
//   node wasm_probe.mjs <cases-out.json>
//
// Run from the repository root after scripts/build-wasm.sh. It loads target/wasm-bindgen/mhfe.js
// with dist/runtime/mhfe.wasm, as scripts/verify-browser-package.mjs does, and gives the core the
// package's single-threaded Emscripten Argon2 build behind a wrapper: the build's own known answer
// (1 MiB, one pass) runs unchanged, and every round, which the core must ask for at the suite's
// cost for its PIM, runs at 256 KiB and one pass, the reduced cost of src/test_support.rs. Memory
// stays far below 800 MiB. Public test data only.
//
// Part 1 writes encryptions and wrong-password readings of many inputs to <cases-out.json>, which
// `oracle.py batch` recomputes independently with OpenSSL Argon2id.
// Part 2 checks refusals that the specification requires before any Argon2id work.
// Part 3 reproduces a rekey whose length is detected and confirmed by the built-in check alone.
// Exits non-zero when an expectation of the implementation itself fails; part 3 prints what it
// observes and asserts the observed behaviour, so that a change of it fails the probe.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const [casesOut] = process.argv.slice(2);
const read = (path) => readFileSync(path);
const sha256 = (path) => createHash("sha256").update(read(path)).digest("hex");
const encode = (text) => new TextEncoder().encode(text);
const noBytes = () => new Uint8Array();

for (const path of [
  "target/wasm-bindgen/mhfe.js",
  "dist/runtime/mhfe.wasm",
  "dist/core/argon2-st.js",
  "web/argon2-engine.js",
]) {
  console.log(`input ${path} sha256 ${sha256(path)}`);
}
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const core = vm.runInThisContext("mhfe");
core.initSync({ module: read("dist/runtime/mhfe.wasm") });
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");
const engine = argon2Engine(await require("../../../../dist/core/argon2-st.js")());

const FULL_KIB = 2097152;
const KNOWN_ANSWER = "1024/1";
let expectedPasses = 12;
let rounds = 0;
const reduced = {
  derive(password, salt, memoryKib, passes, key) {
    if (`${memoryKib}/${passes}` === KNOWN_ANSWER) {
      engine.derive(password, salt, memoryKib, passes, key);
      return;
    }
    assert.deepEqual([memoryKib, passes], [FULL_KIB, expectedPasses], "the core's Argon2 cost");
    rounds += 1;
    engine.derive(password, salt, 256, 1, key);
  },
  reserve: (memoryKib) => assert.equal(memoryKib, FULL_KIB),
};

const encrypt = (phrase, password, options = {}) =>
  JSON.parse(
    core.encrypt(
      encode(phrase),
      encode(password),
      encode(password),
      "",
      0,
      options.pim ?? 0,
      0,
      options.sameLength ?? false,
      0,
      false,
      reduced,
      () => {},
      () => {},
    ),
  );
const decrypt = (container, password, words, pim = 0, onRound = () => {}) =>
  JSON.parse(core.decrypt(container, encode(password), "", 0, pim, 0, words, reduced, onRound));

// BIP39 English list from @scure/bip39, pinned by the SHA-256 of the published english.txt.
const scure =
  "../multi-chain-wallet-tools/node_modules/.pnpm/@scure+bip39@2.4.0/node_modules/@scure/bip39/wordlists/english.js";
const WORDS = /`([^`]*)`/u.exec(read(scure).toString())[1].split("\n").filter(Boolean);
assert.equal(
  createHash("sha256").update(`${WORDS.join("\n")}\n`).digest("hex"),
  "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
);
function mnemonic(entropy) {
  const cs = entropy.length / 4;
  let bits = BigInt(`0x${Buffer.from(entropy).toString("hex")}`);
  const checksum = BigInt(createHash("sha256").update(entropy).digest()[0] >> (8 - cs));
  bits = (bits << BigInt(cs)) | checksum;
  const count = (entropy.length * 8 + cs) / 11;
  const out = [];
  for (let i = count - 1; i >= 0; i -= 1) out.push(WORDS[Number((bits >> BigInt(11 * i)) & 0x7ffn)]);
  return out.join(" ");
}

// Part 1 --------------------------------------------------------------------------------------
let seed = 0x5eed1234;
const next = (bound) => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed % bound;
};
const passwords = [
  "public test password",
  "  two  Spaces  and Case ",
  "P\u00e4ssw\u00f6rd \ufb01 \u2126 \u00bd",
  "e\u0301\u0327x \u1e9b\u0323 \uac00\u11a8",
];
const cases = [];
for (const words of [12, 15, 18, 21, 24]) {
  for (const sameLength of words < 24 ? [false, true] : [false]) {
    for (let draw = 0; draw < 3; draw += 1) {
      const entropy = Uint8Array.from({ length: (words / 3) * 4 }, () => next(256));
      const phrase = mnemonic(entropy);
      const password = passwords[next(passwords.length)];
      const pim = [0, 1, 5][next(3)];
      expectedPasses = 12 * (pim + 1);
      rounds = 0;
      const created = encrypt(phrase, password, { pim, sameLength });
      assert.equal(rounds, 24, "creation runs twelve rounds and a recovery of twelve");
      const label = `${words} words, ${sameLength ? "suite 4" : "suite 3"}, PIM ${pim}`;
      const entry = { label, phrase, password, pim, sameLength, container: created.container };
      // The right password recovers the phrase; detection labels it as the specification says.
      const back = decrypt(created.container, password, 0, pim);
      assert.equal(back.candidates[0].phrase, phrase, label);
      const status = sameLength ? "noBuiltInCheck" : words < 24 ? "verified" : "readAs24";
      assert.equal(back.candidates[0].status, status, label);
      if (!sameLength) {
        const wrong = `${password}x`;
        const reading = decrypt(created.container, wrong, 24, pim);
        assert.equal(reading.candidates[0].status, "readAs24Chosen");
        Object.assign(entry, { wrongPassword: wrong, recoveredAs24: reading.candidates[0].phrase });
        // A short original under a wrong password: its stated length is refused, not read.
        if (words < 24) {
          assert.throws(
            () => decrypt(created.container, wrong, words, pim),
            /^Error: VERIFIER_MISMATCH/u,
          );
        }
      }
      cases.push(entry);
    }
  }
}
writeFileSync(casesOut, `${JSON.stringify(cases, null, 1)}\n`);
console.log(`part 1: ${cases.length} encryptions and readings written to ${casesOut}`);

// Part 2 --------------------------------------------------------------------------------------
expectedPasses = 12;
const zero12 = `${"abandon ".repeat(11)}about`;
const sameLength12 = encrypt(zero12, "public test password", { sameLength: true }).container;
const noRound = () => {
  throw new Error("an Argon2 round started before the refusal");
};
const refusals = [
  ["a 12-word container read as 24 words", () => decrypt(sameLength12, "p", 24, 0, noRound)],
  ["a 12-word container read as 15 words", () => decrypt(sameLength12, "p", 15, 0, noRound)],
  ["a 23-word input", () => decrypt(`${"abandon ".repeat(22)}art`, "p", 0, 0, noRound)],
  ["a bad checksum", () => decrypt(`${"abandon ".repeat(23)}abandon`, "p", 0, 0, noRound)],
  ["PIM 1024", () => decrypt(sameLength12, "p", 0, 1024, noRound)],
  ["memory level 1 in a browser", () => core.decrypt(sameLength12, encode("p"), "", 0, 0, 1, 0, reduced, noRound)],
  ["a 24-word original as suite 4", () => encrypt(`${"abandon ".repeat(23)}art`, "p", { sameLength: true })],
  ["an empty password", () => decrypt(sameLength12, "", 0, 0, noRound)],
];
for (const [name, action] of refusals) {
  rounds = 0;
  assert.throws(action, (error) => /^[A-Z_]+: /u.test(error.message), name);
  assert.equal(rounds, 0, name);
}
console.log(`part 2: ${refusals.length} inputs refused before any Argon2 round`);

// Part 3 --------------------------------------------------------------------------------------
// A 24-word original whose entropy is the packed state of a 21-word phrase, the specification's
// public verifier-serialization fixture: E = 00 01 .. 1b and X = E || dc27f8e8.
const x = Uint8Array.from([...Array(28).keys(), 0xdc, 0x27, 0xf8, 0xe8]);
const original24 = mnemonic(x);
const reading21 = mnemonic(x.slice(0, 28));
const PASSWORD = "public test password";
const NEW_PASSWORD = "another public test password";
const made = encrypt(original24, PASSWORD);
console.log(`part 3: creation otherLengths ${JSON.stringify(made.otherLengths)}, keep ${JSON.stringify(made.keep)}`);
assert.deepEqual(made.otherLengths, [21], "creation names the misreading");
const detected = decrypt(made.container, PASSWORD, 0);
assert.equal(detected.candidates[0].words, 21);
const rekey = new core.RekeySession(made.container, 0, encode(PASSWORD), "", 0, 0, 0, reduced);
rekey.setNew(encode(NEW_PASSWORD), encode(NEW_PASSWORD), "", 0, 0, 0, 0);
let outcome;
try {
  outcome = JSON.parse(rekey.recover("builtInCheck", "", "", "", noBytes(), false, () => {}));
} catch (error) {
  outcome = { refused: error.message };
}
console.log(`part 3: rekey with words 0 and "builtInCheck" -> ${JSON.stringify(outcome)}`);
assert.deepEqual(outcome, { ownerCheck: null }, "observed: the detected length was accepted");
const sealed = JSON.parse(rekey.seal(() => {}, () => {}));
rekey.free();
console.log(`part 3: sealed otherLengths ${JSON.stringify(sealed.otherLengths)}, keep ${JSON.stringify(sealed.keep)}`);
const after = decrypt(sealed.container, NEW_PASSWORD, 0);
console.log(
  `part 3: new container recovers ${after.candidates[0].words} words, status ${after.candidates[0].status}; ` +
    `equals the 24-word original: ${after.candidates[0].phrase === original24}; ` +
    `equals the 21-word reading: ${after.candidates[0].phrase === reading21}`,
);
assert.equal(after.candidates[0].phrase, reading21);
assert.ok(!sealed.keep.some((item) => item.item === "wordCount"), "observed: no word-count note");
// With a stated length of 24 the same rekey refuses the built-in check, as the specification asks.
const stated = new core.RekeySession(made.container, 24, encode(PASSWORD), "", 0, 0, 0, reduced);
stated.setNew(encode(NEW_PASSWORD), encode(NEW_PASSWORD), "", 0, 0, 0, 0);
assert.throws(
  () => stated.recover("builtInCheck", "", "", "", noBytes(), false, noRound),
  /^Error: REFERENCE_REQUIRED/u,
);
console.log("part 3: with words 24 the built-in check is refused before any round (REFERENCE_REQUIRED)");
console.log("PASS wasm probe");
