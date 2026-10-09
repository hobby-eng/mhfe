// Checks that the command-line tool and the browser package give the same results, as both call
// the same library: the program's script mode (--stdin) beside the package's WebAssembly in this
// process, on public data, without any full-cost Argon2 work. Build both first: the program with
// `cargo build --release`, the package with scripts/build-wasm.sh.
//
//   node scripts/verify-cli-browser-parity.mjs [path/to/mhfe]
//
// Compared: the repair words of a container and the repair of a damaged one; the refusals that
// come before any round, by their words, which the program writes after "✗ Error:" and a page
// reads from the package (sentence() in web/runtime.js); and the other lengths that detection
// could read, which the program warns of for the container chosen and readPhrase() lists for each.
// Each run of the program also passes its own startup checks and needs the 2 GiB of free memory
// that a recovery takes, though none is reserved before these refusals.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";

import {
  AMBIGUOUS_12_WORDS,
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
  ZERO_24,
} from "./public-test-data.mjs";

const require = createRequire(import.meta.url);
const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const encode = (text) => new TextEncoder().encode(text);
const noBytes = () => new Uint8Array();

const PROGRAM = process.argv[2] ?? new URL("target/release/mhfe", root).pathname;
/** The program's exit code for input it refuses (src/bin/mhfe/exit.rs). */
const INVALID_INPUT = 2;
/** The mark before an error of the program (src/bin/mhfe/style.rs). */
const ERROR_MARK = "✗ Error:";
/** The Argon2 costs of the known answers that a call of the core checks first (src/engine). */
const KNOWN_ANSWER_COSTS = ["1024/1", "65536/3", "262144/2"];

// The package's wasm-bindgen glue defines the global `mhfe`, the bindings of every module.
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const mhfe = vm.runInThisContext("mhfe");
mhfe.initSync({ module: read("dist/runtime/mhfe.wasm") });
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");
const engine = argon2Engine(await require("../dist/core/argon2-st.js")());
/** Argon2 for the core's refusals: its known answers pass, and a round would fail the check. */
const knownAnswersOnly = {
  derive: (password, salt, memoryKib, passes, key) => {
    assert.ok(
      KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`),
      "a refusal came after the first round started",
    );
    engine.derive(password, salt, memoryKib, passes, key);
  },
};
const noRound = () => {};

/** Runs the program in script mode with `lines` on standard input, without colour. */
function program(args, lines) {
  const result = spawnSync(PROGRAM, args, {
    input: lines.map((line) => `${line}\n`).join(""),
    env: { ...process.env, NO_COLOR: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.error, undefined, `mhfe ${args.join(" ")}: ${result.error}`);
  return result;
}

/** The program's error message, its wrapped lines joined, without the mark. */
function programError(result, what) {
  assert.equal(result.status, INVALID_INPUT, `${what}: exit code ${result.status}`);
  const at = result.stderr.indexOf(ERROR_MARK);
  assert.ok(at >= 0, `${what}: no error in ${JSON.stringify(result.stderr)}`);
  return result.stderr
    .slice(at + ERROR_MARK.length)
    .split("\n")
    .map((line) => line.trim())
    .join(" ")
    .trim();
}

/** The message a page shows for a refusal of the package: its text after the code, a sentence. */
function packageError(code, action, what) {
  let message = "";
  assert.throws(
    action,
    (error) => {
      message = error.message;
      return message.startsWith(`${code}: `);
    },
    `${what}: the package refuses with ${code}`,
  );
  const text = message.slice(code.length + 2);
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Both refuse with the same words; the program may add what it did not do after them. */
function sameRefusal(what, programResult, code, packageCall) {
  const fromProgram = programError(programResult, what);
  const fromPackage = packageError(code, packageCall, what);
  assert.ok(
    fromProgram.startsWith(fromPackage),
    `${what}:\n  program: ${fromProgram}\n  package: ${fromPackage}`,
  );
}

// Repair words, at every count, and a count no card has.
for (const count of JSON.parse(mhfe.repairParameters()).repairWordCounts) {
  const result = program(
    ["repair-words", "--stdin", "--count", String(count)],
    [FULL_SIZE_CONTAINER],
  );
  assert.equal(result.status, 0, `repair-words --count ${count}: ${result.stderr}`);
  assert.equal(
    result.stdout.trim(),
    JSON.parse(mhfe.repairWords(FULL_SIZE_CONTAINER, count)).words,
    `repair-words --count ${count}`,
  );
}
sameRefusal(
  "repair-words --count 3",
  program(["repair-words", "--stdin", "--count", "3"], [FULL_SIZE_CONTAINER]),
  "INVALID_REPAIR_WORDS",
  () => mhfe.repairWords(FULL_SIZE_CONTAINER, 3),
);

// A repair of two unreadable words with the card, and one with nothing to repair.
const card = JSON.parse(mhfe.repairWords(FULL_SIZE_CONTAINER, 4)).words;
const damaged = FULL_SIZE_CONTAINER.split(" ");
damaged[2] = "?";
damaged[16] = "?";
for (const [what, typed, expected] of [
  ["two unreadable words", damaged.join(" "), FULL_SIZE_CONTAINER],
  ["nothing to repair", FULL_SIZE_CONTAINER, ""],
]) {
  const result = program(["repair", "--stdin"], [typed, card]);
  assert.equal(result.status, 0, `repair, ${what}: ${result.stderr}`);
  const repaired = JSON.parse(mhfe.repairContainer(typed, card));
  assert.equal(result.stdout.trim(), repaired.unchanged ? "" : repaired.container, what);
  assert.equal(result.stdout.trim(), expected, what);
}

// Refusals before any round, word for word.
sameRefusal(
  "check --words 24",
  program(["check", "--stdin", "--words", "24"], [FULL_SIZE_CONTAINER]),
  "INVALID_WORD_COUNT",
  () =>
    new mhfe.CheckSession(
      FULL_SIZE_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      "words",
      "24",
      "",
      "",
      noBytes(),
      knownAnswersOnly,
      noRound,
    ),
);
sameRefusal(
  "check --words 12 of a same-length container",
  program(["check", "--stdin", "--words", "12"], [REDUCED_COST_SAME_LENGTH_CONTAINER]),
  "NO_BUILT_IN_CHECK",
  () =>
    new mhfe.CheckSession(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      "words",
      "12",
      "",
      "",
      noBytes(),
      knownAnswersOnly,
      noRound,
    ),
);
sameRefusal(
  "decrypt --words 15 of a same-length container",
  program(["decrypt", "--stdin", "--words", "15"], [REDUCED_COST_SAME_LENGTH_CONTAINER]),
  "LENGTH_CHOICE_NOT_APPLICABLE",
  () =>
    mhfe.decrypt(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      15,
      new Uint8Array(),
      knownAnswersOnly,
      noRound,
    ),
);
/** The raw encryption of the package, with the repetition and the same-length choice given. */
const encrypt = (phrase, password, repeat, sameLength) => () =>
  mhfe.encrypt(
    encode(phrase),
    encode(password),
    encode(repeat),
    "",
    0,
    0,
    0,
    sameLength,
    0,
    false,
    knownAnswersOnly,
    noRound,
    () => {},
  );
sameRefusal(
  "encrypt --same-length of a 24-word phrase",
  program(["encrypt", "--stdin", "--same-length"], [ZERO_24]),
  "SAME_LENGTH_NEEDS_SHORT_PHRASE",
  encrypt(ZERO_24, "public test password", "public test password", true),
);
// The password's own rules come before its repetition is compared, in both.
sameRefusal(
  "encrypt with a tab in the password and another repetition",
  program(["encrypt", "--stdin"], [PHRASE, "a\tb", "a\tc"]),
  "CONTROL_CHARACTER_IN_PASSWORD",
  encrypt(PHRASE, "a\tb", "a\tc", false),
);
sameRefusal(
  "encrypt with another repetition",
  program(["encrypt", "--stdin"], [PHRASE, "public test password", "other"]),
  "PASSWORDS_DIFFER",
  encrypt(PHRASE, "public test password", "other", false),
);

// The other lengths detection could read: warned of for a 24-word container, as the first
// container of readPhrase() lists them, and not for a same-length one, as the second does not.
const facts = JSON.parse(mhfe.describePhrase(encode(AMBIGUOUS_12_WORDS)));
for (const [args, choice] of [
  [["encrypt", "--stdin"], facts.containers[0]],
  [["encrypt", "--stdin", "--same-length"], facts.containers[1]],
]) {
  // Standard input ends at the password: the warning comes before it.
  const result = program(args, [AMBIGUOUS_12_WORDS]);
  const warned = choice.otherLengths.every((words) =>
    result.stderr.includes(`also reads as ${words} words`),
  );
  assert.ok(warned, `mhfe ${args.join(" ")}: ${result.stderr}`);
  assert.equal(
    result.stderr.includes("also reads as"),
    choice.otherLengths.length > 0,
    `mhfe ${args.join(" ")} warns exactly when readPhrase() lists other lengths`,
  );
}
assert.deepEqual(
  facts.containers.map((choice) => choice.otherLengths),
  [[21], []],
);

console.log("The command-line tool and the browser package give the same results.");
