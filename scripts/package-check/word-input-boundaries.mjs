// Direct word-shaped WASM boundary controls; public fixtures only, with no Argon2 work.
import assert from "node:assert/strict";

import { FULL_SIZE_CONTAINER, PHRASE, UTILITY_INPUT_BYTES } from "../public-test-data.mjs";
import { expectCode } from "./expect.mjs";
import { encode } from "./test-values.mjs";

/** Keeps raw count/byte refusals and ordinary extraction semantics visible in the package gate. */
export function checkWordInputBoundaries(bindings) {
  const phrase = " ".repeat(UTILITY_INPUT_BYTES - PHRASE.length) + PHRASE;
  assert.equal(JSON.parse(bindings.describePhrase(encode(phrase))).phrase, PHRASE);
  assert.equal(JSON.parse(bindings.describeContainer(phrase)).container, PHRASE);
  expectCode("INVALID_REQUEST", () => bindings.describePhrase(encode(`${phrase} `)));
  expectCode("INVALID_REQUEST", () => bindings.describeContainer(`${phrase} `));
  const oversized = "é".repeat(UTILITY_INPUT_BYTES / 2) + "x";
  expectCode("INVALID_REQUEST", () => bindings.inspectContainer(oversized));
  expectCode("INVALID_REQUEST", () => bindings.searchCandidates(oversized));
  expectCode("INVALID_REQUEST", () => bindings.repairContainer(FULL_SIZE_CONTAINER, oversized));
  expectCode("INVALID_REQUEST", () => bindings.makePassword("words", 1, encode(oversized), {}));
  assert.deepEqual(JSON.parse(bindings.inspectContainer("? ".repeat(1000))), {
    reading: "wrongLength",
    wordCount: 1000,
    unreadable: [],
  });
  expectCode("INVALID_REPAIR_WORDS", () =>
    bindings.repairContainer(FULL_SIZE_CONTAINER, "? ".repeat(9)),
  );
  const dice = " ".repeat(UTILITY_INPUT_BYTES - "11111".length) + "11111";
  assert.equal(JSON.parse(bindings.makePassword("words", 1, encode(dice), {})).password, "abacus");
  const card = "mhfe-repair-1 1/4 shaft 2/4 pupil 3/4 patient 4/4 jewel";
  assert.equal(JSON.parse(bindings.repairContainer(FULL_SIZE_CONTAINER, card)).unchanged, true);
}
