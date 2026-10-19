// Public raw-WASM password utility limits and review serialization; no Argon2 operation.
import assert from "node:assert/strict";

import { expectCode } from "./expect.mjs";
import { encode, noBytes } from "./test-values.mjs";
import { CHECK_WORD_MISMATCH_REPAIRS, UTILITY_INPUT_BYTES } from "../public-test-data.mjs";

/** Checks the raw binding contract, including exact byte limits and borrowed repair JSON. */
export function checkPasswordBoundaries(passwords) {
  const reviewed = (text) => JSON.parse(passwords.reviewPassword(encode(text), noBytes(), false));
  assert.deepEqual(reviewed("abacus abdomen abdominal abide abiding aids"), {
    profile: "MHFE-PASSWORD-CHECK-1",
    reading: "fits",
    correction: null,
    correctionText: null,
    offersCorrection: false,
    repairsFirst: false,
    repairs: [],
  });
  assert.deepEqual(
    reviewed("abacus abdomen abdominal zoom abiding aids").repairs,
    CHECK_WORD_MISMATCH_REPAIRS,
  );
  const strength = (text, choice = "", position = 0) =>
    JSON.parse(passwords.passwordStrength(encode(text), choice, position));
  assert.deepEqual(strength(""), { bits: 0, weak: true });
  for (const text of [
    "x".repeat(UTILITY_INPUT_BYTES),
    "é".repeat(UTILITY_INPUT_BYTES / 2),
    "\uFDFA".repeat(1024),
  ])
    assert(Number.isFinite(strength(text).bits), "bounded utility text remains accepted");
  console.log("Raw password review JSON and in-bound utility controls passed.");
  for (const text of [
    "x".repeat(UTILITY_INPUT_BYTES + 1),
    "é".repeat(UTILITY_INPUT_BYTES / 2) + "x",
  ])
    for (const choice of ["", "asTyped", "corrected", "repair"])
      expectCode("INVALID_REQUEST", () => strength(text, choice, 3));
  expectCode("INVALID_PASSWORD_UTF8", () =>
    passwords.passwordStrength(new Uint8Array([0xff]), "unknown", 0),
  );
  assert.throws(() => strength("x".repeat(UTILITY_INPUT_BYTES + 1), "unknown"), {
    message: "INVALID_REQUEST: invalid request: unknown password choice",
  });
}
