// Direct WASM boundaries refuse invalid options before engine or progress callbacks.
import assert from "node:assert/strict";

import { FULL_SIZE_CONTAINER, REDUCED_COST_SAME_LENGTH_CONTAINER } from "../public-test-data.mjs";
import { expectCode } from "./expect.mjs";
import { bindings } from "./package.mjs";
import { encode, NEW_PASSWORD, PASSWORD } from "./test-values.mjs";

/** Invalid raw rekey counts and recovery passphrases perform no Argon2 or round work. */
export function checkRawPreflight() {
  checkRawWishFrames();
  let calls = 0;
  const engine = {
    derive() {
      calls += 1;
      throw new Error("public preflight engine stop");
    },
    reserve() {
      calls += 1;
      throw new Error("public preflight reservation stop");
    },
  };
  const noProgress = () => assert.fail("refused input reached progress");
  for (const count of [1, 3, 10, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32]) {
    const session = new bindings.RekeySession(
      FULL_SIZE_CONTAINER,
      0,
      PASSWORD.slice(),
      "",
      0,
      0,
      0,
      engine,
    );
    try {
      expectCode("INVALID_REPAIR_WORDS", () =>
        session.setNew(NEW_PASSWORD.slice(), NEW_PASSWORD.slice(), "", 0, 0, 0, count),
      );
    } finally {
      session.free();
    }
    assert.equal(calls, 0, "invalid repair counts never reach the engine");
  }
  for (const count of [0, 2, 4, 6, 8]) {
    const session = new bindings.RekeySession(
      FULL_SIZE_CONTAINER,
      0,
      PASSWORD.slice(),
      "",
      0,
      0,
      0,
      engine,
    );
    try {
      session.setNew(NEW_PASSWORD.slice(), NEW_PASSWORD.slice(), "", 0, 0, 0, count);
    } finally {
      session.free();
    }
  }
  assert.equal(calls, 0, "valid options alone perform no engine work");
  const decrypt = (container, passphrase) =>
    bindings.decrypt(container, PASSWORD.slice(), "", 0, 0, 0, 0, passphrase, engine, noProgress);
  for (const container of [FULL_SIZE_CONTAINER, REDUCED_COST_SAME_LENGTH_CONTAINER]) {
    for (const text of ["x".repeat(1025), "é".repeat(513), "x".repeat(1023) + "é"]) {
      expectCode("PASSPHRASE_TOO_LONG", () => decrypt(container, encode(text)));
    }
  }
  expectCode("INVALID_PASSPHRASE", () => decrypt(FULL_SIZE_CONTAINER, new Uint8Array([255])));
  assert.equal(calls, 0, "invalid passphrases never reach the engine");
  for (const text of ["x".repeat(1024), "é".repeat(512)]) {
    const before = calls;
    // A valid boundary reaches the external engine, whose deliberate refusal stops the known answer.
    expectCode("SELF_CHECK_FAILED", () => decrypt(FULL_SIZE_CONTAINER, encode(text)));
    assert.equal(calls, before + 1);
  }
}

/** Raw word entries keep their framing and are bounded before collection or entropy work. */
export function checkRawWishFrames() {
  const describe = (chosen, places, excluded) =>
    JSON.parse(bindings.describeDraw(encode(chosen), places, excluded, false));
  assert.equal(describe("", [], "").randomBits, 256);
  assert.equal(describe("\nhappy", [1], "").randomBits, 245);
  assert.ok(describe("", [], "\nabandon").expectedDraws > 1);
  let draws = 0;
  const random = {
    fill() {
      draws += 1;
      assert.fail("malformed wishes reached entropy");
    },
  };
  const noProgress = () => assert.fail("malformed wishes reached progress");
  for (const [chosen, places, excluded, code = "INVALID_WORD_WISH"] of [
    ["happy", [], ""],
    ["", [], "abandon"],
    ["header\nhappy", [1], ""],
    ["", [], "header\nabandon"],
    ["\n", [1], ""],
    ["\n ", [1], ""],
    ["\nhappy zoo", [1], ""],
    ["\nhappy\nzoo", [1, 2], ""],
    ["", [], "\nabandon\nzoo"],
    // The raw frame bound is checked before counting entries in excessive wire text.
    ["\nhappy".repeat(2048), Array(2048).fill(1), "", "INVALID_REQUEST"],
    ["", [], "\nabandon".repeat(2048), "INVALID_REQUEST"],
  ]) {
    expectCode(code, () => describe(chosen, places, excluded));
    expectCode(code, () =>
      bindings.drawPhrase(
        encode(""),
        encode(""),
        encode(chosen),
        places,
        excluded,
        false,
        random,
        noProgress,
      ),
    );
  }
  expectCode("INVALID_REQUEST", () => describe("\nhappy", [], ""));
  assert.equal(draws, 0);
}
