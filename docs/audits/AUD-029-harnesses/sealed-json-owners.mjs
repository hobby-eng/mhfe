// Public reduced-cost encryption JSON heap control; new repair words never arrive as input.
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
const { bindings, coreMemory, realArgon2 } = await import(
  pathToFileURL(resolve("scripts/package-check/package.mjs")).href
);
const { REDUCED_COST_CONTAINER } = await import(
  pathToFileURL(resolve("scripts/public-test-data.mjs")).href
);
const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const encode = (text) => new TextEncoder().encode(text);
let calls = 0;
const engine = {
  derive(password, salt, memoryKib, passes, key) {
    if (["1024/1", "65536/3", "262144/2"].includes(memoryKib + "/" + passes)) {
      return realArgon2.derive(password, salt, memoryKib, passes, key);
    }
    assert.equal(memoryKib, 2097152);
    assert.equal(passes, 12);
    calls++;
    realArgon2.derive(password, salt, 256, 1, key);
  },
  reserve(memoryKib) {
    assert.equal(memoryKib, 2097152);
    return realArgon2.reserve(256);
  },
};
const json = bindings.encrypt(
  encode(phrase),
  encode("public test password"),
  encode("public test password"),
  "",
  0,
  0,
  0,
  false,
  4,
  false,
  engine,
  () => {},
  () => {},
);
const result = JSON.parse(json);
assert.equal(result.container, REDUCED_COST_CONTAINER);
assert.equal(calls, 24);
assert.equal(result.repairWords.split(" ").length, 4);
const needle = Buffer.from(json, "utf8");
const offset = Buffer.from(coreMemory.buffer).indexOf(needle, 1048576);
console.log(
  JSON.stringify({
    operation: "encrypt with repairWordCount4",
    jsonBytes: needle.length,
    repairWords: result.repairWords,
    heapJsonOffset: offset,
    aboveKnownStackEnd: offset >= 1048576,
    publicReducedCostCalls: calls,
  }),
);
assert.equal(
  offset,
  -1,
  "complete JSON containing newly generated repair words remains in linear heap after return",
);
