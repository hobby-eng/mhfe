// AUD-028 raw newline-framing boundary; public synthetic word, no Argon2 or draw.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

vm.runInThisContext(readFileSync("target/wasm-bindgen/mhfe.js", "utf8"));
const bindings = vm.runInThisContext("mhfe");
bindings.initSync({ module: readFileSync("dist/runtime/mhfe.wasm") });
const encoded = (text) => new TextEncoder().encode(text);
const empty = JSON.parse(bindings.describeDraw(encoded(""), [], "", false));
assert.equal(empty.randomBits, 256);
assert.equal(empty.expectedDraws, 1);
const framed = JSON.parse(bindings.describeDraw(encoded(""), [], "\nabandon", false));
assert(framed.randomBits < 256 && framed.expectedDraws > 1);
const attempts = [];
for (const [chosen, excluded] of [
  ["abandon", ""],
  ["", "abandon"],
]) {
  let value, refusal;
  try {
    value = JSON.parse(bindings.describeDraw(encoded(chosen), [], excluded, false));
  } catch (error) {
    refusal = error;
  }
  console.log(
    JSON.stringify({ empty, framed, malformed: value, refused: refusal?.message ?? null }),
  );
  attempts.push(refusal?.message ?? "");
}
for (const refusal of attempts) {
  assert.match(
    refusal,
    /INVALID_WORD_WISH/,
    "a supplied restriction must be refused instead of discarded",
  );
}
console.log("PASS: raw chosen/excluded restrictions cannot disappear through bad framing");
