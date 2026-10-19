// Public bounded examples of the remaining single-word raw-admission variant; no drawing/KDF.
import assert from "node:assert/strict";
import { bindings } from "../../../scripts/package-check/package.mjs";
import { loadClasses, wasm } from "../../../scripts/package-check/page-classes.mjs";
import { installStandInWorker, started } from "../../../scripts/package-check/stand-in-worker.mjs";

const limit = JSON.parse(bindings.walletParameters()).maxInputTextBytes;
assert.equal(limit, 8192);
const encoder = new TextEncoder();
const classes = await loadClasses();
installStandInWorker();
const rows = [];
for (const field of ["chosen", "neverUse"]) {
  const word = field === "chosen" ? "happy" : "abandon";
  const literal =
    field === "chosen"
      ? JSON.parse(bindings.describeDraw(encoder.encode(`\n${word}`), [1], "", false))
      : JSON.parse(bindings.describeDraw(new Uint8Array(), [], `\n${word}`, false));
  for (const bytes of [limit, limit + 1]) {
    for (const multibyte of [false, true]) {
      const count = bytes - word.length;
      const value =
        (multibyte
          ? "\u2003".repeat(Math.floor(count / 3)) + " ".repeat(count % 3)
          : " ".repeat(count)) + word;
      assert.equal(encoder.encode(value).byteLength, bytes);
      const wire = `\n${value}`;
      const result =
        field === "chosen"
          ? JSON.parse(bindings.describeDraw(encoder.encode(wire), [1], "", false))
          : JSON.parse(bindings.describeDraw(new Uint8Array(), [], wire, false));
      assert.deepEqual(result, literal);
      const client = new classes.MhfeWallet({
        workerSource: "public audit stand-in",
        wasm: new Uint8Array(wasm),
      });
      const pending = client.describeDraw(
        field === "chosen" ? { chosen: [{ word: value, position: 1 }] } : { neverUse: [value] },
      );
      const worker = await started((message) => message.operation === "describeDraw");
      const message = worker.messages[0];
      const transferred =
        field === "chosen"
          ? message.chosenWords.byteLength
          : encoder.encode(message.neverUse).byteLength;
      assert.equal(transferred, bytes + 1);
      worker.reply({ type: "result", result });
      assert.deepEqual(await pending, literal);
      rows.push({
        field,
        valueUtf8Bytes: bytes,
        wireUtf8Bytes: transferred,
        multibyte,
        rawAccepted: true,
        classCopiedAndAccepted: true,
      });
    }
  }
}
console.log(
  JSON.stringify(
    { observed: "Unbounded single-entry whitespace reaches class transport and raw parser", rows },
    null,
    2,
  ),
);
assert.equal(rows.filter(({ valueUtf8Bytes }) => valueUtf8Bytes > limit).length, 4);
