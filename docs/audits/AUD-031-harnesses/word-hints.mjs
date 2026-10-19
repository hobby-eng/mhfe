// Tiny public raw-binding/class controls; no Argon2, draws or resource-exhaustion workload.
import assert from "node:assert/strict";

import { bindings } from "../../../scripts/package-check/package.mjs";
import { loadClasses, wasm } from "../../../scripts/package-check/page-classes.mjs";
import { installStandInWorker, started } from "../../../scripts/package-check/stand-in-worker.mjs";

const limit = JSON.parse(bindings.walletParameters()).maxInputTextBytes;
assert.equal(limit, 8192, "independent literal control for the shared byte domain");
const encoder = new TextEncoder();
const classes = await loadClasses();
installStandInWorker();
const rows = [];

for (const [list, Class, prefix, word, suffix] of [
  ["bip39", classes.MhfeWallet, "artw", "artwork", "ork"],
  ["eff", classes.MhfePasswords, "abac", "abacus", "us"],
]) {
  const client = new Class({ workerSource: "public audit stand-in", wasm });
  for (const bytes of [limit, limit + 1]) {
    for (const multibyte of [false, true]) {
      const padding = bytes - prefix.length;
      const text = multibyte
        ? "\u2000".repeat(Math.floor(padding / 3)) + " ".repeat(padding % 3) + prefix
        : " ".repeat(padding) + prefix;
      const encoded = encoder.encode(text);
      assert.equal(encoded.byteLength, bytes);
      const raw = JSON.parse(bindings.wordHints(list, encoded));
      assert.ok(raw.words.includes(word), "literal dictionary positive control");
      assert.equal(raw.completion.letters, suffix);
      const pending = client.wordHints({ typed: text });
      const worker = await started((message) => message.operation === "wordHints");
      const request = worker.messages[0];
      assert.equal(request.typed.byteLength, bytes, "actual class transferred all supplied bytes");
      worker.reply({
        type: "result",
        result: JSON.parse(bindings.wordHints(list, request.typed)),
      });
      const result = await pending;
      assert.deepEqual(result, raw);
      rows.push({
        list,
        rawBytes: bytes,
        multibyte,
        rawAccepted: true,
        classAccepted: true,
        exceedsSharedByteDomain: bytes > limit,
      });
    }
  }
}

assert.equal(rows.filter((row) => row.exceedsSharedByteDomain).length, 4);
console.log(
  JSON.stringify({
    sharedMaxBytes: limit,
    rows,
    observed:
      "Both actual raw bindings and public classes accept raw size beyond the shared domain",
    limits:
      "Class transport uses the existing stand-in worker with actual raw bindings; not real browser scheduling or a memory-exhaustion campaign.",
  }),
);
