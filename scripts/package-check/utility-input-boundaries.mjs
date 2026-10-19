// Raw/class utility boundaries use public words only, without Argon2 or drawing.
import assert from "node:assert/strict";
import { UTILITY_INPUT_BYTES } from "../public-test-data.mjs";
import { expectCode } from "./expect.mjs";
import { bindings } from "./package.mjs";
import { nextTurn } from "./expect.mjs";
import { wasm } from "./page-classes.mjs";
import { StandInWorker, started } from "./stand-in-worker.mjs";

/** Raw hints and single wish entries admit exact UTF-8 limits before their word semantics. */
export function checkUtilityInputBoundaries() {
  const encoder = new TextEncoder();
  for (const [list, prefix, word, suffix] of [
    ["bip39", "artw", "artwork", "ork"],
    ["eff", "abac", "abacus", "us"],
  ]) {
    for (const unit of [" ", "\u2003"]) {
      const size = UTILITY_INPUT_BYTES - prefix.length;
      const text =
        unit.repeat(Math.floor(size / encoder.encode(unit).length)) +
        " ".repeat(size % encoder.encode(unit).length) +
        prefix;
      expectCode("INVALID_REQUEST", () => bindings.wordHints(list, encoder.encode(`${text} `)));
      const answer = JSON.parse(bindings.wordHints(list, encoder.encode(text)));
      assert.ok(answer.words.includes(word));
      assert.equal(answer.completion.letters, suffix);
    }
  }
  for (const field of ["chosen", "neverUse"]) {
    const word = field === "chosen" ? "happy" : "abandon";
    const describe = (text) =>
      field === "chosen"
        ? bindings.describeDraw(encoder.encode(`\n${text}`), [1], "", false)
        : bindings.describeDraw(new Uint8Array(), [], `\n${text}`, false);
    const reference = JSON.parse(describe(word));
    for (const unit of [" ", "\u2003"]) {
      const width = encoder.encode(unit).length;
      const size = UTILITY_INPUT_BYTES - word.length;
      const text = unit.repeat(Math.floor(size / width)) + " ".repeat(size % width) + word;
      assert.deepEqual(JSON.parse(describe(text)), reference);
      expectCode("INVALID_REQUEST", () => describe(`${text} `));
    }
  }
  assert.equal(JSON.parse(bindings.passwordParameters()).maxInputTextBytes, UTILITY_INPUT_BYTES);
}

/** Both secret representations and caller-owned bytes preserve bounded actual class transport. */
export async function checkUtilityClassBoundaries(classes) {
  const encoder = new TextEncoder();
  for (const [Class, list, prefix] of [
    [classes.MhfeWallet, "bip39", "artw"],
    [classes.MhfePasswords, "eff", "abac"],
  ]) {
    const client = new Class({ workerSource: "public utility control", wasm });
    await client.startupCheck();
    for (const text of [
      " ".repeat(UTILITY_INPUT_BYTES - prefix.length) + prefix,
      "\u2003".repeat(2730) + "aa",
    ]) {
      const encoded = encoder.encode(text);
      assert.equal(encoded.byteLength, UTILITY_INPUT_BYTES);
      for (const typed of [text, encoded]) {
        const pending = client.wordHints({ typed });
        const worker = await started((request) => request.operation === "wordHints");
        const request = worker.messages[0];
        const result = JSON.parse(bindings.wordHints(list, request.typed));
        worker.reply({ type: "result", result });
        assert.deepEqual(await pending, result);
        assert.deepEqual(
          encoded,
          encoder.encode(text),
          "caller bytes must remain owned and unchanged",
        );
      }
      for (const typed of [`${text} `, encoder.encode(`${text} `)]) {
        const before = StandInWorker.started.length;
        await assert.rejects(client.wordHints({ typed }), { code: "INVALID_REQUEST" });
        assert.ok(
          StandInWorker.started
            .slice(before)
            .every((worker) => worker.messages[0]?.operation === "parameters"),
        );
      }
    }
  }
  const wallet = new classes.MhfeWallet({ workerSource: "public wish control", wasm });
  await wallet.startupCheck();
  for (const field of ["chosen", "neverUse"]) {
    const word = field === "chosen" ? "happy" : "abandon";
    const value = " ".repeat(UTILITY_INPUT_BYTES - word.length) + word;
    const options =
      field === "chosen" ? { chosen: [{ word: value, position: 1 }] } : { neverUse: [value] };
    const pending = wallet.describeDraw(options);
    const worker = await started((request) => request.operation === "describeDraw");
    const request = worker.messages[0];
    const result = JSON.parse(
      bindings.describeDraw(request.chosenWords, request.places, request.neverUse, false),
    );
    const expected = JSON.parse(
      bindings.describeDraw(
        encoder.encode(field === "chosen" ? `\n${word}` : ""),
        field === "chosen" ? [1] : [],
        field === "neverUse" ? `\n${word}` : "",
        false,
      ),
    );
    worker.reply({ type: "result", result });
    assert.deepEqual(await pending, expected, "exact-limit framed class wishes preserve semantics");
  }
  // Deliberate copy of browser refusal fixtures: the isolated page cannot import this Node harness.
  for (const options of [
    { chosen: [{ word: " ".repeat(UTILITY_INPUT_BYTES) + "happy", position: 1 }] },
    { neverUse: [" ".repeat(UTILITY_INPUT_BYTES) + "abandon"] },
  ]) {
    for (const operation of ["describeDraw", "drawPhrase"]) {
      const before = StandInWorker.started.length;
      await assert.rejects(wallet[operation](options), { code: "INVALID_REQUEST" });
      assert.ok(
        StandInWorker.started
          .slice(before)
          .every((worker) => worker.messages[0]?.operation === "parameters"),
      );
    }
  }
  await checkCancelledWishAdmission(classes.MhfeWallet);
}

/** A late parameter reply cannot revive a drawing cancelled before its wishes were admitted. */
async function checkCancelledWishAdmission(MhfeWallet) {
  const wallet = new MhfeWallet({ workerSource: "public wish control", wasm: wasm.slice() });
  await wallet.startupCheck();
  const before = StandInWorker.started.length;
  StandInWorker.autoParameters = false;
  try {
    const pending = wallet.drawPhrase({ chosen: [{ word: "happy", position: 1 }] });
    const refused = assert.rejects(pending, { code: "CANCELLED" });
    const worker = await started((request) => request.operation === "parameters");
    wallet.cancel();
    await refused;
    worker.reply({ type: "result", result: { maxInputTextBytes: UTILITY_INPUT_BYTES } });
    await nextTurn();
    assert.ok(
      StandInWorker.started
        .slice(before)
        .every((each) => each.messages.every(({ operation }) => operation !== "drawPhrase")),
    );
  } finally {
    StandInWorker.autoParameters = true;
    wallet.cancel();
  }
}
