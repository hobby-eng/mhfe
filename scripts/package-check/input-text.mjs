// Parameter-driven raw-text admission, independently compared with the platform UTF-8 encoder.
import assert from "node:assert/strict";
import {
  UTILITY_INPUT_BYTES,
  PHRASE,
  TEST_PASSWORD,
  FULL_SIZE_CONTAINER,
} from "../public-test-data.mjs";
import { sources, wasm } from "./page-classes.mjs";
import { StandInWorker, RealTextEncoder, encoderKeeping, started } from "./stand-in-worker.mjs";
import { nextTurn } from "./expect.mjs";

/** Raw admission is synchronous, byte-exact and independent of normalized password rules. */
export async function checkInputText(runtime, maximum) {
  assert.equal(typeof runtime.requireInputText, "function");
  assert.equal(typeof runtime.InputTextBoundary, "function");
  assert.equal(maximum, UTILITY_INPUT_BYTES);
  for (const unit of ["a", "é", "\u2003", "🔐"]) {
    const width = new TextEncoder().encode(unit).length;
    for (const size of [maximum - 1, maximum, maximum + 1]) {
      const text = unit.repeat(Math.floor(size / width)) + "a".repeat(size % width);
      assert.equal(new TextEncoder().encode(text).length, size);
      if (size <= maximum) {
        assert.equal(runtime.requireInputText(text, maximum, "container"), undefined);
      } else {
        assert.throws(() => runtime.requireInputText(text, maximum, "container"), {
          code: "INVALID_REQUEST",
        });
      }
    }
  }
  for (const point of [0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff]) {
    const text = `a${String.fromCodePoint(point)}`;
    const bytes = new TextEncoder().encode(text).length;
    runtime.requireInputText(text, bytes, "phrase");
    assert.throws(() => runtime.requireInputText(text, bytes - 1, "phrase"), {
      code: "INVALID_REQUEST",
    });
  }
  for (const text of ["\ud800", "\udfff", "a\ud800b", "a\udfffb"]) {
    assert.throws(() => runtime.requireInputText(text, maximum, "container"), {
      code: "INVALID_REQUEST",
    });
  }
  for (const value of [null, 3, {}, new Uint8Array(1)]) {
    assert.throws(() => runtime.requireInputText(value, maximum, "phrase"), TypeError);
  }
  for (const limit of [0, -1, 1.5, Infinity, "8192", undefined]) {
    assert.throws(() => runtime.requireInputText("a", limit, "phrase"), TypeError);
  }
  runtime.requireInputText("", maximum, "phrase");
  await checkBoundaryCache(runtime, maximum);
  await checkParameterRefusals(runtime, maximum);
  await checkSecretUtilityCopies(runtime, maximum);
}

/** Mutable byte views are admitted after metadata resolves and copied without touching callers. */
async function checkSecretUtilityCopies(runtime, maximum) {
  const boundary = new runtime.InputTextBoundary(async () => ({ maxInputTextBytes: maximum }));
  const caller = new Uint8Array(maximum).fill(97);
  const copy = await boundary.copy(caller, "typed");
  assert.notEqual(copy.buffer, caller.buffer);
  assert.deepEqual(copy, caller);
  copy.fill(0);
  assert.ok(caller.every((byte) => byte === 97));
  const hiddenSize = new Uint8Array(maximum + 1);
  Object.defineProperty(hiddenSize, "byteLength", { value: 0 });
  await assert.rejects(boundary.copy(hiddenSize, "typed"), { code: "INVALID_REQUEST" });
  const buffer = new ArrayBuffer(1, { maxByteLength: maximum + 1 });
  const view = new Uint8Array(buffer);
  let publish;
  const waiting = new runtime.InputTextBoundary(
    () =>
      new Promise((resolve) => {
        publish = resolve;
      }),
  );
  const pending = waiting.copy(view, "typed");
  buffer.resize(maximum + 1);
  publish({ maxInputTextBytes: maximum });
  await assert.rejects(pending, { code: "INVALID_REQUEST" });
  await checkSharedGrowthCopy(boundary, maximum);
  const slot = new runtime.OperationSlot();
  const value = { public: true };
  assert.equal(await slot.after(Promise.resolve(value), (ready) => ready), value);
}

/** Deterministically grow shared storage at the constructor/copy seam, after size admission. */
async function checkSharedGrowthCopy(boundary, maximum) {
  const RealBytes = globalThis.Uint8Array;
  const shared = new SharedArrayBuffer(maximum, { maxByteLength: maximum + 1 });
  const tracking = new RealBytes(shared).fill(97);
  let grew = false;
  globalThis.Uint8Array = class extends RealBytes {
    static [Symbol.hasInstance](value) {
      return value instanceof RealBytes;
    }
    constructor(...arguments_) {
      if (!grew && (arguments_[0] === tracking || arguments_[0] === shared)) {
        shared.grow(maximum + 1);
        grew = true;
      }
      super(...arguments_);
    }
  };
  try {
    const copy = await boundary.copy(tracking, "typed");
    assert.equal(grew, true, "the storage actually grew at the copy seam");
    assert.equal(tracking.byteLength, maximum + 1);
    assert.equal(copy.byteLength, maximum, "only the admitted extent is copied");
    assert.notEqual(copy.buffer, shared);
    copy.fill(0);
    assert.equal(tracking[0], 97, "the caller still owns its data");
  } finally {
    globalThis.Uint8Array = RealBytes;
  }
}

/** Concurrent admissions share one scalar limit and never retain a mutable parameters object. */
async function checkBoundaryCache(runtime, maximum) {
  let calls = 0;
  const parameters = { maxInputTextBytes: maximum };
  const boundary = new runtime.InputTextBoundary(async () => {
    calls++;
    return parameters;
  });
  await assert.rejects(boundary.read(null, "phrase"), TypeError);
  assert.equal(calls, 0, "wrong types are refused before starting a parameter worker");
  await Promise.all([boundary.read("first", "phrase"), boundary.read("second", "container")]);
  assert.equal(calls, 1);
  parameters.maxInputTextBytes++;
  await assert.rejects(boundary.read("a".repeat(maximum + 1), "phrase"), {
    code: "INVALID_REQUEST",
  });
  assert.equal(calls, 1);
}

/** A failed parameter read is retryable; missing or malformed limits cannot open admission. */
async function checkParameterRefusals(runtime, maximum) {
  let calls = 0;
  const boundary = new runtime.InputTextBoundary(async () => {
    if (calls++ === 0) throw new Error("public synthetic worker failure");
    return { maxInputTextBytes: maximum };
  });
  await assert.rejects(boundary.read("a", "phrase"), /public synthetic worker failure/u);
  await boundary.read("a", "phrase");
  assert.equal(calls, 2);
  for (const parameters of [null, {}, { maxInputTextBytes: 0 }, { maxInputTextBytes: "8192" }]) {
    const invalid = new runtime.InputTextBoundary(async () => parameters);
    await assert.rejects(invalid.read("a", "phrase"), { code: "PACKAGE_MISMATCH" });
  }
}

/** Public classes refuse oversized text before copying any operation secret or posting it. */
export async function checkInputTextClients(classes) {
  const oversized = " ".repeat(UTILITY_INPUT_BYTES - PHRASE.length + 1) + PHRASE;
  const client = new classes.MhfeClient(sources);
  const repair = new classes.MhfeRepair({ workerSource: "repair worker", wasm });
  const wallet = new classes.MhfeWallet({ workerSource: "wallet worker", wasm });
  const before = StandInWorker.started.length;
  const copies = [];
  globalThis.TextEncoder = encoderKeeping([oversized, PHRASE, TEST_PASSWORD], copies);
  try {
    for (const call of [
      () => client.readPhrase(oversized),
      () => client.readContainer(oversized),
      () => client.searchCandidates({ container: oversized }),
      () =>
        client.encrypt({
          phrase: oversized,
          password: TEST_PASSWORD,
          passwordRepeat: TEST_PASSWORD,
        }),
      () => client.decrypt({ container: oversized, password: TEST_PASSWORD }),
      () => repair.repairWords({ container: oversized, count: 4 }),
      () => repair.inspectContainer({ container: oversized }),
      () => repair.repairContainer({ container: FULL_SIZE_CONTAINER, card: oversized }),
      () => wallet.fingerprint({ phrase: oversized }),
      () => wallet.walletCheck({ phrase: oversized, passphrase: TEST_PASSWORD }),
    ]) {
      await assert.rejects(call(), { code: "INVALID_REQUEST" });
    }
    assert.equal(copies.length, 0, "size refusals precede all phrase/password transport copies");
    for (const worker of StandInWorker.started.slice(before)) {
      for (const message of worker.messages) {
        assert.ok(
          ["parameters", "selfCheck", "selfCheckArgon2", "selfCheckProcess"].includes(
            message.operation,
          ),
          "only public parameter reads and startup checks precede refusal",
        );
      }
    }
    await checkCancelledAdmission(classes, copies);
  } finally {
    globalThis.TextEncoder = RealTextEncoder;
    client.cancel();
    wallet.cancel();
  }
}

/** Cancel while the scalar limit is loading; a late reply must not start encryption or copy. */
async function checkCancelledAdmission(classes, copies) {
  const client = new classes.MhfeClient(sources);
  StandInWorker.autoParameters = false;
  const before = StandInWorker.started.length;
  try {
    const encrypting = client.encrypt({
      phrase: PHRASE,
      password: TEST_PASSWORD,
      passwordRepeat: TEST_PASSWORD,
    });
    const cancelled = assert.rejects(encrypting, { code: "CANCELLED" });
    const worker = await started(({ operation }) => operation === "parameters");
    client.cancel();
    await cancelled;
    worker.reply({ type: "result", result: { maxInputTextBytes: UTILITY_INPUT_BYTES } });
    await nextTurn();
    assert.equal(copies.length, 0);
    assert.ok(
      StandInWorker.started
        .slice(before)
        .every((each) => each.messages.every(({ operation }) => operation !== "encrypt")),
      "a late parameter reply cannot revive a cancelled operation",
    );
  } finally {
    StandInWorker.autoParameters = true;
    client.cancel();
  }
}
