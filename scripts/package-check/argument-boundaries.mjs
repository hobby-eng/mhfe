// Public option containers and wish lists are admitted before workers or secret copies.
import assert from "node:assert/strict";

import { WISH_COUNT_REFUSALS } from "../public-test-data.mjs";
import { bindings } from "./package.mjs";
import { sources, wasm } from "./page-classes.mjs";
import { StandInWorker, started } from "./stand-in-worker.mjs";

/** Large enough to expose whole-list processing without an exhaustion campaign. */
const LARGE_WISH_LIST_SIZE = 4096;

/** Optional option records refuse non-record shapes before starting any worker. */
export async function checkOptionContainers(classes) {
  const families = [
    [() => new classes.MhfePasswords({ workerSource: "passwords worker", wasm }), "make"],
    [() => new classes.MhfeWallet({ workerSource: "wallet worker", wasm }), "describeDraw"],
    [() => new classes.MhfeWallet({ workerSource: "wallet worker", wasm }), "drawPhrase"],
    [() => new classes.MhfePasswords({ workerSource: "passwords worker", wasm }), "fullCheck"],
    [() => new classes.MhfeWallet({ workerSource: "wallet worker", wasm }), "fullCheck"],
    [() => new classes.MhfeRepair({ workerSource: "repair worker", wasm }), "fullCheck"],
    [() => new classes.MhfeClient(sources), "fullCheck"],
    [() => new classes.MhfeClient(sources), "startupCheck"],
    [() => new classes.MhfeClient(sources), "keepOldContainer"],
  ];
  const RealWorker = globalThis.Worker;
  let workers = 0;
  globalThis.Worker = class {
    constructor() {
      workers += 1;
      throw new Error("Public boundary worker control");
    }
  };
  try {
    for (const [make, method] of families) {
      for (const value of [42, false, "options", Symbol("options"), 1n, () => {}, [], null]) {
        const before = workers;
        await assert.rejects(make()[method](value), { name: "TypeError" }, method);
        assert.equal(workers, before, "a refused option shape starts no worker");
      }
      // Valid omission/default records must reach the external worker seam, not the type refusal.
      for (const args of [[], [undefined], [{}]]) {
        const before = workers;
        await assert.rejects(make()[method](...args), { code: "WORKER_FAILED" }, method);
        assert.ok(workers > before, "valid default options reach the worker seam");
      }
    }
  } finally {
    globalThis.Worker = RealWorker;
  }
}

/** Oversized wishes are refused before reading entries, even on a fresh class. */
export async function checkWishListBoundaries(classes) {
  const parameters = JSON.parse(bindings.walletParameters());
  for (const method of ["describeDraw", "drawPhrase"]) {
    for (const [field, limit, refusal] of [
      [
        "chosen",
        parameters.maxChosenWords,
        wishRefusal(classes.runtime, "\nhappy\nzoo", [1, 2], "", WISH_COUNT_REFUSALS.chosen),
      ],
      [
        "neverUse",
        parameters.maxNeverUseWords,
        wishRefusal(classes.runtime, "", [], "\nabandon\nzoo", WISH_COUNT_REFUSALS.neverUse),
      ],
    ]) {
      for (const count of [limit + 1, LARGE_WISH_LIST_SIZE]) {
        const list = Array(count);
        let reads = 0;
        Object.defineProperty(list, 0, {
          get() {
            reads += 1;
            throw new Error("An oversized wish entry was read");
          },
        });
        const wallet = new classes.MhfeWallet({ workerSource: "wallet worker", wasm });
        const before = StandInWorker.started.length;
        await assert.rejects(wallet[method]({ [field]: list }), {
          code: "INVALID_WORD_WISH",
          message: refusal,
        });
        assert.equal(reads, 0, `${method}/${field}: count precedes entry access`);
        assert.equal(StandInWorker.started.length, before, "no startup or operation worker");
      }
      for (const length of [-1, 0.5, Number.POSITIVE_INFINITY, "1", {}]) {
        const list = new Proxy([], {
          get(target, property) {
            return property === "length" ? length : Reflect.get(target, property);
          },
        });
        const wallet = new classes.MhfeWallet({ workerSource: "wallet worker", wasm });
        await assert.rejects(wallet[method]({ [field]: list }), TypeError);
      }
    }
  }
  const wallet = new classes.MhfeWallet({ workerSource: "wallet worker", wasm });
  const chosen = [{ word: "happy", position: 1 }];
  chosen[Symbol.iterator] = () => assert.fail("wish admission uses the bounded entry count");
  const neverUse = ["abandon"];
  neverUse.every = neverUse.map = () => assert.fail("caller collection methods are not trusted");
  const asking = wallet.describeDraw({
    chosen,
    neverUse,
  });
  const worker = await started((message) => message.operation === "describeDraw");
  const request = worker.messages[0];
  assert.equal(new TextDecoder().decode(request.chosenWords), "\nhappy");
  assert.deepEqual(request.places, [1]);
  assert.equal(request.neverUse, "\nabandon");
  const result = { randomBits: 245 };
  worker.reply({ type: "result", result });
  assert.deepEqual(await asking, result);
}

/** Read the existing library-owned diagnostic, not a second test-side wording template. */
function wishRefusal(runtime, chosen, places, excluded, expected) {
  let message;
  assert.throws(
    () => bindings.describeDraw(new TextEncoder().encode(chosen), places, excluded, false),
    (error) => {
      assert.match(error.message, /^INVALID_WORD_WISH: /u);
      message = error.message.replace(/^INVALID_WORD_WISH: /u, "");
      return true;
    },
  );
  assert.equal(typeof message, "string");
  assert.equal(
    runtime.sentence(message),
    expected,
    "raw binding keeps the established page sentence",
  );
  return expected;
}
