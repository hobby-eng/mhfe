// AUD-008: bounded source-level ownership/race probes; no WASM or Argon2 executes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolveObjectURL } from "node:buffer";
import vm from "node:vm";

const clientSource = readFileSync("web/client.js", "utf8");
const { MhfeClient } = await import(
  `data:text/javascript;base64,${Buffer.from(clientSource).toString("base64")}`
);
const sources = {
  workerSource: "public stub",
  argon2Threaded: "public threaded stub",
  argon2SingleThreaded: "public single stub",
  coreWasm: new Uint8Array([0]),
};
let checks = 0;
class StandInWorker {
  static last;
  constructor(url) {
    this.blob = resolveObjectURL(url);
    this.terminated = false;
    StandInWorker.last = this;
  }
  postMessage(message, transfer) {
    this.received = structuredClone(message, { transfer });
  }
  reply(data) {
    this.onmessage({ data });
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = StandInWorker;
const client = new MhfeClient(sources);
const publicPassword = new TextEncoder().encode("public password");
let rejectOlderCallback;
const older = client.decrypt({
  container: "public container",
  password: publicPassword,
  onProgress: () =>
    new Promise((_, reject) => {
      rejectOlderCallback = reject;
    }),
});
const oldWorker = StandInWorker.last;
oldWorker.reply({ type: "progress", round: 1, rounds: 12 });
client.cancel();
await assert.rejects(older, { code: "CANCELLED" });
assert.equal(oldWorker.terminated, true);
assert.equal(new TextDecoder().decode(publicPassword), "public password");
checks++;
const current = client.readContainer("public container");
const currentWorker = StandInWorker.last;
oldWorker.reply({ type: "result", result: { container: "stale result" } });
oldWorker.reply({ type: "error", error: { code: "INTERNAL_ERROR", message: "stale error" } });
const unhandled = [];
const recordUnhandled = (error) => unhandled.push(error);
process.on("unhandledRejection", recordUnhandled);
const lateError = new Error("public late callback failure");
rejectOlderCallback(lateError);
await new Promise((resolve) => setTimeout(resolve, 0));
process.off("unhandledRejection", recordUnhandled);
assert.deepEqual(unhandled, [lateError]);
assert.equal(currentWorker.terminated, false);
currentWorker.reply({ type: "result", result: { container: "current result" } });
assert.deepEqual(await current, { container: "current result" });
checks++;

for (const pim of [NaN, Infinity, -1, 1.5, 2 ** 32]) {
  const previous = StandInWorker.last;
  await assert.rejects(client.decrypt({ container: "c", password: publicPassword, pim }), {
    code: "INVALID_PIM",
  });
  assert.equal(StandInWorker.last, previous);
}
checks++;
for (const reference of [
  null,
  {},
  { words: 12, fingerprint: "00000000" },
  { words: 12, path: "m/0" },
  { address: "a", coin: "unknown" },
]) {
  const previous = StandInWorker.last;
  await assert.rejects(client.check({ container: "c", password: "p", reference }), TypeError);
  assert.equal(StandInWorker.last, previous);
}
checks++;

const realEncoder = TextEncoder;
const copied = [];
globalThis.TextEncoder = class extends realEncoder {
  encode(text) {
    const bytes = super.encode(text);
    copied.push(bytes);
    return bytes;
  }
};
globalThis.Worker = class extends StandInWorker {
  postMessage() {
    throw new Error("public pre-transfer failure");
  }
};
await assert.rejects(
  client.check({
    container: "c",
    password: "public p",
    passphrase: "public s",
    reference: { fingerprint: "00000000" },
  }),
  { code: "WORKER_FAILED" },
);
assert.ok(copied.length === 2 && copied.every((bytes) => bytes.every((byte) => byte === 0)));
assert.equal(StandInWorker.last.terminated, true);
globalThis.TextEncoder = realEncoder;
globalThis.Worker = StandInWorker;
checks++;

const workerSource = readFileSync("web/mhfe-worker.js", "utf8");
for (const throws of [false, true]) {
  const replies = [];
  const self = { postMessage: (reply) => replies.push(reply) };
  const core = {
    initSync() {},
    check: () => {
      if (throws) throw new Error("PUBLIC_ERROR: synthetic failure");
      return JSON.stringify({ matches: true, path: null });
    },
  };
  const context = vm.createContext({
    self,
    wasm_bindgen: core,
    createArgon2St: async () => ({}),
    argon2Engine: () => ({}),
  });
  vm.runInContext(workerSource, context, { filename: "web/mhfe-worker.js" });
  const password = new Uint8Array([1, 2, 3]);
  const passphrase = new Uint8Array([4, 5]);
  await self.onmessage({ data: { operation: "check", password, passphrase } });
  assert.ok(password.every((byte) => byte === 0) && passphrase.every((byte) => byte === 0));
  assert.equal(replies.at(-1).type, throws ? "error" : "result");
}
checks += 2;

const bridge = readFileSync("web/argon2-engine.js", "utf8");
for (const code of [0, -22, -1]) {
  const heap = new Uint8Array(512).fill(0xaa);
  let next = 64;
  const allocated = [];
  const freed = [];
  const module = {
    HEAPU8: heap,
    _malloc(length) {
      const pointer = next;
      next += length;
      allocated.push([pointer, length]);
      return pointer;
    },
    _free(pointer) {
      freed.push(pointer);
    },
    _argon2id_hash_raw(...args) {
      module.HEAPU8 = heap.slice();
      module.HEAPU8.fill(7, args[7], args[7] + args[8]);
      return code;
    },
  };
  const engine = vm.runInNewContext(`${bridge}\nargon2Engine(module);`, { module });
  const password = new Uint8Array([1, 2, 3]);
  const salt = new Uint8Array(16).fill(4);
  const key = new Uint8Array(32).fill(9);
  if (code === 0) {
    engine.derive(password, salt, 256, 1, key);
    assert.ok(key.every((byte) => byte === 7));
  } else {
    assert.throws(() => engine.derive(password, salt, 256, 1, key));
    assert.ok(key.every((byte) => byte === 9));
  }
  assert.ok(
    allocated.every(([pointer, length]) =>
      module.HEAPU8.subarray(pointer, pointer + length).every((byte) => byte === 0),
    ),
  );
  assert.equal(freed.length, 3);
  assert.deepEqual([...password], [1, 2, 3]);
}
checks += 3;
console.log(
  JSON.stringify({
    outcome: "passed",
    groups: checks,
    actualSources: ["web/client.js", "web/mhfe-worker.js", "web/argon2-engine.js"],
    limits:
      "Stand-ins execute production JS control paths; no real worker, browser CSP, WASM or Argon2 computation.",
  }),
);
