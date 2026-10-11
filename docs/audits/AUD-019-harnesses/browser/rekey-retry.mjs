// AUD-019: public-data, no-KDF probes of the production retry adapter and worker cleanup.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const dataUrl = (text) => `data:text/javascript;base64,${Buffer.from(text).toString("base64")}`;
const runtimeUrl = dataUrl(read("web/runtime.js"));
const runtime = await import(runtimeUrl);
const { MhfeClient } = await import(
  dataUrl(read("web/client.js").replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`))
);
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const secret = () => new TextEncoder().encode("synthetic public test data");
const minimalWasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
let assertions = 0;
function passed(label) {
  assertions += 1;
  console.log(`PASS ${label}`);
}
for (const path of [
  "web/runtime.js",
  "web/client.js",
  "web/core-worker.js",
  "web/worker-runtime.js",
])
  console.log(`SOURCE ${path} ${createHash("sha256").update(read(path)).digest("hex")}`);

class FakeWorker {
  static all = [];
  static serve = null;
  constructor() {
    this.messages = [];
    this.failAnswers = false;
    FakeWorker.all.push(this);
  }
  postMessage(message, transfer = []) {
    if (this.failAnswers && message.type === "answer") throw new Error("synthetic send failure");
    const copy = structuredClone(message, { transfer });
    this.messages.push(copy);
    if (FakeWorker.serve) setTimeout(() => FakeWorker.serve(copy, this), 0);
  }
  reply(data) {
    if (!this.terminated) this.onmessage?.({ data });
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = FakeWorker;

// The page runtime owns these answer bytes until postMessage transfers them. Cancellation or
// a failed transfer must wipe its nested answer fields, without altering the caller's bytes.
for (const failure of ["cancel", "send"]) {
  const caller = secret();
  const owned = runtime.encodeSecret(caller, "passphrase");
  let answer;
  const wait = new Promise((resolve) => {
    answer = resolve;
  });
  const job = new runtime.WorkerJob(["synthetic"], { confirmAgain: () => wait });
  const workersBefore = FakeWorker.all.length;
  const outcome = job.run({}, [], new runtime.CompiledModule(minimalWasm, "wasm"));
  const observed = outcome.catch((error) => error);
  for (let i = 0; i < 50 && FakeWorker.all.length === workersBefore; i += 1) await tick();
  assert.equal(FakeWorker.all.length, workersBefore + 1);
  const worker = FakeWorker.all.at(-1);
  worker.reply({ type: "ready", buildId: runtime.BUILD_ID });
  worker.reply({ type: "ask", question: "confirmAgain", value: null });
  if (failure === "cancel") job.stop(new runtime.MhfeCancelledError());
  else worker.failAnswers = true;
  answer({ message: { passphrase: owned }, transfer: [owned.buffer] });
  await tick();
  assert.ok(owned.every((byte) => byte === 0));
  assert.deepEqual(caller, secret());
  assert.equal((await observed).code, failure === "cancel" ? "CANCELLED" : "WORKER_FAILED");
  passed(`nested retry answer wiped after ${failure}; caller unchanged`);
}

const parameters = {
  maxPim: 1023,
  maxMemoryLevel: 21,
  highestBrowserMemoryLevel: 0,
  wordCounts: [12, 15, 18, 21, 24],
  builtInCheckWordCounts: [12, 15, 18, 21],
  repairWordCounts: [2, 4, 6, 8],
  decoyScanGap: 20,
};
for (const invalid of [false, true]) {
  let ownerCalled = 0;
  const client = new MhfeClient({
    workerSource: "synthetic worker",
    wasm: minimalWasm,
    argon2Threaded: "synthetic threaded source",
    argon2SingleThreaded: "synthetic single-threaded source",
  });
  let retryMessage;
  FakeWorker.serve = (message, worker) => {
    worker.reply({ type: "ready", buildId: runtime.BUILD_ID });
    if (message.operation === "selfCheck") {
      worker.reply({
        type: "result",
        result: {
          version: "synthetic",
          tier: message.tier,
          passed: true,
          ids: ["synthetic"],
          components: [{ id: "synthetic", label: "Synthetic", outcome: "passed" }],
          parameters,
        },
      });
    } else if (message.operation === "rekey") {
      worker.reply({
        type: "ask",
        question: "confirmAgain",
        value: { code: "LENGTH_DIFFERS", message: "synthetic refusal", ownerLengths: [15] },
      });
    } else if (message.type === "answer" && retryMessage === undefined) {
      retryMessage = message.value;
      worker.reply({ type: "ask", question: "ownerCheck", value: { words: 15, statedWords: 12 } });
    } else if (message.type === "answer") {
      assert.equal(message.value, true);
      worker.reply({ type: "result", result: { confirmed: true } });
    }
  };
  const done = client.rekey({
    container: "synthetic public container",
    password: "public old password",
    newPassword: "public new password",
    newPasswordRepeat: "public new password",
    confirmation: { builtInCheck: true },
    words: 12,
    walletHasPassphrase: false,
    onConfirmAgain: ({ error, ownerLengths }) => {
      assert.equal(error.code, "LENGTH_DIFFERS");
      assert.deepEqual(ownerLengths, [15]);
      return {
        owner: (check) => {
          ownerCalled += 1;
          assert.equal(check.statedWords, 12);
          return true;
        },
        ...(invalid ? { words: 18 } : {}),
      };
    },
  });
  if (invalid) {
    await assert.rejects(
      done,
      (error) => error.code === "CALLBACK_FAILED" && error.cause instanceof TypeError,
    );
    assert.equal(retryMessage, undefined);
    assert.equal(ownerCalled, 0);
    passed("retry owner reading outside allowed lengths refused before worker transfer");
  } else {
    assert.equal((await done).confirmed, true);
    assert.equal(retryMessage.confirmKind, "owner");
    assert.equal(retryMessage.words, 15);
    assert.equal(ownerCalled, 1);
    passed("retry adapter supplies unique reading and uses replacement owner callback");
  }
  client.cancel();
}
FakeWorker.serve = null;

// Run the unmodified joined worker control flow with a binding stub. The stub deliberately
// refuses twice, so any repeat of recover(), skipped owner answer, or missed free is visible.
for (const ending of ["success", "stop", "owner-refusal", "confirm-throws"]) {
  const calls = { recover: 0, confirmAgain: 0, ownerAnswer: 0, seal: 0, free: 0 };
  const replies = [];
  const nextSecrets = [];
  class RekeySession {
    setNew() {}
    recover() {
      calls.recover += 1;
      throw new Error("LENGTH_DIFFERS: synthetic first refusal");
    }
    ownerLengths() {
      return JSON.stringify([15]);
    }
    confirmAgain() {
      calls.confirmAgain += 1;
      if (ending === "confirm-throws") throw new Error("INVALID_REQUEST: synthetic retry failure");
      if (calls.confirmAgain === 1) throw new Error("AMBIGUOUS_LENGTH: synthetic second refusal");
      return JSON.stringify({ ownerCheck: { words: 15, statedWords: 12 }, walletCheck: null });
    }
    ownerAnswer(answer) {
      calls.ownerAnswer += 1;
      if (!answer) throw new Error("NOT_CONFIRMED_BY_OWNER: synthetic owner refusal");
    }
    seal() {
      calls.seal += 1;
      return JSON.stringify({ container: "synthetic public sealed container" });
    }
    free() {
      calls.free += 1;
    }
  }
  let asks = 0;
  const sandbox = {
    self: {
      crypto: globalThis.crypto,
      postMessage(message) {
        replies.push(structuredClone(message));
        if (message.type !== "ask") return;
        let value;
        if (message.question === "ownerCheck") value = ending !== "owner-refusal";
        else if (ending === "stop" || (ending === "confirm-throws" && asks === 1)) value = null;
        else {
          value = {
            confirmKind: "owner",
            reference: "",
            coin: "",
            path: "",
            words: 15,
            passphrase: secret(),
          };
          nextSecrets.push(value.passphrase);
        }
        asks += 1;
        Promise.resolve().then(() => sandbox.self.onmessage({ data: { type: "answer", value } }));
      },
    },
    mhfe: { initSync() {}, RekeySession },
    WebAssembly: { Module: { customSections: () => [] }, RuntimeError: WebAssembly.RuntimeError },
    TextDecoder,
    Error,
    console,
  };
  const context = vm.createContext(sandbox);
  for (const path of ["web/worker-runtime.js", "web/core-worker.js"])
    vm.runInContext(read(path), context, { filename: path });
  vm.runInContext(
    "argon2For = async () => ({}); serveOperations(mhfe, { core: CORE_OPERATIONS })",
    context,
  );
  const request = {
    module: "core",
    operation: "rekey",
    compiled: {},
    confirmsAgain: true,
    password: secret(),
    newPassword: secret(),
    newPasswordRepeat: secret(),
    passphrase: secret(),
  };
  await sandbox.self.onmessage({ data: request });
  assert.equal(calls.recover, 1);
  assert.equal(calls.free, 1);
  for (const bytes of [
    request.password,
    request.newPassword,
    request.newPasswordRepeat,
    request.passphrase,
    ...nextSecrets,
  ])
    assert.ok(bytes.every((byte) => byte === 0));
  if (ending === "success") {
    assert.deepEqual(calls, { recover: 1, confirmAgain: 2, ownerAnswer: 1, seal: 1, free: 1 });
    assert.equal(replies.at(-1).result.walletCheck, null);
  } else {
    assert.equal(calls.seal, 0);
    assert.equal(replies.at(-1).type, "error");
    assert.equal(
      replies.at(-1).error.code,
      {
        stop: "LENGTH_DIFFERS",
        "owner-refusal": "NOT_CONFIRMED_BY_OWNER",
        "confirm-throws": "INVALID_REQUEST",
      }[ending],
    );
  }
  passed(`worker retry ${ending}: one recovery, final free, all owned bytes wiped`);
}
console.log(
  `Checks complete: ${assertions} passed assertions; no KDF or real wallet data executed.`,
);
