// Protocol DTO refusals, independently of user callback failures and Rust's business rules.
import assert from "node:assert/strict";

import { wasm } from "./page-classes.mjs";
import { started } from "./stand-in-worker.mjs";

/** A malformed channel never reaches its page handler and ends its worker as PACKAGE_MISMATCH. */
export async function checkPageProtocol(runtime) {
  /** @type {[string, unknown, boolean][]} */
  const cases = [
    ["progress", { stage: "search", candidate: "one", candidates: 2 }, false],
    ["progress", { stage: "decrypt", round: 1 }, false],
    ["progress", { stage: "undeclared", round: 1, rounds: 12 }, false],
    ["unverified", { container: "c" }, false],
    ["componentStart", { id: "part" }, false],
    ["component", { id: "part", label: "Part", outcome: "unknown" }, false],
    ["draws", "one", false],
    ["ready", {}, true],
    ["opened", { phrase: "public synthetic phrase", words: 24 }, true],
    ["refused", { code: "UNDECLARED", message: "synthetic" }, true],
    ["ownerCheck", { phrase: "public synthetic phrase" }, true],
    ["confirmAgain", { code: "LENGTH_DIFFERS", message: "synthetic" }, true],
    ["noLength", { builtInCheck: null }, true],
  ];
  for (const [channel, value, question] of cases) {
    let called = false;
    const job = new runtime.WorkerJob(["synthetic worker"], {
      [channel]: () => {
        called = true;
      },
    });
    const running = job.run(
      { operation: "protocolProbe" },
      new runtime.CompiledModule(wasm, "wasm"),
    );
    const refused = assert.rejects(running, { code: "PACKAGE_MISMATCH" });
    const worker = await started((message) => message.operation === "protocolProbe");
    worker.reply(question ? { type: "ask", question: channel, value } : { type: channel, value });
    await refused;
    assert.equal(called, false, `${channel}: malformed data reaches no callback`);
    assert.equal(worker.terminated, true, `${channel}: malformed data leaves no worker alive`);
  }
}

/** Malformed page envelopes and operation fields are refused; their secret copies are wiped. */
export async function checkWorkerProtocol(inProcessWorker, script, compiled) {
  for (const envelope of [null, [], { type: "unknown" }, { module: 3, operation: "fingerprint" }]) {
    const posted = await inProcessWorker(script)(envelope);
    assert.equal(posted.at(-1).error.code, "PACKAGE_MISMATCH");
  }
  /** @type {[string, string, Record<string, unknown>][]} */
  const cases = [
    ["wallet", "fingerprint", { phrase: "not bytes" }],
    ["passwords", "strength", { password: new Uint8Array([1]), length: "not numeric" }],
    ["repair", "repairWords", { container: "synthetic", count: "not numeric" }],
    ["core", "describePhrase", { phrase: "not bytes" }],
  ];
  for (const [module, operation, fields] of cases) {
    const passphrase = new Uint8Array([7, 8]);
    const posted = await inProcessWorker(script)({
      module,
      operation,
      compiled,
      passphrase,
      ...fields,
    });
    assert.equal(posted.at(-1).error.code, "PACKAGE_MISMATCH", `${module}: typed boundary refusal`);
    assert.ok(
      passphrase.every((byte) => byte === 0),
      `${module}: refused request is wiped`,
    );
  }
}
