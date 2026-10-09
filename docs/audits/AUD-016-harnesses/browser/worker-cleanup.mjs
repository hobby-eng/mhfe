// AUD-016: run the current worker sources with synthetic bindings to force exceptional paths.
// The production worker protocol, operation tables, and cleanup functions run unmodified.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = new URL("../../../../", import.meta.url);
const sources = ["web/worker-runtime.js", "web/core-worker.js", "web/passwords-worker.js"];
const read = (path) => readFileSync(new URL(path, root), "utf8");
const fields = [
  "phrase",
  "password",
  "passwordRepeat",
  "passphrase",
  "passphraseRepeat",
  "chosenWords",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
  "typed",
];
const secret = () => new TextEncoder().encode("synthetic public test data");
let assertions = 0;
function check(label, action) {
  action();
  assertions += 1;
  console.log(`PASS ${label}`);
}

function worker() {
  const messages = [];
  const frees = [];
  class CheckSession {
    compare() {
      throw new Error("INVALID_REQUEST: synthetic compare failure");
    }
    free() {
      frees.push("check");
    }
  }
  class HiddenWalletSession {
    open() {
      throw new Error("INVALID_PASSWORD_TEXT: synthetic password refusal");
    }
    free() {
      frees.push("hidden");
    }
  }
  const sandbox = {
    self: {
      postMessage: (message) => messages.push(structuredClone(message)),
      crypto: globalThis.crypto,
    },
    mhfe: {
      initSync() {},
      CheckSession,
      HiddenWalletSession,
      suiteParameters: () => JSON.stringify({ hiddenWalletRefusals: ["INVALID_PASSWORD_TEXT"] }),
      reviewPassword: () => {
        throw new Error("INVALID_PASSWORD_TEXT: synthetic review failure");
      },
    },
    WebAssembly: { Module: { customSections: () => [] }, RuntimeError: WebAssembly.RuntimeError },
    TextDecoder,
    Error,
    console,
  };
  const context = vm.createContext(sandbox);
  for (const path of sources) vm.runInContext(read(path), context, { filename: path });
  // No cryptography is part of this probe; only the binding calls and finally blocks are tested.
  vm.runInContext("argon2For = async () => ({})", context);
  vm.runInContext(
    "serveOperations(mhfe, { core: CORE_OPERATIONS, passwords: PASSWORD_OPERATIONS })",
    context,
  );
  return { sandbox, context, messages, frees };
}

for (const path of sources)
  console.log(`SOURCE ${path} ${createHash("sha256").update(read(path)).digest("hex")}`);

{
  const instance = worker();
  const request = { module: "passwords", operation: "review", compiled: {} };
  for (const field of fields) request[field] = secret();
  await instance.sandbox.self.onmessage({ data: request });
  check("all request secret fields wipe after binding throws", () => {
    for (const field of fields)
      assert.ok(
        request[field].every((byte) => byte === 0),
        field,
      );
    assert.equal(instance.messages.at(-1).error.code, "INVALID_PASSWORD_TEXT");
  });
}

{
  const instance = worker();
  const request = {
    module: "core",
    operation: "check",
    compiled: {},
    password: secret(),
    passphrase: secret(),
    asksLength: false,
  };
  await instance.sandbox.self.onmessage({ data: request });
  check("check session is freed and request wiped after compare throws", () => {
    assert.deepEqual(instance.frees, ["check"]);
    assert.ok(request.password.every((byte) => byte === 0));
    assert.ok(request.passphrase.every((byte) => byte === 0));
    assert.equal(instance.messages.at(-1).error.code, "INVALID_REQUEST");
  });
}

{
  const instance = worker();
  const request = {
    module: "core",
    operation: "hiddenWallets",
    compiled: {},
    mainPassphrase: secret(),
  };
  const sessionDone = instance.sandbox.self.onmessage({ data: request });
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(instance.messages.at(-1).question, "ready");
  const next = { password: secret(), passwordRepeat: secret() };
  await instance.sandbox.self.onmessage({ data: { type: "answer", value: next } });
  await Promise.resolve();
  await Promise.resolve();
  check("hidden-wallet refusal wipes both passwords and keeps session open", () => {
    assert.ok(next.password.every((byte) => byte === 0));
    assert.ok(next.passwordRepeat.every((byte) => byte === 0));
    assert.equal(instance.messages.at(-1).question, "refused");
    assert.deepEqual(instance.frees, []);
  });
  await instance.sandbox.self.onmessage({ data: { type: "answer", value: { close: true } } });
  await sessionDone;
  check("hidden session close frees binding and wipes main passphrase", () => {
    assert.deepEqual(instance.frees, ["hidden"]);
    assert.ok(request.mainPassphrase.every((byte) => byte === 0));
    assert.deepEqual(instance.messages.at(-1).result, { closed: true });
  });
}

for (const module of ["constructor", "__proto__", "toString"]) {
  const instance = worker();
  const request = { module, operation: "constructor", compiled: {}, password: secret() };
  await instance.sandbox.self.onmessage({ data: request });
  check(`worker refuses inherited operation ${module} and wipes request`, () => {
    assert.equal(instance.messages.at(-1).error.code, "INVALID_REQUEST");
    assert.ok(request.password.every((byte) => byte === 0));
  });
}

console.log(`Checks complete: ${assertions} passed assertions.`);
