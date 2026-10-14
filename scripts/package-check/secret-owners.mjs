// Ownership controls that do not depend on any protocol field's spelling.
import assert from "node:assert/strict";

import { read } from "./package.mjs";

/** Bytes at every request depth transfer once, wipe on refusal, and support explicit disposal. */
export async function checkSecretOwners(runtime) {
  for (const holder of [
    (owned) => ({ passphrase: owned }),
    (owned) => ({ seed: owned }),
    (owned) => ({ value: { passphrase: owned } }),
    (owned) => ({ value: { value: { passphrase: owned } } }),
    (owned) => ({ passwords: [owned] }),
  ]) {
    const owned = runtime.encodeSecret("public synthetic bytes", "probe");
    assert.ok(owned instanceof runtime.SecretBytes);
    const bytes = owned.bytes;
    const request = new runtime.SecretRequest(holder(owned));
    assert.deepEqual(request.transfer, [bytes.buffer]);
    try {
      assert.ok(bytes.some((byte) => byte !== 0));
    } finally {
      request.wipe();
    }
    assert.ok(bytes.every((byte) => byte === 0));
    request.wipe();
  }
  const owned = runtime.encodeSecret("public shared reference", "probe");
  const record = { first: owned, again: [owned] };
  record.loop = record;
  const request = new runtime.SecretRequest(record);
  assert.equal(request.transfer.length, 1, "a repeated buffer transfers once");
  structuredClone(request.message, { transfer: request.transfer });
  assert.equal(owned.bytes.byteLength, 0, "transfer empties the sender");
  request.wipe();
  for (const Owner of [runtime.SecretBytes, runtime.SecretRequest]) {
    const bytes = new Uint8Array([1, 2]);
    const value = Owner === runtime.SecretBytes ? bytes : { bytes };
    new Owner(value)[Symbol.dispose]();
    assert.deepEqual([...bytes], [0, 0]);
  }
  // An older browser lacks the symbol; it can still use both owners' explicit wipe().
  const source = read("web/runtime.js")
    .toString()
    .split("// SECRET_OWNERS_BEGIN\n")[1]
    .split("// SECRET_OWNERS_END")[0]
    .replaceAll("export class ", "class ");
  // oxlint-disable-next-line typescript/no-implied-eval -- the reviewed owner definitions under a browser feature stand-in
  const withoutDispose = new Function(
    "Symbol",
    `${source}\nreturn { SecretBytes, SecretRequest };`,
  )({});
  const bytes = new Uint8Array([3, 4]);
  new withoutDispose.SecretRequest({ seed: new withoutDispose.SecretBytes(bytes) }).wipe();
  assert.deepEqual([...bytes], [0, 0]);
  await checkPendingCompilationWiped(runtime);
}

/** cancel() wipes the request while compilation is pending, before its promise resolves. */
async function checkPendingCompilationWiped(runtime) {
  let finish;
  const compiling = new Promise((resolve) => {
    finish = resolve;
  });
  const owned = runtime.encodeSecret("public pending compilation", "probe");
  const job = new runtime.WorkerJob(["synthetic worker"]);
  const running = job.run({ password: owned }, { get: () => compiling });
  const refused = assert.rejects(running, { code: "CANCELLED" });
  job.stop(new runtime.MhfeCancelledError());
  assert.ok(
    owned.bytes.every((byte) => byte === 0),
    "cancel wipes before compilation settles",
  );
  finish(new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])));
  await refused;
}
