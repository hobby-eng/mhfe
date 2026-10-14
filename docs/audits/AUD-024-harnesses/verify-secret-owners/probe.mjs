// AUD-024 ARC003 remediation probe. The baseline finding and retained logs remain historical;
// this revision exercises the owner API instead of the removed field-name wiping helpers.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const rt = await import(pathToFileURL(resolve("web/runtime.js")).href);
const definitions = (file) => readFileSync(file, "utf8").split("// SECRET_OWNERS_BEGIN\n")[1]
  .split("// SECRET_OWNERS_END")[0].replaceAll("export class ", "class ");
assert.equal(definitions("web/runtime.js"), definitions("web/worker-runtime.js"));
for (const [label, holder] of [
  ["a named field", (secret) => ({ passphrase: secret })],
  ["an arbitrary field", (secret) => ({ seed: secret })],
  ["one level down", (secret) => ({ value: { passphrase: secret } })],
  ["two levels down", (secret) => ({ value: { value: { passphrase: secret } } })],
  ["an array", (secret) => ({ passwords: [secret] })],
]) {
  const secret = rt.encodeSecret("public synthetic probe", "probe");
  assert.ok(secret instanceof rt.SecretBytes);
  const bytes = secret.bytes;
  const request = new rt.SecretRequest(holder(secret));
  assert.deepEqual(request.transfer, [bytes.buffer]);
  try {
    assert.ok(bytes.some((byte) => byte !== 0));
  } finally {
    request.wipe();
  }
  assert.ok(bytes.every((byte) => byte === 0));
  console.log(`ok: ${label} transfers and wipes`);
}
for (const Owner of [rt.SecretBytes, rt.SecretRequest]) {
  const bytes = new Uint8Array([1, 2]);
  new Owner(Owner === rt.SecretBytes ? bytes : { bytes })[Symbol.dispose]();
  assert.deepEqual([...bytes], [0, 0]);
}
console.log("Both owners provide wipe() and conditional Symbol.dispose; definitions match.");
