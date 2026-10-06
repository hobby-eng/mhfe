// AUD-008: independently check malformed Dash padding with the installed @scure/base.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [workspace, recordPath] = process.argv.slice(2);
if (!workspace || !recordPath) throw new Error("usage: script WORKSPACE WALLET-RECORD.json");
const require = createRequire(`${workspace}/multi-chain-wallet-tools/package.json`);
const modulePath = require.resolve("@scure/base");
const { bech32m } = await import(pathToFileURL(modulePath));
const record = JSON.parse(readFileSync(recordPath, "utf8"));
const canonical = "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs";
const reference = bech32m.decodeToBytes(canonical);
if (reference.bytes.length !== 21 || reference.bytes[0] !== 0xb0) {
  throw new Error("wrong positive control");
}
console.log(JSON.stringify({ modulePath, canonical, decodedHex: Buffer.from(reference.bytes).toString("hex") }));
for (const test of record.mismatches) {
  const address = test.input[6];
  // Validate the checksum separately, before enforcing byte conversion padding.
  const words = bech32m.decode(address).words;
  let reason;
  try {
    bech32m.fromWords(words);
    throw new Error("malformed address passed independent padding check");
  } catch (error) {
    reason = error.message;
    if (reason === "malformed address passed independent padding check") throw error;
  }
  console.log(JSON.stringify({ id: test.input[1], address, checksumValid: true, rejected: true, reason }));
}
