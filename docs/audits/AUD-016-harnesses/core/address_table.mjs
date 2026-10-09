// Reuse AUD-015's independent address oracle without copying it or rewriting its old evidence.
// Its literal upstream known answers must pass before it checks the current source table.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const path = "docs/audits/AUD-015-harnesses/r4-wallet/address-oracle.mjs";
const original = readFileSync(path, "utf8");
console.log(`oracle ${path} sha256 ${createHash("sha256").update(original).digest("hex")}`);
const root = 'new URL("../../../../", import.meta.url)';
assert.equal(original.split(root).length, 2, "one oracle root expression");
const marker = "// --- 2. Extra cases for the Rust probe";
assert.equal(original.split(marker).length, 2, "one case-writing boundary");
const tablePath = "src/wallet/known_answers.rs";
const known = readFileSync(tablePath, "utf8");
console.log(`table ${tablePath} sha256 ${createHash("sha256").update(known).digest("hex")}`);
const table = known.slice(known.indexOf("pub(crate) const ADDRESSES:"));
const declared = Number(/const ADDRESSES: \[AddressCase; (\d+)\]/.exec(table)[1]);
const rows = [
  ...table.matchAll(/at\(\s*Coin::(\w+),\s*"([^"]*)",\s*"([^"]*)",\s*(?:true|false),?\s*\)/g),
].map(([, coin, path, address]) => ({ coin, passphrase: "", path, address }));
for (const [, fields] of table.matchAll(/AddressCase\s*\{([^}]+)\}/g)) {
  const coin = /coin:\s*Coin::(\w+)/.exec(fields)[1];
  const value = (name) => new RegExp(`${name}:\\s*"([^"]*)"`).exec(fields)[1];
  rows.push({
    coin,
    passphrase: value("passphrase"),
    path: value("path"),
    address: value("address"),
  });
}
assert.equal(rows.length, declared, "every row of the moved ADDRESSES table was read");
const beforeTable = original.indexOf('const source = readFileSync(new URL("src/wallet.rs", ROOT)');
const assertions = original.slice(
  original.indexOf("let tableChecked = 0;"),
  original.indexOf(marker),
);
assert.ok(beforeTable >= 0 && assertions.startsWith("let tableChecked"), "oracle boundaries");
// The data URL has no filesystem parent. Preserve the original module's repository root,
// read the table moved by AUD-015 remediation, and keep all independent arithmetic/assertions.
// The later case generator is not this probe and must not rewrite retained AUD-015 evidence.
const source = original.slice(0, beforeTable).replace(root, "pathToFileURL(`${process.cwd()}/`)");
const execution = `${source}\nconst rows = ${JSON.stringify(rows)}.map(row => ({...row, coin: COIN_IDS[row.coin]}));\n${assertions}\nconsole.log(\`PASS independent address table: \${tableChecked} current rows\`);\n`;
try {
  await import(`data:text/javascript;base64,${Buffer.from(execution).toString("base64")}`);
} catch (error) {
  console.error(`FAIL oracle: ${error.message}`);
  process.exitCode = 1;
}
