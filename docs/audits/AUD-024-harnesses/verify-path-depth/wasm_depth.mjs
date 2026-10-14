// AUD-024 verifier probe: the built browser package's describeAddress (dist/runtime/mhfe.wasm with
// the glue target/wasm-bindgen/mhfe.js of this checkout) on paths of depth 255, 256 and 100000.
// No Argon2. Exits 1 when a path deeper than 255 is accepted.
import { readFileSync } from "node:fs";
const root = process.argv[2];
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
const address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
let accepted = 0;
for (const depth of [255, 256, 100000]) {
  const path = "m" + "/0".repeat(depth);
  try {
    const got = JSON.parse(mhfe.describeAddress(address, "bitcoin", path, 0));
    console.log(`describeAddress depth ${depth}: accepted, onlyPath=${got.onlyPath}, addresses=${got.addresses}, search ${got.search.length} chars`);
    if (depth > 255) accepted += 1;
  } catch (e) {
    console.log(`describeAddress depth ${depth}: refused: ${(e && e.message) || e}`);
  }
}
try {
  mhfe.describeAddress(address, "bitcoin", "m/x", 0);
} catch (e) {
  console.log(`control m/x: refused: ${(e && e.message) || e}`);
}
console.log(`${accepted} path(s) deeper than 255 accepted`);
process.exit(accepted ? 1 : 0);
