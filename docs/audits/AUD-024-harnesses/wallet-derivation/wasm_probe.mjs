// AUD-024 wallet-derivation: runs wasm-cases.json against the built browser package's WebAssembly
// (dist/runtime/mhfe.wasm with the wasm-bindgen glue target/wasm-bindgen/mhfe.js), calling only
// bindings that run without Argon2. Usage: node wasm_probe.mjs <repo root> <cases.json> [findings]
// Exits 1 when a case fails.
import { readFileSync } from "node:fs";
const [root, file, mode] = process.argv.slice(2);
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
const utf8 = (text) => new TextEncoder().encode(text);
const cases = JSON.parse(readFileSync(file, "utf8")).filter((c) => (mode === "findings") === Boolean(c.finding));
let failed = 0;
const message = (e) => (e && e.message) || String(e);
for (const c of cases) {
  let ok = false;
  let detail = "";
  try {
    if (c.t === "fp") {
      const got = mhfe.walletFingerprint(utf8(c.phrase), utf8(c.pass));
      ok = got === c.fp;
      detail = got;
    } else if (c.t === "decoy") {
      const got = JSON.parse(mhfe.searchDecoy(c.written, c.kind, c.reference, c.coin, c.path, utf8(c.pass), c.gap, () => {}));
      ok = got.found && got.container === c.container && (!c.found_path || got.path === c.found_path);
      detail = JSON.stringify({ found: got.found, path: got.path });
    } else if (c.t === "scope") {
      const got = JSON.parse(mhfe.describeAddress(c.address, c.coin, c.path, c.gap));
      ok = got.search === c.search && got.addresses === c.addresses;
      detail = JSON.stringify(got);
    } else if (c.t === "refused") {
      try {
        const got = mhfe.describeAddress(c.address, c.coin, c.path, 0);
        detail = `accepted: ${got.slice(0, 60)}...`;
      } catch (e) {
        ok = message(e).startsWith(c.code);
        detail = message(e);
      }
    } else if (c.t === "message") {
      try {
        detail = `accepted: ${mhfe.searchCandidates(c.written)}`;
      } catch (e) {
        detail = message(e);
        ok = !detail.includes(c.not_contains);
      }
    }
  } catch (e) {
    detail = `threw ${message(e)}`;
  }
  if (!ok) failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${c.id}${ok ? "" : `: ${detail}`}`);
}
console.log(`${cases.length} cases, ${cases.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
