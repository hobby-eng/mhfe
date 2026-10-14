// AUD-024 harness (verify-input-limits): the built browser package must refuse an oversized
// address text and an oversized BIP39 passphrase at once (CORE-48, CORE-50). It loads the package's
// WebAssembly (dist/runtime/mhfe.wasm) with the wasm-bindgen glue of dist/runtime/worker.js, read
// only, and calls describeAddress and walletFingerprint as the wallet worker does. Exits 1 when a
// check fails, 0 when both pass.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = process.argv[2] ?? ".";
const glue = readFileSync(`${root}/dist/runtime/worker.js`, "utf8");
const marker = "})({ __proto__: null });";
const source = `${glue.slice(0, glue.indexOf(marker) + marker.length)}\nglobalThis.mhfe = mhfe;`;
const context = vm.createContext({ TextEncoder, TextDecoder, WebAssembly, FinalizationRegistry,
  console, Uint8Array, Uint32Array, DataView, Error, Object, Number, String, Array, JSON, Symbol });
vm.runInContext(source, context);
const mhfe = context.mhfe;
mhfe.initSync({ module: new WebAssembly.Module(readFileSync(`${root}/dist/runtime/mhfe.wasm`)) });

let failed = false;
const outcomeOf = (run) => {
  const started = performance.now();
  let outcome;
  try {
    outcome = { accepted: true, text: String(run()).slice(0, 60) };
  } catch (error) {
    outcome = { accepted: false, text: String(error?.message ?? error).slice(0, 100) };
  }
  return { ...outcome, ms: performance.now() - started };
};

const address = outcomeOf(() => mhfe.describeAddress("2".repeat(32_000), "bitcoin", "", 0));
const addressOk = !address.accepted && address.ms < 50;
console.log(`${addressOk ? "PASS" : "FAIL"} address text of 32000 characters refused within 50 ms: ` +
  `${address.accepted ? "accepted" : "refused"} after ${address.ms.toFixed(1)} ms (${address.text})`);
failed ||= !addressOk;

const phrase = new TextEncoder().encode(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
const passphrase = outcomeOf(() => mhfe.walletFingerprint(phrase, new Uint8Array(8 << 20).fill(0x61)));
const passphraseOk = !passphrase.accepted;
console.log(`${passphraseOk ? "PASS" : "FAIL"} BIP39 passphrase of 8 MiB refused: ` +
  `${passphrase.accepted ? "accepted" : "refused"} after ${passphrase.ms.toFixed(1)} ms (${passphrase.text})`);
failed ||= !passphraseOk;

process.exit(failed ? 1 : 0);
