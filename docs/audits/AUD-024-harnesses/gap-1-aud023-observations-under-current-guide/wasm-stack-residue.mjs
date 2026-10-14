// AUD-024 harness: the BIP32 master private key and chain code of BIP39's published vector
// ("abandon ... about" with the passphrase "TREZOR", xprv9s21...UsAF) left in the browser
// package's WebAssembly memory after walletFingerprint has returned, and where. A control then
// zeroes the dead shadow stack (below the initial __stack_pointer, no WebAssembly frame active)
// and calls again. Exits 1 when copies are left after the call. Needs dist/runtime/mhfe.wasm and
// target/wasm-bindgen/mhfe.js from scripts/build-wasm.sh, read through
// scripts/package-check/package.mjs.
//
//   node docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/wasm-stack-residue.mjs
import { instanceOver, packageWasm } from "../../../../scripts/package-check/package.mjs";

const PHRASE = `${"abandon ".repeat(11)}about`;
const XPRV =
  "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF";
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
let n = 0n;
for (const c of XPRV) n = n * 58n + BigInt(B58.indexOf(c));
const raw = Buffer.from(n.toString(16).padStart(164, "0"), "hex");
const NEEDLES = { "master chain code": raw.subarray(13, 45), "master private key": raw.subarray(46, 78) };

/** The initial value of global 0, __stack_pointer in a wasm-bindgen Rust module. */
function stackTop(wasm) {
  let at = 8;
  const leb = () => {
    let result = 0;
    let shift = 0;
    let byte;
    do {
      byte = wasm[at++];
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    return result;
  };
  while (at < wasm.length) {
    const id = wasm[at++];
    const end = leb() + at;
    if (id === 6) {
      leb();
      at += 2;
      if (wasm[at++] !== 0x41) throw new Error("global 0 is not an i32.const");
      return leb();
    }
    at = end;
  }
  throw new Error("no global section");
}

const top = stackTop(packageWasm);
const { instance, memory } = instanceOver(packageWasm);
const encode = (text) => new TextEncoder().encode(text);
const left = (label) => {
  const heap = Buffer.from(memory.buffer);
  let total = 0;
  for (const [name, needle] of Object.entries(NEEDLES)) {
    const found = [];
    for (let at = heap.indexOf(needle); at !== -1; at = heap.indexOf(needle, at + 1)) found.push(at);
    const stack = found.filter((at) => at < top).length;
    total += found.length;
    console.log(`${label}: ${name}: ${found.length} copies, ${stack} in the shadow stack below ${top}`);
  }
  return total;
};
console.log(`walletFingerprint returned ${instance.walletFingerprint(encode(PHRASE), encode("TREZOR"))}`);
const afterCall = left("after the call");
new Uint8Array(memory.buffer, 0, top).fill(0);
left("control, after zeroing the dead shadow stack");
console.log(`control, a later call still works: ${instance.walletFingerprint(encode(PHRASE), encode(""))}`);
console.log(
  afterCall > 0
    ? "FAIL: the master key and chain code stay in the WebAssembly memory after the call"
    : "PASS: no copy of the master key or chain code is left after the call",
);
process.exit(afterCall > 0 ? 1 : 0);
