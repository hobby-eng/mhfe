// AUD-024 verifier harness (commit b6fca69): wallet secrets left in the browser package's
// WebAssembly memory below the stack top (the dead shadow stack) after a call returns, and a
// control that zeroes [0, stack top) and shows that the module and a session still work.
// Needles are computed independently with node:crypto from public BIP39 test data. Exits 1 when a
// copy is left after a call, 0 when none is, 2 when the check cannot run.
//
//   node docs/audits/AUD-024-harnesses/verify-wasm-stack-residue/stack-residue.mjs
import crypto from "node:crypto";

import { REDUCED_COST_CONTAINER } from "../../../../scripts/public-test-data.mjs";
import { instanceOver, packageWasm, realArgon2 } from "../../../../scripts/package-check/package.mjs";
import {
  KNOWN_ANSWER_COSTS,
  NEW_PASSWORD,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  encode,
  noBytes,
} from "../../../../scripts/package-check/test-values.mjs";

/** The initial value of global 0 (__stack_pointer) and the lowest active data segment offset. */
function layout(w) {
  let at = 8;
  const leb = () => {
    let r = 0;
    let s = 0;
    let b;
    do {
      b = w[at++];
      r += (b & 0x7f) * 2 ** s;
      s += 7;
    } while (b & 0x80);
    return r;
  };
  let top = null;
  let lowestData = Infinity;
  while (at < w.length) {
    const id = w[at++];
    const end = leb() + at;
    if (id === 6) {
      leb();
      at += 2;
      if (w[at++] !== 0x41) throw new Error("global 0 is not an i32.const");
      top = leb();
    } else if (id === 11) {
      const count = leb();
      for (let i = 0; i < count; i++) {
        const flag = leb();
        if (flag === 1) {
          const length = leb();
          at += length;
          continue;
        }
        if (flag === 2) leb();
        at++;
        const offset = leb();
        at++;
        const length = leb();
        at += length;
        lowestData = Math.min(lowestData, offset);
      }
    }
    at = end;
  }
  return { top, lowestData };
}
const { top, lowestData } = layout(packageWasm);
if (top === null || lowestData < top) {
  console.log(`cannot run: stack top ${top}, lowest data segment ${lowestData}`);
  process.exit(2);
}
console.log(`stack top (global 0 init) ${top}; lowest data segment ${lowestData}: [0, ${top}) is stack only`);

const needlesOf = (phrase, passphrase) => {
  const seed = crypto.pbkdf2Sync(Buffer.from(phrase), Buffer.from(`mnemonic${passphrase}`), 2048, 64, "sha512");
  const master = crypto.createHmac("sha512", "Bitcoin seed").update(seed).digest();
  const needles = {
    "seed first half": seed.subarray(0, 32),
    "seed second half": seed.subarray(32),
    "master private key": master.subarray(0, 32),
    "master chain code": master.subarray(32),
  };
  if (passphrase !== "") needles[`salt block mnemonic${passphrase}`] = Buffer.from(`mnemonic${passphrase}`);
  return needles;
};
const scan = (memory, label, needles) => {
  const heap = Buffer.from(memory.buffer);
  let below = 0;
  for (const [name, needle] of Object.entries(needles)) {
    const found = [];
    for (let at = heap.indexOf(needle); at !== -1; at = heap.indexOf(needle, at + 1)) found.push(at);
    const stack = found.filter((a) => a < top).length;
    below += stack;
    console.log(`  ${label}: ${name}: ${found.length} copies [${found.join(", ")}], ${stack} below ${top}`);
  }
  return below;
};
const scrub = (memory) => new Uint8Array(memory.buffer, 0, top).fill(0);
let left = 0;

// 1. walletFingerprint, BIP39's published 12-word vector with TREZOR (xprv9s21...UsAF).
{
  const phrase = `${"abandon ".repeat(11)}about`;
  const { instance, memory } = instanceOver(packageWasm);
  const needles = needlesOf(phrase, "TREZOR");
  console.log(`1. walletFingerprint(abandon x11 about, TREZOR) = ${instance.walletFingerprint(encode(phrase), encode("TREZOR"))}`);
  left += scan(memory, "after the call", needles);
  scrub(memory);
  scan(memory, "after zeroing [0, stack top)", needles);
  console.log(`  control: a later call still gives ${instance.walletFingerprint(encode(phrase), encode(""))} (73c5da0a expected)`);
}
// 2. walletCheck, BIP39's published 24-word vector with TREZOR (seed bda85446...).
{
  const phrase = `${"abandon ".repeat(23)}art`;
  const { instance, memory } = instanceOver(packageWasm);
  const needles = needlesOf(phrase, "TREZOR");
  console.log(`2. walletCheck(abandon x23 art, TREZOR) = ${instance.walletCheck(encode(phrase), encode("TREZOR"))}`);
  left += scan(memory, "after the call", needles);
  scrub(memory);
  scan(memory, "after zeroing [0, stack top)", needles);
  console.log(`  control: a later call still gives ${instance.walletCheck(encode(phrase), encode("TREZOR"))}`);
}
// 3. A session of hidden wallets at its wait for the page (web/core-worker.js awaits
// host.ask("opened") right after session.open returns), at the package check's reduced cost.
{
  const reduced = {
    derive: (password, salt, memoryKib, passes, key) =>
      KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)
        ? realArgon2.derive(password, salt, memoryKib, passes, key)
        : realArgon2.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key),
    reserve: () => {},
  };
  const { instance, memory } = instanceOver(packageWasm);
  const session = new instance.HiddenWalletSession(REDUCED_COST_CONTAINER, 0, 0, noBytes(), reduced);
  const wallet = JSON.parse(session.open(NEW_PASSWORD.slice(), NEW_PASSWORD.slice(), "", 0, () => {}));
  const needles = needlesOf(wallet.phrase, "");
  console.log(`3. hidden wallet opened (${wallet.words} words, fingerprint ${wallet.fingerprintWithoutPassphrase}); the session waits`);
  left += scan(memory, "at the wait", needles);
  scrub(memory);
  scan(memory, "after zeroing [0, stack top)", needles);
  let again;
  try {
    session.open(NEW_PASSWORD.slice(), NEW_PASSWORD.slice(), "", 0, () => {});
    again = "opened";
  } catch (error) {
    again = error.message.split(":")[0];
  }
  const other = encode("a third public test password");
  const next = JSON.parse(session.open(other, other.slice(), "", 0, () => {}));
  session.free();
  console.log(`  control: the same password again -> ${again}; another password opens ${next.words} words; freed`);
}
console.log(
  left > 0
    ? `FAIL: ${left} copies of a seed, master key, chain code or passphrase salt block stay below the stack top after the calls`
    : "PASS: no copy is left below the stack top after the calls",
);
process.exit(left > 0 ? 1 : 0);
