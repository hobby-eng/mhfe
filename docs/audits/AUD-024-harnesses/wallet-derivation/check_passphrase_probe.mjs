// AUD-024 wallet-derivation: the browser package's rehearsal check (CheckSession) given a BIP39
// passphrase beside a stated length, the built-in check, which takes none. It loads the built
// dist/runtime/mhfe.wasm with the glue target/wasm-bindgen/mhfe.js and hands it a stand-in Argon2
// object: the 1 MiB known answer is computed with Node's own Argon2id (OpenSSL), and every larger
// call, a round of a real recovery, throws "CANCELLED", so that no full-cost Argon2 runs. A
// refusal before the rounds names its own code; a passphrase taken without a refusal reaches the
// first round and ends "CANCELLED". Usage: node check_passphrase_probe.mjs <repo root>
// Exits 1 when a case does not give the behaviour stated for it.
import { argon2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
const root = process.argv[2] ?? ".";
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
let rounds = 0;
const argon2 = {
  derive(password, salt, memoryKib, passes, key) {
    if (memoryKib > 1024) {
      rounds += 1;
      throw new Error("CANCELLED: the stand-in Argon2 runs no full-cost round");
    }
    const tag = argon2Sync("argon2id", { message: password, nonce: salt, parallelism: 4, tagLength: 32, memory: memoryKib, passes });
    key.set(tag);
  },
  reserve() {},
};
const utf8 = (text) => new TextEncoder().encode(text);
// Any 24-word phrase is a container's words for the checks before Argon2: "abandon" x23 "art".
const container = `${"abandon ".repeat(23)}art`;
const session = (kind, reference, passphrase) =>
  new mhfe.CheckSession(container, utf8("public test password"), "", 0, 0, 0, kind, reference, "", "", utf8(passphrase), argon2, () => {});
const cases = [
  // The library's own rule (rehearsal::refuse_unused_passphrase) and its doc comment: the built-in
  // check takes no passphrase, and one dropped without a word would let a person believe the
  // wallet with it was compared. searchWallet and rekey apply it; the check should too.
  { id: "a passphrase beside { words: 12 } is refused before any round", kind: "words", reference: "12", passphrase: "x", want: "INVALID_REQUEST" },
  { id: "a passphrase beside { words: 21 } is refused before any round", kind: "words", reference: "21", passphrase: "x", want: "INVALID_REQUEST" },
  // Contrast: references the check refuses before its rounds today.
  { id: "contrast: the wallet check without a passphrase is refused before any round", kind: "walletCheck", reference: "", passphrase: "", want: "WALLET_CHECK_NEEDS_PASSPHRASE" },
  { id: "contrast: 24 stated words have no built-in check", kind: "words", reference: "24", passphrase: "", want: "INVALID_WORD_COUNT" },
];
let failed = 0;
for (const c of cases) {
  rounds = 0;
  let code;
  try {
    session(c.kind, c.reference, c.passphrase);
    code = "ACCEPTED";
  } catch (error) {
    code = String(error?.message ?? error).split(":")[0];
  }
  const ok = code === c.want && rounds === 0;
  if (!ok) failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${c.id}${ok ? "" : `: ${code} after ${rounds} full-cost round call(s)`}`);
}
// The searchWallet binding refuses the same passphrase beside its built-in check (contrast).
rounds = 0;
let code = "ACCEPTED";
try {
  mhfe.searchWallet(`${"abandon ".repeat(23)}?`, utf8("public test password"), "", 0, 0, 0, "builtInCheck", "", "", "", utf8("x"), argon2, () => {}, () => {});
} catch (error) {
  code = String(error?.message ?? error).split(":")[0];
}
const ok = code === "INVALID_REQUEST" && rounds === 0;
if (!ok) failed += 1;
console.log(`${ok ? "PASS" : "FAIL"} contrast: searchWallet refuses a passphrase beside builtInCheck${ok ? "" : `: ${code}`}`);
console.log(`${cases.length + 1} cases, ${failed} failed`);
process.exit(failed ? 1 : 0);
