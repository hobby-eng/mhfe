// AUD-024 wallet-derivation: a rekey in the browser package's RekeySession whose owner answers the
// shown phrase with a BIP39 passphrase that the replacement's rehearsal does not use
// (rehearsalNeedsPassphrase false). Reduced cost only: the stand-in Argon2 object computes every
// call with Node's own Argon2id at 1 MiB and one pass, the exact cost of the known answer.
// Usage: node owner_answer_probe.mjs <repo root>. Exits 1 when the passphrase is taken without a
// refusal (the library's rule rehearsal::refuse_unused_passphrase refuses one where unused).
import { argon2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
const root = process.argv[2] ?? ".";
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
const argon2 = {
  derive(password, salt, memoryKib, passes, key) {
    key.set(argon2Sync("argon2id", { message: password, nonce: salt, parallelism: 4, tagLength: 32, memory: Math.min(memoryKib, 1024), passes: memoryKib > 1024 ? 1 : passes }));
  },
  reserve() {},
};
const utf8 = (text) => new TextEncoder().encode(text);
const phrase = `${"abandon ".repeat(11)}about`;
const password = "public test password";
const sealed = JSON.parse(mhfe.encrypt(utf8(phrase), utf8(password), utf8(password), "", 0, 0, 0, false, 0, undefined, argon2, () => {}, () => {}));
// 15 words stated: the built-in check finds 12 (LENGTH_DIFFERS); the owner then confirms at 15.
const session = new mhfe.RekeySession(sealed.container, 15, utf8(password), "", 0, 0, 0, argon2);
session.setNew(utf8("another public test password"), utf8("another public test password"), "", 0, 0, 0, 0);
try {
  session.recover("builtInCheck", "", "", "", utf8(""), false, () => {});
  console.log("unexpected: the built-in check confirmed 15 stated words");
} catch (error) {
  console.log(`recover: ${String(error.message).split(":")[0]}; ownerLengths ${session.ownerLengths()}`);
}
const recovered = JSON.parse(session.confirmAgain("owner", "", "", "", utf8(""), 15, () => {}));
console.log(`owner check: words ${recovered.ownerCheck.words}, statedWords ${recovered.ownerCheck.statedWords}, rehearsalNeedsPassphrase ${recovered.rehearsalNeedsPassphrase}`);
let answer;
try {
  session.ownerAnswer(true, utf8("a passphrase the rehearsal does not use"));
  const resealed = JSON.parse(session.seal(() => {}, () => {}));
  answer = `accepted; rehearsal ${JSON.stringify(resealed.rehearsal)}`;
} catch (error) {
  answer = `refused: ${error.message}`;
}
const ok = answer.startsWith("refused: INVALID_REQUEST");
console.log(`${ok ? "PASS" : "FAIL"} an owner's passphrase that the rehearsal does not use is refused: ${answer}`);
process.exit(ok ? 0 : 1);
