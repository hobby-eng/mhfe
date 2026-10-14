// AUD-024 wallet-derivation: the rehearsal check's outcome with the wallet-check reference
// ({ walletCheck: true }) for a container whose original is a 12-word phrase, through the built
// browser package's bindings (dist/runtime/mhfe.wasm, glue target/wasm-bindgen/mhfe.js). Reduced
// cost only: a stand-in Argon2 object computes every call with Node's own Argon2id (OpenSSL) at
// 1 MiB and one pass, which is the exact cost of the known answer, so that the container is valid
// for this stand-in only and no full-cost round runs. Usage: node wallet_check_reference_probe.mjs
// <repo root>. Prints the outcome and evidence of each reference; exits 1 when the wallet-check
// reference reports "doesNotMatch" while the same recovery gives a verified 12-word reading.
import { argon2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
const root = process.argv[2] ?? ".";
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });
const argon2 = {
  derive(password, salt, memoryKib, passes, key) {
    const memory = Math.min(memoryKib, 1024);
    key.set(argon2Sync("argon2id", { message: password, nonce: salt, parallelism: 4, tagLength: 32, memory, passes: memoryKib > 1024 ? 1 : passes }));
  },
  reserve() {},
};
const utf8 = (text) => new TextEncoder().encode(text);
const phrase = `${"abandon ".repeat(11)}about`; // the public BIP39 test phrase, 12 words
const password = "public test password";
const sealed = JSON.parse(mhfe.encrypt(utf8(phrase), utf8(password), utf8(password), "", 0, 0, 0, false, 0, undefined, argon2, () => {}, () => {}));
const session = new mhfe.CheckSession(sealed.container, utf8(password), "", 0, 0, 0, "fingerprint", "73c5da0a", "", "", utf8(""), argon2, () => {});
const compare = (kind, reference, passphrase) => JSON.parse(session.compare(kind, reference, "", "", utf8(passphrase)));
const results = {
  "fingerprint 73c5da0a": compare("fingerprint", "73c5da0a", ""),
  "words 0 (length detected)": compare("words", "0", ""),
  "words 12": compare("words", "12", ""),
  "walletCheck, passphrase TREZOR": compare("walletCheck", "", "TREZOR"),
};
for (const [name, result] of Object.entries(results)) console.log(`${name}: ${JSON.stringify(result)}`);
const wallet = results["walletCheck, passphrase TREZOR"];
const verifiedShortReading = wallet.evidence.builtInCheck === 12;
const ok = !(wallet.outcome === "doesNotMatch" && verifiedShortReading);
console.log(`${ok ? "PASS" : "FAIL"} the wallet-check reference does not report "doesNotMatch" beside a verified 12-word reading`);
process.exit(ok ? 0 : 1);
