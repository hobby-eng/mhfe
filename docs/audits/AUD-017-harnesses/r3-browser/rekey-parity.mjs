// AUD-017 R3: the 0.5.1 recovery and rekey surface of the built browser core (dist/runtime/mhfe.wasm
// with its wasm-bindgen glue), compared with what the command-line tool does for the same input,
// at a reduced Argon2 cost.
//
//   timeout 60 node --max-old-space-size=1024 docs/audits/AUD-017-harnesses/r3-browser/rekey-parity.mjs
//
// Run from the repository root after scripts/build-wasm.sh. The core gets the package's
// single-threaded Emscripten Argon2 build behind a wrapper (as AUD-015 r1-crypto/wasm_probe.mjs):
// the build's own known answer (1 MiB, one pass) runs unchanged, every round the core asks for at
// full cost runs at 256 KiB and one pass. Memory stays far below 1 GiB. Read-only; public test
// data only: the BIP39 test phrase "abandon x11 about" and fixed test passwords.
//
// "CHECK" lines count towards the exit code (1 when any fails: a defect reproduced); "INFO" lines
// record behaviour.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const read = (path) => readFileSync(path);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const encode = (text) => new TextEncoder().encode(text);

let failures = 0;
function check(name, ok, evidence) {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} CHECK ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
}
function info(name, evidence) {
  console.log(`INFO ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
}
function attempt(run) {
  try {
    return { ok: run() };
  } catch (error) {
    const text = String(error?.message ?? error);
    const match = /^([A-Z][A-Z0-9_]+): (.*)$/su.exec(text);
    return { error: match ? { code: match[1], message: match[2] } : { code: "?", message: text } };
  }
}

// The glue used here must be the one the package ships at the start of runtime/worker.js.
const glue = read("target/wasm-bindgen/mhfe.js");
const worker = read("dist/runtime/worker.js");
check("glue is the start of dist/runtime/worker.js", worker.subarray(0, glue.length).equals(glue), {
  glue: sha256(glue),
  wasm: sha256(read("dist/runtime/mhfe.wasm")),
});
vm.runInThisContext(glue.toString(), { filename: "mhfe.js" });
const core = vm.runInThisContext("mhfe");
core.initSync({ module: read("dist/runtime/mhfe.wasm") });
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");
const engine = argon2Engine(await require("../../../../dist/core/argon2-st.js")());
const reduced = {
  derive(password, salt, memoryKib, passes, key) {
    if (memoryKib === 1024 && passes === 1) engine.derive(password, salt, 1024, 1, key);
    else engine.derive(password, salt, 256, 1, key);
  },
  reserve: () => {},
};
const nothing = () => {};

const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD = "public test password";
const NEW_PASSWORD = "another public test password";
const made = JSON.parse(
  core.encrypt(encode(PHRASE), encode(PASSWORD), encode(PASSWORD), "", 0, 0, 0, false, 0, false,
    reduced, nothing, nothing),
);
const decrypt = (words, passphrase = "", password = PASSWORD) =>
  JSON.parse(
    core.decrypt(made.container, encode(password), "", 0, 0, 0, words, encode(passphrase), reduced,
      nothing),
  );

// D: decrypt's new fields.
{
  const detected = decrypt(0, "TREZOR");
  const stated15 = decrypt(15);
  const stated24 = decrypt(24);
  const wrong24 = decrypt(24, "TREZOR", "wrong public test password");
  const fields = (c) => ({ words: c.words, status: c.status, walletCheck: c.walletCheck,
    statedWords: c.statedWords, otherLengths: c.otherLengths });
  info("D decrypt candidates", {
    detected: detected.candidates.map(fields),
    stated15: { kind: stated15.kind, candidates: stated15.candidates.map(fields) },
    stated24: { kind: stated24.kind, candidates: stated24.candidates.map(fields) },
    wrong24: wrong24.candidates.map(fields),
  });
  check(
    "D decrypt: 12-word reading walletCheck null, stated 15 named, 24-word reading a boolean",
    detected.candidates[0].walletCheck === null &&
      stated15.candidates[0].statedWords === 15 &&
      typeof wrong24.candidates[0].walletCheck === "boolean" &&
      stated24.kind === "ambiguous",
  );
}

function rekey(words, kind, reference = "", wallet = false) {
  const session = new core.RekeySession(made.container, words, encode(PASSWORD), "", 0, 0, 0,
    reduced);
  try {
    session.setNew(encode(NEW_PASSWORD), encode(NEW_PASSWORD), "", 0, 0, 0, 0);
    return attempt(() =>
      JSON.parse(session.recover(kind, reference, kind === "address" ? "bitcoin" : "", "",
        new Uint8Array(), wallet, nothing)),
    );
  } finally {
    session.free();
  }
}

// A: the length detected and the built-in check alone. The CLI (src/bin/mhfe/rekey.rs:145-147)
// offers only an address, the fingerprint or the owner under ConfirmationNeeded::Detected.
{
  const outcome = rekey(0, "builtInCheck");
  info("A browser rekey words 0 + builtInCheck on a 12-word original", outcome);
  check(
    "A browser refuses what the CLI never offers: built-in check alone with the length detected",
    outcome.error !== undefined,
    outcome,
  );
}

// C: LENGTH_DIFFERS under the built-in check, 15 stated.
{
  const outcome = rekey(15, "builtInCheck");
  check("C words 15 + builtInCheck rejects with LENGTH_DIFFERS", outcome.error?.code === "LENGTH_DIFFERS",
    outcome);
  const owner24 = rekey(24, "owner");
  check("C words 24 + owner rejects with LENGTH_DIFFERS (API.md:283)",
    owner24.error?.code === "LENGTH_DIFFERS", owner24);
}

// B: the owner with 15 stated on a 12-word original. The CLI warns "The built-in check finds 12
// words, not the 15 you gave." before showing the phrase (src/bin/mhfe/rekey.rs:236-245); the
// owner callback in the browser must be able to say the same.
{
  const outcome = rekey(15, "owner");
  const shown = outcome.ok?.ownerCheck ?? {};
  info("B owner check fields (phrase withheld)", {
    keys: Object.keys(shown),
    words: shown.words,
    walletCheck: outcome.ok?.walletCheck,
    error: outcome.error,
  });
  check(
    "B the owner's check names the stated length the built-in check overrode (statedWords)",
    Object.hasOwn(shown, "statedWords") && shown.statedWords === 15,
  );
}

// E: decrypt's passphrase as text: invalid UTF-8 is refused without echoing it, and the 24-word
// reading's walletCheck agrees with the wallet module's walletCheck for NFC and NFD forms.
{
  const bad = attempt(() =>
    core.decrypt(made.container, encode(PASSWORD), "", 0, 0, 0, 24, Uint8Array.from([0xff, 0x41]),
      reduced, nothing),
  );
  check("E invalid UTF-8 passphrase rejects with INVALID_PASSPHRASE", bad.error?.code ===
    "INVALID_PASSPHRASE", bad);
  const rows = [];
  for (const passphrase of ["TREZOR", "Pässwörd", "Pässwörd", ""]) {
    const reading = decrypt(24, passphrase, "wrong public test password").candidates[0];
    const direct = attempt(() => core.walletCheck(encode(reading.phrase), encode(passphrase)));
    rows.push({ passphrase: passphrase.normalize("NFC") === passphrase ? "nfc" : "nfd",
      decrypt: reading.walletCheck, wallet: direct.ok ?? direct.error?.code });
  }
  info("E walletCheck of the same 24-word reading: decrypt vs MhfeWallet binding", rows);
  check("E decrypt.walletCheck equals the wallet module for every non-empty passphrase",
    rows.slice(0, 3).every((row) => row.decrypt === row.wallet) && rows[1].decrypt === rows[2].decrypt);
}

console.log(`\n${failures === 0 ? "every CHECK passed" : `${failures} CHECK(s) failed`}`);
process.exit(failures === 0 ? 0 : 1);
