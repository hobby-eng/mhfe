// AUD-024 verify-unused-passphrase: whether the browser package's core WebAssembly refuses a BIP39
// passphrase that is not empty where the comparison takes none (rehearsal::refuse_unused_passphrase),
// in the rehearsal check with a stated length and in a rekey owner's answer.
//
// Reduced cost only: the stand-in Argon2 object computes the 1 MiB known answer exactly with Node's
// Argon2id and every larger call at 1 MiB and one pass, so every round is cheap but encryption and
// recovery stay consistent with each other. No full-cost Argon2 runs. Public test data only: the
// "abandon ... about" phrase and "abandon x23 art", a public test password.
//
// Usage, from the repository root: node docs/audits/AUD-024-harnesses/verify-unused-passphrase/probe.mjs .
// Exits 1 when a case does not give the behaviour the library's own rule states for it.
import { argon2Sync } from "node:crypto";
import { readFileSync } from "node:fs";

const root = process.argv[2] ?? ".";
const glue = readFileSync(`${root}/target/wasm-bindgen/mhfe.js`, "utf8");
// oxlint-disable-next-line typescript/no-implied-eval -- the package's own glue, as a worker loads it
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: readFileSync(`${root}/dist/runtime/mhfe.wasm`) });

let largeCalls = 0;
const argon2 = {
  derive(password, salt, memoryKib, passes, key) {
    if (memoryKib > 1024) largeCalls += 1;
    key.set(
      argon2Sync("argon2id", {
        message: password,
        nonce: salt,
        parallelism: 4,
        tagLength: 32,
        memory: Math.min(memoryKib, 1024),
        passes: memoryKib > 1024 ? 1 : passes,
      }),
    );
  },
  reserve() {},
};
const utf8 = (text) => new TextEncoder().encode(text);
const code = (error) => String(error?.message ?? error).split(":")[0];
const PASSWORD = "public test password";
const NEW_PASSWORD = "another public test password";

let failed = 0;
const report = (ok, id, detail) => {
  if (!ok) failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${id}: ${detail}`);
};

const seal = (phrase) =>
  JSON.parse(
    mhfe.encrypt(utf8(phrase), utf8(PASSWORD), utf8(PASSWORD), "", 0, 0, 0, false, 0, false, argon2, () => {}, () => {}),
  ).container;

// A 12-word original sealed in a 24-word container (suite 3).
const short = seal(`${"abandon ".repeat(11)}about`);
console.log(`setup: 12-word original sealed, container of ${short.split(" ").length} words`);

const check = (kind, reference, passphrase) =>
  new mhfe.CheckSession(short, utf8(PASSWORD), "", 0, 0, 0, kind, reference, "", "", utf8(passphrase), argon2, () => {});

// Case 1: CheckSession::new with { words: 12 } and a non-empty passphrase.
for (const words of ["12", "21"]) {
  largeCalls = 0;
  let detail;
  let refused = false;
  try {
    const session = check("words", words, "x");
    const withX = session.compare("words", words, "", "", utf8("x"));
    const withEmpty = session.compare("words", words, "", "", utf8(""));
    const withOther = session.compare("words", words, "", "", utf8("another passphrase"));
    session.free();
    detail = `accepted after ${largeCalls} reduced round call(s); compare with "x": ${withX}; identical with "" and with another passphrase: ${withX === withEmpty && withX === withOther}`;
  } catch (error) {
    refused = code(error) === "INVALID_REQUEST" && largeCalls === 0;
    detail = `refused: ${error.message} after ${largeCalls} reduced round call(s)`;
  }
  report(refused, `CheckSession { words: ${words} } with passphrase "x" is refused before any round (INVALID_REQUEST)`, detail);
}

// Case 2: the onNoLength answer path of the worker, session.compare(next), with { words: 12 } and a
// passphrase, on a session made with the length detected.
{
  const session = check("words", "0", "");
  const detected = session.compare("words", "0", "", "", utf8(""));
  let detail;
  let refused = false;
  try {
    detail = `accepted: ${session.compare("words", "12", "", "", utf8("x"))} (detection gave ${detected})`;
  } catch (error) {
    refused = code(error) === "INVALID_REQUEST";
    detail = `refused: ${error.message}`;
  }
  session.free();
  report(refused, 'CheckSession.compare("words", "12") with passphrase "x" is refused (INVALID_REQUEST)', detail);
}

// Contrast: the same library rule applied elsewhere in the same build.
{
  largeCalls = 0;
  let detail = "accepted";
  try {
    mhfe.searchWallet(`${"abandon ".repeat(23)}?`, utf8(PASSWORD), "", 0, 0, 0, "builtInCheck", "", "", "", utf8("x"), argon2, () => {}, () => {});
  } catch (error) {
    detail = error.message;
  }
  report(detail.startsWith("INVALID_REQUEST") && largeCalls === 0, "contrast: searchWallet refuses a passphrase beside builtInCheck", detail);
}
{
  const session = new mhfe.RekeySession(short, 12, utf8(PASSWORD), "", 0, 0, 0, argon2);
  session.setNew(utf8(NEW_PASSWORD), utf8(NEW_PASSWORD), "", 0, 0, 0, 0);
  largeCalls = 0;
  let detail = "accepted";
  try {
    session.recover("builtInCheck", "", "", "", utf8("x"), false, () => {});
  } catch (error) {
    detail = error.message;
  }
  report(detail.startsWith("INVALID_REQUEST") && largeCalls === 0, "contrast: RekeySession.recover refuses a passphrase beside builtInCheck", detail);
}

// Case 3: a rekey owner's answer with a passphrase where rehearsalNeedsPassphrase is false and the
// wallet is stated to have none. A 12-word original, 15 words stated: the built-in check finds 12
// (LENGTH_DIFFERS), then the owner compares at the stated 15 (ownerLengths) and answers yes with a
// passphrase.
const ownerAnswer = (container, words, stated, label) => {
  const session = new mhfe.RekeySession(container, words, utf8(PASSWORD), "", 0, 0, 0, argon2);
  session.setNew(utf8(NEW_PASSWORD), utf8(NEW_PASSWORD), "", 0, 0, 0, 0);
  let recovered;
  try {
    recovered = JSON.parse(session.recover("owner", "", "", "", utf8(""), false, () => {}));
  } catch (error) {
    const lengths = JSON.parse(session.ownerLengths());
    console.log(`${label}: recover("owner") refused with ${code(error)}; ownerLengths ${JSON.stringify(lengths)}`);
    if (lengths === null || lengths.length === 0) return { outcome: "no owner confirmation possible" };
    recovered = JSON.parse(session.confirmAgain("owner", "", "", "", utf8(""), stated ?? lengths[0], () => {}));
  }
  const ownerCheck = recovered.ownerCheck ?? {};
  console.log(
    `${label}: owner shown words ${ownerCheck.words}, statedWords ${ownerCheck.statedWords}, rehearsalNeedsPassphrase ${ownerCheck.rehearsalNeedsPassphrase ?? recovered.rehearsalNeedsPassphrase}`,
  );
  try {
    session.ownerAnswer(true, utf8("x"));
    const sealed = JSON.parse(session.seal(() => {}, () => {}));
    return { outcome: `accepted; sealed; rehearsal ${JSON.stringify(sealed.rehearsal)}; keep ${JSON.stringify(sealed.keep)}` };
  } catch (error) {
    return { outcome: `refused: ${error.message}`, refused: code(error) === "INVALID_REQUEST" };
  }
};
{
  const { outcome, refused } = ownerAnswer(short, 15, 15, "owner of a verified 12-word phrase");
  report(Boolean(refused), "an owner's yes with passphrase \"x\", wallet stated to have none, verified phrase, is refused (INVALID_REQUEST)", outcome);
}
// Contrast: the same answer for a phrase without a built-in check (a 24-word original), where the
// rehearsal is the fingerprint: the library refuses it.
{
  const long = seal(`${"abandon ".repeat(23)}art`);
  const { outcome, refused } = ownerAnswer(long, 24, undefined, "owner of a 24-word phrase");
  report(Boolean(refused), "contrast: the same yes for a 24-word phrase (fingerprint rehearsal) is refused (INVALID_REQUEST)", outcome);
}

console.log(`${failed} case(s) failed`);
process.exit(failed ? 1 : 0);
