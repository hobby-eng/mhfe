// AUD-015 R4: the browser package's wallet and word exports against the same independent oracles
// as the native probe (address-oracle.mjs, wallet-check-oracle.mjs) and the documented rules: what
// scripts/verify-cli-browser-parity.mjs does not compare. It loads the package's WebAssembly in
// this process, as that script does, from target/wasm-bindgen/mhfe.js and dist/runtime/mhfe.wasm
// (build them first with scripts/build-wasm.sh), and runs no Argon2.
//
//   node docs/audits/AUD-015-harnesses/r4-wallet/wasm-parity.mjs
//
// Compared: walletParameters(); walletFingerprint() for every oracle fingerprint; describeAddress()
// for every oracle case and the scan-gap statement; wordHints() for every prefix of both lists
// against the documented rule; describeDraw() figures and refusals that must not name a word;
// walletCheck() and drawPhrase() on the fresh vector, the latter from a scripted source just before
// it, with and without a chosen word. Exits 1 with every difference listed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ROOT = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT));
const encode = (text) => new TextEncoder().encode(text);
const evidence = (name) => JSON.parse(read(`docs/audits/AUD-015-evidence/${name}`).toString());

vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const mhfe = vm.runInThisContext("mhfe");
mhfe.initSync({ module: read("dist/runtime/mhfe.wasm") });

const failures = [];
let checks = 0;
const check = (ok, what) => {
  checks += 1;
  if (!ok) {
    failures.push(what());
    console.error(`FAIL ${failures.at(-1)}`);
  }
};
const codeOf = (action) => {
  try {
    action();
    return null;
  } catch (error) {
    return String(error.message ?? error);
  }
};

// --- Parameters ---------------------------------------------------------------------------------
const parameters = JSON.parse(mhfe.walletParameters());
check(
  JSON.stringify(parameters.coins.map((coin) => coin.id)) ===
    JSON.stringify([
      "bitcoin",
      "bitcoin-cash",
      "cosmos",
      "dash",
      "dogecoin",
      "ethereum",
      "ethereum-classic",
      "injective",
      "litecoin",
      "tron",
      "xrp",
      "zcash",
    ]),
  () => `coins ${JSON.stringify(parameters.coins)}`,
);
for (const [field, value] of [
  ["walletCheckBits", 16],
  ["drawReportInterval", 1024],
  ["maxChosenWords", 1],
  ["maxNeverUseWords", 1],
  ["recommendedRandomBits", 240],
]) {
  check(parameters[field] === value, () => `walletParameters().${field} = ${parameters[field]}`);
}

// --- Fingerprints and address statements --------------------------------------------------------
const data = evidence("r4-wallet-cases.json");
for (const { phraseIndex, passphrase, fingerprint } of data.fingerprints) {
  const got = mhfe.walletFingerprint(encode(data.phrases[phraseIndex]), encode(passphrase));
  check(got === fingerprint, () => `walletFingerprint ${phraseIndex} ${passphrase}: ${got}`);
}
/** The statement each form should get, from the coins' standards (as in the native probe). */
const STATEMENTS = {
  "bitcoin-p2pkh": ["legacy (BIP44)", "44'/0'"],
  "bitcoin-p2sh-p2wpkh": ["nested SegWit (BIP49)", "49'/0'"],
  "bitcoin-p2wpkh": ["native SegWit (BIP84)", "84'/0'"],
  "bitcoin-p2tr": ["Taproot (BIP86)", "86'/0'"],
  "bitcoin-testnet-p2pkh": ["testnet, legacy (BIP44)", "44'/1'"],
  "bitcoin-testnet-p2sh-p2wpkh": ["testnet, nested SegWit (BIP49)", "49'/1'"],
  "bitcoin-testnet-p2wpkh": ["testnet, native SegWit (BIP84)", "84'/1'"],
  "bitcoin-testnet-p2tr": ["testnet, Taproot (BIP86)", "86'/1'"],
  "litecoin-p2pkh": ["legacy (BIP44)", "44'/2'"],
  "litecoin-p2sh-p2wpkh": ["nested SegWit (BIP49)", "49'/2'"],
  "litecoin-p2sh-p2wpkh-3": ["nested SegWit (BIP49)", "49'/2'"],
  "litecoin-p2wpkh": ["native SegWit (BIP84)", "84'/2'"],
  dogecoin: [null, "44'/3'"],
  "dash-core": ["Core (BIP44)", "44'/5'"],
  zcash: ["transparent", "44'/133'"],
  "bitcoin-cash": [null, "44'/{145,0}'"],
  "bitcoin-cash-legacy": [null, "44'/{145,0}'"],
  "bitcoin-cash-second-root": [null, "44'/{145,0}'"],
  xrp: [null, "44'/144'"],
  tron: [null, "44'/195'"],
  ethereum: [null, "44'/60'"],
  "ethereum-classic": [null, "44'/{61,60}'"],
  "ethereum-classic-second-root": [null, "44'/{61,60}'"],
  cosmos: [null, "44'/118'"],
  injective: [null, "44'/60'"],
  "dash-platform": ["Platform payment (DIP17)", "9'/5'/17'"],
  "dash-platform-testnet": ["testnet, Platform payment (DIP17)", "9'/1'/17'"],
  "outside-default-limits": ["native SegWit (BIP84)", "84'/0'"],
};
for (const { coin, form, address, path } of data.cases) {
  const [type, roots] = STATEMENTS[form];
  const chains = form.startsWith("dash-platform") ? "0'-1'" : "0-1";
  const expected = {
    type,
    search: `m/${roots}/0'-9'/${chains}/0-99`,
    addresses: roots.includes("{") ? 4000 : 2000,
    onlyPath: false,
  };
  const got = JSON.parse(mhfe.describeAddress(address, coin, "", 0));
  check(
    JSON.stringify(got) === JSON.stringify(expected),
    () => `describeAddress ${form} ${address}: ${JSON.stringify(got)}`,
  );
  const only = JSON.parse(mhfe.describeAddress(address, coin, path, 0));
  check(
    only.search === path && only.addresses === 1 && only.onlyPath === true,
    () => `describeAddress ${form} at ${path}: ${JSON.stringify(only)}`,
  );
}
const gap = JSON.parse(
  mhfe.describeAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bitcoin", "", 20),
);
console.log(`describeAddress scanGap 20: ${JSON.stringify(gap)}`);
check(gap.addresses === 40, () => `scan gap 20: ${JSON.stringify(gap)}`);

// --- Word hints ---------------------------------------------------------------------------------
const bip39Words = readFileSync(
  new URL(
    "../multi-chain-wallet-tools/node_modules/@scure/bip39/wordlists/english.js",
    ROOT,
  ),
)
  .toString()
  .match(/`([\s\S]*?)`/)[1]
  .split("\n")
  .map((word) => word.trim())
  .filter(Boolean);
assert.equal(bip39Words.length, 2048);
const effWords = read("vendor/eff-large-wordlist/eff_large_wordlist.txt")
  .toString()
  .trim()
  .split("\n")
  .map((line) => line.split("\t")[1]);
assert.equal(effWords.length, 7776);

/** The documented rule (README, API.md, BROWSER-PACKAGE.md), as in the native probe. */
function documented(words, line) {
  const token = line.split(/\s/).at(-1);
  if (!token || !/^[A-Za-z-]+$/.test(token)) return { hint: "nothing", count: 0, words: [] };
  const lower = token.toLowerCase();
  const matches = words.filter((word) => word.startsWith(lower));
  if (matches.length === 0) return { hint: "noWord", count: 0, words: [] };
  if (matches.length === 1 && matches[0] === lower) return { hint: "nothing", count: 0, words: [] };
  if (lower.length === 1) return { hint: "count", count: matches.length, words: [] };
  return { hint: "words", count: matches.length, words: matches };
}
let longMismatches = 0;
for (const [list, words] of [
  ["bip39", bip39Words],
  ["eff", effWords],
]) {
  const lines = [];
  for (const word of words) {
    for (let end = 1; end <= word.length; end += 1) {
      lines.push(word.slice(0, end), `${word.slice(0, end)}q`, `abandon ${word.slice(0, end).toUpperCase()}`);
    }
    for (const extra of ["x", "xyz"]) lines.push(`${word}${extra}`);
  }
  for (const line of lines) {
    const got = JSON.parse(mhfe.wordHints(list, encode(line)));
    const want = documented(words, line);
    const same =
      got.hint === want.hint &&
      got.count === want.count &&
      JSON.stringify(got.words) === JSON.stringify(want.words);
    if (!same && line.split(" ").at(-1).length > 9 && got.hint === "nothing" && want.hint === "noWord") {
      longMismatches += 1;
      continue;
    }
    check(same, () => `wordHints ${list} ${JSON.stringify(line)}: ${JSON.stringify(got)}`);
  }
}
console.log(`wordHints: ${longMismatches} lines of more than 9 letters get "nothing", not "noWord"`);
check(longMismatches === 0, () => `${longMismatches} long-word lines without "noWord"`);
check(
  codeOf(() => mhfe.wordHints("BIP39", encode("ab"))).startsWith("INVALID_REQUEST"),
  () => "wordHints refuses an unknown list",
);

// --- describeDraw -------------------------------------------------------------------------------
const L = 2048;
const never23 = 23 * Math.log2(2047 / L);
const anywhereNever = Math.log2((2047 / L) ** 24 - (2046 / L) ** 24);
for (const [what, words, places, never, walletCheck, bits, draws] of [
  ["fixed+never+check", "happy", [1], "abandon", true, 256 - 11 + never23 - 16, 2 ** 16 / (2047 / L) ** 23],
  ["fixed+never", "happy", [1], "abandon", false, 256 - 11 + never23, 1 / (2047 / L) ** 23],
  ["anywhere+never+check", "happy", [0], "abandon", true, 256 + anywhereNever - 16, 2 ** 16 / 2 ** anywhereNever],
  ["last word", "zoo", [24], "", false, 245, 256],
  ["none+check", "", [], "", true, 240, 65536],
  ["none", "", [], "", false, 256, 1],
]) {
  const got = JSON.parse(mhfe.describeDraw(encode(words), Uint32Array.from(places), never, walletCheck));
  check(
    Math.abs(got.randomBits - bits) < 1e-9 && Math.abs(got.expectedDraws - draws) / draws < 1e-9,
    () => `describeDraw ${what}: ${JSON.stringify(got)} vs ${bits} bits, ${draws} draws`,
  );
  check(got.recognisable === (words !== ""), () => `describeDraw ${what} recognisable`);
}
for (const [what, words, places, never] of [
  ["not a word", "zzzq", [1], ""],
  ["position 25", "happy", [25], ""],
  ["also never to use", "happy", [3], "happy"],
  ["two chosen", "happy zoo", [1, 2], ""],
]) {
  const message = codeOf(() => mhfe.describeDraw(encode(words), Uint32Array.from(places), never, false));
  check(
    message?.startsWith("INVALID_WORD_WISH") &&
      !words.split(" ").some((word) => message.includes(word)),
    () => `describeDraw refusal ${what}: ${message}`,
  );
}

// --- Wallet check and drawPhrase on the fresh vector ------------------------------------------
const vector = evidence("r4-wallet-check-vector.json");
check(
  mhfe.walletCheck(encode(vector.mnemonic), encode(vector.passphrase)) === true,
  () => "walletCheck of the fresh vector",
);
check(
  mhfe.walletCheck(encode(vector.mnemonic), encode(vector.passphraseNfkd)) === true,
  () => "walletCheck with the NFKD passphrase",
);
check(
  mhfe.walletCheck(encode(vector.mnemonic), encode("Cafe fi")) === false,
  () => "walletCheck with an ASCII look-alike",
);
check(
  codeOf(() => mhfe.walletCheck(encode(vector.mnemonic), encode(""))).startsWith(
    "WALLET_CHECK_NEEDS_PASSPHRASE",
  ),
  () => "walletCheck without a passphrase",
);
check(
  codeOf(() => mhfe.walletCheck(encode(data.phrases[0]), encode("TREZOR"))).startsWith(
    "INVALID_WORD_COUNT",
  ),
  () => "walletCheck of 12 words",
);
const counted = (counter) => {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setBigUint64(24, BigInt(counter));
  return bytes;
};
const words = vector.mnemonic.split(" ");
for (const [what, chosen, places] of [
  ["no wish", "", []],
  ["last word chosen", words[23], [24]],
]) {
  let next = vector.counter - 3;
  const random = {
    fill(bytes) {
      next += 1;
      bytes.set(counted(next));
    },
  };
  const drawn = JSON.parse(
    mhfe.drawPhrase(
      encode(vector.passphrase),
      encode(vector.passphrase),
      encode(chosen),
      Uint32Array.from(places),
      "",
      true,
      random,
      () => {},
    ),
  );
  const fingerprint = mhfe.walletFingerprint(encode(vector.mnemonic), encode(vector.passphrase));
  check(
    drawn.phrase === vector.mnemonic &&
      drawn.words === 24 &&
      drawn.walletCheck === true &&
      drawn.fingerprintWithPassphrase === fingerprint,
    () => `drawPhrase ${what}: ${JSON.stringify({ ...drawn, phrase: drawn.phrase === vector.mnemonic })}`,
  );
}
console.log(`wasm-parity: ${checks} checks, ${failures.length} failures`);
process.exit(failures.length === 0 ? 0 : 1);
