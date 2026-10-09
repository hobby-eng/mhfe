// AUD-015 R1: the optional profiles as the built browser package computes them.
//
//   node profiles_probe.mjs <cases-out.json>
//
// Run from the repository root. Loads target/wasm-bindgen/mhfe.js with dist/runtime/mhfe.wasm and
// records, for `oracle.py profilecases` to recompute independently:
//   - MHFE-REPAIR-1: repair words of random containers of every length for k = 2, 4, 6, 8, and the
//     repair of random damage within 2e + s <= k, on the container phrase and on the card;
//   - MHFE-PASSWORD-CHECK-1: the review of passwords that fit, miss a word ("?") or have one
//     replaced word;
//   - MHFE-WALLET-CHECK-SEED-1: walletCheck of random 24-word phrases and of the published vectors.
// No Argon2 is involved. Public, synthetic data only.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import vm from "node:vm";

const [casesOut] = process.argv.slice(2);
const read = (path) => readFileSync(path);
const encode = (text) => new TextEncoder().encode(text);
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const core = vm.runInThisContext("mhfe");
core.initSync({ module: read("dist/runtime/mhfe.wasm") });

const scure =
  "../multi-chain-wallet-tools/node_modules/.pnpm/@scure+bip39@2.4.0/node_modules/@scure/bip39/wordlists/english.js";
const WORDS = /`([^`]*)`/u.exec(read(scure).toString())[1].split("\n").filter(Boolean);
assert.equal(
  createHash("sha256").update(`${WORDS.join("\n")}\n`).digest("hex"),
  "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
);
const EFF = read("vendor/eff-large-wordlist/eff_large_wordlist.txt")
  .toString()
  .split("\n")
  .filter(Boolean)
  .map((line) => line.split("\t")[1]);

let seed = 0x0dd5eed;
const next = (bound) => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed % bound;
};
function mnemonic(entropy) {
  const cs = entropy.length / 4;
  let bits = BigInt(`0x${Buffer.from(entropy).toString("hex")}`);
  bits = (bits << BigInt(cs)) | BigInt(createHash("sha256").update(entropy).digest()[0] >> (8 - cs));
  const out = [];
  for (let i = (entropy.length * 8 + cs) / 11 - 1; i >= 0; i -= 1) {
    out.push(WORDS[Number((bits >> BigInt(11 * i)) & 0x7ffn)]);
  }
  return out.join(" ");
}
const randomPhrase = (words) =>
  mnemonic(Uint8Array.from({ length: (words / 3) * 4 }, () => next(256)));
const errorCode = (action) => {
  try {
    return { value: action() };
  } catch (error) {
    return { error: error.message.split(":")[0] };
  }
};

const repair = [];
for (let i = 0; i < 60; i += 1) {
  const words = [12, 15, 18, 21, 24][i % 5];
  const container = randomPhrase(words);
  for (const k of [2, 4, 6, 8]) {
    const card = JSON.parse(core.repairWords(container, k)).words;
    // Damage within the bound: s unreadable ("?") and e wrong words, at distinct positions over
    // the container phrase and the card together.
    const s = next(k + 1);
    const e = next(Math.floor((k - s) / 2) + 1);
    const all = [...container.split(" "), ...card.split(" ")];
    const damaged = [...all];
    const positions = [];
    while (positions.length < s + e) {
      const position = next(all.length);
      if (!positions.includes(position)) positions.push(position);
    }
    positions.forEach((position, index) => {
      if (index < s) {
        damaged[position] = "?";
      } else {
        let other = WORDS[next(2048)];
        while (other === all[position]) other = WORDS[next(2048)];
        damaged[position] = other;
      }
    });
    const written = damaged.slice(0, words).join(" ");
    const typedCard = damaged.slice(words).join(" ");
    const outcome = errorCode(() => JSON.parse(core.repairContainer(written, typedCard)));
    repair.push({ container, k, card, written, typedCard, positions, s, e, outcome });
  }
}

const checkWord = [];
for (let i = 0; i < 300; i += 1) {
  const drawn = Array.from({ length: 5 }, () => next(7776));
  const c = (drawn[0] + 5 * drawn[1] + 7 * drawn[2] + 11 * drawn[3] + 13 * drawn[4]) % 7776;
  const words = [...drawn, c].map((index) => EFF[index]);
  const variants = [words.join(" ")];
  const gap = [...words];
  gap[next(6)] = "?";
  variants.push(gap.join(" "));
  const replaced = [...words];
  const at = next(6);
  let other = EFF[next(7776)];
  while (other === replaced[at]) other = EFF[next(7776)];
  replaced[at] = other;
  variants.push(replaced.join(" "));
  for (const text of variants) {
    const outcome = errorCode(() =>
      JSON.parse(core.reviewPassword(encode(text), encode(text), true)),
    );
    checkWord.push({ original: words.join(" "), text, outcome });
  }
}

const walletCheck = [];
const counter = (value) => {
  const entropy = new Uint8Array(32);
  new DataView(entropy.buffer).setBigUint64(24, BigInt(value));
  return mnemonic(entropy);
};
for (const [phrase, passphrase] of [
  [counter(76562), "TREZOR"],
  [counter(98918), "TREZOR"],
  [counter(76562), ""],
  [randomPhrase(12), "TREZOR"],
  ...Array.from({ length: 60 }, (_, i) => [randomPhrase(24), ["TREZOR", "p\u00e4ss \ufb01", "x"][i % 3]]),
]) {
  const outcome = errorCode(() => core.walletCheck(encode(phrase), encode(passphrase)));
  walletCheck.push({ phrase, passphrase, outcome });
}

writeFileSync(casesOut, `${JSON.stringify({ repair, checkWord, walletCheck }, null, 1)}\n`);
console.log(
  `profiles: ${repair.length} repair cases, ${checkWord.length} password reviews, ` +
    `${walletCheck.length} wallet checks written to ${casesOut}`,
);
