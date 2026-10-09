// AUD-014 bounded real-browser exercise of the fresh wallet package; no Argon2 or checked draw.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium, firefox } from "playwright";
import { bundleClasses } from "../../../../scripts/bundle-browser-classes.mjs";
import { readBytes, sha256 } from "./browser-sources.mjs";

const root = new URL("../../../../", import.meta.url);
const manifest = JSON.parse(readBytes("dist/modules.json"));
const wasm = readBytes("dist/runtime/mhfe.wasm");
const worker = readBytes("dist/runtime/worker.js").toString("utf8");
assert.equal(sha256(wasm), manifest.runtime.files["mhfe.wasm"]);
assert.equal(sha256(worker), manifest.runtime.files["worker.js"]);
const classes = bundleClasses(root, ["wallet/wallet.js"]);
const literal = (value) => JSON.stringify(value).replaceAll("<", "\\u003c");

// Read only the fixed-position ASCII fixtures from their single source. These complete phrases
// were computed by the independent implementation named in the Rust fixture's provenance; they
// are not reconstructed by the implementation under test or copied into a second golden list.
const knownAnswers = readBytes("src/word_wishes/known_answers.rs").toString("utf8");
const fixedCases = [
  ...knownAnswers.matchAll(
    /chosen:\s*&\[\(Place::At\((\d+)\), "([a-z]+)"\)\],\s*never_use:\s*&\[([^\]\r\n]*)\],\s*phrase:\s*"((?:[a-z ]|\\\r?\n\s*)+)",/g,
  ),
].map(([, position, word, neverUse, phrase]) => ({
  request: {
    chosen: [{ word, position: Number(position) }],
    neverUse: JSON.parse(`[${neverUse}]`),
  },
  expectedPhrase: phrase.replace(/\\\r?\n\s*/g, ""),
}));
const drawingsExpected = [24, 1].map((position) => {
  const matches = fixedCases.filter((entry) => entry.request.chosen[0].position === position);
  assert.equal(matches.length, 1, `one independent fixed-position KAT exists for ${position}`);
  return matches[0];
});
assert.deepEqual(drawingsExpected[0].request, {
  chosen: [{ word: "zoo", position: 24 }],
  neverUse: [],
});
assert.deepEqual(drawingsExpected[1].request, {
  chosen: [{ word: "happy", position: 1 }],
  neverUse: ["abandon"],
});

// Only drawPhrase receives a scripted source. Both startup and fullCheck keep the worker's real
// crypto.getRandomValues. Two distinct probe blocks precede the public xorshift32 entropy stream
// from src/word_wishes/known_answers.rs, so the production source guard still runs unchanged.
const scriptedDraw = `
{
  const ordinaryDraw = WALLET_OPERATIONS.drawPhrase;
  WALLET_OPERATIONS.drawPhrase = (request, host) => {
    let probes = 0;
    let state = 0x2545f491;
    const random = { fill(bytes) {
      for (let at = 0; at < bytes.length; at += 1) {
        if (probes < 64) bytes[at] = ++probes;
        else {
          state ^= state << 13;
          state ^= state >>> 17;
          state ^= state << 5;
          bytes[at] = state & 255;
        }
      }
    } };
    return ordinaryDraw(request, { ...host, random });
  };
}
`;

const script = `${classes}
window.auditFinished = false;
try {
  const fail = (condition, what) => { if (!condition) throw new Error(what); };
  const wasm = Uint8Array.from(atob(${literal(wasm.toString("base64"))}), (letter) => letter.charCodeAt(0));
  const compiled = await WebAssembly.compile(wasm);
  const wallet = new MhfeWallet({
    workerSource: ${literal(`${worker}\n${scriptedDraw}`)},
    wasm: compiled,
  });
  const began = performance.now();
  const startup = await wallet.startupCheck();
  const startupMs = performance.now() - began;
  fail(startup.passed, "the real worker startup check failed");
  fail(startup.version === ${literal(manifest.version)}, "the startup report is of another version");
  fail(startup.buildId === ${literal(manifest.buildId)}, "the startup report is of another build");
  fail(startup.components.some(({ id, outcome }) => id === "word-wishes" && outcome === "passed"),
    "the actual WordWishes component is missing or failed");
  fail(startupMs < 2000, "the wallet startup check exceeds its two-second browser bound");
  const fullBegan = performance.now();
  const full = await wallet.fullCheck();
  const fullMs = performance.now() - fullBegan;
  fail(full.passed && full.tier === "full", "the real bounded wallet full check failed");
  fail(full.components.some(({ id, outcome }) => id === "word-wishes" && outcome === "passed"),
    "the full WordWishes component is missing or failed");
  fail(full.components.some(({ id, outcome }) => id === "random-source" && outcome === "passed"),
    "the real host random source was not checked successfully");
  const drawings = [];
  for (const { request, expectedPhrase } of ${literal(drawingsExpected)}) {
    const drawn = await wallet.drawPhrase(request);
    fail(drawn.phrase === expectedPhrase, "the real draw differs from its independent complete phrase KAT");
    const words = drawn.phrase.split(" ");
    fail(words.length === 24 && drawn.words === 24, "the real draw has another word count");
    fail(drawn.walletCheck === false && drawn.workers === 1, "an unchecked draw used another mode");
    const wished = request.chosen[0];
    fail(words[wished.position - 1] === wished.word.toLowerCase(), "the chosen position differs");
    fail((request.neverUse ?? []).every((word) => !words.includes(word)), "an excluded word appears");
    // Fingerprinting parses and validates the returned BIP39 phrase through its normal API.
    const fingerprint = await wallet.fingerprint({ phrase: drawn.phrase });
    fail(/^[0-9a-f]{8}$/.test(fingerprint), "the returned BIP39 phrase cannot be fingerprinted");
    drawings.push({ position: wished.position, word: words[wished.position - 1],
      excludesAbandon: !words.includes("abandon"), words: drawn.words, workers: drawn.workers,
      fingerprint, matchesIndependentPhrase: true });
  }
  let refusal;
  try { await wallet.drawPhrase({ chosen: [{ word: "notaword", position: 1 }] }); }
  catch (error) { refusal = error.code; }
  fail(refusal === "INVALID_WORD_WISH", "the real worker accepted an invalid chosen word");
  window.auditResult = { passed: true, startupMs, fullMs, version: startup.version, buildId: startup.buildId,
    startupComponents: startup.components.map(({ id, outcome }) => ({ id, outcome })),
    fullComponents: full.components.map(({ id, outcome }) => ({ id, outcome })), drawings,
    invalidChosenWord: refusal };
} catch (error) {
  window.auditResult = { passed: false, error: String(error), stack: error.stack };
} finally {
  window.auditFinished = true;
}
`;
const scriptHash = createHash("sha256").update(script).digest("base64");
const policy = [
  "default-src 'none'",
  `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
  "worker-src blob:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");
const evidence = new URL("docs/audits/AUD-014-evidence/", root);
mkdirSync(evidence, { recursive: true });
const pageFile = new URL("integration-startup-browser.html", evidence);
writeFileSync(
  pageFile,
  `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><script type="module">${script}</script>`,
);

// A whole-run deadline keeps launch and page waits within the requested thirty-second budget.
const deadline = performance.now() + 25_000;
const remaining = (bound) => {
  const left = deadline - performance.now();
  assert.ok(left > 0, "the whole browser smoke exceeded its twenty-five-second deadline");
  return Math.min(bound, left);
};
const results = [];
for (const [name, browserType] of [
  ["chromium", chromium],
  ["firefox", firefox],
]) {
  const browser = await browserType.launch({ timeout: remaining(8_000) });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    const network = [];
    page.on("pageerror", (error) => errors.push(error.message));
    context.on("request", (request) => {
      if (/^https?:/i.test(request.url())) network.push(request.url());
    });
    await context.route(/^https?:/i, (route) => route.abort());
    await page.goto(pathToFileURL(fileURLToPath(pageFile)).href, {
      waitUntil: "load",
      timeout: remaining(5_000),
    });
    await page.waitForFunction(() => window.auditFinished, null, { timeout: remaining(8_000) });
    const result = await page.evaluate(() => window.auditResult);
    assert.deepEqual(errors, [], `${name}: no uncaught page errors`);
    assert.deepEqual(network, [], `${name}: no network requests`);
    assert.equal(result.passed, true, `${name}: ${JSON.stringify(result)}`);
    const row = { browser: name, browserVersion: browser.version(), ...result };
    results.push(row);
    console.log(JSON.stringify(row));
    await context.close();
  } finally {
    await browser.close();
  }
}
console.log(
  JSON.stringify({
    browsers: results.length,
    version: manifest.version,
    buildId: manifest.buildId,
    wasmSha256: sha256(wasm),
    workerSha256: sha256(worker),
    knownAnswersSha256: sha256(knownAnswers),
    page: fileURLToPath(pageFile),
    limitations:
      "Wallet-only, normal file-page policy; no Argon2, checked draws, Deriver UI, or full browser suite.",
  }),
);
