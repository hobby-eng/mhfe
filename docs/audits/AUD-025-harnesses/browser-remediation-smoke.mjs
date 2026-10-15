// AUD-025 remediation: bounded real-browser startup/API smoke, public fixtures only.
// Run after scripts/build-wasm.sh; no encryption, wallet drawing or full-cost vectors.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { chromium, firefox } from "playwright";

import { bundlePackageClasses, inline, pagePolicy, read, root } from "../../../scripts/bundle-browser-classes.mjs";
import { PHRASE, PHRASE_FINGERPRINT } from "../../../scripts/public-test-data.mjs";

const source = {
  workerSource: read("dist/runtime/worker.js").toString(),
  argon2Threaded: read("dist/core/argon2-mt.js").toString(),
  argon2SingleThreaded: read("dist/core/argon2-st.js").toString(),
  wasm: read("dist/runtime/mhfe.wasm").toString("base64"),
};
const script = `${bundlePackageClasses(root)}
const sources = ${inline(source)};
sources.wasm = Uint8Array.from(atob(sources.wasm), (character) => character.charCodeAt(0));
const phrase = ${inline(PHRASE)};
const fingerprint = ${inline(PHRASE_FINGERPRINT)};
(${browserChecks.toString()})().then(
  (result) => { window.mhfeSmoke = { result }; },
  (error) => { window.mhfeSmoke = { error: { code: error.code, message: error.message } }; },
);`;
const folder = new URL("../../../target/aud025-smoke/", import.meta.url);
mkdirSync(folder, { recursive: true });
const pagePath = fileURLToPath(new URL("standard.html", folder));
writeFileSync(pagePath, `<!doctype html><meta http-equiv="Content-Security-Policy" content="${pagePolicy(script)}"><script type="module">${script}</script>`);

for (const [name, engine] of [["chromium", chromium], ["firefox", firefox]]) {
  const browser = await engine.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const escapedRequests = [];
    page.on("request", (request) => {
      if (/^https?:/u.test(request.url())) escapedRequests.push(request.url());
    });
    await page.goto(pathToFileURL(pagePath).href);
    await page.waitForFunction(() => window.mhfeSmoke !== undefined, undefined, { timeout: 120_000 });
    const result = await page.evaluate(() => window.mhfeSmoke);
    assert.equal(result.error, undefined, `${name}: ${JSON.stringify(result.error)}`);
    assert.deepEqual(escapedRequests, [], `${name}: no HTTP request leaves the offline page`);
    console.log(JSON.stringify({ browser: name, ...result.result }));
  } finally {
    await browser.close();
  }
}

/** Runs only current package entry points under the offline page's actual CSP and Blob workers. */
async function browserChecks() {
  const check = (value, label) => { if (!value) throw new Error(label); };
  const classes = {
    core: new MhfeClient(sources),
    repair: new MhfeRepair(sources),
    passwords: new MhfePasswords(sources),
    wallet: new MhfeWallet(sources),
  };
  const startupMs = {};
  for (const [name, client] of Object.entries(classes)) {
    const start = performance.now();
    const report = await client.startupCheck();
    startupMs[name] = Math.round(performance.now() - start);
    check(report.passed, `${name}: startup failed`);
    if (name === "core") check(report.components.find(({ id }) => id === "argon2")?.outcome === "passed", "the actual standard Argon2 backend ran");
  }
  const parameters = await classes.core.parameters();
  check(JSON.stringify(parameters.progressStages) === '["recover","encrypt","check","compare"]', "progress stages");
  check(JSON.stringify(parameters.progressRoundTotals) === '[12,24,36]', "progress totals");
  check(parameters.openedWordCount === 24, "opened word count");
  check((await classes.core.readPhrase(phrase.toUpperCase())).phrase === phrase, "phrase normalization");
  check(await classes.wallet.fingerprint({ phrase }) === fingerprint, "independent BIP39/BIP32 fingerprint");
  check((await classes.passwords.review({ password: "abacus abdomen abdominal abide abiding aids" })).reading === "fits", "published password check-word vector");
  const markerPart = "SYNTHETIC_PRIVATE_MARKER";
  const marker = markerPart.repeat(1000);
  const safeMessage = "The seed phrase is not a valid English BIP39 phrase: word 12 is not in the English BIP39 word list";
  const privateRefusal = (message) => message === safeMessage;
  check(privateRefusal(safeMessage), "safe refusal control");
  for (const echo of [markerPart, markerPart.slice(0, 8)]) {
    check(!privateRefusal(`${safeMessage}: ${echo}`), "partial input echo is refused by the test");
  }
  try {
    await classes.core.readPhrase(phrase.replace("about", marker));
    throw new Error("overlong token was accepted");
  } catch (error) {
    check(error.code === "INVALID_PHRASE", "overlong token code");
    check(privateRefusal(error.message), "refusal gives only the position and no part of its input");
    let readonly = false;
    try { error.code = "INTERNAL_ERROR"; } catch (cause) { readonly = cause instanceof TypeError; }
    check(readonly && error.code === "INVALID_PHRASE", "error code is readonly");
  }
  return { buildId: BUILD_ID, startupMs, checks: "startup, metadata, phrase, fingerprint, check word, overlong refusal, readonly error" };
}
