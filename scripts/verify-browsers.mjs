// Runs the browser package from dist/ in real browsers, Chromium and Firefox, with Playwright:
//
//   node scripts/verify-browsers.mjs
//
// Build the package first with scripts/build-wasm.sh, install the tools with `npm ci` and the two
// browsers with `npx playwright install chromium firefox`.
//
// scripts/verify-browser-package.mjs checks the same code under Node.js with a stand-in worker.
// This check adds what only a browser does: Blob workers under the Content-Security-Policy of the
// offline wallet tools, the transfer of secrets to them, the threaded Argon2 build in a
// cross-origin isolated page, cancellation and the page's failing callbacks. Each browser opens
// the page twice: as a file (standard mode) and from a loopback server with the isolation
// headers (fast mode), as `mhfe serve` gives them.
//
// So that it takes seconds, a test-only wrapper in the page's copy of the worker runs Argon2 with
// 256 KiB and one pass instead of the 2 GiB and twelve passes of suite 3, after checking that
// the core asked for those. The container must then be REDUCED_COST_CONTAINER, which the native
// tests (src/mhfe.rs) and scripts/verify-browser-package.mjs check at the same cost. Only public
// test data is used, and no request may leave the page. The same-length container must be
// REDUCED_COST_SAME_LENGTH_CONTAINER of src/mhfe.rs at that cost.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath, pathToFileURL } from "node:url";

import { chromium, firefox } from "playwright";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
/** JSON that is safe inside a script element: "</script" cannot appear in it. */
const inline = (value) => JSON.stringify(value).replaceAll("<", "\\u003c");

/** How long one page may take; a run takes a few seconds per browser and mode. */
const PAGE_TIMEOUT_MS = 120_000;

// The suite 3 cost the core must ask for, and the reduced cost that replaces it here: the cost of
// REDUCED_COST_CONTAINER in src/mhfe.rs.
const reducedCostWrapper = `
const fullCostArgon2Engine = argon2Engine;
argon2Engine = (module) => {
  const engine = fullCostArgon2Engine(module);
  return {
    derive(password, salt, memoryKib, passes, key) {
      if (memoryKib !== 2097152 || passes !== 12) {
        throw new Error("TEST_COST: the core did not ask for the suite 3 cost");
      }
      return engine.derive(password, salt, 256, 1, key);
    },
  };
};
`;

const checks = `
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD = "public test password";
const REDUCED_COST_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
const REDUCED_COST_SAME_LENGTH_CONTAINER =
  "program adjust rain raven flip eternal spider bulb under soup enrich ensure";
// The BIP32 master key fingerprint of the wallet of PHRASE without a passphrase.
const FINGERPRINT = "73c5da0a";

const results = [];
const failures = [];
function expect(condition, description) {
  results.push((condition ? "ok   " : "FAIL ") + description);
  if (!condition) failures.push(description);
}

async function expectRejection(promise, code, description, cause) {
  try {
    await promise;
    expect(false, description + " (it resolved)");
  } catch (error) {
    const sameCause = cause === undefined || error.cause === cause;
    expect(error.code === code && sameCause, description + " -> " + error.code);
  }
}

async function main() {
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    coreWasm: Uint8Array.from(atob(CORE_WASM_BASE64), (character) => character.charCodeAt(0)),
  });

  const read = await client.readPhrase(PHRASE.toUpperCase());
  expect(read.phrase === PHRASE && read.words === 12 && read.otherLengths.length === 0,
    "readPhrase writes every word out");
  await expectRejection(
    client.encrypt({ phrase: PHRASE, password: "a\\tb", passwordRepeat: "a\\tb" }),
    "CONTROL_CHARACTER_IN_PASSWORD", "a password with a TAB is refused");

  const rounds = [];
  let unverified = null;
  const { container } = await client.encrypt({
    phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD,
    onProgress: ({ round }) => rounds.push(round),
    onUnverified: (result) => { unverified = result.container; },
  });
  expect(container === REDUCED_COST_CONTAINER && unverified === container && rounds.length === 24,
    "encrypt gives the native container after 24 rounds, shown unverified first");
  const recovery = await client.decrypt({ container, password: PASSWORD });
  const [candidate] = recovery.candidates;
  expect(recovery.kind === "phrase" && candidate.phrase === PHRASE && candidate.verified,
    "decrypt recovers the verified 12-word phrase");
  const { matches } = await client.check({ container, password: PASSWORD, reference: { fingerprint: FINGERPRINT } });
  expect(matches === true, "check matches the master key fingerprint");

  const same = await client.encrypt({
    phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD, sameLength: true,
  });
  expect(same.container === REDUCED_COST_SAME_LENGTH_CONTAINER
    && same.suiteId === "MHFE-BIP39-LP-EXPERIMENTAL-4",
    "encrypt with sameLength gives the native 12-word container");
  const sameRecovery = await client.decrypt({ container: same.container, password: PASSWORD });
  expect(sameRecovery.candidates[0].phrase === PHRASE && !sameRecovery.candidates[0].verified,
    "a same-length container recovers the phrase, not verified");

  const cancelledAtOnce = client.decrypt({ container, password: PASSWORD });
  client.cancel();
  await expectRejection(cancelledAtOnce, "CANCELLED", "cancel before the first round");
  const cancelledLater = client.decrypt({
    container, password: PASSWORD,
    onProgress: ({ round }) => { if (round === 2) client.cancel(); },
  });
  await expectRejection(cancelledLater, "CANCELLED", "cancel in the second round");
  expect((await client.readContainer(container)).container === container,
    "a new operation runs after a cancel");

  const pageError = new Error("synthetic page error");
  await expectRejection(
    client.decrypt({ container, password: PASSWORD, onProgress: () => { throw pageError; } }),
    "CALLBACK_FAILED", "a throwing onProgress stops the operation", pageError);
  await expectRejection(
    client.encrypt({ phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD,
      onUnverified: () => { throw pageError; } }),
    "CALLBACK_FAILED", "a throwing onUnverified stops the operation", pageError);
  await expectRejection(
    client.decrypt({ container, password: PASSWORD, onProgress: async () => { throw pageError; } }),
    "CALLBACK_FAILED", "an async onProgress that rejects stops the operation", pageError);
  expect((await client.readPhrase(PHRASE)).phrase === PHRASE,
    "a new operation runs after a callback failed");
  return client.mode();
}

main()
  .then((mode) => { window.mhfeCheck = { mode, results, failures }; })
  .catch((error) => {
    failures.push("page error: " + (error.code ?? "") + " " + error.message);
    window.mhfeCheck = { mode: null, results, failures };
  });
`;

const sources = `
const WORKER_SOURCE = ${inline(read("dist/mhfe-worker.js").toString() + reducedCostWrapper)};
const ARGON2_THREADED = ${inline(read("dist/argon2-mt.js").toString())};
const ARGON2_SINGLE_THREADED = ${inline(read("dist/argon2-st.js").toString())};
const CORE_WASM_BASE64 = ${inline(read("dist/mhfe_core_bg.wasm").toString("base64"))};
`;
const script = read("dist/client.js").toString() + sources + checks;

// The policy of scripts/build-browser-check.mjs and the offline wallet tools: nothing but this
// one script, WebAssembly and Blob workers.
const scriptHash = createHash("sha256").update(script, "utf8").digest("base64");
const policy = [
  "default-src 'none'",
  `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
  "connect-src 'none'",
  "worker-src blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");
const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${policy}" />
    <title>MHFE browser check</title>
  </head>
  <body>
    <script type="module">${script}</script>
  </body>
</html>
`;
const pagePath = fileURLToPath(new URL("target/browser-check/reduced-cost.html", root));
mkdirSync(new URL("target/browser-check/", root), { recursive: true });
writeFileSync(pagePath, page);

// The headers that make the page cross-origin isolated, so that the threaded Argon2 build runs.
const server = createServer((request, response) => {
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
  });
  response.end(page);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

const addresses = {
  standard: pathToFileURL(pagePath).href,
  fast: `http://127.0.0.1:${server.address().port}/`,
};
let failed = false;
try {
  for (const browserType of [chromium, firefox]) {
    const browser = await browserType.launch();
    try {
      for (const [mode, address] of Object.entries(addresses)) {
        failed = !(await checkPage(browser, browserType.name(), mode, address)) || failed;
      }
    } finally {
      await browser.close();
    }
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}
if (failed) {
  console.error("The browser check failed.");
  process.exit(1);
}
console.log("The browser package passes its checks in Chromium and Firefox, in both modes.");

/** Opens the page in a new tab and reports its results; true when everything passed. */
async function checkPage(browser, browserName, mode, address) {
  const page = await browser.newPage();
  const strayRequests = [];
  const pageErrors = [];
  // The page itself and its Blob workers are the only things it may load.
  page.on("request", (request) => {
    const url = request.url();
    if (url !== address && !url.startsWith("blob:")) strayRequests.push(url);
  });
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  try {
    await page.goto(address);
    await page.waitForFunction(() => window.mhfeCheck !== undefined, null, {
      timeout: PAGE_TIMEOUT_MS,
    });
    const { mode: clientMode, results, failures } = await page.evaluate(() => window.mhfeCheck);
    if (clientMode !== mode) failures.push(`the client ran in ${clientMode} mode, not ${mode}`);
    for (const url of strayRequests) failures.push(`a request left the page: ${url}`);
    for (const error of pageErrors) failures.push(`uncaught page error: ${error}`);
    console.log(`${browserName} ${browser.version()}, ${mode} mode:`);
    for (const line of results) console.log(`  ${line}`);
    for (const failure of failures) console.log(`  FAIL ${failure}`);
    return failures.length === 0;
  } finally {
    await page.close();
  }
}
