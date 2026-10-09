// AUD-015 R3 short browser probe: the package's classes from dist/ on a page under the strict
// Content-Security-Policy of the offline wallet tools (one hashed script, 'wasm-unsafe-eval',
// connect-src 'none', worker-src blob:), standard mode, then the same page without
// 'wasm-unsafe-eval'. It records the startup reports, a few quick operations on public test data,
// every request that leaves the page and every CSP violation. No Argon2 operation runs; the core's
// startup check runs Argon2's 1 MiB known answer once.
//
//   node docs/audits/AUD-015-harnesses/r3-browser/csp-page.mjs chromium
//   node docs/audits/AUD-015-harnesses/r3-browser/csp-page.mjs firefox
//
// One browser per run, closed at the end. Exit code 1 when a check fails.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { chromium, firefox } from "playwright";

import { bundleClasses } from "../../../../scripts/bundle-browser-classes.mjs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(join(root.pathname, path));
const browserType = { chromium, firefox }[process.argv[2]];
if (browserType === undefined) {
  console.error("Usage: node csp-page.mjs chromium|firefox");
  process.exit(2);
}

/** The BIP39 test phrase and its master key fingerprint (BIP32 test vectors, public). */
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PHRASE_FINGERPRINT = "73c5da0a";

function pageScript() {
  const results = {};
  const record = async (name, action) => {
    try {
      results[name] = { resolved: await action() };
    } catch (error) {
      results[name] = { rejected: { name: error?.name, code: error?.code, message: error?.message } };
    }
  };
  const run = async () => {
    const bytes = Uint8Array.from(atob(WASM_BASE64), (c) => c.charCodeAt(0));
    const parts = { workerSource: WORKER_SOURCE, wasm: bytes };
    const repair = new MhfeRepair(parts);
    const passwords = new MhfePasswords(parts);
    const wallet = new MhfeWallet(parts);
    const client = new MhfeClient({
      ...parts,
      argon2Threaded: ARGON2_THREADED,
      argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    });
    const summary = (report) => ({
      passed: report.passed,
      failed: report.components.filter((c) => c.outcome === "failed"),
      notPassed: report.components.filter((c) => c.outcome !== "passed").map((c) => c.id),
    });
    await record("repair.startupCheck", async () => summary(await repair.startupCheck()));
    await record("passwords.startupCheck", async () => summary(await passwords.startupCheck()));
    await record("wallet.startupCheck", async () => summary(await wallet.startupCheck()));
    await record("client.startupCheck", async () => summary(await client.startupCheck()));
    await record("client.mode", async () => client.mode());
    await record("wallet.fingerprint", () => wallet.fingerprint({ phrase: PHRASE }));
    await record("repair.inspectContainer", () => repair.inspectContainer({ container: PHRASE }));
    await record("passwords.make", async () => {
      const made = await passwords.make({ kind: "words" });
      return { words: made.password.split(" ").length, checkWord: made.checkWord };
    });
    await record("client.readPhrase", async () => (await client.readPhrase(PHRASE)).words);
    await record("wallet.parameters", async () => (await wallet.parameters()).version);
  };
  run().finally(() => {
    window.r3Result = results;
  });
}

const script = `${bundleClasses(root, [
  "core/client.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
])}
const WORKER_SOURCE = ${JSON.stringify(read("dist/runtime/worker.js").toString())};
const WASM_BASE64 = ${JSON.stringify(read("dist/runtime/mhfe.wasm").toString("base64"))};
const ARGON2_THREADED = ${JSON.stringify(read("dist/core/argon2-mt.js").toString())};
const ARGON2_SINGLE_THREADED = ${JSON.stringify(read("dist/core/argon2-st.js").toString())};
const PHRASE = ${JSON.stringify(PHRASE)};
(${pageScript.toString()})();
`;
const scriptHash = createHash("sha256").update(script, "utf8").digest("base64");
const policy = (wasmEval) =>
  [
    "default-src 'none'",
    `script-src 'sha256-${scriptHash}'${wasmEval ? " 'wasm-unsafe-eval'" : ""}`,
    "connect-src 'none'",
    "worker-src blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
const page = (wasmEval) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="${policy(wasmEval)}" />
<title>AUD-015 R3 CSP probe</title></head>
<body><script type="module">${script}</script></body></html>
`;
const server = createServer((request, response) => {
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  response.end(page(!request.url.startsWith("/no-wasm-eval")));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

let failures = 0;
const check = (name, ok, evidence) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
};

const browser = await browserType.launch();
try {
  console.log(`${browserType.name()} ${browser.version()}`);
  for (const [label, address] of [
    ["strict CSP", `${base}/`],
    ["strict CSP without 'wasm-unsafe-eval'", `${base}/no-wasm-eval`],
  ]) {
    const tab = await browser.newPage();
    const stray = [];
    const errors = [];
    tab.on("request", (request) => {
      const url = request.url();
      if (url !== address && !url.startsWith("blob:")) stray.push(url);
    });
    tab.on("pageerror", (error) => errors.push(String(error)));
    await tab.goto(address);
    await tab.waitForFunction(() => window.r3Result !== undefined, null, { timeout: 60_000 });
    const results = await tab.evaluate(() => window.r3Result);
    console.log(`--- ${label}`);
    for (const [name, outcome] of Object.entries(results)) {
      console.log(`  ${name}: ${JSON.stringify(outcome)}`);
    }
    check(`${label}: no request left the page`, stray.length === 0, stray);
    check(`${label}: no uncaught page error`, errors.length === 0, errors);
    if (label === "strict CSP") {
      check(
        "strict CSP: every class passes its startup check and the quick operations answer",
        ["repair", "passwords", "wallet", "client"].every(
          (name) => results[`${name}.startupCheck`]?.resolved?.passed === true,
        ) &&
          results["wallet.fingerprint"]?.resolved === PHRASE_FINGERPRINT &&
          results["repair.inspectContainer"]?.resolved?.reading !== undefined &&
          results["passwords.make"]?.resolved?.words === 5 &&
          results["client.readPhrase"]?.resolved === 12,
      );
    } else {
      check(
        "without 'wasm-unsafe-eval': every class reports browser-features failed and refuses work",
        ["repair", "passwords", "wallet", "client"].every((name) =>
          results[`${name}.startupCheck`]?.resolved?.failed?.some(
            (c) => c.id === "browser-features",
          ),
        ) && results["wallet.fingerprint"]?.rejected?.code === "SELF_CHECK_FAILED",
      );
    }
    await tab.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
console.log(failures === 0 ? "every check passed" : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
