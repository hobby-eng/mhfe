// Runs the browser package from dist/ in real browsers, Chromium and Firefox, with Playwright:
//
//   node scripts/verify-browsers.mjs [--browser chromium|firefox] [--mode standard|fast]
//
// Without an option it checks both browsers in both modes; an option keeps one of them, for
// example to run Firefox's fast mode again and again.
//
// Build the package first with scripts/build-wasm.sh, install the tools with
// `pnpm install --frozen-lockfile` and the two browsers with
// `pnpm exec playwright install chromium firefox`.
//
// scripts/verify-browser-package.mjs checks the same code under Node.js with a stand-in worker.
// This check adds what only a browser does: Blob workers under the Content-Security-Policy of the
// offline wallet tools, the transfer of secrets to them, the threaded Argon2 build in a
// cross-origin isolated page, cancellation and the page's failing callbacks. Each browser opens
// the page twice: as a file (standard mode) and from a loopback server with the isolation
// headers (fast mode), as `mhfe serve` gives them. The page calls every method of the four classes
// with each of its options and compares the results, or the refusals, with known values: public
// vectors, values computed independently, or the results of another method or class.
//
// So that Argon2 takes seconds, a test-only wrapper in the page's copy of the worker runs it with
// 256 KiB and one pass instead of the 2 GiB and twelve passes of suite 3, after checking that
// the core asked for those. The container must then be REDUCED_COST_CONTAINER, which the native
// tests (src/mhfe.rs) and scripts/verify-browser-package.mjs check at the same cost. Only public
// test data is used, and no request may leave the page. The same-length container must be
// REDUCED_COST_SAME_LENGTH_CONTAINER of src/mhfe.rs at that cost. The same wrapper stands for a
// browser that cannot give the memory, for one marker password and one marker container. A run
// takes a few minutes, mostly for the two phrases per page drawn to pass the wallet check, about
// 65,536 BIP39 seeds each.
//
// What the reduced cost cannot show: a PIM above 0 (the wrapper refuses any cost but suite 3's,
// so the page only checks the cost the core asks for) and the self-test's verdict on the published
// vectors, which are computed at full cost (the page checks that it runs both and says "not as
// published"). Nor can a page see whether a worker it stopped has really ended. The known answers
// of the Argon2 builds, at 1, 64 and 256 MiB, pass the wrapper unchanged: every class's startup
// check runs in each page, with its time, under the same policy, the full self-checks too, and a
// WebAssembly whose vector was damaged must close its classes, while an Argon2 build that does
// not start must leave the client open and one of another build must be refused.
//
// The page's code is in scripts/browser-check/: its constants in page-values.mjs, and its checks,
// which run from their source text in the page, in the other modules (harness.mjs says how).
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { chromium, firefox } from "playwright";

import * as clientChecks from "./browser-check/client-checks.mjs";
import * as decryptChecks from "./browser-check/decrypt-checks.mjs";
import * as encryptChecks from "./browser-check/encrypt-checks.mjs";
import * as harness from "./browser-check/harness.mjs";
import * as hiddenWalletChecks from "./browser-check/hidden-wallet-checks.mjs";
import * as pageValues from "./browser-check/page-values.mjs";
import * as passwordChecks from "./browser-check/password-checks.mjs";
import * as rehearsalChecks from "./browser-check/rehearsal-checks.mjs";
import * as rekeyChecks from "./browser-check/rekey-checks.mjs";
import * as rekeyOwnerChecks from "./browser-check/rekey-owner-checks.mjs";
import * as rekeyRefusalChecks from "./browser-check/rekey-refusal-checks.mjs";
import * as rekeySameLengthChecks from "./browser-check/rekey-same-length-checks.mjs";
import * as repairChecks from "./browser-check/repair-checks.mjs";
import * as selfChecks from "./browser-check/self-checks.mjs";
import * as walletChecks from "./browser-check/wallet-checks.mjs";
import { bundleClasses, inline, pagePolicy, read, root } from "./bundle-browser-classes.mjs";
import { FULL_SIZE_CONTAINER } from "./public-test-data.mjs";

// How long a page may take (AUD-023-BLD005). Its checks take a minute or two, but each of its two
// drawings of a phrase that passes the wallet check takes about 65,536 BIP39 seeds on average, a
// number that is random: more than N times the average happens about once in e^N drawings. A page
// therefore has no fixed time. Each drawing gets DRAW_BUDGET times its mean at the rate the page
// measures on the computer it runs on, with the workers it really has, and fails once it takes
// longer (once in e^16 drawings, nine million, by chance). Between two results or two drawing
// reports a page takes seconds; one that goes STALL_MS without either has stopped, and fails with
// its partial results, the check it was in and its console messages, which a log in
// target/browser-check/ keeps (CI uploads them when the step fails). PAGE_LIMIT_MS ends a page
// that keeps reporting but never ends.
const DRAW_BUDGET = 16;
const STALL_MS = 120_000;
const PAGE_LIMIT_MS = 3_600_000;
/** How often the script asks the page how far it is. */
const POLL_MS = 2_000;
/** The browsers and the modes a run can check. */
const BROWSERS = { chromium, firefox };
const MODES = ["standard", "fast"];
/** The usage, said with a refused command line. */
const USAGE =
  "usage: node scripts/verify-browsers.mjs [--browser chromium|firefox] [--mode standard|fast]";

/** The browsers and modes of the command line, all of each by default; null for a refused one. */
function selection(args) {
  try {
    const { values } = parseArgs({
      args,
      options: { browser: { type: "string" }, mode: { type: "string" } },
    });
    const browsers = values.browser === undefined ? Object.keys(BROWSERS) : [values.browser];
    const modes = values.mode === undefined ? MODES : [values.mode];
    const known = browsers.every((name) => Object.hasOwn(BROWSERS, name));
    return known && modes.every((mode) => MODES.includes(mode)) ? { browsers, modes } : null;
  } catch {
    return null;
  }
}

const selected = selection(process.argv.slice(2));
if (selected === null) {
  console.error(USAGE);
  process.exit(2);
}

// The password whose encryption check the wrapper below spoils.
const FAULTY_CHECK_PASSWORD = "public test password, faulty check";
// The password and the container for which the wrapper below fails as a browser does that cannot
// give the Argon2 memory: in every round of the password, and when a session of hidden wallets on
// the container reserves its work area. The container is the public vector zero-12.
const MEMORY_FAILURE_PASSWORD = "public test password, memory refused";
const MEMORY_FAILURE_CONTAINER = FULL_SIZE_CONTAINER;

// The suite 3 cost the core must ask for, and the reduced cost that replaces it here: the cost of
// REDUCED_COST_CONTAINER in src/mhfe.rs. Any other cost is refused with the cost asked for in the
// message, so that the page sees what a PIM asks for. With FAULTY_CHECK_PASSWORD the wrapper
// changes one bit of the key from the 13th call on, the rounds in which an encryption checks its
// new container: it stands for a fault during the long computation, which that check must catch.
// The memory markers fail with the message of the real Argon2 bridge (web/argon2-engine.js), whose
// prefix the core turns into MEMORY_ALLOCATION_FAILED. The wrapper replaces argon2For, which
// receives the request, so that the reserve sees the container; a block keeps its names apart
// from those of the worker and of the Argon2 build in front of it.
const reducedCostWrapper = `
{
  const fullCostArgon2For = argon2For;
  const encoder = new TextEncoder();
  const faultyCheckPassword = encoder.encode(${inline(FAULTY_CHECK_PASSWORD)});
  const memoryFailurePassword = encoder.encode(${inline(MEMORY_FAILURE_PASSWORD)});
  const sameBytes = (bytes, other) =>
    bytes.length === other.length && bytes.every((byte, index) => byte === other[index]);
  const memoryFailure = () =>
    new Error("MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory");
  // The costs of the builds' known answers (src/engine/known_answers.rs), which reach the build.
  const knownAnswerCosts = ["1024/1", "65536/3", "262144/2"];
  argon2For = async (request) => {
    const engine = await fullCostArgon2For(request);
    let calls = 0;
    return {
      derive(password, salt, memoryKib, passes, key) {
        if (knownAnswerCosts.includes(memoryKib + "/" + passes)) {
          return engine.derive(password, salt, memoryKib, passes, key);
        }
        if (memoryKib !== 2097152 || passes !== 12) {
          throw new Error(
            "TEST_COST: the core asked for " + memoryKib + " KiB and " + passes + " passes",
          );
        }
        if (sameBytes(password, memoryFailurePassword)) throw memoryFailure();
        engine.derive(password, salt, 256, 1, key);
        calls += 1;
        if (sameBytes(password, faultyCheckPassword) && calls > 12) key[0] ^= 1;
      },
      reserve(memoryKib) {
        if (memoryKib !== 2097152) throw new Error("TEST_COST: the core did not reserve 2 GiB");
        if (request.container === ${inline(MEMORY_FAILURE_CONTAINER)}) throw memoryFailure();
        return engine.reserve(256);
      },
    };
  };
}
`;

const { version, buildId } = JSON.parse(read("dist/modules.json").toString());
const sources = `
const DRAW_BUDGET = ${inline(DRAW_BUDGET)};
const VERSION = ${inline(version)};
const PACKAGE_BUILD_ID = ${inline(buildId)};
const WORKER_SOURCE = ${inline(read("dist/runtime/worker.js").toString() + reducedCostWrapper)};
const WASM_BASE64 = ${inline(read("dist/runtime/mhfe.wasm").toString("base64"))};
const ARGON2_THREADED = ${inline(read("dist/core/argon2-mt.js").toString())};
const ARGON2_SINGLE_THREADED = ${inline(read("dist/core/argon2-st.js").toString())};
const FAULTY_CHECK_PASSWORD = ${inline(FAULTY_CHECK_PASSWORD)};
const MEMORY_FAILURE_PASSWORD = ${inline(MEMORY_FAILURE_PASSWORD)};
const MEMORY_FAILURE_CONTAINER = ${inline(MEMORY_FAILURE_CONTAINER)};
`;

// The page's checks (scripts/browser-check/harness.mjs): the constants of page-values.mjs, the
// page's record and the source text of every function of the page's modules, in one block, so
// that their names shadow those of the package's classes instead of clashing with them, and two
// of one name stop the script.
const pageModules = [
  harness,
  selfChecks,
  clientChecks,
  encryptChecks,
  decryptChecks,
  rehearsalChecks,
  rekeyChecks,
  rekeyOwnerChecks,
  rekeySameLengthChecks,
  rekeyRefusalChecks,
  hiddenWalletChecks,
  repairChecks,
  passwordChecks,
  walletChecks,
];
const checks = [
  "{",
  ...Object.entries(pageValues).map(([name, value]) => `const ${name} = ${inline(value)};`),
  "const { results, failures, progress } = pageRecord();",
  ...pageModules.flatMap((module) => Object.values(module).map(String)),
  "runPage();",
  "}",
  "",
].join("\n");
const classes = bundleClasses(root, [
  "core/client.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
]);
const script = classes + sources + checks;

// The policy of the offline wallet tools, which scripts/build-browser-check.mjs shares
// (pagePolicy of scripts/bundle-browser-classes.mjs).
const policy = pagePolicy(script);
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
  for (const name of selected.browsers) {
    const browser = await BROWSERS[name].launch();
    try {
      for (const mode of selected.modes) {
        failed = !(await checkPage(browser, name, mode, addresses[mode])) || failed;
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
console.log(
  `The browser package passes its checks in ${selected.browsers.join(" and ")}, in ` +
    `${selected.modes.join(" and ")} mode.`,
);

/** Opens the page in a new tab and reports its results; true when everything passed. */
async function checkPage(browser, browserName, mode, address) {
  const page = await browser.newPage();
  const strayRequests = [];
  const pageErrors = [];
  const consoleLines = [];
  // The page itself and its Blob workers are the only things it may load.
  page.on("request", (request) => {
    const url = request.url();
    if (url !== address && !url.startsWith("blob:")) strayRequests.push(url);
  });
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
  try {
    await page.goto(address);
    const { mode: clientMode, results, failures } = await pageOutcome(page, pageErrors);
    // A page that stopped has no mode to compare: its stop is the failure.
    if (clientMode !== null && clientMode !== mode) {
      failures.push(`the client ran in ${clientMode} mode, not ${mode}`);
    }
    for (const url of strayRequests) failures.push(`a request left the page: ${url}`);
    for (const error of pageErrors) failures.push(`uncaught page error: ${error}`);
    const lines = [
      `${browserName} ${browser.version()}, ${mode} mode:`,
      ...results.map((line) => `  ${line}`),
      ...failures.map((failure) => `  FAIL ${failure}`),
    ];
    console.log(lines.join("\n"));
    // The console messages go to the log alone, which CI keeps when the step fails.
    const log = [
      ...lines,
      "Console messages of the page:",
      ...consoleLines.map((line) => `  ${line}`),
    ];
    writeFileSync(
      new URL(`target/browser-check/${browserName}-${mode}.log`, root),
      log.join("\n") + "\n",
    );
    return failures.length === 0;
  } finally {
    await page.close();
  }
}

/**
 * Waits for the page's results. A page that stops (an uncaught error, STALL_MS without a result or
 * a drawing report, or PAGE_LIMIT_MS in all) gives its partial results instead, with the check it
 * was in as a failure.
 */
async function pageOutcome(page, pageErrors) {
  const start = Date.now();
  for (;;) {
    const state = await ask(page, () => ({
      finished: window.mhfeCheck !== undefined,
      quietMs: window.mhfeProgress === undefined ? 0 : Date.now() - window.mhfeProgress.updated,
    }));
    if (state?.finished) return page.evaluate(() => window.mhfeCheck);
    let stopped = null;
    if (pageErrors.length > 0) stopped = "an uncaught error stopped the page's script";
    else if (state === null) stopped = `the page did not answer for ${STALL_MS / 1000} s`;
    else if (state.quietMs > STALL_MS) {
      stopped = `no result or drawing report for ${Math.round(state.quietMs / 1000)} s`;
    } else if (Date.now() - start > PAGE_LIMIT_MS) {
      stopped = `the page did not end within ${PAGE_LIMIT_MS / 60_000} minutes`;
    }
    if (stopped !== null) return partialOutcome(page, stopped);
    await sleep(POLL_MS);
  }
}

/** The results a stopped page has given so far, and why and where it stopped as a failure. */
async function partialOutcome(page, stopped) {
  const progress = await ask(page, () => {
    const { results = [], failures = [], running = "starting" } = window.mhfeProgress ?? {};
    return { results: [...results], failures: [...failures], running };
  });
  if (progress === null) return { mode: null, results: [], failures: [stopped] };
  const { results, failures, running } = progress;
  return { mode: null, results, failures: [...failures, `${stopped}, in "${running}"`] };
}

/** What `question` gives in the page, or null when the page does not answer within STALL_MS. */
async function ask(page, question) {
  const answered = new AbortController();
  const silence = sleep(STALL_MS, null, { signal: answered.signal }).catch(() => null);
  try {
    return await Promise.race([page.evaluate(question), silence]);
  } finally {
    answered.abort();
  }
}
