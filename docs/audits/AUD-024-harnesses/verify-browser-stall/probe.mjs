// AUD-024 verifier probe (commit b6fca69): runs the wait loop of scripts/verify-browsers.mjs
// (pageOutcome, partialOutcome and ask, taken verbatim from the file at run time) with scaled
// constants (STALL_MS 6 s, PAGE_LIMIT_MS 30 s, POLL_MS 1 s) against small pages in Chromium and
// Firefox, and reports after how long and why each page is called stopped. Run from the mhfe
// repository root; it writes only into a new folder under the system's temporary directory. Exits 1 when a page whose script never starts is not reported within
// 2 * STALL_MS (the documented stall rule), 0 otherwise. Cases: a module refused by the page
// policy, a parse error, an import the policy refuses, and a control page that reports then stops.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const require = createRequire(`${process.cwd()}/package.json`);
const { chromium, firefox } = require("playwright");
// The generated loop module and pages go to a fresh temporary folder, never into the repository.
const here = pathToFileURL(mkdtempSync(join(tmpdir(), "aud024-stall-")) + "/");

const source = readFileSync("scripts/verify-browsers.mjs", "utf8");
const begin = source.indexOf("async function pageOutcome(");
const end = source.indexOf("\n}\n", source.indexOf("async function ask(")) + 3;
const loopText = source.slice(begin, end);
const loopFile = new URL("loop.mjs", here);
writeFileSync(
  loopFile,
  'import { setTimeout as sleep } from "node:timers/promises";\n' +
    "const STALL_MS = 6_000;\nconst PAGE_LIMIT_MS = 30_000;\nconst POLL_MS = 1_000;\n" +
    loopText +
    "\nexport { pageOutcome };\n",
);
const { pageOutcome } = await import(loopFile.href);
console.log(`loop text: ${loopText.split("\n").length} lines, sha256 ` +
  createHash("sha256").update(loopText).digest("hex").slice(0, 16));

const hash = (text) => createHash("sha256").update(text, "utf8").digest("base64");
const page = (policyHash, script) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-${policyHash}' 'wasm-unsafe-eval'; worker-src blob:" />
<title>stall probe</title></head>
<body><script type="module">${script}</script></body></html>
`;
// The page record as harness.mjs's pageRecord sets it, then nothing more.
const recordOnly = "window.mhfeProgress = { results: ['ok one'], failures: [], running: 'checkA', updated: Date.now() };";
const cases = {
  // The script's hash is not the policy's: the browser refuses the inline module.
  "csp-refused": page(hash(recordOnly + " "), recordOnly),
  // Two declarations of one name in one block (the case the runner's comment names).
  "parse-error": page(hash("{ const a = 1; const a = 2; }"), "{ const a = 1; const a = 2; }"),
  // A module import left in the script (an unbundled class): the policy refuses its fetch.
  "unbundled-import": page(hash('import "./client.js";\n' + recordOnly), 'import "./client.js";\n' + recordOnly),
  // Control: the script runs, sets its record and then stops reporting.
  "record-then-silent": page(hash(recordOnly), recordOnly),
};
let bad = false;
for (const [name, launcher] of Object.entries({ chromium, firefox })) {
  const browser = await launcher.launch();
  try {
    for (const [label, html] of Object.entries(cases)) {
      const file = new URL(`${label}.html`, here);
      writeFileSync(file, html);
      const tab = await browser.newPage();
      const pageErrors = [];
      const consoleLines = [];
      tab.on("pageerror", (error) => pageErrors.push(String(error)));
      tab.on("console", (m) => consoleLines.push(`${m.type()}: ${m.text().split(homedir()).join("/home/user").slice(0, 90)}`));
      await tab.goto(file.href);
      const started = Date.now();
      const outcome = await pageOutcome(tab, pageErrors);
      const seconds = Math.round((Date.now() - started) / 1000);
      console.log(`${name} ${browser.version()} ${label}: stopped after ${seconds} s: ` +
        `${JSON.stringify(outcome.failures)}; page errors ${pageErrors.length}; console ${JSON.stringify(consoleLines)}`);
      if (label !== "record-then-silent" && seconds > 12) bad = true;
      await tab.close();
    }
  } finally {
    await browser.close();
  }
}
if (bad) {
  console.log("FAIL: a page whose script never started was not reported within 2 * STALL_MS");
  process.exit(1);
}
console.log("ok");
