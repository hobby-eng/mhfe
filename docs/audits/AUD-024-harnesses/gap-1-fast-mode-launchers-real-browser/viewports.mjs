// AUD-024, role gap-1-fast-mode-launchers-real-browser, reviewed commit b6fca69.
//
// CHECK-UI-001 for the fast-mode route: the browser-check page, served by `mhfe serve`, opened in
// Chromium and Firefox at the widths of the audit guide (1280, 1024, 800, 640, 390) with a normal
// and a short height. Each page must reach PASS in fast mode; the script saves a screenshot of
// each and reports whether the page scrolls sideways (the page is a log in a <pre>, which the
// browser package does not lay out: a host page owns its layout).
//
//   node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/viewports.mjs \
//     <mhfe binary> <folder with the page and its mhfe-fast-mode.sha256> <folder for screenshots>
//
// Exits 1 when a page does not pass in fast mode.
import { spawn } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { chromium, firefox } from "playwright";

const [mhfe, folder, shots] = process.argv.slice(2);
if (shots === undefined) {
  console.error("usage: viewports.mjs <mhfe> <page folder> <screenshot folder>");
  process.exit(2);
}
mkdirSync(shots, { recursive: true });
const SIZES = [
  [1280, 800],
  [1280, 500],
  [1024, 768],
  [800, 600],
  [640, 480],
  [390, 844],
  [390, 500],
];
const page = join(folder, readdirSync(folder).find((name) => name.endsWith(".html")));
const child = spawn(mhfe, ["serve", "--no-browser", page], {
  env: { ...process.env, NO_COLOR: "1" },
  stdio: ["ignore", "ignore", "pipe"],
});
let output = "";
const address = await new Promise((done, fail) => {
  child.stderr.on("data", (chunk) => {
    output += chunk;
    const found = /Open (http:\/\/127\.0\.0\.1:\d+\/) in your browser\./u.exec(output);
    if (found) done(found[1]);
  });
  setTimeout(() => fail(new Error(output)), 20_000);
});
let failed = 0;
try {
  for (const [name, engine] of Object.entries({ chromium, firefox })) {
    const browser = await engine.launch({ headless: true });
    try {
      for (const [width, height] of SIZES) {
        const tab = await browser.newPage({ viewport: { width, height } });
        await tab.goto(`${address}#check`);
        await tab.waitForFunction(() => ["PASS", "FAIL"].includes(document.title), null, {
          timeout: 600_000,
        });
        const state = await tab.evaluate(() => ({
          title: document.title,
          fast: document.getElementById("log").textContent.startsWith("mode: fast"),
          isolated: self.crossOriginIsolated,
          scrollWidth: document.documentElement.scrollWidth,
          innerWidth: window.innerWidth,
        }));
        const file = join(shots, `${name}-${width}x${height}.png`);
        await tab.screenshot({ path: file });
        const ok = state.title === "PASS" && state.fast && state.isolated;
        if (!ok) failed += 1;
        console.log(
          `${ok ? "ok  " : "FAIL"}  ${name} ${browser.version()} ${width}x${height}: ` +
            `${state.title}, fast mode ${state.fast}, isolated ${state.isolated}, ` +
            `scrolls sideways ${state.scrollWidth > state.innerWidth} ` +
            `(${state.scrollWidth} > ${state.innerWidth}), screenshot ${file}`,
        );
        await tab.close();
      }
    } finally {
      await browser.close();
    }
  }
} finally {
  child.kill("SIGTERM");
}
console.log(failed === 0 ? "RESULT: PASS" : `RESULT: FAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);
