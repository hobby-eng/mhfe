// AUD-024, role gap-1-fast-mode-launchers-real-browser, reviewed commit b6fca69.
//
// Cookies are kept per host, not per port: a cookie that any other local service sets for
// 127.0.0.1 is sent with the browser's request to the fast-mode launcher too. This script gives the
// browser such cookies (as another service on 127.0.0.1 would) and asks each launcher for the page:
// (a) one cookie with a UTF-8 value, (b) cookies of 20,000 bytes in all, beyond the launchers'
// 16 KiB limit of a request head. It reports the status each launcher gives in Chromium and Firefox.
//
//   node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/cookies.mjs \
//     <mhfe binary> <folder with a page and its mhfe-fast-mode.sha256>
//
// The Python launcher says it does what `mhfe serve` does: the script exits 1 when, for the same
// browser and cookies, the two launchers answer with different statuses.
import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

import { chromium, firefox } from "playwright";

const [mhfe, folder] = process.argv.slice(2);
const page = join(folder, readdirSync(folder).find((name) => name.endsWith(".html")));
const repo = process.cwd();

async function launcher(kind) {
  const command =
    kind === "rust"
      ? [mhfe, ["serve", "--no-browser", page]]
      : ["python3", [join(repo, "packaging", "mhfe-fast-mode.py"), "--no-browser", page]];
  const child = spawn(command[0], command[1], {
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
  return { address, stop: () => child.kill("SIGTERM") };
}

const CASES = {
  "one cookie with a UTF-8 value": [{ name: "service", value: "café" }],
  "cookies of 20,000 bytes": Array.from({ length: 5 }, (_, index) => ({
    name: `service${index}`,
    value: "x".repeat(3990),
  })),
};

const statuses = new Map();
for (const [name, engine] of Object.entries({ chromium, firefox })) {
  const browser = await engine.launch({ headless: true });
  try {
    for (const kind of ["rust", "python"]) {
      const served = await launcher(kind);
      try {
        for (const [label, cookies] of Object.entries(CASES)) {
          const context = await browser.newContext();
          await context.addCookies(
            cookies.map((cookie) => ({ ...cookie, domain: "127.0.0.1", path: "/" })),
          );
          const tab = await context.newPage();
          const response = await tab.goto(`${served.address}#check`, { waitUntil: "commit" });
          const sent = (await response.request().allHeaders()).cookie ?? "";
          const key = `${name} ${browser.version()}: ${label}`;
          statuses.set(key, [...(statuses.get(key) ?? []), `${kind} ${response.status()}`]);
          console.log(
            `${name} ${browser.version()} / ${kind}: ${label}: status ${response.status()}, ` +
              `Cookie header of ${Buffer.byteLength(sent)} bytes sent`,
          );
          await context.close();
        }
      } finally {
        served.stop();
      }
    }
  } finally {
    await browser.close();
  }
}
let differ = 0;
for (const [key, answers] of statuses) {
  const same = new Set(answers.map((answer) => answer.split(" ")[1])).size === 1;
  if (!same) differ += 1;
  console.log(`${same ? "ok  " : "FAIL"}  ${key}: the launchers answer alike (${answers.join(", ")})`);
}
console.log(differ === 0 ? "RESULT: PASS" : `RESULT: FAIL (${differ})`);
process.exit(differ === 0 ? 0 : 1);
