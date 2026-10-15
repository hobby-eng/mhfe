// Exercise the runner's actual wait loop without starting a browser or Argon2 (AUD-024-BLD003).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { parseArgs } from "node:util";

if (process.argv.length !== 2) {
  console.error("Usage: node scripts/verify-browser-wait.mjs");
  process.exit(2);
}
const source = readFileSync(new URL("verify-browsers.mjs", import.meta.url), "utf8");
const selectionStart = source.indexOf("function selection(");
const selectionEnd = source.indexOf("const selected = selection(");
assert.ok(selectionStart >= 0 && selectionEnd > selectionStart, "the runner defines selection");
// oxlint-disable-next-line typescript/no-implied-eval -- the runner's own command-line selector
const select = new Function(
  "parseArgs",
  "BROWSERS",
  "MODES",
  `${source.slice(selectionStart, selectionEnd)}\nreturn selection;`,
)(parseArgs, { chromium: {}, firefox: {} }, ["standard", "fast"]);
assert.deepEqual(select([]), {
  browsers: ["chromium", "firefox"],
  modes: ["standard", "fast"],
  launchers: ["native", "python"],
});
for (const launcher of ["native", "python"]) {
  assert.deepEqual(select(["--browser", "chromium", "--mode", "fast", "--launcher", launcher]), {
    browsers: ["chromium"],
    modes: ["fast"],
    launchers: [launcher],
  });
  assert.equal(select(["--launcher", launcher]), null);
  assert.equal(select(["--mode", "standard", "--launcher", launcher]), null);
}
for (const args of [
  ["--browser", "other"],
  ["--mode", "other"],
  ["--mode", "fast", "--launcher", "other"],
]) {
  assert.equal(select(args), null);
}
const offset = source.indexOf("async function pageOutcome(");
assert.ok(offset >= 0, "the runner defines its wait loop");

/** Run the actual page wait functions with a synthetic page and a clock advanced by polling. */
async function outcome(window, errors = []) {
  let time = 0;
  const clock = { now: () => time };
  const sleep = async (ms, value, { signal } = {}) => {
    if (signal)
      return new Promise((resolve) =>
        signal.addEventListener("abort", () => resolve(value), { once: true }),
      );
    time += ms;
    return value;
  };
  // oxlint-disable-next-line typescript/no-implied-eval -- the repository's own wait functions
  const wait = new Function(
    "sleep",
    "Date",
    "STALL_MS",
    "PAGE_LIMIT_MS",
    "POLL_MS",
    `${source.slice(offset)}\nreturn pageOutcome;`,
  )(sleep, clock, 6, 30, 1);
  const page = {
    evaluate: (question) =>
      vm.runInNewContext(`(${question.toString()})()`, { window, Date: clock }),
  };
  const report = await wait(page, errors);
  return { report, time };
}

const missing = await outcome({});
assert.ok(missing.time <= 7, "a page whose script never starts stops at the stall limit");
assert.match(missing.report.failures[0], /script did not start/u);
const stopped = await outcome({
  mhfeProgress: {
    results: ["passed first"],
    failures: [],
    running: "second",
    updated: 0,
  },
});
assert.ok(stopped.time <= 7);
assert.deepEqual(Array.from(stopped.report.results), ["passed first"]);
assert.match(stopped.report.failures[0], /no result.*second/u);
const finished = { mode: "standard", results: ["done"], failures: [] };
assert.equal((await outcome({ mhfeCheck: finished })).report, finished);
assert.match((await outcome({}, ["script error"])).report.failures[0], /uncaught error/u);
console.log("The browser wait loop stops scripts that never start and retains partial results.");
