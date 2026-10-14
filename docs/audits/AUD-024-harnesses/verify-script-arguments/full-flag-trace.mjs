// AUD-024 probe (review only, commit b6fca69): how scripts/verify-browser-package.mjs reads its
// command line, without running it (it writes target/build-id-check/). It lists every place the
// script reads process.argv, evaluates that exact expression for misspellings of --full, and
// checks that nothing in the script refuses an argument. Exits 1 when a misspelling is silently
// read as "no full-size run" (the defect), 0 otherwise.
import { readFileSync } from "node:fs";

const path = "scripts/verify-browser-package.mjs";
const lines = readFileSync(path, "utf8").split("\n");
const argvLines = lines
  .map((text, index) => ({ line: index + 1, text: text.trim() }))
  .filter(({ text }) => /process\.argv|parseArgs/u.test(text));
for (const { line, text } of argvLines) console.log(`${path}:${line}: ${text}`);
const refusal = lines.some((text) => /process\.exit\(2\)|usage/iu.test(text));
console.log(`a usage or exit-2 refusal in the script: ${refusal}`);
const exitLine = lines.findIndex((text) => text.includes("process.exit(0)")) + 1;
console.log(`unconditional end: ${path}:${exitLine}: ${lines[exitLine - 1].trim()}`);

let silent = 0;
for (const argument of ["--full", "--Full", "-full", "--full-size", "--fulll", "full", "--full=1"]) {
  const argv = ["node", path, argument];
  // The expression of line 54, verbatim.
  const fullRun = argv.includes("--full");
  console.log(`${argument.padEnd(12)} full-size run: ${fullRun}`);
  if (!fullRun && argument !== "--full") silent += 1;
}
console.log(`${silent} misspellings run only the fast parts, with no refusal`);
process.exit(silent > 0 && !refusal ? 1 : 0);
