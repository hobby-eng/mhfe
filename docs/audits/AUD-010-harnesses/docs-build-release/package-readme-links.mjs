// AUD-010 probe (docs-build-release): the README.md that the browser package carries (dist/README.md,
// docs/BROWSER-PACKAGE.md with the SHA-256 of the build) is read where it ships, beside the package's
// files, not in docs/. Every relative link in it must resolve there, in dist/ or among the files
// that scripts/package-release.sh adds to the browser archive. Exits 1 on a link that does not.
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/package-readme-links.mjs [dist]
//
// The regression class of AUD-008-DOC003 (a packaged README link to an absent measurements file).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dist = process.argv[2] ?? "dist";
// Added to the browser archive by scripts/package-release.sh (add_common_files).
const ARCHIVE_EXTRAS = new Set([
  "README-mhfe.md",
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
  "BUILD-INFO.txt",
  "licenses",
  "licenses/argon2-LICENSE",
  "licenses/eff-large-wordlist.md",
]);
const lines = readFileSync(join(dist, "README.md"), "utf8").split("\n");
const problems = [];
let checked = 0;
let inFence = false;
for (const [index, line] of lines.entries()) {
  if (/^\s*(```|~~~)/u.test(line)) inFence = !inFence;
  if (inFence) continue;
  for (const match of line.replace(/`[^`]*`/gu, "").matchAll(/\]\(([^)\s]+)\)/gu)) {
    const target = match[1];
    if (/^[a-z]+:/u.test(target) || target.startsWith("#")) continue;
    checked += 1;
    const path = target.split("#")[0];
    if (!existsSync(join(dist, path)) && !ARCHIVE_EXTRAS.has(path)) {
      problems.push(`${dist}/README.md:${index + 1}: ${target} is not in the package`);
    }
  }
}
console.log(`Checked ${checked} relative links of ${dist}/README.md.`);
for (const problem of problems) console.log(`FAIL ${problem}`);
if (problems.length > 0) process.exit(1);
console.log("PASS: every relative link resolves inside the package.");
