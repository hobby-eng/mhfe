// AUD-010 probe (docs-build-release): checks the repository's own Markdown and the README links of
// the command-line tool. Exits 1 when any check fails; prints one line per problem.
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/doc-checks.mjs
//
// - Every relative link resolves to a file or folder of the working tree, and its #anchor to a
//   heading of the target file (GitHub's rule: lower case, punctuation other than "-" and "_"
//   dropped, spaces to "-", a repeated heading gets "-1", "-2", ...).
// - Every link to https://github.com/hobby-eng/mhfe (the README, blob/<ref>/<path> or
//   tree/<ref>/<path>) resolves the same way against the working tree, whatever the ref.
// - No blank line inside a Markdown list (the workspace rule; same algorithm as
//   multi-chain-wallet-tools/tooling/verify-project-facts.mjs).
// - Every README link in src/bin/mhfe/*.rs (the "More:" lines) names a README heading.
// Audit records (docs/audits/) and vendored upstream text (vendor/phc-winner-argon2/) are records
// of their own and are skipped.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, normalize } from "node:path";

const SKIPPED = ["docs/audits/", "vendor/phc-winner-argon2/"];
const REPOSITORY = "https://github.com/hobby-eng/mhfe";
const tracked = execFileSync("git", ["ls-files", "-c", "-o", "--exclude-standard", "-z"], {
  encoding: "utf8",
})
  .split("\0")
  .filter((path) => path !== "" && existsSync(path));
const markdown = tracked.filter(
  (path) => path.endsWith(".md") && !SKIPPED.some((prefix) => path.startsWith(prefix)),
);
const problems = [];

/** GitHub's anchors for the headings of a Markdown text. */
function anchorsOf(text) {
  const anchors = new Set();
  const seen = new Map();
  let inFence = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/u.test(line)) inFence = !inFence;
    if (inFence) continue;
    const heading = /^#{1,6}\s+(.*?)\s*#*\s*$/u.exec(line);
    if (!heading) continue;
    const base = heading[1]
      .toLowerCase()
      .replace(/<[^>]*>/gu, "")
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s/gu, "-");
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  // Explicit HTML anchors.
  for (const match of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/gu)) anchors.add(match[1]);
  return anchors;
}

const anchorCache = new Map();
function anchorsOfFile(path) {
  if (!anchorCache.has(path)) anchorCache.set(path, anchorsOf(readFileSync(path, "utf8")));
  return anchorCache.get(path);
}

function checkTarget(source, line, target, label) {
  const [pathPart, anchor] = target.split("#");
  const path = pathPart === "" ? source : normalize(join(dirname(source), pathPart));
  if (!existsSync(path)) {
    problems.push(`${source}:${line}: ${label} -> ${path} does not exist`);
    return;
  }
  if (anchor === undefined || anchor === "") return;
  if (statSync(path).isDirectory() || !path.endsWith(".md")) return;
  if (!anchorsOfFile(path).has(decodeURIComponent(anchor))) {
    problems.push(`${source}:${line}: ${label} -> no heading #${anchor} in ${path}`);
  }
}

/** A link to this repository on GitHub, as a path of the working tree, or undefined. */
function repositoryPath(url) {
  if (!url.startsWith(REPOSITORY)) return undefined;
  const rest = url.slice(REPOSITORY.length);
  if (rest === "" || rest.startsWith("#")) return `README.md${rest}`;
  const ref = /^\/(?:blob|tree)\/[^/]+\/(.*)$/u.exec(rest);
  if (ref) return ref[1] === "" ? "." : ref[1];
  return undefined; // releases, actions, attestations: not files
}

for (const source of markdown) {
  const lines = readFileSync(source, "utf8").split("\n");
  let inFence = false;
  for (const [index, text] of lines.entries()) {
    if (/^\s*(```|~~~)/u.test(text)) inFence = !inFence;
    if (inFence) continue;
    const withoutCode = text.replace(/`[^`]*`/gu, "");
    for (const match of withoutCode.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/gu)) {
      const target = match[1];
      if (/^(mailto:|data:)/u.test(target)) continue;
      if (/^https?:/u.test(target)) {
        const local = repositoryPath(target);
        if (local !== undefined) checkTarget(".", index + 1, local, target);
        continue;
      }
      checkTarget(source, index + 1, target, target);
    }
  }
}

// Loose lists.
const LIST_ITEM = /^\s*(?:[-*+]|\d+[.)])\s/u;
const CODE_FENCE = /^\s*(?:```|~~~)/u;
const INDENTED_TEXT = /^\s{2,}\S/u;
function looseListLine(lines) {
  let inFence = false;
  let inList = false;
  let blankInList = false;
  for (const [index, line] of lines.entries()) {
    if (CODE_FENCE.test(line)) {
      const indented = /^\s/u.test(line);
      if (!inFence && blankInList && indented) return index;
      if (!inFence && !indented) inList = false;
      inFence = !inFence;
      blankInList = false;
      continue;
    }
    if (inFence) continue;
    if (line.trim() === "") {
      if (inList) blankInList = true;
      continue;
    }
    if (LIST_ITEM.test(line) || (blankInList && INDENTED_TEXT.test(line))) {
      if (blankInList) return index;
      inList = true;
      continue;
    }
    if (blankInList || line.startsWith("#")) inList = false;
    blankInList = false;
  }
  return undefined;
}
for (const source of markdown) {
  const line = looseListLine(readFileSync(source, "utf8").split("\n"));
  if (line !== undefined) problems.push(`${source}:${line}: blank line inside a list`);
}

// README links of the command-line tool.
const readmeAnchors = anchorsOfFile("README.md");
for (const file of readdirSync("src/bin/mhfe").filter((name) => name.endsWith(".rs"))) {
  const path = join("src/bin/mhfe", file);
  const lines = readFileSync(path, "utf8").split("\n");
  for (const [index, text] of lines.entries()) {
    // Full links, and the section!("anchor") form of src/bin/mhfe/readme.rs.
    const links = /(?:github\.com\/hobby-eng\/mhfe#|section!\(")([A-Za-z0-9_-]+)/gu;
    for (const match of text.matchAll(links)) {
      if (!readmeAnchors.has(match[1])) {
        problems.push(`${path}:${index + 1}: README has no heading #${match[1]}`);
      }
    }
  }
}

console.log(`Checked ${markdown.length} Markdown files and src/bin/mhfe/*.rs.`);
for (const problem of problems) console.log(`FAIL ${problem}`);
if (problems.length > 0) process.exit(1);
console.log("PASS: links, anchors and lists.");
