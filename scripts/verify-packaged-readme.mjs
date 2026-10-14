// Checks the rendered README links inside each staged release folder, without network access.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { runGate, reported } from "./gate-command-line.mjs";

/** Rendered content only: code examples do not create links in the document. */
function rendered(text) {
  return text.replace(/```[^\n]*\n[\s\S]*?```/gu, "");
}

/** Relative Markdown destinations and image/link attributes in the rendered document. */
function destinations(text) {
  const content = rendered(text);
  return [
    ...content.matchAll(/\]\((?:<([^>]+)>|([^\s)]+))(?:\s+"[^"]*")?\)/gu),
    ...content.matchAll(/\b(?:src|href)=["']([^"']+)["']/gu),
  ].map((match) => match[1] ?? match[2]);
}

/** GitHub's heading fragments for these English Markdown documents, including repeated names. */
function headings(text) {
  const counts = new Map();
  return new Set(
    [...rendered(text).matchAll(/^#{1,6}\s+(.+)$/gmu)].map((match) => {
      const base = match[1]
        .replace(/<[^>]*>/gu, "")
        .toLowerCase()
        .replace(/[^\p{L}\p{N}_\- ]/gu, "")
        .trim()
        .replace(/\s/gu, "-");
      const used = counts.get(base) ?? 0;
      counts.set(base, used + 1);
      return used === 0 ? base : `${base}-${used}`;
    }),
  );
}

/** Missing destinations, archive escapes and missing local heading fragments. */
function findings(folder, name, text, present, read) {
  const found = [];
  for (const destination of destinations(text)) {
    if (/^(?:https?:|mailto:|\/\/)/iu.test(destination)) continue;
    const [path, fragment] = destination.split("#");
    const target = resolve(folder, dirname(name), decodeURIComponent(path.split("?")[0] || name));
    const inside = relative(folder, target);
    if (isAbsolute(inside) || inside === ".." || inside.startsWith(`..${sep}`)) {
      found.push(`${name}: link leaves its archive: ${destination}`);
    } else if (!present(target)) {
      found.push(`${name}: missing packaged link: ${destination}`);
    } else if (fragment && !headings(read(target)).has(decodeURIComponent(fragment))) {
      found.push(`${name}: missing packaged heading: ${destination}`);
    }
  }
  return found;
}

/** A shipped image, absent image/file, valid/missing fragment, escape and fenced example. */
function selfTest() {
  const folder = resolve("virtual-package");
  const files = new Map([
    [resolve(folder, "README.md"), "# Ready"],
    [resolve(folder, "assets/image.png"), ""],
  ]);
  const check = (text) =>
    findings(
      folder,
      "README.md",
      text,
      (path) => files.has(path),
      (path) => files.get(path),
    );
  assert.deepEqual(check('<img src="assets/image.png"> [ready](#ready)'), []);
  assert.equal(check('<img src="missing.png">').length, 1);
  assert.equal(check("[missing](missing.md)").length, 1);
  assert.equal(check("[missing](#missing)").length, 1);
  assert.equal(check("[escape](../README.md)").length, 1);
  assert.deepEqual(check('```html\n<img src="example.html">\n```'), []);
  console.log("The packaged README link controls pass.");
}

runGate("Usage: node scripts/verify-packaged-readme.mjs <folder> | --self-test", {
  selfTest,
  operand: (folder) => {
    const root = resolve(folder);
    const names = ["README.md", "README-mhfe.md"].filter((name) => existsSync(resolve(root, name)));
    if (names.length === 0) throw new Error("The staged release has no README.");
    const found = names.flatMap((name) =>
      findings(root, name, readFileSync(resolve(root, name), "utf8"), existsSync, (path) =>
        readFileSync(path, "utf8"),
      ),
    );
    return reported(
      found,
      (count) => `${count} packaged README links fail.`,
      "The packaged README relative links resolve.",
    );
  },
});
