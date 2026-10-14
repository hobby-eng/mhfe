// Validate the exact object-name syntax git blame reads, then prove the list works with Git.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { reported, runGate } from "./gate-command-line.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const file = ".git-blame-ignore-revs";
const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" });

/** A full object ID on each nonempty line, with Git's comments and whitespace removed. */
function revisions(text, digits) {
  const pattern = new RegExp(`^[0-9a-f]{${digits}}$`, "u");
  return text
    .split("\n")
    .map((line) => line.replace(/#[^\n]*/u, "").trim())
    .filter(Boolean)
    .map((hash) => {
      if (!pattern.test(hash))
        throw new Error(`${file} needs a full ${digits}-digit object ID: ${hash}`);
      return hash;
    });
}

/** Syntax needs no history; the complete check asks Git to read the real file too. */
function check(syntaxOnly) {
  const found = [];
  try {
    const digits = git("rev-parse", "--show-object-format").trim() === "sha256" ? 64 : 40;
    const hashes = revisions(readFileSync(new URL(`../${file}`, import.meta.url), "utf8"), digits);
    if (!syntaxOnly) {
      if (git("rev-parse", "--is-shallow-repository").trim() === "true") {
        throw new Error(
          "A shallow clone cannot check ignored commits: git fetch --unshallow first.",
        );
      }
      for (const hash of hashes) git("cat-file", "-e", `${hash}^{commit}`);
      git("blame", "--ignore-revs-file", file, "--", "README.md");
    }
  } catch (error) {
    found.push(error.message);
  }
  return reported(
    found,
    () => "The ignored-revisions check failed.",
    syntaxOnly
      ? "The ignored-revisions list has valid syntax."
      : "Git blame accepts every ignored revision.",
  );
}

/** Controls cover refused forms, comments, CRLF and both Git object formats. */
function selfTest() {
  for (const digits of [40, 64]) {
    const hash = "a".repeat(digits);
    for (const text of [hash, `${hash} # comment\r\n`, `  # comment\r\n  ${hash}\r\n`]) {
      assert.deepEqual(revisions(text, digits), [hash]);
    }
    for (const text of [hash.slice(0, 12), "HEAD~3", "v0.6.0", "z".repeat(digits)]) {
      assert.throws(() => revisions(text, digits), /needs a full/u);
    }
  }
  assert.throws(() => readFileSync(new URL("../no-such-blame-revisions", import.meta.url)), {
    code: "ENOENT",
  });
  console.log("The ignored-revisions controls pass.");
}

runGate("Usage: node scripts/verify-blame-revs.mjs [--self-test | --syntax-only]", {
  selfTest,
  check: () => check(false),
  modes: { "--syntax-only": () => check(true) },
});
