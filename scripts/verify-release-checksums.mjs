// A release checksum list names exactly the archives in its folder, each once and readable.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { runGate } from "./gate-command-line.mjs";

/** Strict sha256sum lines, using only archive basenames, with no omissions or duplicates. */
function checkList(text, archives) {
  const names = text
    .trimEnd()
    .split("\n")
    .map((line) => {
      const parsed = /^[a-f0-9]{64}  ([^/\\\r\n]+)$/u.exec(line);
      if (parsed === null)
        throw new Error("SHA256SUMS has a malformed line or a path outside its folder.");
      return parsed[1];
    });
  if (
    archives.length === 0 ||
    new Set(names).size !== names.length ||
    JSON.stringify(names.toSorted()) !== JSON.stringify(archives.toSorted())
  ) {
    throw new Error("SHA256SUMS must name every release archive exactly once.");
  }
}

/** Complete and malformed lists, missing/stale archives and duplicate names. */
function selfTest() {
  const line = `${"0".repeat(64)}  one.tar.gz`;
  checkList(`${line}\n`, ["one.tar.gz"]);
  for (const [text, archives] of [
    [line, []],
    [line, ["one.tar.gz", "two.zip"]],
    [line, ["two.zip"]],
    [`${line}\n${line}`, ["one.tar.gz"]],
    ["not a sum", ["one.tar.gz"]],
    [`${"0".repeat(64)}  ../one.tar.gz`, ["one.tar.gz"]],
  ])
    assert.throws(() => checkList(text, archives));
  console.log("The release checksum-list controls pass.");
}

runGate("Usage: node scripts/verify-release-checksums.mjs <folder> | --self-test", {
  selfTest,
  operand: (folder) => {
    const archives = readdirSync(folder).filter((name) => /\.(?:tar\.gz|zip)$/u.test(name));
    checkList(readFileSync(`${folder}/SHA256SUMS`, "utf8"), archives);
    execFileSync("sha256sum", ["--check", "--strict", "SHA256SUMS"], {
      cwd: folder,
      stdio: "inherit",
    });
    return true;
  },
});
