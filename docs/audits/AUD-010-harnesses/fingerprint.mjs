// Source fingerprint of the reviewed working tree, by the method of AUD-009: SHA-256 of the JSON
// text of the sorted [path, SHA-256 of the bytes] records of every file `git ls-files -c -o
// --exclude-standard` lists, docs/audits excluded; a tracked file that is missing is recorded as
// "deleted". Prints {"fingerprint", "paths", "head", "records"} as JSON.
//
//   node docs/audits/AUD-010-harnesses/fingerprint.mjs > snapshot.json
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" });
const paths = git("ls-files", "-c", "-o", "--exclude-standard", "-z")
  .split("\0")
  .filter((path) => path !== "" && !path.startsWith("docs/audits/"));
const records = [...new Set(paths)]
  .sort()
  .map((path) => [
    path,
    existsSync(path) ? createHash("sha256").update(readFileSync(path)).digest("hex") : "deleted",
  ]);
const fingerprint = createHash("sha256").update(JSON.stringify(records)).digest("hex");
const head = git("rev-parse", "HEAD").trim();
process.stdout.write(
  `${JSON.stringify({ fingerprint, paths: records.length, head, records }, null, 2)}\n`,
);
