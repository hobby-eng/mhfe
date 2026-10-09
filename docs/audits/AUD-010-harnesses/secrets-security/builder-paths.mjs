// AUD-010 secrets-security probe (CHECK-SEC-001, privacy of the shipped files; known input from the
// wallet tools' AUD-023): absolute paths of the computer that built the browser package, embedded
// in its files.
//
// Scans every file of dist/ for absolute paths under a home directory (/home/<user>/, /Users/<user>/,
// /root/, C:\Users\<user>\) and prints each distinct path prefix with its count and the file. Rust
// embeds the source location of every panic that can occur; without --remap-path-prefix those are
// the builder's own paths, here under CARGO_HOME and RUSTUP_HOME.
//
// Exits 1 when any file holds such a path.
//
//   node docs/audits/AUD-010-harnesses/secrets-security/builder-paths.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const HOME_PATH = /(\/home\/[^/\0\s"']+\/|\/Users\/[^/\0\s"']+\/|\/root\/|[A-Z]:\\Users\\[^\\\0\s"']+\\)[\x21-\x7e]*/gu;

function files(directory) {
  const found = [];
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) found.push(...files(path));
    else found.push(path);
  }
  return found;
}

let total = 0;
for (const file of files("dist")) {
  const text = readFileSync(file).toString("latin1");
  const paths = [...text.matchAll(HOME_PATH)].map((match) => match[0]);
  if (paths.length === 0) continue;
  total += paths.length;
  // Group by the first five path segments: the home, the workspace and the tool home.
  const groups = new Map();
  for (const path of paths) {
    const prefix = path.split("/").slice(0, 7).join("/");
    groups.set(prefix, (groups.get(prefix) ?? 0) + 1);
  }
  console.log(`${file}: ${paths.length} absolute builder paths`);
  for (const [prefix, count] of groups) console.log(`  ${count} x ${prefix}/...`);
  for (const path of [...new Set(paths)].slice(0, 5)) console.log(`  e.g. ${path.slice(0, 160)}`);
}
if (total > 0) {
  console.log(`FAILED: ${total} absolute builder paths in dist/.`);
  process.exit(1);
}
console.log("PASSED: no absolute builder path in dist/.");
