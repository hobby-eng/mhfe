// AUD-010 probe (docs-build-release): lists the absolute file paths that a WebAssembly or native
// binary carries, grouped by where they come from, and exits 1 when any of them names a builder's
// own folders (a home directory, CARGO_HOME or RUSTUP_HOME) rather than a path that rustc already
// remaps (/rustc/<commit>/ for the standard library, /rust/deps/ for its dependencies).
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/wasm-builder-paths.mjs [file ...]
//
// Without arguments it reads dist/runtime/mhfe.wasm. A .tar.gz argument is read with `tar -xzOf`
// for the member given after a colon, e.g. archive.tar.gz:./mhfe_core_bg.wasm.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

/** Prefixes that rustc writes for the standard library itself: not the builder's folders. */
const REMAPPED_BY_RUSTC = ["/rustc/", "/rust/deps/"];
/** The shortest run of printable bytes counted as a path, as `strings -n 6` would. */
const MIN_PATH_LENGTH = 6;

function readTarget(spec) {
  const colon = spec.indexOf(".tar.gz:");
  if (colon === -1) return readFileSync(spec);
  const archive = spec.slice(0, colon + ".tar.gz".length);
  const member = spec.slice(colon + ".tar.gz:".length);
  return execFileSync("tar", ["-xzOf", archive, member], { maxBuffer: 64 * 1024 * 1024 });
}

/** Absolute paths among the printable runs of `bytes`, each ending at a .rs or .c file name. */
function absolutePaths(bytes) {
  const text = bytes.toString("latin1");
  // The file name ends where no further name character follows, so ".crates.io" inside a registry
  // folder name is not taken for a C file.
  const pattern = new RegExp(
    `/[\\x21-\\x7e]{${MIN_PATH_LENGTH - 1},}?\\.(?:rs|c|h)(?![A-Za-z0-9_])`,
    "gu",
  );
  const found = [];
  for (const match of text.matchAll(pattern)) {
    // A path starts at a slash that follows a non-path byte, so "src/x.rs" inside a longer run
    // is not counted as absolute.
    const before = match.index === 0 ? "" : text[match.index - 1];
    if (/[\x21-\x7e]/u.test(before)) continue;
    found.push(match[0]);
  }
  return found;
}

function origin(path) {
  if (REMAPPED_BY_RUSTC.some((prefix) => path.startsWith(prefix))) return "remapped by rustc";
  const registry = /^(.*?)\/registry\/src\/[^/]+\//u.exec(path);
  if (registry) return `cargo registry under ${registry[1]}`;
  const toolchain = /^(.*?)\/toolchains\/[^/]+\//u.exec(path);
  if (toolchain) return `rustup toolchain under ${toolchain[1]}`;
  return "other absolute path";
}

const targets = process.argv.slice(2);
if (targets.length === 0) targets.push("dist/runtime/mhfe.wasm");
let builderPaths = 0;
for (const target of targets) {
  const paths = absolutePaths(readTarget(target));
  const groups = new Map();
  for (const path of paths) {
    const key = origin(path);
    groups.set(key, [...(groups.get(key) ?? []), path]);
  }
  console.log(`${target}: ${paths.length} absolute paths`);
  for (const [key, list] of groups) {
    console.log(`  ${list.length}  ${key}`);
    if (key !== "remapped by rustc") {
      builderPaths += list.length;
      for (const path of [...new Set(list)].sort()) console.log(`       ${path}`);
    }
  }
}
if (builderPaths > 0) {
  console.log(`FAIL: ${builderPaths} paths name the builder's own folders.`);
  process.exit(1);
}
console.log("PASS: no builder path.");
