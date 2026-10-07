// Stamps the build of the browser package in dist/ into its parts, so that a page and a worker
// tell files of different builds apart before they use them together (PackageCheck and WorkerJob
// in web/runtime.js, requireSameBuild in web/worker-runtime.js, startArgon2 in
// web/core-worker.js):
//
//   node scripts/stamp-build-id.mjs dist
//
// The build is derived from every file a page loads, BUILD_FILES, before any of them is stamped:
// the first 16 hex digits of the SHA-256 of a list with one line per file, in that order, the
// file's own SHA-256, two spaces and its path, as `sha256sum` prints it. So two reproducible
// builds stamp the same, and two builds that differ in any of these files, in a script alone too,
// stamp different ones. The build goes into runtime/mhfe.wasm as the custom section "mhfe-build",
// and in place of "development" into the build constant of every script of BUILD_FILES. A script
// that does not hold exactly one such constant, or a WebAssembly stamped already, stops the build.
// It catches parts of different builds mixed by accident, not deliberate tampering, which
// SHA256SUMS and its signature cover.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The custom section that names the build; web/worker-runtime.js reads it. */
const BUILD_SECTION = "mhfe-build";
/** Hex digits of the SHA-256 kept: 64 bits tell builds apart well beyond any need. */
const BUILD_ID_DIGITS = 16;
/** The WebAssembly, which carries its build in BUILD_SECTION. */
const WASM_FILE = "runtime/mhfe.wasm";
/**
 * Every file a page loads, by path in the package, in the order of the list the build is derived
 * from. Each script holds a build constant; the Argon2 builds get theirs from scripts/build-wasm.sh.
 */
const BUILD_FILES = [
  WASM_FILE,
  "runtime/runtime.js",
  "runtime/worker.js",
  "core/client.js",
  "core/argon2-mt.js",
  "core/argon2-st.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
];
/** A build constant before stamping, such as `const CLIENT_BUILD_ID = "development";`. */
const UNSTAMPED = /^((?:export )?const [A-Z0-9_]*BUILD_ID = )"development";$/gmu;

const [packageDir] = process.argv.slice(2);
if (packageDir === undefined) {
  console.error("Usage: node scripts/stamp-build-id.mjs <package folder>");
  process.exit(1);
}

const files = new Map(BUILD_FILES.map((path) => [path, readFileSync(join(packageDir, path))]));
const wasm = files.get(WASM_FILE);
if (WebAssembly.Module.customSections(new WebAssembly.Module(wasm), BUILD_SECTION).length > 0) {
  throw new Error(`${join(packageDir, WASM_FILE)} is stamped already; build it again.`);
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const list = BUILD_FILES.map((path) => `${sha256(files.get(path))}  ${path}\n`).join("");
const buildId = sha256(list).slice(0, BUILD_ID_DIGITS);

for (const path of BUILD_FILES.filter((each) => each !== WASM_FILE)) {
  const file = join(packageDir, path);
  const text = files.get(path).toString("utf8");
  const count = [...text.matchAll(UNSTAMPED)].length;
  if (count !== 1) throw new Error(`${file} holds ${count} build constants instead of one.`);
  writeFileSync(file, text.replace(UNSTAMPED, `$1"${buildId}";`));
}
writeFileSync(
  join(packageDir, WASM_FILE),
  Buffer.concat([wasm, customSection(BUILD_SECTION, buildId)]),
);
console.log(`Stamped build ${buildId} into the package.`);

/**
 * A WebAssembly custom section (the specification's section 5.5.3): id 0, the size of what
 * follows, the name as a vector of UTF-8 bytes, then the content. A module may end with one.
 */
function customSection(name, content) {
  const nameBytes = Buffer.from(name, "utf8");
  const body = Buffer.concat([leb128(nameBytes.length), nameBytes, Buffer.from(content, "utf8")]);
  const CUSTOM_SECTION_ID = 0;
  return Buffer.concat([Buffer.from([CUSTOM_SECTION_ID]), leb128(body.length), body]);
}

/** An unsigned LEB128 number, as WebAssembly encodes sizes: seven bits a byte, low bits first. */
function leb128(value) {
  const bytes = [];
  let rest = value;
  do {
    const low = rest & 0x7f;
    rest >>>= 7;
    bytes.push(rest === 0 ? low : low | 0x80);
  } while (rest !== 0);
  return Buffer.from(bytes);
}
