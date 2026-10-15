// Part 3 of the checks of the browser package (scripts/verify-browser-package.mjs): the package's
// manifest, versions and scripts, that its WebAssembly names no folder of the machine that built
// it, its build against another one, and the error codes that one source gives every part.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { browserSource } from "../browser-source.mjs";
import { checkNetworkCodeList, networkCodeIn } from "../network-code.mjs";
import { PHRASE } from "../public-test-data.mjs";
import { isVectorText, rustStrings } from "../rust-strings.mjs";
import { sorted } from "./expect.mjs";
import {
  compiledPackage,
  inProcessWorker,
  repairRequest,
  unstamped,
  workerMismatch,
  workerScript,
} from "./in-process-worker.mjs";
import { BUILD_ID, VERSION, bindings, packageWasm, read, root } from "./package.mjs";
import { reports } from "./self-checks.mjs";
import { PHRASE_ADDRESS } from "./test-values.mjs";

/** The wallet module's bindings: the bindings of the package's one WebAssembly. */
const wallet = bindings;

/** The codes the page's runtime and classes give themselves, never the Rust core. */
const BROWSER_ERROR_CODES = [
  "BUSY",
  "CALLBACK_FAILED",
  "INVALID_PASSWORD_TEXT",
  "PACKAGE_MISMATCH",
  "SESSION_CLOSED",
  "WORKER_FAILED",
];
/** The codes `pattern` finds in `path` between `start` and the first `end` after it, sorted. */
function errorCodes(path, start, end, pattern) {
  const text = path === "web/runtime.js" ? browserSource("runtime") : read(path).toString();
  const from = text.indexOf(start);
  assert.ok(from !== -1, `${path} holds ${start}`);
  const part = text.slice(from, text.indexOf(end, from));
  return sorted(new Set([...part.matchAll(pattern)].map((match) => match[1])));
}

/**
 * The error codes have one source, ErrorCode in src/error_code.rs: the table of docs/API.md
 * lists exactly those, and the page's MhfeErrorCode type those and the browser's own, named here
 * (AUD-023-ARC011). A code added or removed in one place and not the others fails this.
 */
export function checkErrorCodes() {
  const libraryCodes = errorCodes(
    "src/error_code.rs",
    "error_codes! {",
    "\n}\n",
    /=> "([A-Z0-9_]+)"/gu,
  );
  assert.ok(libraryCodes.length >= 50, "ErrorCode gives every library code");
  assert.deepEqual(
    errorCodes("docs/API.md", "| Code ", "\n\n", /^\| `([A-Z0-9_]+)`/gmu),
    libraryCodes,
    "docs/API.md lists exactly the codes of MhfeError::code()",
  );
  assert.deepEqual(
    errorCodes(
      "web/runtime.d.ts",
      "export type MhfeErrorCode",
      ";\n\n",
      /^ {2}\| "([A-Z0-9_]+)"/gmu,
    ),
    sorted([...libraryCodes, ...BROWSER_ERROR_CODES]),
    "MhfeErrorCode is the codes of MhfeError::code() and the browser's own",
  );
  assert.deepEqual(
    errorCodes("web/runtime.js", "const KNOWN_ERROR_CODES", "];", /"([A-Z0-9_]+)"/gu),
    sorted([...libraryCodes, ...BROWSER_ERROR_CODES]),
    "The deliberate runtime error-code copy covers every declared code and nothing else",
  );
  // No binding types a code again: each comes from the error it names. Every file of the
  // bindings is read, so that one added later is checked too.
  const bindings = readdirSync(new URL("src/wasm_api/", root), { recursive: true })
    .filter((name) => name.endsWith(".rs"))
    .map((name) => `src/wasm_api/${name}`);
  for (const path of ["src/wasm_api.rs", ...sorted(bindings)]) {
    assert.doesNotMatch(
      read(path).toString(),
      /whole_number\([^)]*"[A-Z_]+"/u,
      `${path} passes a code to whole_number as text`,
    );
  }
}

/** The package's manifest, dist/modules.json. */
const manifest = JSON.parse(read("dist/modules.json").toString());

/**
 * The manifest matches the files, one build derived from every file a page loads is stamped into
 * each, another build is refused, and the JavaScript passes the lexical network tripwire, names no
 * coin or carries a wallet vector; gives the other build, which part 4b gives a class file of.
 */
export async function checkPackageManifest() {
  checkManifestFiles();
  checkNoBuilderPaths();
  checkPackageScripts();
  const unstampedFiles = checkBuildStamps();
  return await checkOtherBuild(unstampedFiles);
}

/** The manifest's version, and the digest of every file it lists. */
function checkManifestFiles() {
  assert.equal(manifest.version, VERSION);
  const hash = (path) => createHash("sha256").update(read(path)).digest("hex");
  for (const [name, file] of Object.entries(manifest.runtime.files)) {
    assert.equal(hash(`dist/runtime/${name}`), file, `runtime/${name}`);
  }
  for (const [module, { files, requires }] of Object.entries(manifest.modules)) {
    assert.deepEqual(requires, ["runtime"], `${module} needs no other module`);
    for (const [name, file] of Object.entries(files)) {
      assert.equal(hash(`dist/${module}/${name}`), file, `${module}/${name}`);
    }
  }
}

/**
 * The WebAssembly names no folder of the machine that built it (AUD-010): scripts/build-wasm.sh
 * remaps the checkout, CARGO_HOME and RUSTUP_HOME to the relative names mhfe, cargo and rustup
 * with packaging/remap-builder-paths.sh, as every native build does, so that the panic locations
 * of the dependencies carry no account name or folder layout. Neither this machine's folders nor
 * any absolute source path but those rustc writes for its own sources may appear, whatever
 * machine built it.
 */
function checkNoBuilderPaths() {
  const wasmText = packageWasm.toString("latin1");
  for (const path of [
    "/home/",
    fileURLToPath(root).replace(/\/$/u, ""),
    process.env.CARGO_HOME ?? join(homedir(), ".cargo"),
    process.env.RUSTUP_HOME ?? join(homedir(), ".rustup"),
  ]) {
    const at = wasmText.indexOf(path);
    assert.equal(
      at,
      -1,
      `runtime/mhfe.wasm names ${path} of the machine that built it, in ` +
        JSON.stringify(wasmText.slice(Math.max(at, 0), at + 160)),
    );
  }
  /** Where rustc puts the standard library's sources and its dependencies' itself. */
  const REMAPPED_BY_RUSTC = ["/rustc/", "/rust/deps/"];
  // A source path is a run of printable bytes ending in a Rust or C file name; it is absolute when
  // it starts with a slash that no other printable byte precedes.
  const sourcePaths = [
    ...wasmText.matchAll(/(?<![\x21-\x7e])\/[\x21-\x7e]{5,}?\.(?:rs|c|h)(?![A-Za-z0-9_])/gu),
  ].map(([path]) => path);
  assert.ok(sourcePaths.length > 0, "the WebAssembly's panic locations are found");
  assert.deepEqual(
    sourcePaths.filter((path) => !REMAPPED_BY_RUSTC.some((prefix) => path.startsWith(prefix))),
    [],
    "runtime/mhfe.wasm names no absolute source path but rustc's own",
  );
  assert.match(
    wasmText,
    /(?<![\x21-\x7e])cargo\/registry\/src\/[^/]+\/bip39-/u,
    "the dependencies' paths are there, remapped from CARGO_HOME to cargo/",
  );
}

/**
 * The package's JavaScript passes the lexical network/dynamic-code tripwire, names no coin and
 * carries no vector; nor does any self-check report. The Python loopback launcher is not JavaScript.
 */
function checkPackageScripts() {
  const scriptsOf = (folder, files) =>
    Object.keys(files)
      .filter((name) => name.endsWith(".js"))
      .map((name) => `${folder}/${name}`);
  const scripts = [
    ...scriptsOf("runtime", manifest.runtime.files),
    ...Object.entries(manifest.modules).flatMap(([module, { files }]) => scriptsOf(module, files)),
  ];
  assert.ok(scripts.includes("runtime/worker.js"), "the worker is checked too");
  // The list of scripts/network-code.mjs, which the build checks too, finds each of its samples
  // and passes a clean script, so that it can fail.
  checkNetworkCodeList();
  for (const script of scripts) {
    const workerSite =
      script === "runtime/runtime.js"
        ? "runtime"
        : script === "core/argon2-mt.js"
          ? "threaded"
          : undefined;
    const found = networkCodeIn(read(`dist/${script}`).toString(), workerSite);
    assert.equal(found, undefined, `${script} contains ${found}`);
  }
  // No script names a coin: the coins live in the WebAssembly only, so that a page for one coin
  // carries no other coin's name (the wallet tools' Dash edition refuses any other in its page).
  const coinNames = JSON.parse(wallet.walletParameters()).coins.flatMap(({ id, name }) => [
    id,
    name,
  ]);
  const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  for (const script of scripts) {
    const text = read(`dist/${script}`).toString();
    for (const coin of coinNames) {
      const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
      assert.equal(pattern.test(text), false, `${script} names the coin ${coin}`);
    }
  }
  // Nor does any script carry the vectors of the wallet's or the rehearsal's checks, which name
  // coins' addresses: they stay in the WebAssembly, whose text the Dash edition does not read.
  // A vector is a string of those files of 8 or more characters that has a digit and no space (an
  // address, a digest, a seed or a path) or 12 words or more (a phrase); the names, identifiers and
  // details of the parts are not vectors.
  const vectorTexts = [
    ...new Set(
      [
        "src/wallet/known_answers.rs",
        "src/wallet/known_answers/addresses.rs",
        "src/rehearsal/known_answers.rs",
        "src/vectors/inputs.rs",
      ]
        .flatMap((path) => rustStrings(read(path).toString()))
        .filter(isVectorText),
    ),
  ];
  assert.ok(vectorTexts.includes(PHRASE_ADDRESS), "the strings of the Rust files are read");
  assert.ok(vectorTexts.includes(PHRASE), "the shared Rust phrase is read");
  const continued = PHRASE.split(" ").join(" \\\n    ");
  assert.deepEqual(
    rustStrings(`const PHRASE: &str = "${continued}";`),
    [PHRASE],
    "a Rust string over several lines is read whole",
  );
  for (const script of scripts) {
    const text = read(`dist/${script}`).toString();
    for (const vector of vectorTexts) {
      assert.equal(text.includes(vector), false, `${script} carries the vector text ${vector}`);
    }
  }
  // The labels and details of every self-check report, failures included, name no coin and carry
  // no vector.
  const reportTexts = reports.flatMap((report) =>
    report.components.flatMap(({ label, detail }) => [label, detail ?? ""]),
  );
  assert.ok(reportTexts.includes("address 3 of 18 stops with INVALID_ADDRESS"));
  for (const text of reportTexts) {
    for (const coin of coinNames) {
      const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
      assert.equal(pattern.test(text), false, `the report text "${text}" names the coin ${coin}`);
    }
    for (const vector of vectorTexts) {
      assert.equal(text.includes(vector), false, `the report text "${text}" carries ${vector}`);
    }
  }
}

/** Every script a page loads, with its build constant; the Argon2 builds end with theirs. */
const STAMPED_SCRIPTS = new Map([
  ["runtime/runtime.js", "export const BUILD_ID"],
  ["runtime/worker.js", "const WORKER_BUILD_ID"],
  ["core/client.js", "const CLIENT_BUILD_ID"],
  ["core/argon2-mt.js", "const ARGON2_THREADED_BUILD_ID"],
  ["core/argon2-st.js", "const ARGON2_SINGLE_THREADED_BUILD_ID"],
  ["repair/repair.js", "const REPAIR_BUILD_ID"],
  ["passwords/passwords.js", "const PASSWORDS_BUILD_ID"],
  ["wallet/wallet.js", "const WALLET_BUILD_ID"],
]);
// The build is derived from every file a page loads before any was stamped: the first 16 hex
// digits of the SHA-256 of their list, one line per file in this order, its SHA-256, two spaces
// and its path, as sha256sum prints it. Here it is derived again from the files with their stamps
// taken out.
const BUILD_FILES = [
  "runtime/mhfe.wasm",
  "runtime/runtime.js",
  "runtime/worker.js",
  "core/client.js",
  "core/argon2-mt.js",
  "core/argon2-st.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
/** The build of `files`, a map from each of BUILD_FILES to its bytes before stamping. */
const buildOf = (files) =>
  sha256(BUILD_FILES.map((path) => `${sha256(files.get(path))}  ${path}\n`).join("")).slice(0, 16);

/** One build named everywhere, and derived again from the files; gives them as built. */
function checkBuildStamps() {
  // One build: modules.json, the WebAssembly's section and every stamped part name the same.
  assert.equal(manifest.buildId, BUILD_ID);
  assert.match(BUILD_ID, /^[0-9a-f]{16}$/u);
  assert.deepEqual(
    WebAssembly.Module.customSections(compiledPackage, "mhfe-build").map((section) =>
      new TextDecoder().decode(section),
    ),
    [BUILD_ID],
  );
  for (const [file, constant] of STAMPED_SCRIPTS) {
    const text = read(`dist/${file}`).toString();
    assert.equal(text.split(`${constant} = "${BUILD_ID}";`).length, 2, `${file} is stamped once`);
    assert.equal(
      text.includes('BUILD_ID = "development"'),
      false,
      `${file} has no unstamped build`,
    );
  }
  for (const [file, constant] of [...STAMPED_SCRIPTS].filter(([file]) => file.includes("argon2"))) {
    assert.ok(
      read(`dist/${file}`).toString().endsWith(`\n${constant} = "${BUILD_ID}";\n`),
      `${file} ends with its build`,
    );
  }
  const unstampedFiles = new Map([
    ["runtime/mhfe.wasm", unstamped],
    ...[...STAMPED_SCRIPTS].map(([file, constant]) => [
      file,
      Buffer.from(
        read(`dist/${file}`)
          .toString()
          .replace(`${constant} = "${BUILD_ID}";`, `${constant} = "development";`),
      ),
    ]),
  ]);
  assert.deepEqual(
    sorted(unstampedFiles.keys()),
    sorted(BUILD_FILES),
    "every file is derived from",
  );
  assert.equal(buildOf(unstampedFiles), BUILD_ID);
  return unstampedFiles;
}

/** The folder of the other build, which this check writes and stamps. */
const otherBuildDir = fileURLToPath(new URL("target/build-id-check/", root));
/** Writes `files` into the other build's folder, as scripts/build-wasm.sh leaves them. */
function writeBuildFiles(files) {
  rmSync(otherBuildDir, { recursive: true, force: true });
  for (const [path, bytes] of files) {
    mkdirSync(join(otherBuildDir, dirname(path)), { recursive: true });
    writeFileSync(join(otherBuildDir, path), bytes);
  }
}
/** Stamps the other build's folder with the build's own script, and gives what it printed. */
const stampBuild = () =>
  execFileSync(process.execPath, ["scripts/stamp-build-id.mjs", otherBuildDir], {
    cwd: fileURLToPath(root),
    stdio: "pipe",
  }).toString();
/** The bytes of the file at `path` of the other build. */
export const readOtherBuild = (path) => readFileSync(join(otherBuildDir, path));

// Two builds that differ in one script alone have different builds, so that their files are not
// used together: the files of this package, unstamped, with a comment added to repair/repair.js,
// stamped again by the build's own script in a folder of their own. Then every file of that build
// carries the other build: its WebAssembly is refused by this worker, its Argon2 build too, and
// part 4b gives its class file this runtime.
async function checkOtherBuild(unstampedFiles) {
  const { otherFiles, otherBuildId, otherWasm } = stampOtherBuild(unstampedFiles);
  await checkOtherBuildRefused(otherBuildId, otherWasm);
  checkStampRefusals(unstampedFiles, otherFiles);
  console.log(
    "The manifest matches the files, one build derived from every file a page loads is stamped " +
      "into each, another build is refused, and the package JavaScript passes the lexical network tripwire, " +
      "names a coin or carries a wallet vector.",
  );
  return otherBuildId;
}

/** The other build, stamped by the build's own script: every file carries it. */
function stampOtherBuild(unstampedFiles) {
  const otherFiles = new Map(unstampedFiles);
  otherFiles.set(
    "repair/repair.js",
    Buffer.concat([unstampedFiles.get("repair/repair.js"), Buffer.from("// another build\n")]),
  );
  writeBuildFiles(otherFiles);
  const otherBuildId = buildOf(otherFiles);
  assert.notEqual(otherBuildId, BUILD_ID, "a script alone changes the build");
  assert.equal(stampBuild(), `Stamped build ${otherBuildId} into the package.\n`);
  for (const [file, constant] of STAMPED_SCRIPTS) {
    assert.ok(
      readOtherBuild(file).toString().includes(`${constant} = "${otherBuildId}";`),
      `${file} of the other build carries it`,
    );
  }
  const otherWasm = readOtherBuild("runtime/mhfe.wasm");
  assert.deepEqual(otherWasm.subarray(0, unstamped.length), unstamped, "the same WebAssembly");
  return { otherFiles, otherBuildId, otherWasm };
}

/** The other build's WebAssembly and its Argon2 build are refused by this worker. */
async function checkOtherBuildRefused(otherBuildId, otherWasm) {
  assert.deepEqual(
    await inProcessWorker(workerScript)({
      ...repairRequest,
      compiled: new WebAssembly.Module(otherWasm),
    }),
    [
      {
        type: "error",
        error: {
          code: "PACKAGE_MISMATCH",
          message: workerMismatch("runtime/mhfe.wasm", otherBuildId),
        },
      },
    ],
    "the other build's WebAssembly, the same bytes but for its build, is refused",
  );
  // The other build's single-threaded Argon2 build, the very file, in front of this worker.
  assert.deepEqual(
    await inProcessWorker(`${readOtherBuild("core/argon2-st.js")}\n;\n${workerScript}`)({
      module: "core",
      operation: "selfTest",
      compiled: compiledPackage,
    }),
    [
      { type: "ready", buildId: BUILD_ID },
      {
        type: "error",
        error: {
          code: "PACKAGE_MISMATCH",
          message: workerMismatch("core/argon2-st.js", otherBuildId),
        },
      },
    ],
  );
}

/**
 * The stamped package is not stamped again, and a script without its build constant, such as an
 * Argon2 build that scripts/build-wasm.sh did not give one, stops the build.
 */
function checkStampRefusals(unstampedFiles, otherFiles) {
  assert.throws(stampBuild, (error) =>
    error.stderr
      .toString()
      .includes(`${join(otherBuildDir, "runtime/mhfe.wasm")} is stamped already; build it again.`),
  );
  const withoutConstant = new Map(unstampedFiles);
  withoutConstant.set(
    "core/argon2-st.js",
    Buffer.from(
      unstampedFiles
        .get("core/argon2-st.js")
        .toString()
        .replace('\nconst ARGON2_SINGLE_THREADED_BUILD_ID = "development";\n', ""),
    ),
  );
  writeBuildFiles(withoutConstant);
  assert.throws(stampBuild, (error) =>
    error.stderr
      .toString()
      .includes(
        `${join(otherBuildDir, "core/argon2-st.js")} holds 0 build constants instead of one.`,
      ),
  );
  writeBuildFiles(otherFiles);
  stampBuild();
}
