// AUD-010 browser-package probe of the public surface and the package composition
// (CHECK-API-003, CHECK-BLD-001): the value exports of every module of dist/ against its
// declarations (AUD-009-API003), named imports that must link, one error class shared by every
// module, the result shapes of the real WebAssembly against the declarations, the error codes the
// package can produce against MhfeErrorCode and docs/API.md, dist/modules.json and the build
// recomputed from the files, each class importable with runtime/ alone, and the parts of each
// class's self-check against docs/BROWSER-PACKAGE.md. Exits non-zero when a check fails.
//
//   node docs/audits/AUD-010-harnesses/browser-package/surface.mjs
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { Checks, dataUrl, loadPackage, packageModule } from "./lib.mjs";

const checks = new Checks("AUD-010 browser-package: public surface and composition");
const read = (path) => readFileSync(path, "utf8");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// --- Part 1: value exports against the declarations, in web/ and dist/ ---------------------
/** The value names a declaration file exports (classes, constants, functions, re-exports). */
function declaredValues(text) {
  return new Set([
    ...[...text.matchAll(/^export (?:declare )?(?:class|const|function) (\w+)/gmu)].map(
      (m) => m[1],
    ),
    ...[...text.matchAll(/^export \{([^}]*)\} from/gmu)].flatMap((m) =>
      m[1]
        .split(",")
        .map((name) => name.trim())
        .filter((name) => name !== "" && !name.startsWith("type ")),
    ),
  ]);
}
for (const folder of ["web", "dist"]) {
  const pkg = await loadPackage(folder);
  const files = {
    runtime: folder === "web" ? "web/runtime.d.ts" : "dist/runtime/runtime.d.ts",
    core: folder === "web" ? "web/client.d.ts" : "dist/core/client.d.ts",
    repair: folder === "web" ? "web/repair.d.ts" : "dist/repair/repair.d.ts",
    passwords: folder === "web" ? "web/passwords.d.ts" : "dist/passwords/passwords.d.ts",
    wallet: folder === "web" ? "web/wallet.d.ts" : "dist/wallet/wallet.d.ts",
  };
  for (const [name, declarations] of Object.entries(files)) {
    const declared = declaredValues(read(declarations));
    const actual = new Set(Object.keys(pkg[name]));
    const missing = [...declared].filter((each) => !actual.has(each));
    const undeclared = [...actual].filter((each) => !declared.has(each));
    checks.ok(
      missing.length === 0,
      `${folder} ${name}: every declared value export exists (${[...declared].join(", ")})`,
      `missing at runtime: ${missing.join(", ")}`,
    );
    if (undeclared.length > 0) {
      checks.note(
        `${folder} ${name}: exported at runtime but not declared: ${undeclared.join(", ")}`,
      );
    }
  }
  // The error classes of every module are the one runtime's.
  checks.ok(
    pkg.repair.MhfeError === pkg.runtime.MhfeError &&
      pkg.passwords.MhfeError === pkg.runtime.MhfeError &&
      pkg.wallet.MhfeError === pkg.runtime.MhfeError &&
      pkg.core.MhfeError === pkg.runtime.MhfeError &&
      pkg.wallet.MhfeCancelledError === pkg.runtime.MhfeCancelledError &&
      pkg.core.MhfeCancelledError === pkg.runtime.MhfeCancelledError,
    `${folder}: every module re-exports the runtime's own error classes`,
  );
}
// AUD-009-API003: named imports that TypeScript accepts must link at runtime.
{
  const runtimeUrl = dataUrl(read("dist/runtime/runtime.js"));
  const classUrl = (path) =>
    dataUrl(read(path).replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl)));
  const importer = `
    import { MhfeError as RepairError, MhfeRepair } from ${JSON.stringify(classUrl("dist/repair/repair.js"))};
    import { MhfeError as PasswordsError, MhfePasswords } from ${JSON.stringify(classUrl("dist/passwords/passwords.js"))};
    import { MhfeError as WalletError, MhfeCancelledError as WalletCancelled, MhfeWallet } from ${JSON.stringify(classUrl("dist/wallet/wallet.js"))};
    import { MhfeError as CoreError, MhfeCancelledError, FAST_MODE, STANDARD_MODE, MhfeClient } from ${JSON.stringify(classUrl("dist/core/client.js"))};
    export const linked = [RepairError, PasswordsError, WalletError, WalletCancelled, CoreError,
      MhfeCancelledError, FAST_MODE, STANDARD_MODE, MhfeRepair, MhfePasswords, MhfeWallet,
      MhfeClient].every((value) => value !== undefined);
  `;
  const linked = await import(dataUrl(importer)).then(
    (module) => module.linked,
    (error) => error,
  );
  checks.ok(
    linked === true,
    "AUD-009-API003: the declared named imports of every module link",
    String(linked),
  );
}

// --- Part 2: result shapes of the real WebAssembly against the declarations ----------------
const worker = read("dist/runtime/worker.js");
const glue = worker.slice(0, worker.indexOf("// The bridge from the Rust core"));
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: packageModule() });
const keys = (value) => Object.keys(value).sort().join(",");
const expectKeys = (label, value, expected) =>
  checks.ok(
    keys(value) === [...expected].sort().join(","),
    `${label} has the declared fields`,
    keys(value),
  );
const suite = JSON.parse(mhfe.suiteParameters());
expectKeys("suiteParameters (MhfeParameters)", suite, [
  "version",
  "suiteId",
  "sameLengthSuiteId",
  "rounds",
  "maxPim",
  "maxMemoryLevel",
  "highestBrowserMemoryLevel",
  "wordCounts",
  "builtInCheckWordCounts",
  "repairWordCounts",
  "recommendedRepairWords",
  "repairCapacities",
]);
expectKeys("repairParameters", JSON.parse(mhfe.repairParameters()), [
  "version",
  "profile",
  "repairWordCounts",
  "recommendedRepairWords",
  "repairCapacities",
]);
expectKeys("passwordParameters", JSON.parse(mhfe.passwordParameters()), [
  "version",
  "checkWordProfile",
  "defaultWords",
  "recommendedWords",
  "mostWords",
  "defaultCharacters",
  "recommendedCharacters",
  "mostCharacters",
  "weakBelowBits",
]);
const walletParameters = JSON.parse(mhfe.walletParameters());
expectKeys("walletParameters", walletParameters, [
  "version",
  "coins",
  "walletCheckBits",
  "drawReportInterval",
]);
checks.ok(
  walletParameters.coins.every((coin) => keys(coin) === "addressForms,id,name"),
  "every coin of walletParameters is { id, name, addressForms }",
);
const coinUnion = /export type MhfeCoin =([\s\S]*?);/u.exec(read("web/client.d.ts"))[1];
const declaredCoins = [...coinUnion.matchAll(/"([a-z-]+)"/gu)].map((m) => m[1]).sort();
const coinIds = walletParameters.coins.map((coin) => coin.id);
checks.ok(
  declaredCoins.join() === [...coinIds].sort().join(),
  `MhfeCoin in client.d.ts lists the ${coinIds.length} coins of parameters().coins`,
  `declared ${declaredCoins.join(", ")}; WebAssembly ${coinIds.join(", ")}`,
);
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
expectKeys(
  "describeAddress",
  JSON.parse(mhfe.describeAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bitcoin", "")),
  ["type", "search", "addresses", "onlyPath"],
);
expectKeys("describePhrase (MhfePhraseFacts)", JSON.parse(mhfe.describePhrase(PHRASE)), [
  "phrase",
  "words",
  "otherLengths",
  "containers",
]);
expectKeys("describeContainer (MhfeContainerFacts)", JSON.parse(mhfe.describeContainer(PHRASE)), [
  "container",
  "words",
  "suiteId",
  "phraseLengths",
  "builtInCheckLengths",
  "confirmationFor",
  "hiddenWallets",
  "offersWalletCheck",
  "containerFingerprint",
]);
expectKeys("repairWords (MhfeRepairCard)", JSON.parse(mhfe.repairWords(PHRASE, 4)), [
  "profile",
  "words",
  "repairsUnreadable",
  "repairsWrong",
]);
const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
expectKeys(
  "makePassword",
  JSON.parse(mhfe.makePassword("words", undefined, new Uint8Array(0), random)),
  ["password", "bits", "weak", "checkWord"],
);
expectKeys(
  "drawPhrase (MhfeNewPhrase without workers)",
  JSON.parse(mhfe.drawPhrase(new Uint8Array(0), false, random, () => {})),
  ["phrase", "words", "walletCheck", "fingerprintWithPassphrase"],
);
const noop = () => {};

// --- Part 3: the self-check parts of each class against docs/BROWSER-PACKAGE.md ------------
const DOCUMENTED_PARTS = {
  core: "cipher-hashes argon2 cipher-rounds formats container-facts keep-advice password-unicode bip39-words repair-words password-check-word wallet-hashes bip39-seed bip32 addresses wallet-check hidden-wallets rekey rehearsal",
  repair: "bip39-words repair-words",
  passwords: "password-unicode password-check-word password-generator random-source",
  wallet:
    "bip39-words wallet-hashes bip39-seed bip32 addresses address-search wallet-check random-source",
};
const reports = {
  core: JSON.parse(mhfe.selfCheckCore("startup", [], undefined, noop, noop)),
  repair: JSON.parse(mhfe.selfCheckRepair("startup", [], noop, noop)),
  passwords: JSON.parse(mhfe.selfCheckPasswords("startup", [], random, noop, noop)),
  wallet: JSON.parse(mhfe.selfCheckWallet("startup", [], random, noop, noop)),
};
const coinWords = walletParameters.coins.flatMap((coin) => [coin.id, coin.name]);
for (const [name, report] of Object.entries(reports)) {
  checks.ok(
    report.ids.join(" ") === DOCUMENTED_PARTS[name],
    `${name}: the self-check parts are those BROWSER-PACKAGE.md lists, in its order`,
    report.ids.join(" "),
  );
  checks.ok(report.passed === true, `${name}: the startup self-check passes in this process`);
  const texts = report.components.flatMap((c) => [c.label, c.detail ?? ""]);
  const named = coinWords.filter((coin) =>
    texts.some((text) =>
      new RegExp(`\\b${coin.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\b`, "iu").test(text),
    ),
  );
  checks.ok(named.length === 0, `${name}: no label or detail names a coin`, named.join(", "));
}
checks.ok(
  reports.core.components.find((c) => c.id === "argon2")?.outcome === "notRun",
  "core without Argon2 lists argon2 as not run",
);

// --- Part 4: error codes ---------------------------------------------------------------------
const rustCodes = new Set(
  [...read("src/error.rs").matchAll(/=> "([A-Z][A-Z0-9_]+)",/gu)].map((m) => m[1]),
);
const jsSources = [
  "web/runtime.js",
  "web/client.js",
  "web/repair.js",
  "web/passwords.js",
  "web/wallet.js",
  "web/worker-runtime.js",
  "web/core-worker.js",
  "web/argon2-engine.js",
];
const jsCodes = new Set(
  jsSources.flatMap((path) => [
    ...[...read(path).matchAll(/new MhfeError\(\s*"([A-Z][A-Z0-9_]+)"/gu)].map((m) => m[1]),
    ...[...read(path).matchAll(/["`]([A-Z][A-Z0-9_]{3,}): /gu)].map((m) => m[1]),
  ]),
);
jsCodes.add("CANCELLED"); // MhfeCancelledError
const translatorCodes = new Set(
  readdirSync("src/wasm_api").flatMap((file) => [
    ...[...read(`src/wasm_api/${file}`).matchAll(/whole_number\([^,]+,\s*"([A-Z_]+)"/gu)].map(
      (m) => m[1],
    ),
    ...[...read(`src/wasm_api/${file}`).matchAll(/"([A-Z][A-Z0-9_]+): /gu)].map((m) => m[1]),
  ]),
);
// "CODE" is the placeholder of a comment ("CODE: message"), not a code.
const produced = new Set(
  [...rustCodes, ...jsCodes, ...translatorCodes].filter((code) => code !== "CODE"),
);
const unionText = /export type MhfeErrorCode =([\s\S]*?);\n/u.exec(read("web/runtime.d.ts"))[1];
const declaredCodes = new Set([...unionText.matchAll(/\| "([A-Z][A-Z0-9_]+)"/gu)].map((m) => m[1]));
const notDeclared = [...produced].filter((code) => !declaredCodes.has(code));
const neverProduced = [...declaredCodes].filter((code) => !produced.has(code));
checks.ok(
  notDeclared.length === 0,
  `every code the package can produce is in MhfeErrorCode (${produced.size})`,
  notDeclared.join(", "),
);
if (neverProduced.length > 0)
  checks.note(`declared but not produced by the browser package: ${neverProduced.join(", ")}`);
const apiText = read("docs/API.md");
const apiCodes = new Set([...apiText.matchAll(/`([A-Z][A-Z0-9_]{3,})`/gu)].map((m) => m[1]));
const undocumented = [...declaredCodes].filter((code) => !apiCodes.has(code));
checks.ok(
  undocumented.length === 0,
  "docs/API.md names every code of MhfeErrorCode",
  undocumented.join(", "),
);

// --- Part 5: the manifest and the build, recomputed ------------------------------------------
const manifest = JSON.parse(read("dist/modules.json"));
const folders = { runtime: manifest.runtime, ...manifest.modules };
for (const [folder, entry] of Object.entries(folders)) {
  const onDisk = readdirSync(`dist/${folder}`).sort();
  checks.ok(
    onDisk.join() === Object.keys(entry.files).sort().join(),
    `modules.json lists exactly the files of ${folder}/`,
  );
  for (const [file, hash] of Object.entries(entry.files)) {
    checks.ok(
      sha256(readFileSync(`dist/${folder}/${file}`)) === hash,
      `${folder}/${file} has its SHA-256`,
    );
  }
  if (folder !== "runtime") {
    checks.ok(
      JSON.stringify(entry.requires) === '["runtime"]',
      `${folder} requires the runtime only`,
    );
  }
}
checks.ok(
  JSON.stringify(readdirSync("dist").sort()) ===
    JSON.stringify([
      "README.md",
      "core",
      "modules.json",
      "passwords",
      "repair",
      "runtime",
      "wallet",
    ]),
  "dist/ holds the four modules, the runtime, modules.json and README.md only",
);
// The build: the first 16 hex digits of the SHA-256 of `sha256  path` lines of the nine files a
// page loads, before stamping (docs/API.md).
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
const build = manifest.buildId;
const wasm = readFileSync("dist/runtime/mhfe.wasm");
const section = WebAssembly.Module.customSections(new WebAssembly.Module(wasm), "mhfe-build");
checks.ok(
  section.length === 1 && new TextDecoder().decode(section[0]) === build,
  "the WebAssembly carries one mhfe-build section, the manifest's build",
);
// The section is appended last: id 0, size, name length, name, content.
const name = Buffer.from("mhfe-build");
const tailLength = 1 + 1 + 1 + name.length + build.length;
const unstampedWasm = wasm.subarray(0, wasm.length - tailLength);
const unstamped = BUILD_FILES.map((path) => {
  if (path === "runtime/mhfe.wasm") return unstampedWasm;
  const text = read(`dist/${path}`);
  const constants = [
    ...text.matchAll(/^((?:export )?const [A-Z0-9_]*BUILD_ID = )"([0-9a-f]{16})";$/gmu),
  ];
  checks.ok(constants.length === 1 && constants[0][2] === build, `${path} carries the build once`);
  return Buffer.from(
    text.replace(`${constants[0]?.[1]}"${build}";`, `${constants[0]?.[1]}"development";`),
  );
});
const recomputed = sha256(
  BUILD_FILES.map((path, index) => `${sha256(unstamped[index])}  ${path}\n`).join(""),
).slice(0, 16);
checks.ok(
  recomputed === build,
  `the build ${build} follows from the nine files before stamping`,
  recomputed,
);
const readme = read("dist/README.md");
checks.ok(
  Object.entries(folders).every(([folder, entry]) =>
    Object.entries(entry.files).every(([file, hash]) =>
      readme.includes(`${hash}  ${folder}/${file}`),
    ),
  ) && readme.includes(`build ${build}`),
  "dist/README.md lists the build and the SHA-256 of every file",
);
// Files outside the build: shipped and hashed in the manifest, but not part of the build id.
const outside = Object.entries(folders)
  .flatMap(([folder, entry]) => Object.keys(entry.files).map((file) => `${folder}/${file}`))
  .filter((path) => !BUILD_FILES.includes(path));
checks.note(`files hashed in modules.json but not in the build id: ${outside.join(", ")}`);

// --- Part 6: each class with runtime/ alone ----------------------------------------------------
for (const path of [
  "core/client.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
]) {
  const text = read(`dist/${path}`);
  const specifiers = [...text.matchAll(/^(?:import|export)[^;]*?from\s+"([^"]+)"/gmsu)].map(
    (m) => m[1],
  );
  checks.ok(
    specifiers.every((specifier) => specifier === "../runtime/runtime.js") && specifiers.length > 0,
    `${path} imports only ../runtime/runtime.js`,
    specifiers.join(", "),
  );
  checks.ok(!/\bimport\s*\(/u.test(text), `${path} has no dynamic import`);
}

checks.finish();
