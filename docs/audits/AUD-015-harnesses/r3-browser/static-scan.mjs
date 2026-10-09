// AUD-015 R3 static probe of the browser package: error codes, active browser APIs, documented
// WebAssembly exports, the two secret-field lists, the worker's operation tables and the build
// stamps. Read-only: it reads web/, src/wasm_api/, src/error.rs, docs/API.md and dist/.
//
//   node docs/audits/AUD-015-harnesses/r3-browser/static-scan.mjs
//
// Each check prints PASS or FAIL with its evidence; the exit code is 1 when any check fails.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../../../../", import.meta.url).pathname;
const read = (path) => readFileSync(join(root, path), "utf8");
const results = [];
function check(name, ok, evidence) {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
  if (evidence !== undefined) console.log(`     ${JSON.stringify(evidence)}`);
}

// S1: every code the bindings, the library and the classes give is declared, and no declared code
// is given by nothing; the union has no doc comment without its code.
const declaration = read("web/runtime.d.ts");
// The union ends at the first code followed by ";" (doc comments inside it hold semicolons).
const unionStart = declaration.indexOf("export type MhfeErrorCode =");
const union = declaration.slice(unionStart, declaration.indexOf('";', unionStart) + 2);
const declared = new Set([...union.matchAll(/\| "([A-Z0-9_]+)"/gu)].map((m) => m[1]));
const errorRs = read("src/error.rs");
const codeFn = errorRs.slice(errorRs.indexOf("pub const fn code(&self)"));
const emitted = new Map();
const add = (code, where) => {
  if (!emitted.has(code)) emitted.set(code, new Set());
  emitted.get(code).add(where);
};
for (const m of codeFn.matchAll(/=> "([A-Z0-9_]+)"/gu)) add(m[1], "src/error.rs code()");
const wasmApi = readdirSync(join(root, "src/wasm_api")).map((f) => `src/wasm_api/${f}`);
for (const file of [...wasmApi, "src/engine/browser.rs"]) {
  const text = read(file);
  for (const m of text.matchAll(/whole_number\([^,]+,\s*"([A-Z0-9_]+)"/gu)) add(m[1], file);
  for (const m of text.matchAll(/"([A-Z][A-Z0-9_]+): /gu)) add(m[1], file);
}
const webJs = readdirSync(join(root, "web")).filter((f) => f.endsWith(".js"));
for (const file of webJs) {
  const text = read(`web/${file}`);
  for (const m of text.matchAll(/new MhfeError\(\s*"([A-Z0-9_]+)"/gu)) add(m[1], `web/${file}`);
  for (const m of text.matchAll(/requireSetting\([^,]+,[^,]+,\s*"([A-Z0-9_]+)"/gu)) {
    add(m[1], `web/${file}`);
  }
  for (const m of text.matchAll(/["`]([A-Z][A-Z0-9_]+): /gu)) add(m[1], `web/${file}`);
  // "CODE: message" in comments describes the form, not a code.
  for (const m of text.matchAll(/super\("([A-Z0-9_]+)"/gu)) add(m[1], `web/${file}`);
}
emitted.delete("CODE");
// describeError's fallback in web/worker-runtime.js.
add("INTERNAL_ERROR", "web/worker-runtime.js describeError");
const undeclared = [...emitted.keys()].filter((code) => !declared.has(code));
const unused = [...declared].filter((code) => !emitted.has(code));
check("S1a every emitted error code is in MhfeErrorCode", undeclared.length === 0, {
  undeclared: Object.fromEntries(undeclared.map((c) => [c, [...emitted.get(c)]])),
});
check("S1b every MhfeErrorCode is emitted somewhere", unused.length === 0, { unused });
const orphanDocs = [];
const unionLines = union.split("\n");
for (let i = 0; i + 1 < unionLines.length; i += 1) {
  const here = unionLines[i].trim();
  const next = unionLines[i + 1].trim();
  if (here.startsWith("/**") && here.endsWith("*/") && next.startsWith("/**")) {
    orphanDocs.push(here);
  }
}
check("S1c no doc comment in MhfeErrorCode lacks its code", orphanDocs.length === 0, {
  orphanDocs,
});

// S2: what the package's scripts can reach: network, storage, DOM, dynamic code.
const distScripts = [];
for (const dir of readdirSync(join(root, "dist"), { withFileTypes: true })) {
  if (!dir.isDirectory()) continue;
  for (const file of readdirSync(join(root, "dist", dir.name))) {
    if (file.endsWith(".js")) distScripts.push(`dist/${dir.name}/${file}`);
  }
}
const FORBIDDEN = {
  network: [
    /\bfetch\s*\(/u,
    /\bXMLHttpRequest\b/u,
    /\bWebSocket\b/u,
    /\bEventSource\b/u,
    /\bsendBeacon\b/u,
    /\bRTCPeerConnection\b/u,
    /\bWebTransport\b/u,
  ],
  storage: [/\blocalStorage\b/u, /\bsessionStorage\b/u, /\bindexedDB\b/u, /\bcaches\./u],
  dom: [/\bdocument\.(?!currentScript)/u, /\binnerHTML\b/u, /\bwindow\.open\b/u, /\balert\(/u],
  dynamicCode: [/\beval\s*\(/u, /\bnew Function\b/u, /\bimportScripts\s*\(/u, /\bimport\s*\(/u],
};
const hits = {};
for (const file of distScripts) {
  const text = read(file);
  for (const [kind, patterns] of Object.entries(FORBIDDEN)) {
    for (const pattern of patterns) {
      const count = text.split("\n").filter((line) => pattern.test(line)).length;
      if (count > 0) (hits[kind] ??= []).push({ file, pattern: String(pattern), count });
    }
  }
}
check("S2a no network API in any dist script", hits.network === undefined, hits.network);
check("S2b no storage API in any dist script", hits.storage === undefined, hits.storage);
// Emscripten's glue may test `document` for a main-thread environment; it is listed, not judged.
console.log(`INFO S2c DOM-like references: ${JSON.stringify(hits.dom ?? [])}`);
console.log(`INFO S2d dynamic-code references: ${JSON.stringify(hits.dynamicCode ?? [])}`);
const workerCreation = distScripts.map((file) => ({
  file,
  newWorker: read(file).split("new Worker(").length - 1,
  createObjectURL: read(file).split("createObjectURL(").length - 1,
}));
console.log(`INFO S2e worker and Blob URL creation sites: ${JSON.stringify(workerCreation)}`);

// S3: the export list of docs/API.md against the glue's exports.
const glueExports = new Set(
  [...read("dist/runtime/worker.js").matchAll(/^ {4}exports\.(\w+) = /gmu)].map((m) => m[1]),
);
const api = read("docs/API.md");
const listStart = api.indexOf("The WebAssembly's exports are in `src/wasm_api/`");
const listEnd = api.indexOf("Each module has its", listStart);
const documented = new Set(
  [...api.slice(listStart, listEnd).matchAll(/`(\w+)`/gu)]
    .map((m) => m[1])
    .filter((name) => !name.startsWith("src")),
);
// Self-check exports are documented in the next sentences.
const selfChecks = [...glueExports].filter((name) => name.startsWith("selfCheck"));
const missingFromDoc = [...glueExports].filter(
  (name) => !documented.has(name) && !selfChecks.includes(name),
);
const notExported = [...documented].filter((name) => !glueExports.has(name));
check("S3a docs/API.md names every WebAssembly export", missingFromDoc.length === 0, {
  missingFromDoc,
});
check("S3b docs/API.md names no export that does not exist", notExported.length === 0, {
  notExported,
});

// S4: the two copies of SECRET_FIELDS, and every field a class fills with encodeSecret is one.
const fieldsOf = (text) =>
  /const SECRET_FIELDS = \[([^\]]*)\]/u
    .exec(text)[1]
    .split(",")
    .map((s) => s.trim().replaceAll('"', ""))
    .filter(Boolean);
const pageFields = fieldsOf(read("dist/runtime/runtime.js"));
const workerFields = fieldsOf(read("dist/runtime/worker.js"));
check(
  "S4a SECRET_FIELDS equal in dist runtime.js and worker.js",
  JSON.stringify(pageFields) === JSON.stringify(workerFields),
  { pageFields, workerFields },
);
const encodedFields = new Set();
for (const file of ["client.js", "passwords.js", "wallet.js", "runtime.js"]) {
  const text = read(`web/${file}`);
  // Fields of a request: `message.x = encodeSecret(` or `x: encodeSecret(` in an object literal.
  for (const m of text.matchAll(/message\.(\w+) = encodeSecret\(|\b(\w+): encodeSecret\(/gu)) {
    encodedFields.add(m[1] ?? m[2]);
  }
}
// wallet.js copies its secrets from an object literal; runtime.js names `typed`.
for (const m of read("web/wallet.js").matchAll(/const secrets = \{([^}]*)\}/gu)) {
  for (const part of m[1].split(",")) encodedFields.add(part.split(":")[0].trim());
}
encodedFields.delete("bytes");
const notWiped = [...encodedFields].filter((field) => !pageFields.includes(field));
check("S4b every encoded secret field is a SECRET_FIELDS entry", notWiped.length === 0, {
  encodedFields: [...encodedFields],
  notWiped,
});

// S5: every operation a class sends exists in its worker table, and every table's binding exists.
const tables = {
  core: read("web/core-worker.js"),
  repair: read("web/repair-worker.js"),
  passwords: read("web/passwords-worker.js"),
  wallet: read("web/wallet-worker.js"),
};
const tableOps = Object.fromEntries(
  Object.entries(tables).map(([module, text]) => {
    const body = text.slice(text.indexOf("_OPERATIONS = {"));
    const ops = new Set(
      [...body.matchAll(/^ {2}(?:async )?(\w+)(?:: |\()/gmu)].map((m) => m[1]),
    );
    return [module, ops];
  }),
);
const classOps = {
  core: read("web/client.js"),
  repair: read("web/repair.js"),
  passwords: read("web/passwords.js"),
  wallet: read("web/wallet.js"),
};
const missingOps = [];
for (const [module, text] of Object.entries(classOps)) {
  for (const m of text.matchAll(/operation: "(\w+)"/gu)) {
    if (!tableOps[module].has(m[1])) missingOps.push(`${module}.${m[1]}`);
  }
}
// The runtime sends "parameters", "selfCheck" and "wordHints" for the module classes.
for (const module of ["repair", "passwords", "wallet"]) {
  for (const op of ["parameters", "selfCheck"]) {
    if (!tableOps[module].has(op)) missingOps.push(`${module}.${op}`);
  }
}
for (const module of ["passwords", "wallet"]) {
  if (!tableOps[module].has("wordHints")) missingOps.push(`${module}.wordHints`);
}
check("S5a every operation a class sends is in its worker table", missingOps.length === 0, {
  missingOps,
});
const missingBindings = [];
for (const [module, text] of Object.entries(tables)) {
  for (const m of text.matchAll(/mhfe\.(\w+)\(/gu)) {
    if (!glueExports.has(m[1])) missingBindings.push(`${module}: mhfe.${m[1]}`);
  }
  for (const m of text.matchAll(/new mhfe\.(\w+)\(/gu)) {
    if (!glueExports.has(m[1])) missingBindings.push(`${module}: new mhfe.${m[1]}`);
  }
}
check("S5b every binding a worker table calls is exported", missingBindings.length === 0, {
  missingBindings,
});
const unusedExports = [...glueExports].filter(
  (name) => !Object.values(tables).some((text) => text.includes(`mhfe.${name}`)),
);
console.log(`INFO S5c exports no worker operation calls: ${JSON.stringify(unusedExports)}`);

// S6: the stamps and the manifest.
const manifest = JSON.parse(read("dist/modules.json"));
const stamps = distScripts
  .map((file) => {
    const found = [...read(file).matchAll(/const [A-Z0-9_]*BUILD_ID = "([0-9a-z]+)";/gu)].map(
      (m) => m[1],
    );
    return { file, found };
  })
  .filter(({ found }) => found.length > 0);
const wasm = readFileSync(join(root, "dist/runtime/mhfe.wasm"));
const section = WebAssembly.Module.customSections(new WebAssembly.Module(wasm), "mhfe-build").map(
  (bytes) => new TextDecoder().decode(bytes),
);
const allStamps = new Set([...stamps.flatMap(({ found }) => found), ...section]);
check(
  "S6a one build id in every stamped script, the WebAssembly and modules.json",
  allStamps.size === 1 && allStamps.has(manifest.buildId) && section.length === 1,
  { stamps, section, manifestBuild: manifest.buildId },
);
const sha = (path) => createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
const wrongHashes = [];
for (const [name, hash] of Object.entries(manifest.runtime.files)) {
  if (sha(`dist/runtime/${name}`) !== hash) wrongHashes.push(`runtime/${name}`);
}
for (const [module, { files }] of Object.entries(manifest.modules)) {
  for (const [name, hash] of Object.entries(files)) {
    if (sha(`dist/${module}/${name}`) !== hash) wrongHashes.push(`${module}/${name}`);
  }
}
check("S6b modules.json SHA-256 values match dist files", wrongHashes.length === 0, {
  wrongHashes,
});
const listed = new Set([
  ...Object.keys(manifest.runtime.files).map((n) => `dist/runtime/${n}`),
  ...Object.entries(manifest.modules).flatMap(([m, { files }]) =>
    Object.keys(files).map((n) => `dist/${m}/${n}`),
  ),
]);
const allDist = [];
for (const dir of readdirSync(join(root, "dist"), { withFileTypes: true })) {
  if (dir.isDirectory()) {
    for (const file of readdirSync(join(root, "dist", dir.name))) {
      allDist.push(`dist/${dir.name}/${file}`);
    }
  }
}
const unlisted = allDist.filter((file) => !listed.has(file));
check("S6c every file in a dist folder is listed in modules.json", unlisted.length === 0, {
  unlisted,
});

const failed = results.filter(({ ok }) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`);
process.exit(failed.length === 0 ? 0 : 1);
