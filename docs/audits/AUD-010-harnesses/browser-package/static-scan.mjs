// AUD-010 browser-package static scan (CHECK-SEC-006, the CSP part of CHECK-SEC-002, and the Dash
// edition's constraint of CHECK-BLD-001): searches web/ and every file of dist/ for DOM sinks,
// storage, dynamic code, console calls, network code, remote URLs, coin names, public vector texts
// and absolute builder paths, and classifies each match as first-party code or generated glue
// (the wasm-bindgen part of runtime/worker.js, the Emscripten builds core/argon2-*.js). Counts are
// recorded so that a later change is visible. Exits non-zero when a check fails.
//
//   node docs/audits/AUD-010-harnesses/browser-package/static-scan.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { Checks, packageModule } from "./lib.mjs";

const checks = new Checks("AUD-010 browser-package: static scan");
const read = (path) => readFileSync(path, "utf8");

/** Every file under `folder`. */
function filesOf(folder) {
  return readdirSync(folder).flatMap((name) => {
    const path = join(folder, name);
    return statSync(path).isDirectory() ? filesOf(path) : [path];
  });
}

/** The parts of the scanned text, each first-party or generated. */
function partsOf(path) {
  const text = read(path);
  if (path === "dist/runtime/worker.js") {
    const split = text.indexOf("// The bridge from the Rust core");
    return [
      { kind: "generated wasm-bindgen glue", file: `${path} [glue]`, text: text.slice(0, split) },
      { kind: "first-party", file: `${path} [web/ parts]`, text: text.slice(split) },
    ];
  }
  if (/argon2-(mt|st)\.js$/u.test(path)) {
    return [{ kind: "generated Emscripten build", file: path, text }];
  }
  return [{ kind: "first-party", file: path, text }];
}

const PATTERNS = {
  "DOM sink":
    /\b(?:innerHTML|outerHTML|insertAdjacentHTML|createContextualFragment|DOMParser)\b|document\.write/gu,
  storage:
    /\b(?:localStorage|sessionStorage|indexedDB|IDBFactory|document\.cookie|navigator\.storage)\b|\bcaches\./gu,
  "dynamic code":
    /\beval\s*\(|\bnew Function\s*\(|\bFunction\s*\(\s*["'`]|\bset(?:Timeout|Interval)\s*\(\s*["'`]|\bimportScripts\s*\(|\bimport\s*\(/gu,
  console: /\bconsole\.\w+/gu,
  network:
    /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|\bsendBeacon\b|\bRTCPeerConnection\b/gu,
  "remote URL": /\b(?:https?|wss?|ftp):\/\/[^\s"'`)]+/gu,
};

const scripts = [
  ...filesOf("web").filter((path) => path.endsWith(".js")),
  ...filesOf("dist").filter((path) => path.endsWith(".js")),
];
const firstPartyDynamic = [];
for (const [category, pattern] of Object.entries(PATTERNS)) {
  const counts = [];
  for (const path of scripts) {
    for (const part of partsOf(path)) {
      const matches = [...part.text.matchAll(pattern)].map((m) => m[0]);
      if (matches.length === 0) continue;
      counts.push(
        `${part.file} (${part.kind}): ${matches.length} [${[...new Set(matches)].slice(0, 6).join(" | ")}]`,
      );
      if (part.kind === "first-party") {
        for (const match of matches) firstPartyDynamic.push({ category, file: part.file, match });
      }
    }
  }
  checks.note(`${category}: ${counts.length === 0 ? "no match" : counts.join("; ")}`);
}
// First-party code: no DOM sink, storage, eval-like code, network or remote URL; the only
// accepted matches are the classes' Blob workers and documentation URLs in comments.
const disallowed = firstPartyDynamic.filter(
  ({ category }) => !["console", "remote URL"].includes(category),
);
checks.ok(
  disallowed.length === 0,
  "first-party scripts have no DOM sink, storage, dynamic code or network code",
  disallowed.map(({ category, file, match }) => `${category} in ${file}: ${match}`).join("; "),
);
const consoleCalls = firstPartyDynamic.filter(({ category }) => category === "console");
checks.ok(
  consoleCalls.length === 0,
  "first-party scripts write nothing to the console",
  consoleCalls.map(({ file, match }) => `${file}: ${match}`).join("; "),
);
const remote = firstPartyDynamic.filter(({ category }) => category === "remote URL");
checks.note(
  `first-party remote URL texts: ${remote.length === 0 ? "none" : remote.map(({ file, match }) => `${file}: ${match}`).join("; ")}`,
);
// Network code anywhere in dist/, generated glue included (the package claim).
const networkAnywhere = filesOf("dist")
  .filter((path) => path.endsWith(".js"))
  .filter((path) =>
    /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|\bsendBeacon\b/u.test(
      read(path),
    ),
  );
checks.ok(
  networkAnywhere.length === 0,
  "no script of dist/ holds network code, glue included",
  networkAnywhere.join(", "),
);
// The classes create workers only from Blob URLs; the threaded Argon2 build's lane workers too.
for (const path of ["dist/runtime/runtime.js", "dist/core/argon2-mt.js"]) {
  const workers = [...read(path).matchAll(/new Worker\(([^,)]+)/gu)].map((m) => m[1].trim());
  checks.note(`${path}: new Worker(${workers.join(" | ")})`);
}
const mt = read("dist/core/argon2-mt.js");
checks.note(
  `argon2-mt.js: mainScriptUrlOrBlob ${mt.includes("mainScriptUrlOrBlob") ? "supported" : "absent"}, ` +
    `createObjectURL ${(mt.match(/createObjectURL/gu) ?? []).length}x, importScripts ${(mt.match(/importScripts/gu) ?? []).length}x`,
);

// --- Coin names: none in a file a page loads ------------------------------------------------
const worker = read("dist/runtime/worker.js");
const glue = worker.slice(0, worker.indexOf("// The bridge from the Rust core"));
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: packageModule() });
const coins = JSON.parse(mhfe.walletParameters()).coins.flatMap(({ id, name }) => [id, name]);
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
const PAGE_FILES = [
  "dist/runtime/runtime.js",
  "dist/runtime/worker.js",
  "dist/core/client.js",
  "dist/core/argon2-mt.js",
  "dist/core/argon2-st.js",
  "dist/repair/repair.js",
  "dist/passwords/passwords.js",
  "dist/wallet/wallet.js",
];
for (const path of filesOf("dist").filter((each) => !each.endsWith(".wasm"))) {
  const text = read(path);
  const named = coins.filter((coin) => new RegExp(`\\b${escape(coin)}\\b`, "iu").test(text));
  if (PAGE_FILES.includes(path)) {
    checks.ok(named.length === 0, `${path}, which a page loads, names no coin`, named.join(", "));
  } else if (named.length > 0) {
    checks.note(
      `${path} (not loaded by a page) names ${new Set(named.map((c) => c.toLowerCase())).size} coin words`,
    );
  }
}
// Public wallet vectors must not be in a page's scripts (they stay in the WebAssembly).
for (const vector of [
  "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "73c5da0a",
]) {
  const carriers = PAGE_FILES.filter((path) => read(path).includes(vector));
  checks.ok(
    carriers.length === 0,
    `no page script carries the public vector text ${vector.slice(0, 24)}…`,
    carriers.join(", "),
  );
}

// --- Absolute builder paths in every file of dist/ -----------------------------------------
for (const path of filesOf("dist")) {
  const bytes = readFileSync(path);
  const found = [...new Set(bytes.toString("latin1").match(/\/home\/[A-Za-z0-9_.\/-]+/gu) ?? [])];
  if (found.length > 0) {
    const user = [...new Set(found.map((each) => each.split("/")[2]))];
    checks.note(
      `${path}: ${found.length} distinct absolute paths under /home (user part: ${user.join(", ")})`,
    );
  }
}

checks.finish();
