// AUD-010 probe (docs-build-release): shows whether the browser package in dist/ was built from the
// files of this working tree, without building anything. Exits 1 on the first claim that fails.
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/dist-freshness.mjs [dist]
//
// It checks that
// - modules.json lists exactly the files of each folder with their SHA-256, and README.md is
//   docs/BROWSER-PACKAGE.md followed by the same sums;
// - every script copied from web/ equals its source once the stamped build is put back to
//   "development", and runtime/worker.js ends with the web/ parts in build-wasm.sh's order;
// - runtime/mhfe.wasm without its trailing "mhfe-build" section is target/wasm-bindgen/mhfe_bg.wasm;
// - the build recomputed from the unstamped files, by scripts/stamp-build-id.mjs's rule, is the
//   one stamped;
// - every source file in cargo's dep-info for target/wasm32-unknown-unknown/release/mhfe.wasm is
//   older than that WebAssembly (the dep-info lists what rustc read).
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const dist = process.argv[2] ?? "dist";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
let failures = 0;
function claim(ok, text) {
  console.log(`${ok ? "ok  " : "FAIL"} ${text}`);
  if (!ok) failures += 1;
}

const manifest = JSON.parse(readFileSync(join(dist, "modules.json"), "utf8"));
const buildId = manifest.buildId;
const folders = { runtime: manifest.runtime.files };
for (const [name, module] of Object.entries(manifest.modules)) folders[name] = module.files;
const sums = [];
for (const [folder, files] of Object.entries(folders)) {
  const onDisk = readdirSync(join(dist, folder)).sort();
  claim(
    JSON.stringify(onDisk) === JSON.stringify(Object.keys(files).sort()),
    `${folder}/ holds exactly the files modules.json lists (${onDisk.length})`,
  );
  for (const [file, hash] of Object.entries(files)) {
    claim(sha256(readFileSync(join(dist, folder, file))) === hash, `${folder}/${file} hash`);
    sums.push(`${hash}  ${folder}/${file}`);
  }
}
const readme = readFileSync(join(dist, "README.md"), "utf8");
const guide = readFileSync("docs/BROWSER-PACKAGE.md", "utf8");
claim(readme.startsWith(guide), "README.md starts with docs/BROWSER-PACKAGE.md as it is now");
claim(
  sums.every((line) => readme.includes(line)),
  "README.md lists the SHA-256 of every file",
);

const unstamp = (text) => text.split(`"${buildId}"`).join('"development"');
const copies = {
  "runtime/runtime.js": "web/runtime.js",
  "runtime/runtime.d.ts": "web/runtime.d.ts",
  "core/client.js": "web/client.js",
  "core/client.d.ts": "web/client.d.ts",
  "core/mhfe-fast-mode.py": "packaging/mhfe-fast-mode.py",
  "repair/repair.js": "web/repair.js",
  "repair/repair.d.ts": "web/repair.d.ts",
  "passwords/passwords.js": "web/passwords.js",
  "passwords/passwords.d.ts": "web/passwords.d.ts",
  "wallet/wallet.js": "web/wallet.js",
  "wallet/wallet.d.ts": "web/wallet.d.ts",
};
for (const [built, source] of Object.entries(copies)) {
  const same = unstamp(readFileSync(join(dist, built), "utf8")) === readFileSync(source, "utf8");
  claim(same, `${built} is ${source} with the build stamped`);
}
const workerParts = [
  "web/argon2-engine.js",
  "web/worker-runtime.js",
  "web/core-worker.js",
  "web/repair-worker.js",
  "web/passwords-worker.js",
  "web/wallet-worker.js",
  "web/worker-start.js",
].map((path) => readFileSync(path, "utf8"));
const worker = unstamp(readFileSync(join(dist, "runtime/worker.js"), "utf8"));
claim(worker.endsWith(workerParts.join("")), "runtime/worker.js ends with the web/ worker parts");
const glue = readFileSync("target/wasm-bindgen/mhfe.js", "utf8");
claim(
  worker === glue + workerParts.join(""),
  "runtime/worker.js is the bindgen glue of target/wasm-bindgen/ plus those parts",
);

// The stamp is the last section: id 0, its size, the name "mhfe-build", the build.
const stamped = readFileSync(join(dist, "runtime/mhfe.wasm"));
const name = Buffer.from("mhfe-build");
const section = Buffer.concat([
  Buffer.from([0, 1 + name.length + buildId.length, name.length]),
  name,
  Buffer.from(buildId),
]);
const tail = stamped.subarray(stamped.length - section.length);
claim(tail.equals(section), "runtime/mhfe.wasm ends with the mhfe-build section of this build");
const unstampedWasm = stamped.subarray(0, stamped.length - section.length);
claim(
  unstampedWasm.equals(readFileSync("target/wasm-bindgen/mhfe_bg.wasm")),
  "runtime/mhfe.wasm without its stamp is target/wasm-bindgen/mhfe_bg.wasm",
);

const buildFiles = [
  "runtime/runtime.js",
  "runtime/worker.js",
  "core/client.js",
  "core/argon2-mt.js",
  "core/argon2-st.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
];
const list =
  `${sha256(unstampedWasm)}  runtime/mhfe.wasm\n` +
  buildFiles
    .map(
      (path) =>
        `${sha256(Buffer.from(unstamp(readFileSync(join(dist, path), "utf8"))))}  ${path}\n`,
    )
    .join("");
claim(
  sha256(list).slice(0, 16) === buildId,
  `the build ${buildId} follows from the unstamped files`,
);

const wasmTarget = "target/wasm32-unknown-unknown/release/mhfe.wasm";
const built = statSync(wasmTarget).mtimeMs;
const depInfo = readFileSync("target/wasm32-unknown-unknown/release/mhfe.d", "utf8");
const sources = depInfo
  .split("\n")[0]
  .split(": ")[1]
  .split(" ")
  .filter((path) => path !== "");
const newer = sources.filter((path) => statSync(path).mtimeMs > built);
claim(
  newer.length === 0,
  `all ${sources.length} sources in the dep-info are older than ${wasmTarget}` +
    (newer.length ? `; newer: ${newer.join(", ")}` : ""),
);

if (failures > 0) {
  console.log(`FAIL: ${failures} claims do not hold.`);
  process.exit(1);
}
console.log(`PASS: dist/ (build ${buildId}) follows from this working tree.`);
