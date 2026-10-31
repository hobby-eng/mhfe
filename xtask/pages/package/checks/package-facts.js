// Part 3: what only the running package can tell. `cargo xtask wasm verify` checks the rest of the
// package, and `cargo xtask package-check` stamped the other build, which differs in one script
// alone, and checked the stamp's refusals.
const manifest = JSON.parse(read("dist/modules.json").toString());
const scriptsOf = (folder, files) =>
  Object.keys(files)
    .filter((name) => name.endsWith(".js"))
    .map((name) => `${folder}/${name}`);
const scripts = [
  ...scriptsOf("runtime", manifest.runtime.files),
  ...Object.entries(manifest.modules).flatMap(([module, { files }]) => scriptsOf(module, files)),
];
assert.ok(scripts.includes("runtime/worker.js"), "the worker is checked too");
// No script names a coin: the coins live in the WebAssembly only, so that a page for one coin
// carries no other coin's name (the wallet tools' Dash edition refuses any other in its page).
const coinNames = JSON.parse(wallet.walletParameters()).coins.flatMap(({ id, name }) => [id, name]);
const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
for (const script of scripts) {
  const text = read(`dist/${script}`).toString();
  for (const coin of coinNames) {
    const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
    assert.equal(pattern.test(text), false, `${script} names the coin ${coin}`);
  }
}
// The labels and details of every self-check report, failures included, name no coin and carry
// no vector.
const reportTexts = reports.flatMap((report) =>
  report.components.flatMap(({ label, detail }) => [label, detail ?? ""])
);
assert.ok(reportTexts.includes("address 3 of 18 stops with INVALID_ADDRESS"));
for (const text of reportTexts) {
  for (const coin of coinNames) {
    const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
    assert.equal(pattern.test(text), false, `the report text "${text}" names the coin ${coin}`);
  }
  for (const vector of VECTOR_TEXTS) {
    assert.equal(text.includes(vector), false, `the report text "${text}" carries ${vector}`);
  }
}

// Every file of the other build carries that build: its WebAssembly is refused by this worker,
// its Argon2 build too, and part 4b gives its class file this runtime.
const otherWasm = readOtherBuild("runtime/mhfe.wasm");
assert.deepEqual(otherWasm.subarray(0, unstamped.length), unstamped, "the same WebAssembly");
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
        message: workerMismatch("runtime/mhfe.wasm", OTHER_BUILD_ID),
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
        message: workerMismatch("core/argon2-st.js", OTHER_BUILD_ID),
      },
    },
  ],
);
console.log("No script names a coin, no report carries a vector, and another build is refused.");
