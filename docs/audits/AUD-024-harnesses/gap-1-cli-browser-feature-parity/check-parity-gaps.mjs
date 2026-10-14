// AUD-024, role gap-1-cli-browser-feature-parity, commit b6fca69: the gaps between the command-line
// tool and the browser package that the audit found, each as a check that passes once the gap is
// closed. Run from the repository root:
//
//   node docs/audits/AUD-024-harnesses/gap-1-cli-browser-feature-parity/check-parity-gaps.mjs [mhfe]
//
// [mhfe] is a release or debug build of the same commit (default target/release/mhfe). The
// browser bindings are read from target/wasm-bindgen/mhfe.js and dist/runtime/mhfe.wasm, as
// scripts/build-wasm.sh writes them. Nothing runs Argon2: the program is asked only for --help.
// Prints one line per check and exits 1 if any fails.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const program = process.argv[2] ?? "target/release/mhfe";
const read = (path) => readFileSync(path, "utf8");
let failed = 0;
const report = (ok, name, detail) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `: ${detail}`}`);
  if (!ok) failed += 1;
};

// C1: a rekey confirmed by an address takes the address's coin and one path on the command line,
// as MhfeClient.rekey()'s confirmation { address, coin, path } does (rekey.rs Options).
const help = spawnSync(
  program,
  ["rekey", "--confirm", "address", "--coin", "bitcoin", "--path", "m/84'/0'/0'/0/0", "--help"],
  { env: { ...process.env, NO_COLOR: "1" }, encoding: "utf8", stdin: "ignore" },
);
report(
  help.status === 0,
  "C1 mhfe rekey takes --coin and --path",
  `exit ${help.status}: ${(help.stderr ?? "").trim().split("\n")[0]}`,
);

// C2: the core's fixed values give a page the wallet check's size, so that a check that is not
// verified can say how often a wrong password passes it, as mhfe check does.
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js"), { filename: "mhfe.js" });
const mhfe = vm.runInThisContext("mhfe");
mhfe.initSync({ module: readFileSync("dist/runtime/mhfe.wasm") });
const core = JSON.parse(mhfe.suiteParameters());
report(
  "walletCheckBits" in core || "walletCheckOdds" in core,
  "C2 MhfeClient.parameters() gives the wallet check's bits or odds",
  `keys ${Object.keys(core).join(", ")}`,
);

// C3: the page's duty about a same-length container names a mistyped setting too (mhfe_spec
// README.md: "a mistyped password or setting is not detected").
const page = read("docs/BROWSER-PACKAGE.md");
const duties = page.slice(page.indexOf("## What the page should do"));
const bullet = duties.slice(duties.indexOf("- offer the container length"));
const sameLength = bullet.slice(0, bullet.indexOf("\n- ", 2));
report(
  /setting|PIM|memory level/u.test(sameLength),
  "C3 BROWSER-PACKAGE.md says a same-length container does not detect a mistyped setting",
  JSON.stringify(sameLength.replace(/\s+/gu, " ").slice(0, 160)),
);

// C4: the rekey of the browser package can tell the other lengths that detection would read
// before it seals the new container, as mhfe rekey warns of them before the new password.
const declaration = read("web/client.d.ts");
const rekeyStart = declaration.indexOf("  rekey(");
const rekeyOptions = declaration.slice(rekeyStart, declaration.indexOf("  ): Promise<", rekeyStart));
report(
  rekeyOptions.includes("otherLengths"),
  "C4 MhfeClient.rekey() gives the other detected lengths before the seal",
  "no otherLengths among rekey()'s options and callbacks in web/client.d.ts",
);

// C5: mhfe check lists the phrase's own checks that passed beside "does not match" too, as the
// browser's evidence.passed does (check.rs report()).
const check = read("src/bin/mhfe/check.rs");
const arm = check.slice(check.indexOf("CheckOutcome::DoesNotMatch => {"));
const doesNotMatch = arm.slice(0, arm.indexOf("\n        }\n"));
report(
  doesNotMatch.includes("passed()"),
  "C5 mhfe check lists the checks that passed beside \"does not match\"",
  "the DoesNotMatch arm of report() prints no passed check",
);

console.log(failed === 0 ? "Every check passes." : `${failed} check(s) fail.`);
process.exit(failed === 0 ? 0 : 1);
