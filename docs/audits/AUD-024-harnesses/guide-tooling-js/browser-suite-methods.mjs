// AUD-024, role guide-tooling-js: does the real-browser suite (scripts/verify-browsers.mjs, whose
// page code is scripts/browser-check/) call every public method of the browser package's classes?
// CORE-33 of the coding guide: "A feature has its case in the browser regression suite". The page
// code of that suite calls the classes only, never the WebAssembly bindings, so a call
// `.<method>(` there is a call of a class method.
//
// The harness reads the methods (constructors aside) that the four module classes a page uses,
// MhfeClient, MhfeRepair, MhfePasswords and MhfeWallet, declare in web/*.d.ts, with those of their
// base MhfeModuleClass in web/runtime.d.ts, and counts their calls in
// scripts/browser-check/*.mjs, and, for information, in scripts/package-check/*.mjs (where a call
// may also be one of the raw bindings, such as core.keepOldContainer). Reads only.
//
//   node docs/audits/AUD-024-harnesses/guide-tooling-js/browser-suite-methods.mjs
//
// Exit 0 when the browser suite calls every declared method; exit 1 when it misses one.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const repo = process.cwd();
const read = (path) => readFileSync(join(repo, path), "utf8");
const textOf = (folder) =>
  readdirSync(join(repo, folder))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => read(`${folder}/${name}`))
    .join("\n");
const browserSuite = textOf("scripts/browser-check");
const packageCheck = textOf("scripts/package-check");

const CLASSES = ["MhfeClient", "MhfeRepair", "MhfePasswords", "MhfeWallet", "MhfeModuleClass"];
const declared = [];
for (const file of ["client.d.ts", "repair.d.ts", "passwords.d.ts", "wallet.d.ts", "runtime.d.ts"]) {
  let current = null;
  for (const line of read(`web/${file}`).split("\n")) {
    const opened = /^export (?:declare )?class (\w+)/u.exec(line);
    if (opened) current = CLASSES.includes(opened[1]) ? opened[1] : null;
    else if (line.startsWith("}")) current = null;
    const method = current && /^ {2}(?:async )?([a-z]\w*)\(/u.exec(line);
    if (method && method[1] !== "constructor") declared.push([current, method[1], file]);
  }
}
const count = (text, name) => text.split(`.${name}(`).length - 1;
let failed = false;
for (const [owner, method, file] of declared) {
  const inBrowser = count(browserSuite, method);
  const inPackage = count(packageCheck, method);
  if (inBrowser === 0) failed = true;
  console.log(
    `${inBrowser > 0 ? "ok  " : "FAIL"} ${owner}.${method}() (web/${file}): ${inBrowser} calls in ` +
      `the browser suite, ${inPackage} calls of that name in the package check`,
  );
}
console.log(
  failed
    ? "The browser suite does not call every declared method."
    : "The browser suite calls every declared method.",
);
process.exit(failed ? 1 : 0);
