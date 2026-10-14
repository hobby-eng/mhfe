// Checks the built browser package with Node.js; the detailed runner is in package-check/checks.mjs.
//
//   node scripts/verify-browser-package.mjs [--full]
//
// --full adds one full-size encryption; the default keeps reduced-cost checks.
import { scriptArguments } from "./gate-command-line.mjs";

const { values } = scriptArguments("usage: node scripts/verify-browser-package.mjs [--full]", {
  options: { full: { type: "boolean" } },
});
const { checkBrowserPackage } = await import("./package-check/checks.mjs");
await checkBrowserPackage(values.full === true);
// The threaded build keeps its lane workers alive; end the process explicitly.
process.exit(0);
