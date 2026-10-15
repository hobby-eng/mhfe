// Preserve the published runtime/core paths while reviewing their source modules separately.
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { browserSource } from "./browser-source.mjs";
import { scriptArguments } from "./gate-command-line.mjs";

const {
  positionals: [destination],
} = scriptArguments("usage: node scripts/build-browser-sources.mjs <package folder>", {
  operands: 1,
});
for (const [name, path] of [
  ["runtime", "runtime/runtime.js"],
  ["client", "core/client.js"],
]) {
  writeFileSync(join(destination, path), browserSource(name));
}
