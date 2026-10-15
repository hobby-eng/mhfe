// The source JavaScript must pass the same lexical tripwire as generated package files.
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { browserSource } from "./browser-source.mjs";
import { runGate, reported } from "./gate-command-line.mjs";
import { checkNetworkCodeList, networkCodeIn } from "./network-code.mjs";

const folder = new URL("../web/", import.meta.url);
runGate("Usage: node scripts/verify-network-code.mjs [--self-test]", {
  selfTest: checkNetworkCodeList,
  check: () => {
    const bundled = new Map([
      ["runtime.js", browserSource("runtime")],
      ["client.js", browserSource("client")],
    ]);
    // Check each complete shipped scope once, with its one reviewed Blob Worker site. Unwired
    // source files are still scanned individually; moving a file cannot remove it from review.
    const covered = new Set(
      [...bundled.values()].flatMap((source) =>
        [...source.matchAll(/^\/\/ Source: (.+)$/gmu)].map((match) => match[1]),
      ),
    );
    const found = readdirSync(folder, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
      .map((entry) =>
        relative(fileURLToPath(folder), join(entry.parentPath, entry.name)).replaceAll("\\", "/"),
      )
      .filter((name) => bundled.has(name) || !covered.has(name))
      .flatMap((name) => {
        const pattern = networkCodeIn(
          bundled.get(name) ?? readFileSync(new URL(name, folder), "utf8"),
          name === "runtime.js" ? "runtime" : undefined,
        );
        return pattern === undefined ? [] : [`web/${name}: forbidden construct ${pattern}`];
      });
    return reported(
      found,
      () => "The source JavaScript failed the lexical network tripwire.",
      "The source JavaScript passes the lexical network tripwire.",
    );
  },
});
