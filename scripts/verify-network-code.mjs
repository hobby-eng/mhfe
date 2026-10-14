// The source JavaScript must pass the same lexical tripwire as generated package files.
import { readFileSync, readdirSync } from "node:fs";

import { runGate, reported } from "./gate-command-line.mjs";
import { checkNetworkCodeList, networkCodeIn } from "./network-code.mjs";

const folder = new URL("../web/", import.meta.url);
runGate("Usage: node scripts/verify-network-code.mjs [--self-test]", {
  selfTest: checkNetworkCodeList,
  check: () => {
    const found = readdirSync(folder)
      .filter((name) => name.endsWith(".js"))
      .flatMap((name) => {
        const pattern = networkCodeIn(
          readFileSync(new URL(name, folder), "utf8"),
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
