// Part 4 of the checks of the browser package (scripts/verify-browser-package.mjs): the page-side
// classes, loaded as a page loads them, with what every page-side check gives them.
//
// The classes are ES modules that import "../runtime/runtime.js". The nearest package.json, the
// repository's tooling, cannot declare "type": "module" (the Emscripten builds are CommonJS), so
// each is imported as text with that import pointed at the runtime's text.
import assert from "node:assert/strict";

import { bundleClasses } from "../bundle-browser-classes.mjs";
import { parameters, read, root } from "./package.mjs";

/** The runtime's text as a module address, which each class file's import is pointed at. */
export const runtimeUrl = `data:text/javascript;base64,${read("dist/runtime/runtime.js").toString("base64")}`;
/** Imports the class file `text` with its import of the runtime pointed at the runtime's text. */
export const importClassText = (text) =>
  import(
    `data:text/javascript;base64,${Buffer.from(
      text.replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`),
    ).toString("base64")}`
  );
/** Imports the package's class file at `path`. */
const importClass = (path) => importClassText(read(path).toString());

/**
 * Loads the classes of the package: as one module, as a page that inlines the package joins them,
 * and each file alone, whose declarations name only values it exports. Gives the classes.
 */
export async function loadClasses() {
  // A page that inlines the package joins the runtime and its classes into one module, as
  // scripts/bundle-browser-classes.mjs does; their top-level names must not collide.
  const joined = bundleClasses(root, [
    "core/client.js",
    "repair/repair.js",
    "passwords/passwords.js",
    "wallet/wallet.js",
  ]);
  await import(`data:text/javascript;base64,${Buffer.from(joined).toString("base64")}`).catch(
    (error) => {
      throw new Error(`The classes do not join into one module: ${error.message}`);
    },
  );
  const { MhfeClient, MhfeCancelledError, MhfeError } = await importClass("dist/core/client.js");
  const { MhfeRepair } = await importClass("dist/repair/repair.js");
  const { MhfePasswords } = await importClass("dist/passwords/passwords.js");
  const { MhfeWallet } = await importClass("dist/wallet/wallet.js");

  // Every value a declaration file exports exists in its module, so that a named import that
  // TypeScript accepts also links.
  const runtimeNamespace = await import(runtimeUrl);
  for (const [declarations, namespace] of [
    ["dist/runtime/runtime.d.ts", runtimeNamespace],
    ["dist/core/client.d.ts", await importClass("dist/core/client.js")],
    ["dist/repair/repair.d.ts", await importClass("dist/repair/repair.js")],
    ["dist/passwords/passwords.d.ts", await importClass("dist/passwords/passwords.js")],
    ["dist/wallet/wallet.d.ts", await importClass("dist/wallet/wallet.js")],
  ]) {
    const text = read(declarations).toString();
    const declared = [
      ...[...text.matchAll(/^export (?:declare )?(?:class|const|function) (\w+)/gmu)].map(
        (match) => match[1],
      ),
      ...[...text.matchAll(/^export \{([^}]*)\} from/gmu)].flatMap((match) =>
        match[1]
          .split(",")
          .map((name) => name.trim())
          .filter((name) => name !== "" && !name.startsWith("type ")),
      ),
    ];
    for (const name of declared) {
      assert.ok(name in namespace, `${declarations} declares ${name}, which its module lacks`);
    }
  }
  return {
    MhfeClient,
    MhfeCancelledError,
    MhfeError,
    MhfeRepair,
    MhfePasswords,
    MhfeWallet,
    runtime: runtimeNamespace,
  };
}

/** The client's own limits, checked before any secret is copied, equal the core's. */
export function checkClientLimits() {
  const clientText = read("dist/core/client.js").toString();
  const clientConstant = (name) =>
    JSON.parse(new RegExp(`^const ${name} = (.+);$`, "mu").exec(clientText)[1]);
  assert.equal(clientConstant("MAX_PIM"), parameters.maxPim);
  assert.equal(clientConstant("MAX_MEMORY_LEVEL"), parameters.maxMemoryLevel);
  assert.equal(
    clientConstant("HIGHEST_BROWSER_MEMORY_LEVEL"),
    parameters.highestBrowserMemoryLevel,
  );
  assert.deepEqual(clientConstant("WORD_COUNTS"), parameters.wordCounts);
  assert.deepEqual(clientConstant("REPAIR_WORD_COUNTS"), [0, ...parameters.repairWordCounts]);
  assert.deepEqual(clientConstant("BUILT_IN_CHECK_WORD_COUNTS"), parameters.builtInCheckWordCounts);
  assert.equal(clientConstant("DECOY_SCAN_GAP"), parameters.decoyScanGap);
  assert.deepEqual(
    [clientConstant("ARGON2_PART"), clientConstant("ARGON2_SIZES_PART")],
    parameters.argon2Parts,
  );
}

/** A real compiled module, so that the classes' compilation succeeds; the stand-in ignores it. */
export const wasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
/** What a page gives the core client: its worker and Argon2 sources, and the WebAssembly. */
export const sources = {
  workerSource: "worker source",
  wasm,
  argon2Threaded: "threaded source",
  argon2SingleThreaded: "single-threaded source",
};
