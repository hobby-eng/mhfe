// The browser package under test, as the parts of scripts/verify-browser-package.mjs share it: the
// bindings of its WebAssembly through its own wasm-bindgen glue, the page's Argon2 bridge over
// both Emscripten builds, the core's operations with named arguments, and the stand-ins the checks
// pass for the page's callbacks and its random source.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";

import { encode, noBytes } from "./test-values.mjs";

const require = createRequire(import.meta.url);
/** The repository's root folder. */
export const root = new URL("../../", import.meta.url);
/** The bytes of the file at `path` from the repository's root. */
export const read = (path) => readFileSync(new URL(path, root));
/** The release version of Cargo.toml, which every part of the package states. */
export const VERSION = /^version = "([^"]+)"/mu.exec(read("Cargo.toml").toString())[1];
/** The build stamped into the package, as dist/modules.json names it. */
export const BUILD_ID = JSON.parse(read("dist/modules.json").toString()).buildId;
/** Does nothing: a callback whose calls a check does not watch. */
export const noop = () => {};

// The package's wasm-bindgen glue defines the global `mhfe`, the bindings of every module.
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
/** The bindings of every module of the package's WebAssembly, the instance the parts share. */
export const bindings = vm.runInThisContext("mhfe");
/** The memory of that instance, in which no secret may stay. */
export const coreMemory = bindings.initSync({ module: read("dist/runtime/mhfe.wasm") }).memory;
const glue = read("target/wasm-bindgen/mhfe.js").toString();
/** The package's WebAssembly, the bytes of runtime/mhfe.wasm. */
export const packageWasm = read("dist/runtime/mhfe.wasm");
/** A fresh instance of the package's bindings over `wasm`, and its memory. */
export function instanceOver(wasm) {
  // The glue's text, run again as a page runs it, gives an instance of its own.
  // oxlint-disable-next-line typescript/no-implied-eval -- the package's own glue text
  const fresh = new Function(`${glue}\nreturn mhfe;`)();
  const { memory } = fresh.initSync({ module: wasm });
  return { instance: fresh, memory };
}
/** A new instance of the package's bindings over `wasm`, apart from the shared one. */
export const bindingsOver = (wasm) => instanceOver(wasm).instance;

vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
/** The page's Argon2 bridge (web/argon2-engine.js): an Argon2 engine over an Emscripten build. */
export const argon2Engine = vm.runInThisContext("argon2Engine");
/** Both Emscripten builds of Argon2 by the names printed, each a function that starts one. */
export const builds = {
  threaded: require("../../dist/core/argon2-mt.js"),
  "single-threaded": require("../../dist/core/argon2-st.js"),
};
/** The single-threaded build as it is, which the checks' own Argon2 engines wrap. */
export const realArgon2 = argon2Engine(await builds["single-threaded"]());
/** The core's facts, whose limits every file of the package shares. */
export const parameters = JSON.parse(bindings.suiteParameters());

/** The core module's bindings: the bindings of the package's one WebAssembly. */
const core = bindings;
/**
 * The positional arguments of the core's operations, from named ones. encrypt's phrase goes as its
 * UTF-8 bytes, as the worker passes it. encrypt's walletHasPassphrase is false only when the
 * options leave it out: one given as undefined or null reaches the core as it is, which then names
 * any passphrase of the wallet in what to keep.
 */
export const operations = {
  encrypt: (phrase, password, argon2, options = {}) =>
    JSON.parse(
      core.encrypt(
        encode(phrase),
        password,
        options.repeat ?? password.slice(),
        options.choice ?? "",
        options.position ?? 0,
        options.pim ?? 0,
        options.memoryLevel ?? 0,
        options.sameLength ?? false,
        options.repairWordCount ?? 0,
        Object.hasOwn(options, "walletHasPassphrase") ? options.walletHasPassphrase : false,
        argon2,
        options.onRound ?? (() => {}),
        options.onUnverified ?? (() => {}),
      ),
    ),
  decrypt: (container, password, argon2, options = {}) =>
    JSON.parse(
      core.decrypt(
        container,
        password,
        options.choice ?? "",
        options.position ?? 0,
        options.pim ?? 0,
        options.memoryLevel ?? 0,
        options.words ?? 0,
        encode(options.passphrase ?? ""),
        argon2,
        options.onRound ?? (() => {}),
      ),
    ),
  // The worker's check: one recovery in a session, then the comparison.
  check: (container, password, argon2, kind, reference, options = {}) => {
    const coin = options.coin ?? "";
    const path = options.path ?? "";
    const passphrase = options.passphrase ?? noBytes();
    const copy = passphrase.slice();
    const session = new core.CheckSession(
      container,
      password,
      "",
      0,
      options.pim ?? 0,
      0,
      kind,
      reference,
      coin,
      path,
      passphrase,
      argon2,
      options.onRound ?? (() => {}),
    );
    try {
      return JSON.parse(session.compare(kind, reference, coin, path, copy));
    } finally {
      session.free();
    }
  },
};

/**
 * drawPhrase of the WebAssembly with no chosen words, no places and no words never to use, as a
 * draw without wishes passes them.
 */
export const drawWithoutWishes = (
  instance,
  passphrase,
  repeat,
  walletCheck,
  random,
  onDraws = noop,
) =>
  instance.drawPhrase(
    passphrase,
    repeat,
    noBytes(),
    new Float64Array(),
    "",
    walletCheck,
    random,
    onDraws,
  );

let counter = 0;
/** A deterministic stand-in for crypto.getRandomValues, one sequence for every part. */
export const testRandom = {
  fill: (bytes) => {
    for (let index = 0; index < bytes.length; index += 1) {
      counter = (counter * 1664525 + 1013904223) >>> 0;
      bytes[index] = counter >>> 24;
    }
  },
};
