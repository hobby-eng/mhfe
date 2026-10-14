// AUD-024 gap-1-browser-argon2-heap-residue: the bridge (web/argon2-engine.js) at its edges, over
// both Emscripten builds of b6fca69, at reduced cost with public data: _malloc(0), an empty password
// (which the core refuses before Argon2 as EMPTY_PASSWORD, so only reachable through the bridge),
// the error codes the reference code returns for inputs it refuses, and that a failed call leaves
// no copy of the password in the heap.
//   node bridge-edges.mjs <repository root>
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = process.argv[2] ?? process.cwd();
const pkg = await import(pathToFileURL(join(ROOT, "scripts/package-check/package.mjs")).href);
const enc = new TextEncoder();
const hex = (b) => Buffer.from(b).toString("hex");
const out = {};
for (const build of ["threaded", "single-threaded"]) {
  const module = await pkg.builds[build]();
  const engine = pkg.argon2Engine(module);
  const zero = module._malloc(0) >>> 0;
  module._free(zero);
  const key = new Uint8Array(32);
  const salt = enc.encode("0123456789abcdef");
  engine.derive(new Uint8Array(0), salt, 1024, 1, key);
  const reference = JSON.parse(
    execFileSync(process.env.MHFE_BLOCKS ?? join(here, "..", "blocks"), ["", hex(salt), "1024", "1"]).toString(),
  ).tag;
  const refusals = {};
  const password = enc.encode("aud024 gap1 refused-call password");
  for (const [name, args] of Object.entries({
    "salt of 7 bytes": [password, enc.encode("1234567"), 1024, 1],
    "16 KiB, below 8 blocks per lane": [password, salt, 16, 1],
    "0 passes": [password, salt, 1024, 0],
    "4 GiB (above the 32-bit limit of 2 GiB)": [password, salt, 4194304, 1],
  })) {
    try {
      engine.derive(...args, new Uint8Array(32));
      refusals[name] = "no error";
    } catch (error) {
      refusals[name] = String(error.message);
    }
  }
  const heap = Buffer.from(module.HEAPU8.buffer, 0, module.HEAPU8.length);
  out[build] = {
    malloc0: zero,
    emptyPasswordKey: hex(key),
    emptyPasswordReference: reference,
    emptyPasswordEqual: hex(key) === reference,
    refusals,
    passwordCopiesAfterRefusals: heap.indexOf(Buffer.from(password)) === -1 ? 0 : "found",
  };
}
console.log(JSON.stringify(out, null, 1));
process.exit(0);
