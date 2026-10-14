// AUD-024 gap-1-browser-argon2-heap-residue: searches both Emscripten builds' heaps, after a secret
// derive through the bridge and after the 1 MiB known answer that follows, for H0 (RFC 9106 3.2:
// the 64-byte BLAKE2b of the parameters, password and salt, from which the call's output follows
// without the password) and for its first 16 bytes, computed with Python's hashlib.
//   node h0-search.mjs <repository root>
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.argv[2] ?? process.cwd();
const pkg = await import(pathToFileURL(join(ROOT, "scripts/package-check/package.mjs")).href);
const le32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const password = Buffer.from("aud024 gap1 h0 secret password");
const salt = Buffer.from("aud024gap1h0salt");
const kib = 32768;
const input = Buffer.concat([
  le32(4), le32(32), le32(kib), le32(1), le32(0x13), le32(2),
  le32(password.length), password, le32(salt.length), salt, le32(0), le32(0),
]);
const h0 = Buffer.from(
  execFileSync("python3", [
    "-c",
    "import sys,hashlib;print(hashlib.blake2b(bytes.fromhex(sys.argv[1])).hexdigest())",
    input.toString("hex"),
  ]).toString().trim(),
  "hex",
);
const result = {};
for (const build of ["threaded", "single-threaded"]) {
  const module = await pkg.builds[build]();
  const engine = pkg.argon2Engine(module);
  const count = (needle) => {
    const heap = Buffer.from(module.HEAPU8.buffer, 0, module.HEAPU8.length);
    let n = 0;
    for (let at = heap.indexOf(needle); at !== -1; at = heap.indexOf(needle, at + 1)) n += 1;
    return n;
  };
  engine.derive(new Uint8Array(password), new Uint8Array(salt), kib, 1, new Uint8Array(32));
  const afterSecret = { h0: count(h0), h0First16: count(h0.subarray(0, 16)), password: count(password) };
  engine.derive(Buffer.from("public test password"), Buffer.from("0123456789abcdef"), 1024, 1, new Uint8Array(32));
  const afterKnownAnswer = { h0: count(h0), h0First16: count(h0.subarray(0, 16)), password: count(password) };
  result[build] = { afterSecret, afterKnownAnswer };
}
console.log(JSON.stringify(result));
process.exit(0);
