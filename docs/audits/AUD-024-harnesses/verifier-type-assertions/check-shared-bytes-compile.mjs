// AUD-024 verifier harness (review only): web/runtime.js:98-100 casts the page's Uint8Array to
// BufferSource and says that "WebAssembly.compile checks that itself and rejects" bytes over a
// SharedArrayBuffer. This asks Node.js and the Playwright Chromium and Firefox of the repository's
// node_modules whether WebAssembly.compile rejects such bytes. Exit 0 when every engine rejects
// them (the comment holds), 1 when one compiles them (the named check does not exist there).
// The bytes are the 8-byte empty module header; no network, no package code.
import { createRequire } from "node:module";

const require = createRequire(`${process.cwd()}/package.json`);
const { chromium, firefox } = require("playwright");

const probe = async () => {
  // A shared WebAssembly.Memory gives a SharedArrayBuffer without cross-origin isolation.
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
  const kind = Object.prototype.toString.call(memory.buffer);
  const bytes = new Uint8Array(memory.buffer, 0, 8);
  bytes.set([0, 97, 115, 109, 1, 0, 0, 0]);
  try {
    const module = await WebAssembly.compile(bytes);
    return { rejected: false, line: `${kind} view: compiled (${module instanceof WebAssembly.Module})` };
  } catch (error) {
    return { rejected: true, line: `${kind} view: rejected ${error.name}: ${error.message}` };
  }
};

let compiled = 0;
const node = await probe();
console.log(`node ${process.version}: ${node.line}`);
if (!node.rejected) compiled += 1;
for (const [name, engine] of [
  ["chromium", chromium],
  ["firefox", firefox],
]) {
  const browser = await engine.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent("<!doctype html><title>probe</title>");
    const result = await page.evaluate(probe);
    console.log(`${name} ${browser.version()}: ${result.line}`);
    if (!result.rejected) compiled += 1;
  } finally {
    await browser.close();
  }
}
console.log(
  compiled === 0
    ? "every engine rejects bytes over a SharedArrayBuffer, as web/runtime.js:98-99 says"
    : `${compiled} engine(s) compile bytes over a SharedArrayBuffer: the check named at web/runtime.js:98-99 does not happen there`,
);
process.exit(compiled === 0 ? 0 : 1);
