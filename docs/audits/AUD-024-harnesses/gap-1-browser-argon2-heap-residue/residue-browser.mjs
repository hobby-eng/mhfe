// AUD-024 gap-1-browser-argon2-heap-residue: the same residue search as residue-node.mjs, in a real
// browser worker (Playwright's Chromium and Firefox), at reduced cost, with public data only.
//
// The page is served by page.route() with the COOP and COEP headers of fast mode, so it is
// cross-origin isolated without a listening socket. Its Blob worker holds dist/core/argon2-mt.js (or
// argon2-st.js) of b6fca69 and web/argon2-engine.js, as runtime/worker.js places them, and the lane
// workers run argon2-mt.js from a Blob, as web/core-worker.js passes it (mainScriptUrlOrBlob). The
// worker runs a "secret" derive and then the 1 MiB known answer through the bridge, searches its
// own Emscripten heap for each lane's last block (computed by ./blocks, passed in), and returns
// what it found; the tag is rebuilt here from those heap bytes with Python's hashlib.
//
//   node residue-browser.mjs <repository root> [memory KiB]
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = process.argv[2] ?? process.cwd();
const KIB = Number(process.argv[3] ?? 32768);
const require = createRequire(join(ROOT, "package.json"));
const { chromium, firefox } = require("playwright");

const read = (path) => readFileSync(join(ROOT, path), "utf8");
const scripts = {
  mt: read("dist/core/argon2-mt.js"),
  st: read("dist/core/argon2-st.js"),
  bridge: read("web/argon2-engine.js"),
};
const hex = (text) => Buffer.from(text).toString("hex");
const PASSWORD = "aud024 gap1 browser secret password";
const SALT = "aud024gap1salt16";
const ref = JSON.parse(
  execFileSync(process.env.MHFE_BLOCKS ?? join(here, "blocks"), [hex(PASSWORD), hex(SALT), String(KIB), "1"]).toString(),
);

// Runs in the Blob worker, after the Argon2 build and the bridge.
const workerProbe = `
const threads = [];
let currentModule = null, currentCall = "none";
if (typeof Worker === "function") {
  const post = Worker.prototype.postMessage;
  Worker.prototype.postMessage = function (message, transfer) {
    if (message && message.cmd === 2 && currentModule) {
      const view = new DataView(currentModule.HEAPU8.buffer);
      const ptr = message.pthread_ptr >>> 0;
      const high = view.getUint32(ptr + 48, true), size = view.getUint32(ptr + 52, true);
      threads.push({ call: currentCall, low: high - size, high });
    }
    return post.call(this, message, transfer);
  };
}
const fromHex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
self.onmessage = async ({ data }) => {
  try {
    const module = data.threaded
      ? await createArgon2Mt({ mainScriptUrlOrBlob: data.laneScript })
      : await createArgon2St();
    currentModule = module;
    const engine = argon2Engine(module);
    const enc = new TextEncoder();
    const key = new Uint8Array(32);
    currentCall = "secret";
    engine.derive(enc.encode(data.password), enc.encode(data.salt), data.kib, 1, key);
    const kat = new Uint8Array(32);
    currentCall = "known answer";
    engine.derive(enc.encode("public test password"), enc.encode("0123456789abcdef"), 1024, 1, kat);
    const heap = module.HEAPU8;
    const words = new BigUint64Array(heap.buffer, 0, Math.floor(heap.length / 8));
    const lanes = data.last.map((h) => {
      const block = fromHex(h);
      const want = new DataView(block.buffer).getBigUint64(0, true);
      const blockWords = new BigUint64Array(block.buffer);
      const found = [];
      for (let i = 0; i + 256 <= words.length; i++) {
        if ((words[i] ^ words[i + 128]) === want) {
          let whole = true;
          for (let k = 0; k < 128 && whole; k++) whole = (words[i + k] ^ words[i + 128 + k]) === blockWords[k];
          if (whole) found.push({ kind: "xor-pair", at: i * 8 });
        }
        if (words[i] === want) {
          let whole = true;
          for (let k = 0; k < 128 && whole; k++) whole = words[i + k] === blockWords[k];
          if (whole) found.push({ kind: "copy", at: i * 8 });
        }
      }
      return found.map((f) => {
        const t = threads.findLast((u) => f.at >= u.low && f.at < u.high);
        return { ...f, stack: t ? { call: t.call, fromTop: t.high - f.at } : null };
      });
    });
    let x = null;
    if (lanes.every((l) => l.length > 0)) {
      x = new Uint8Array(1024);
      for (const l of lanes) {
        const { kind, at } = l[0];
        for (let k = 0; k < 1024; k++) x[k] ^= kind === "copy" ? heap[at + k] : heap[at + k] ^ heap[at + 1024 + k];
      }
    }
    self.postMessage({
      crossOriginIsolated: self.crossOriginIsolated,
      threadsStarted: threads.length,
      threadsOfSecret: threads.filter((t) => t.call === "secret").length,
      heapBytes: heap.length,
      key: Array.from(key, (b) => b.toString(16).padStart(2, "0")).join(""),
      kat: Array.from(kat, (b) => b.toString(16).padStart(2, "0")).join(""),
      lanes,
      x: x && Array.from(x, (b) => b.toString(16).padStart(2, "0")).join(""),
    });
  } catch (error) {
    self.postMessage({ error: String(error && error.stack || error) });
  }
};
`;

const pageScript = `
window.runProbe = (threaded, password, salt, kib, last) => new Promise((resolve) => {
  const s = ${JSON.stringify(scripts)};
  const laneScript = new Blob([s.mt], { type: "text/javascript" });
  const source = [threaded ? s.mt : s.st, s.bridge, ${JSON.stringify(workerProbe)}].join("\\n;\\n");
  const worker = new Worker(URL.createObjectURL(new Blob([source], { type: "text/javascript" })));
  worker.onmessage = ({ data }) => { worker.terminate(); resolve(data); };
  worker.onerror = (e) => resolve({ error: "worker error: " + e.message });
  worker.postMessage({ threaded, laneScript, password, salt, kib, last });
});
`;
const page = `<!doctype html><html><head><meta charset="utf-8"><title>probe</title></head>
<body><script>${pageScript}</script></body></html>`;

const hPrime32 = (x) =>
  execFileSync("python3", [
    "-c",
    "import sys,hashlib;print(hashlib.blake2b(bytes.fromhex(sys.argv[1]),digest_size=32).hexdigest())",
    `20000000${x}`,
  ])
    .toString()
    .trim();

const ADDRESS = "http://mhfe-probe.localhost/";
const out = { memoryKib: KIB, referenceTag: ref.tag, runs: [] };
for (const [name, type] of [
  ["chromium", chromium],
  ["firefox", firefox],
]) {
  const browser = await type.launch();
  try {
    const context = await browser.newContext();
    const tab = await context.newPage();
    const requests = [];
    tab.on("request", (r) => requests.push(r.url()));
    await tab.route("**/*", (route) =>
      route.request().url() === ADDRESS
        ? route.fulfill({
            status: 200,
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Cross-Origin-Opener-Policy": "same-origin",
              "Cross-Origin-Embedder-Policy": "require-corp",
            },
            body: page,
          })
        : route.abort(),
    );
    await tab.goto(ADDRESS);
    const version = browser.version();
    for (const threaded of [true, false]) {
      const result = await tab.evaluate(
        ([t, p, s, k, l]) => window.runProbe(t, p, s, k, l),
        [threaded, PASSWORD, SALT, KIB, ref.last],
      );
      const rebuilt = result.x ? hPrime32(result.x) : null;
      out.runs.push({
        browser: `${name} ${version}`,
        build: threaded ? "argon2-mt.js (threaded)" : "argon2-st.js (single-threaded)",
        pageCrossOriginIsolated: await tab.evaluate(() => self.crossOriginIsolated),
        ...result,
        x: undefined,
        keyEqualsReferenceTag: result.key === ref.tag,
        knownAnswerOk: result.kat === "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2",
        tagRebuiltFromHeapAfterKnownAnswer: rebuilt === null ? "not every lane found" : rebuilt === result.key,
        requestsOtherThanPageAndBlobs: requests.filter((u) => u !== ADDRESS && !u.startsWith("blob:")),
      });
    }
  } finally {
    await browser.close();
  }
}
process.stdout.write(`${JSON.stringify(out, null, 1)}\n`);
// The check: no run may let the key be rebuilt from the heap after the known answer. Exit 1 when
// any does, in any browser or build.
const rebuilt = out.runs.filter((r) => r.tagRebuiltFromHeapAfterKnownAnswer === true || r.error);
for (const r of rebuilt) console.error(`FAIL ${r.browser}, ${r.build}: ${r.error ?? "the key is rebuilt from the heap after the known answer"}`);
console.error(rebuilt.length === 0 ? "PASS: nothing rebuilt" : `${rebuilt.length} failing run(s)`);
process.exit(rebuilt.length === 0 ? 0 : 1);
