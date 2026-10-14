// AUD-024 gap-1-browser-argon2-heap-residue: where an Argon2 call's secret-derived bytes stay in the
// Emscripten heap of the browser package's Argon2 builds, at reduced cost, with public data only.
//
// Uses the package as scripts/package-check/package.mjs loads it: dist/core/argon2-mt.js and
// argon2-st.js of b6fca69 through the page's bridge web/argon2-engine.js (argon2Engine), and the
// package's WebAssembly core for whole operations. No offsets are assumed: the heap is searched for
// each lane's last block, computed independently by ./blocks (vendored ref.c built natively with
// FLAG_clear_internal_memory = 0), both as a copy and as the XOR of two adjacent 1024-byte windows
// (ref.c fill_block's blockR and block_tmp: next_block = block_tmp ^ blockR). The tag is then
// rebuilt from the heap bytes alone with Python's hashlib (RFC 9106 3.2/3.3: H'^32 is
// BLAKE2b-256(LE32(32) || XOR of the lanes' last blocks)). The lane stacks are located by hooking
// worker_threads.Worker.prototype.postMessage, which the threaded glue's spawnThread calls with
// { cmd: 2, pthread_ptr }; the stack bounds are read at pthread_ptr + 48 and + 52, where the glue's
// establishStackSpace reads them.
//
//   node residue-node.mjs <repository root> <part: bridge | operations> [memory KiB]
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import worker_threads from "node:worker_threads";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = process.argv[2] ?? process.cwd();
const PART = process.argv[3] ?? "bridge";
const KIB = Number(process.argv[4] ?? 32768);
const pkg = await import(pathToFileURL(join(ROOT, "scripts/package-check/package.mjs")).href);
const values = await import(pathToFileURL(join(ROOT, "scripts/package-check/test-values.mjs")).href);
const data = await import(pathToFileURL(join(ROOT, "scripts/public-test-data.mjs")).href);

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const BLOCK = 1024;

// Lane stacks: every thread the threaded build starts, in order, with the call it belongs to.
let current = { module: null, call: "none" };
const threads = [];
const originalPost = worker_threads.Worker.prototype.postMessage;
worker_threads.Worker.prototype.postMessage = function (message, transfer) {
  if (message && message.cmd === 2 && current.module) {
    const view = new DataView(current.module.HEAPU8.buffer);
    const ptr = message.pthread_ptr >>> 0;
    const high = view.getUint32(ptr + 48, true);
    const size = view.getUint32(ptr + 52, true);
    threads.push({ call: current.call, ptr, low: high - size, high });
  }
  return originalPost.call(this, message, transfer);
};

/** The reference blocks of a call, from the native helper. */
const referenceCache = new Map();
function reference(passwordHex, saltHex, kib, passes) {
  const id = `${passwordHex}/${saltHex}/${kib}/${passes}`;
  if (!referenceCache.has(id)) {
    const out = execFileSync(process.env.MHFE_BLOCKS ?? join(here, "blocks"), [passwordHex, saltHex, String(kib), String(passes)]);
    const parsed = JSON.parse(out.toString());
    referenceCache.set(id, {
      tag: parsed.tag,
      last: parsed.last.map((h) => Buffer.from(h, "hex")),
      inner: parsed.inner.map((h) => Buffer.from(h, "hex")),
    });
  }
  return referenceCache.get(id);
}

/** Where `block` lies in `heap`: copies, and XOR pairs of adjacent windows, at 8-byte steps. */
function locate(heap, block) {
  const words = new BigUint64Array(heap.buffer, 0, Math.floor(heap.length / 8));
  const want = Buffer.from(block).readBigUInt64LE(0);
  const direct = [];
  const pairs = [];
  for (let i = 0; i + 256 <= words.length; i += 1) {
    const a = words[i];
    if (a === want && Buffer.from(heap.buffer, i * 8, BLOCK).equals(block)) direct.push(i * 8);
    if ((a ^ words[i + 128]) === want) {
      let whole = true;
      for (let k = 0; k < 128 && whole; k += 1) {
        whole = (words[i + k] ^ words[i + 128 + k]) === Buffer.from(block).readBigUInt64LE(k * 8);
      }
      if (whole) pairs.push(i * 8);
    }
  }
  return { direct, pairs };
}

/** The most recent lane stack an address lies in, if any, and the call that thread served. */
function stackOf(address) {
  const index = threads.findLastIndex((t) => address >= t.low && address < t.high);
  if (index < 0) return null;
  const t = threads[index];
  const ofCall = threads.filter((u) => u.call === t.call);
  return {
    thread: index,
    call: t.call,
    threadOfCall: `${ofCall.indexOf(t) + 1} of ${ofCall.length}`,
    stackLow: t.low,
    stackHigh: t.high,
    fromTop: t.high - address,
  };
}

/** BLAKE2b-256(LE32(32) || x) with Python's hashlib, an implementation independent of the build. */
function hPrime32(x) {
  return execFileSync("python3", [
    "-c",
    "import sys,hashlib;print(hashlib.blake2b(bytes.fromhex(sys.argv[1]),digest_size=32).hexdigest())",
    Buffer.concat([Buffer.from([32, 0, 0, 0]), x]).toString("hex"),
  ])
    .toString()
    .trim();
}

/** What the heap holds of one call: its lanes' last blocks, the tag rebuilt from them, its inputs. */
function evaluate(module, call) {
  const heap = module.HEAPU8;
  const ref = reference(call.passwordHex, call.saltHex, call.kib, call.passes);
  const lanes = ref.last.map((block) => {
    const where = locate(heap, block);
    return { ...where, at: [...where.direct, ...where.pairs].map((a) => ({ address: a, stack: stackOf(a) })) };
  });
  let rebuilt = null;
  if (lanes.every((l) => l.direct.length + l.pairs.length > 0)) {
    const x = Buffer.alloc(BLOCK);
    for (const l of lanes) {
      const a = l.direct.length > 0 ? l.direct[0] : l.pairs[0];
      for (let k = 0; k < BLOCK; k += 1) {
        x[k] ^= l.direct.length > 0 ? heap[a + k] : heap[a + k] ^ heap[a + BLOCK + k];
      }
    }
    rebuilt = hPrime32(x);
  }
  const bytes = Buffer.from(heap.buffer, 0, heap.length);
  const count = (needle) => {
    let n = 0;
    for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) n += 1;
    return n;
  };
  return {
    call: call.name,
    lanesFound: lanes.map((l) => ({ copies: l.direct.length, xorPairs: l.pairs.length, at: l.at.slice(0, 2) })),
    keyRebuiltFromHeap: rebuilt === null ? "not every lane found" : rebuilt === call.keyHex,
    referenceTagEqualsKey: ref.tag === call.keyHex,
    copiesOfPassword: count(Buffer.from(call.passwordHex, "hex")),
    copiesOfSalt: count(Buffer.from(call.saltHex, "hex")),
    copiesOfKey: count(Buffer.from(call.keyHex, "hex")),
    innerWorkAreaBlocksFound: ref.inner.filter((b) => {
      const where = locate(heap, b);
      return where.direct.length > 0;
    }).length,
  };
}

/** An engine over the bridge that records every call and runs the rounds at `kib`. */
function recording(engine, kib, calls, module) {
  let rounds = 0;
  return {
    derive: (password, salt, memoryKib, passes, key) => {
      const knownAnswer = values.KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`);
      const name = knownAnswer ? `known answer ${memoryKib} KiB` : `round ${(rounds += 1)}`;
      const cost = knownAnswer ? [memoryKib, passes] : [kib, 1];
      current = { module, call: name };
      engine.derive(password, salt, cost[0], cost[1], key);
      calls.push({ name, passwordHex: hex(password), saltHex: hex(salt), kib: cost[0], passes: cost[1], keyHex: hex(key) });
    },
    reserve: () => {},
  };
}

async function bridgePart(build) {
  const module = await pkg.builds[build]();
  const engine = pkg.argon2Engine(module);
  const calls = [];
  const run = (name, password, salt, kib, passes) => {
    current = { module, call: name };
    const key = new Uint8Array(32);
    engine.derive(password, salt, kib, passes, key);
    calls.push({ name, passwordHex: hex(password), saltHex: hex(salt), kib, passes, keyHex: hex(key) });
  };
  const secretSalt = (s) => new Uint8Array(createHash("sha256").update(s).digest().subarray(0, 16));
  const steps = [];
  const snapshot = (after) =>
    steps.push({
      after,
      heapBytes: module.HEAPU8.length,
      calls: calls.filter((c) => !c.name.startsWith("known")).map((c) => evaluate(module, c)),
    });
  const katPassword = new TextEncoder().encode("public test password");
  const katSalt = new TextEncoder().encode("0123456789abcdef");
  run("secret A", new TextEncoder().encode("aud024 gap1 secret password A"), secretSalt("A"), KIB, 1);
  snapshot("secret A");
  run("known answer 1", katPassword, katSalt, 1024, 1);
  snapshot("secret A, then the 1 MiB known answer");
  run("secret B", new TextEncoder().encode("aud024 gap1 secret password B"), secretSalt("B"), KIB, 1);
  snapshot("secret B (same size as A)");
  run("known answer 2", katPassword, katSalt, 1024, 1);
  snapshot("secret B, then the 1 MiB known answer");
  run("secret C (two passes)", new TextEncoder().encode("aud024 gap1 secret password C"), secretSalt("C"), KIB, 2);
  run("known answer 3", katPassword, katSalt, 1024, 1);
  snapshot("secret C at two passes, then the 1 MiB known answer");
  // Where each call's lane stacks lay: the ranges of the threads of its last segment.
  const callNames = [...new Set(threads.map((t) => t.call))];
  const laneStacks = callNames.map((call) => {
    const ofCall = threads.filter((t) => t.call === call);
    return {
      call,
      threads: ofCall.length,
      distinctStackRanges: new Set(ofCall.map((t) => `${t.low}-${t.high}`)).size,
      lastSegment: ofCall.slice(-4).map((t) => [t.low, t.high]),
    };
  });
  return { build, steps, threadsStarted: threads.length, laneStacks };
}

async function operationsPart(build) {
  const module = await pkg.builds[build]();
  const engine = pkg.argon2Engine(module);
  const results = [];
  // 1. An encryption with its rehearsal: 12 rounds, the container, 12 rounds of its check, then
  //    the known answer after the last round (src/wasm_api/core.rs sealed_for_page / verified).
  let calls = [];
  const enc = pkg.operations.encrypt(data.PHRASE, values.PASSWORD, recording(engine, KIB, calls, module));
  const rounds = calls.filter((c) => c.name.startsWith("round"));
  results.push({
    operation: "encrypt (returned, worker not yet terminated)",
    derives: calls.map((c) => c.name),
    roundsWhoseKeyIsRebuilt: rounds.map((c) => ({ c, e: evaluate(module, c) })).filter(({ e }) => e.keyRebuiltFromHeap === true).map(({ c }) => c.name),
    lastRound: evaluate(module, rounds.at(-1)),
    container: enc.container.split(" ").length,
  });
  // 2. A session of hidden wallets on that container, waiting for the page after one wallet.
  calls = [];
  const session = new pkg.bindings.HiddenWalletSession(enc.container, 0, 0, values.noBytes(), recording(engine, KIB, calls, module));
  const opened = JSON.parse(session.open(values.encode("aud024 gap1 hidden wallet password"), values.encode("aud024 gap1 hidden wallet password"), "", 0, () => {}));
  const walletRounds = calls.filter((c) => c.name.startsWith("round"));
  results.push({
    operation: "hidden-wallet session after one wallet, waiting for the page",
    derives: calls.map((c) => c.name),
    roundsWhoseKeyIsRebuilt: walletRounds.map((c) => ({ c, e: evaluate(module, c) })).filter(({ e }) => e.keyRebuiltFromHeap === true).map(({ c }) => c.name),
    lastRound: evaluate(module, walletRounds.at(-1)),
    words: opened.words,
  });
  session.free();
  results.push({
    operation: "the same session after free() (the Rust session dropped, the worker not terminated)",
    lastRound: evaluate(module, walletRounds.at(-1)),
  });
  return { build, memoryKib: KIB, results };
}

const out = [];
for (const build of ["threaded", "single-threaded"]) {
  threads.length = 0;
  out.push(PART === "operations" ? await operationsPart(build) : await bridgePart(build));
}
process.stdout.write(`${JSON.stringify(out, null, 1)}\n`);
// The check: after a call or an operation, no Argon2 output may be rebuilt from the heap and no
// password, salt, key or work-area block may remain. Exit 1 when any build fails it.
const failures = [];
for (const result of out) {
  const evaluations =
    PART === "operations"
      ? result.results.map((r) => ({ where: r.operation, e: r.lastRound, rounds: r.roundsWhoseKeyIsRebuilt ?? [] }))
      : result.steps.flatMap((s) => s.calls.map((e) => ({ where: s.after, e, rounds: [] })));
  for (const { where, e, rounds } of evaluations) {
    const leaks = [];
    if (e.keyRebuiltFromHeap === true) leaks.push(`the key of ${e.call} is rebuilt from the heap`);
    if (rounds.length > 0) leaks.push(`round keys rebuilt: ${rounds.join(", ")}`);
    for (const field of ["copiesOfPassword", "copiesOfSalt", "copiesOfKey", "innerWorkAreaBlocksFound"]) {
      if (e[field] > 0) leaks.push(`${field} ${e[field]}`);
    }
    if (leaks.length > 0) failures.push(`${result.build}, after ${where}: ${[...new Set(leaks)].join("; ")}`);
  }
}
for (const failure of failures) console.error(`FAIL ${failure}`);
console.error(failures.length === 0 ? "PASS: nothing rebuilt or left" : `${failures.length} failing step(s)`);
process.exit(failures.length === 0 ? 0 : 1);
