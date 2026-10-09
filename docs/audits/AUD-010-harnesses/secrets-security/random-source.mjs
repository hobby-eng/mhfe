// AUD-010 secrets-security probe (CHECK-SEC-004, CHECK-SEC-005): the browser package's handling of
// its random source, with bounded stand-ins for crypto.getRandomValues.
//
// Calls the real bindings of runtime/mhfe.wasm (makePassword, drawPhrase without the wallet check,
// selfCheckPasswords and selfCheckWallet at the full tier) with sources that throw, fill nothing,
// repeat a byte, repeat one random block, or fill only part of the buffer, and checks:
//   R1 a source that cannot be random is refused with RANDOM_FAILED before anything is drawn;
//   R2 the full self-check fails its random-source part for a stuck or narrow source and passes
//      with the platform's generator;
//   R3 no draw asks for more than 65,536 bytes at once, the most crypto.getRandomValues fills;
//   R4 a generation that fails midway leaves no part of the password in the linear memory.
// Characterized, not a pass condition: whether a source that fills only half of each buffer is
// noticed (the probe of two 32-byte blocks cannot see it; the worker's source is the browser's own
// crypto.getRandomValues, which fills the whole view or throws).
//
// Exits 1 when R1 to R4 fail.
//
//   node docs/audits/AUD-010-harnesses/secrets-security/random-source.mjs
import { readFileSync } from "node:fs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const glue = read("target/wasm-bindgen/mhfe.js").toString();
const module = new WebAssembly.Module(read("dist/runtime/mhfe.wasm"));
const encode = (text) => new TextEncoder().encode(text);
/** crypto.getRandomValues fills at most this many bytes per call (Web Crypto, QuotaExceededError). */
const GET_RANDOM_VALUES_LIMIT = 65536;

function fresh() {
  const bindings = new Function(`${glue}\nreturn mhfe;`)();
  const { memory } = bindings.initSync({ module });
  return { bindings, memory };
}

const failures = [];
function report(ok, text) {
  console.log(`${ok ? "pass" : "FAIL"} ${text}`);
  if (!ok) failures.push(text);
}

function code(action) {
  try {
    action();
    return "resolved";
  } catch (error) {
    return String(error.message ?? error).split(":")[0];
  }
}

/** Sources, each a fresh `{ fill(bytes) }` that also records the largest request. */
let largest = 0;
const platform = () => ({
  fill(bytes) {
    largest = Math.max(largest, bytes.length);
    globalThis.crypto.getRandomValues(bytes);
  },
});
const SOURCES = {
  throws: () => ({
    fill() {
      throw new Error("synthetic refusal");
    },
  }),
  "fills nothing": () => ({ fill() {} }),
  "repeats one byte value": () => ({ fill: (bytes) => bytes.fill(0x5a) }),
  "repeats one random block": () => {
    const block = globalThis.crypto.getRandomValues(new Uint8Array(32));
    return { fill: (bytes) => bytes.set(block.subarray(0, bytes.length)) };
  },
};

// R1: refused before any draw.
for (const [name, make] of Object.entries(SOURCES)) {
  const { bindings } = fresh();
  const words = code(() => bindings.makePassword("words", 5, new Uint8Array(), make()));
  const characters = code(() => bindings.makePassword("characters", 16, new Uint8Array(), make()));
  const phrase = code(() => bindings.drawPhrase(new Uint8Array(), false, make(), () => {}));
  report(
    [words, characters, phrase].every((result) => result === "RANDOM_FAILED"),
    `R1 a source that ${name}: words ${words}, characters ${characters}, new phrase ${phrase}`,
  );
}

// R2: the full self-checks try the live source.
for (const [set, run] of [
  ["passwords", (m, source) => m.selfCheckPasswords("full", [], source, () => {}, () => {})],
  ["wallet", (m, source) => m.selfCheckWallet("full", [], source, () => {}, () => {})],
]) {
  const outcomeOf = (make) => {
    const report = JSON.parse(run(fresh().bindings, make()));
    const part = report.components.find((component) => component.id === "random-source");
    return `${report.passed ? "passed" : "failed"}/${part?.outcome}`;
  };
  const working = outcomeOf(platform);
  const stuck = outcomeOf(SOURCES["repeats one byte value"]);
  // Sixteen values only: passes the probe of two blocks, not the spread of 1,024 bytes.
  const narrow = outcomeOf(() => ({
    fill(bytes) {
      globalThis.crypto.getRandomValues(bytes);
      for (let i = 0; i < bytes.length; i += 1) bytes[i] &= 0x0f;
    },
  }));
  report(
    working === "passed/passed" && stuck === "failed/failed" && narrow === "failed/failed",
    `R2 ${set} full self-check: platform ${working}, stuck ${stuck}, narrow ${narrow}`,
  );
}

// R3: the largest single request.
{
  const { bindings } = fresh();
  largest = 0;
  bindings.makePassword("words", 32, new Uint8Array(), platform());
  bindings.makePassword("characters", 64, new Uint8Array(), platform());
  bindings.makePassword("checkWord", undefined, new Uint8Array(), platform());
  bindings.drawPhrase(new Uint8Array(), false, platform(), () => {});
  JSON.parse(bindings.selfCheckPasswords("full", [], platform(), () => {}, () => {}));
  JSON.parse(bindings.selfCheckWallet("full", [], platform(), () => {}, () => {}));
  report(
    largest > 0 && largest <= GET_RANDOM_VALUES_LIMIT,
    `R3 largest single request ${largest} bytes (limit ${GET_RANDOM_VALUES_LIMIT})`,
  );
}

// R4: a source that fails midway. A counter source gives the same password each time; the
// probe learns it whole and how many fills it took, then fails the last fill, so that every word or
// character but the last was drawn into the password's buffer before the failure, and looks for
// them in the linear memory.
function counter(failAtCall = Infinity) {
  let state = 0x2545f491;
  const source = {
    calls: 0,
    fill(bytes) {
      source.calls += 1;
      if (source.calls >= failAtCall) throw new Error("synthetic failure midway");
      for (let i = 0; i < bytes.length; i += 1) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        bytes[i] = state >>> 24;
      }
    },
  };
  return source;
}
for (const [kind, count] of [
  ["words", 8],
  ["characters", 40],
]) {
  const learning = counter();
  const made = fresh().bindings.makePassword(kind, count, new Uint8Array(), learning);
  const whole = JSON.parse(String(made)).password;
  const parts = kind === "words" ? whole.split(" ") : [...whole];
  const prefix = parts.slice(0, -1).join(kind === "words" ? " " : "");
  const { bindings, memory } = fresh();
  const result = code(() =>
    bindings.makePassword(kind, count, new Uint8Array(), counter(learning.calls)),
  );
  const found = Buffer.from(memory.buffer).indexOf(Buffer.from(prefix)) !== -1;
  report(
    result === "RANDOM_FAILED" && !found,
    `R4 ${kind} password failing at its last draw: ${result}; its first ${parts.length - 1} ` +
      `${kind} ${found ? "FOUND" : "not found"} in the linear memory`,
  );
}

// Characterized: a source that fills only the first half of each buffer.
{
  const half = () => ({
    fill(bytes) {
      globalThis.crypto.getRandomValues(bytes.subarray(0, Math.ceil(bytes.length / 2)));
    },
  });
  const { bindings } = fresh();
  const characters = code(() => bindings.makePassword("characters", 16, new Uint8Array(), half()));
  const phrase = code(() => bindings.drawPhrase(new Uint8Array(), false, half(), () => {}));
  console.log(
    `info a source that fills half of each buffer: characters ${characters}, new phrase ${phrase} ` +
      "(the probe compares whole blocks only; the package's worker fills with getRandomValues)",
  );
}

if (failures.length > 0) {
  console.log(`FAILED: ${failures.length} checks.`);
  process.exit(1);
}
console.log("PASSED: R1 to R4.");
void encode;
