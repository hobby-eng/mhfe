// Checks the browser package in dist/ with Node.js. Build it first with scripts/build-wasm.sh.
//
//   node scripts/verify-browser-package.mjs          fast checks, a few seconds
//   node scripts/verify-browser-package.mjs --full   also one full-size encryption (2 GiB)
//
// Part 1 runs the real Rust core and the real Argon2 bridge with both Emscripten builds. To stay
// fast it lowers the Argon2 cost in a test wrapper; the result must equal the container that the
// native engine gives at the same cost (REDUCED_COST_CONTAINER in src/mhfe.rs). Part 2 checks
// the page-side client against a stand-in worker. The real worker runs in a browser test.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolveObjectURL } from "node:buffer";
import { createRequire } from "node:module";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));

const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD = new TextEncoder().encode("public test password");
// Packs to the first state of AMBIGUOUS_STATES in src/packing.rs, which also passes the 21-word check.
const AMBIGUOUS_12_WORDS =
  "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
/** Four Argon2 lanes need at least 32 KiB; 256 KiB and one pass match the native test. */
const REDUCED_MEMORY_KIB = 256;
const REDUCED_PASSES = 1;
const REDUCED_COST_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
/** The same at the same cost as a container of the phrase's own length (suite 4). */
const REDUCED_COST_SAME_LENGTH_CONTAINER =
  "program adjust rain raven flip eternal spider bulb under soup enrich ensure";
const ZERO_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/** The same phrase and password at full size, as the native tool and an OpenSSL script give it. */
const FULL_SIZE_CONTAINER =
  "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";

// Part 1: the Rust core and the Argon2 bridge.
vm.runInThisContext(read("target/wasm-bindgen/mhfe_core.js").toString(), {
  filename: "mhfe_core.js",
});
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const core = vm.runInThisContext("wasm_bindgen");
const argon2Engine = vm.runInThisContext("argon2Engine");
const coreMemory = core.initSync({ module: read("dist/mhfe_core_bg.wasm") }).memory;

const parameters = JSON.parse(core.suiteParameters());
assert.equal(parameters.suiteId, "MHFE-BIP39-256-EXPERIMENTAL-3");
assert.equal(parameters.sameLengthSuiteId, "MHFE-BIP39-LP-EXPERIMENTAL-4");
assert.equal(parameters.highestBrowserMemoryLevel, 0);
assert.equal(parameters.apiVersion, 7, "the same-length choice of encrypt");

function expectCode(code, action) {
  assert.throws(action, (error) => error.message.startsWith(`${code}: `), code);
}

const builds = {
  threaded: require("../dist/argon2-mt.js"),
  "single-threaded": require("../dist/argon2-st.js"),
};
for (const [name, createModule] of Object.entries(builds)) {
  const engine = argon2Engine(await createModule());
  const reduced = {
    derive: (password, salt, memoryKib, passes, key) => {
      assert.deepEqual(
        [memoryKib, passes],
        [2097152, 12],
        "the core asks for the suite 3 defaults",
      );
      engine.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key);
    },
  };
  const steps = [];
  const onStep = (round, rounds) => steps.push(`${round}/${rounds}`);
  const onUnverified = (container) => steps.push(`unverified ${container}`);
  const created = JSON.parse(
    core.encrypt(PHRASE, PASSWORD, 0, 0, false, reduced, onStep, onUnverified),
  );
  const container = created.container;
  assert.equal(container, REDUCED_COST_CONTAINER, `${name}: same container as the native engine`);
  assert.equal(created.suiteId, "MHFE-BIP39-256-EXPERIMENTAL-3");
  // An encryption runs its 12 rounds, hands over the unchecked container, then runs 12 more to
  // decrypt its words and compare the result.
  const encryptionSteps = Array.from({ length: 24 }, (_, index) => `${index + 1}/24`);
  encryptionSteps.splice(12, 0, `unverified ${REDUCED_COST_CONTAINER}`);
  assert.deepEqual(steps, encryptionSteps);
  steps.length = 0;

  const recovery = JSON.parse(core.decrypt(container, PASSWORD, 0, 0, 0, reduced, onStep));
  assert.deepEqual(
    steps,
    Array.from({ length: 12 }, (_, index) => `${index + 1}/12`),
  );
  assert.deepEqual(recovery, {
    kind: "phrase",
    candidates: [
      { words: 12, verified: true, phrase: PHRASE, suiteId: "MHFE-BIP39-256-EXPERIMENTAL-3" },
    ],
  });
  const wrong = JSON.parse(
    core.decrypt(container, new TextEncoder().encode("wrong"), 0, 0, 0, reduced, () => {}),
  );
  assert.deepEqual([wrong.candidates[0].words, wrong.candidates[0].verified], [24, false]);

  const noPassphrase = new Uint8Array();
  assert.equal(
    core.check(container, PASSWORD, 0, 0, "words", "12", "", noPassphrase, reduced, () => {}),
    true,
  );
  assert.equal(
    core.check(
      container,
      PASSWORD,
      0,
      0,
      "fingerprint",
      "73c5da0a",
      "",
      noPassphrase,
      reduced,
      () => {},
    ),
    true,
  );
  const address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
  assert.equal(
    core.check(container, PASSWORD, 0, 0, "address", address, "", noPassphrase, reduced, () => {}),
    true,
  );
  const trezor = new TextEncoder().encode("TREZOR");
  assert.equal(
    core.check(container, PASSWORD, 0, 0, "fingerprint", "73c5da0a", "", trezor, reduced, () => {}),
    false,
  );

  // Refusals happen before any Argon2 call.
  expectCode("MEMORY_LEVEL_NOT_SUPPORTED_HERE", () =>
    core.encrypt(
      PHRASE,
      PASSWORD,
      0,
      1,
      false,
      reduced,
      () => {},
      () => {},
    ),
  );
  expectCode("INVALID_PIM", () =>
    core.encrypt(
      PHRASE,
      PASSWORD,
      1024,
      0,
      false,
      reduced,
      () => {},
      () => {},
    ),
  );
  expectCode("INVALID_PHRASE", () =>
    core.encrypt(
      "abandon about",
      PASSWORD,
      0,
      0,
      false,
      reduced,
      () => {},
      () => {},
    ),
  );
  // Numbers the raw API gets straight from JavaScript are refused unless they are whole numbers
  // in range; a u32 parameter would have turned 2^32 into 0 and -1 into 4294967295.
  for (const value of [2 ** 32, 2 ** 32 + 1, -1, 0.5, NaN, Infinity]) {
    expectCode("INVALID_PIM", () =>
      core.encrypt(
        PHRASE,
        PASSWORD,
        value,
        0,
        false,
        reduced,
        () => {},
        () => {},
      ),
    );
    expectCode("INVALID_MEMORY_LEVEL", () =>
      core.decrypt(container, PASSWORD, 0, value, 0, reduced, () => {}),
    );
    expectCode("INVALID_WORD_COUNT", () =>
      core.decrypt(container, PASSWORD, 0, 0, value, reduced, () => {}),
    );
  }
  // A refused password must not leave the separately given BIP39 passphrase in the core's memory.
  const sentinel = new TextEncoder().encode("public sentinel passphrase 7f3a9c");
  expectCode("EMPTY_PASSWORD", () =>
    core.check(
      container,
      new Uint8Array(0),
      0,
      0,
      "fingerprint",
      "73c5da0a",
      "",
      sentinel.slice(),
      reduced,
      () => {},
    ),
  );
  assert.equal(
    Buffer.from(coreMemory.buffer).indexOf(Buffer.from(sentinel)),
    -1,
    "the passphrase was wiped",
  );
  // The container is read back with every word written out, whatever case and short forms were typed.
  const typed = container
    .toUpperCase()
    .split(" ")
    .map((word) => word.slice(0, 4))
    .join("  ");
  assert.equal(core.checkContainer(typed), container);
  assert.equal(core.readPhrase(PHRASE.toUpperCase().replaceAll(" ", "\t")), PHRASE);
  // A public 12-word phrase whose packed state also passes the 21-word check (src/packing.rs).
  assert.deepEqual([...core.otherDetectedLengths(PHRASE)], []);
  assert.deepEqual([...core.otherDetectedLengths(AMBIGUOUS_12_WORDS)], [21]);
  expectCode("UNASSIGNED_CHARACTER", () => core.checkPassword(new TextEncoder().encode("a͸")));
  expectCode("INVALID_PASSWORD_UTF8", () => core.checkPassword(new Uint8Array([0xff])));
  expectCode("CONTROL_CHARACTER_IN_PASSWORD", () =>
    core.checkPassword(new TextEncoder().encode("first\r\nsecond")),
  );
  expectCode("CONTROL_CHARACTER_IN_PASSWORD", () =>
    core.checkPassword(new TextEncoder().encode("tab\there")),
  );
  // A progress callback that throws stops the operation.
  expectCode("CANCELLED", () =>
    core.encrypt(
      PHRASE,
      PASSWORD,
      0,
      0,
      false,
      reduced,
      () => {
        throw new Error("stop");
      },
      () => {},
    ),
  );
  // A container of the phrase's own length, only when asked for.
  const sameLength = JSON.parse(
    core.encrypt(
      PHRASE,
      PASSWORD,
      0,
      0,
      true,
      reduced,
      () => {},
      () => {},
    ),
  );
  assert.deepEqual(sameLength, {
    container: REDUCED_COST_SAME_LENGTH_CONTAINER,
    suiteId: "MHFE-BIP39-LP-EXPERIMENTAL-4",
  });
  assert.deepEqual(
    JSON.parse(
      core.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, 0, 0, 0, reduced, () => {}),
    ),
    {
      kind: "phrase",
      candidates: [
        { words: 12, verified: false, phrase: PHRASE, suiteId: "MHFE-BIP39-LP-EXPERIMENTAL-4" },
      ],
    },
  );
  assert.equal(
    core.check(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      PASSWORD,
      0,
      0,
      "fingerprint",
      "73c5da0a",
      "",
      noPassphrase,
      reduced,
      () => {},
    ),
    true,
  );
  expectCode("NO_BUILT_IN_CHECK", () =>
    core.check(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      PASSWORD,
      0,
      0,
      "words",
      "12",
      "",
      noPassphrase,
      reduced,
      () => {},
    ),
  );
  expectCode("SAME_LENGTH_NEEDS_SHORT_PHRASE", () =>
    core.encrypt(
      ZERO_24,
      PASSWORD,
      0,
      0,
      true,
      reduced,
      () => {},
      () => {},
    ),
  );
  expectCode("LENGTH_CHOICE_NOT_APPLICABLE", () =>
    core.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, 0, 0, 15, reduced, () => {}),
  );
  assert.equal(
    core.checkContainer(REDUCED_COST_SAME_LENGTH_CONTAINER.toUpperCase()),
    REDUCED_COST_SAME_LENGTH_CONTAINER,
  );
  console.log(`The ${name} build gives the native container and passes the API checks.`);
}

if (process.argv.includes("--full")) {
  const engine = argon2Engine(await builds.threaded());
  const container = core.encrypt(
    PHRASE,
    PASSWORD,
    0,
    0,
    false,
    engine,
    () => {},
    () => {},
  );
  assert.equal(JSON.parse(container).container, FULL_SIZE_CONTAINER);
  console.log("A full-size encryption with the threaded build gives the native container.");
}

// No script of the package contains code that could reach the network, not even code that never
// runs (scripts/remove-network-code.mjs removes the loaders the tools emit).
for (const script of ["client.js", "mhfe-worker.js", "argon2-mt.js", "argon2-st.js"]) {
  const text = read(`dist/${script}`).toString();
  for (const pattern of [
    /\bfetch\s*\(/u,
    /\bXMLHttpRequest\b/u,
    /\bWebSocket\b/u,
    /\bEventSource\b/u,
  ]) {
    assert.equal(pattern.test(text), false, `${script} contains ${pattern}`);
  }
}
console.log("No script of the package contains network code.");

// Part 2: the page-side client, with a stand-in worker.
// dist/client.js is an ES module, but the nearest package.json, the repository's tooling, cannot
// declare "type": "module": the Emscripten builds next to it are CommonJS. Imported from a file,
// Node would parse it twice and warn; its text imported as a module is the same code.
const clientSource = read("dist/client.js").toString("base64");
const { MhfeClient, MhfeCancelledError } = await import(
  `data:text/javascript;base64,${clientSource}`
);
const sources = {
  workerSource: "worker source",
  argon2Threaded: "threaded source",
  argon2SingleThreaded: "single-threaded source",
  coreWasm: new Uint8Array([0, 97, 115, 109]),
};

class StandInWorker {
  static last = null;
  constructor(url) {
    this.script = resolveObjectURL(url);
    this.terminated = false;
    this.messages = [];
    StandInWorker.last = this;
  }
  postMessage(message, transfer) {
    // structuredClone with a transfer list empties the sender's buffers, as a real worker does.
    this.messages.push(structuredClone(message, { transfer }));
  }
  reply(data) {
    this.onmessage({ data });
  }
  terminate() {
    this.terminated = true;
  }
}
globalThis.Worker = StandInWorker;

const client = new MhfeClient(sources);
assert.equal(client.mode(), "standard");
assert.equal(client.maxSupportedMemLevel(), 0);

const progress = [];
const password = new TextEncoder().encode("public test password");
const pending = client.encrypt({
  phrase: PHRASE,
  password,
  passwordRepeat: password.slice(),
  onProgress: (step) => progress.push(`${step.round}/${step.rounds}`),
  onUnverified: ({ container }) => progress.push(`unverified ${container}`),
});
const worker = StandInWorker.last;
assert.equal(await worker.script.text(), "single-threaded source\n;\nworker source");
assert.equal(worker.messages[0].argon2Script, null);
assert.equal(worker.messages[0].sameLength, false, "24 words unless the page asks otherwise");
assert.deepEqual(
  [...worker.messages[0].password],
  [...password],
  "the worker receives the password",
);
assert.equal(password.length, 20, "the caller's array is copied, not emptied");
worker.reply({ type: "progress", round: 12, rounds: 24 });
worker.reply({ type: "unverified", container: "c" });
worker.reply({ type: "progress", round: 13, rounds: 24 });
worker.reply({ type: "result", result: { container: "c" } });
assert.deepEqual(await pending, { container: "c" });
assert.deepEqual(progress, ["12/24", "unverified c", "13/24"]);
assert.equal(worker.terminated, true, "each worker ends with its operation");

globalThis.crossOriginIsolated = true;
assert.equal(client.mode(), "fast");
const fast = client.decrypt({ container: "c", password: "public test password" });
assert.equal(await StandInWorker.last.script.text(), "threaded source\n;\nworker source");
assert.equal(await StandInWorker.last.messages[0].argon2Script.text(), "threaded source");
await assert.rejects(client.decrypt({ container: "c", password: "x" }), { code: "BUSY" });
StandInWorker.last.reply({
  type: "error",
  error: { code: "VERIFIER_MISMATCH", message: "the password or the settings are wrong" },
});
// The core's message becomes a sentence that a page can show as it is.
await assert.rejects(fast, {
  code: "VERIFIER_MISMATCH",
  message: "The password or the settings are wrong",
});
delete globalThis.crossOriginIsolated;

// Reading words starts a worker with the Rust core only.
const reading = client.readContainer("DONA stov");
assert.equal(await StandInWorker.last.script.text(), "\n;\nworker source");
assert.equal(StandInWorker.last.messages[0].operation, "readContainer");
assert.equal(StandInWorker.last.messages[0].password, undefined);
StandInWorker.last.reply({ type: "result", result: { container: "donate stove" } });
assert.deepEqual(await reading, { container: "donate stove" });

const cancelled = client.check({ container: "c", password: "p", reference: { words: 12 } });
client.cancel();
await assert.rejects(cancelled, (error) => error instanceof MhfeCancelledError);
assert.equal(StandInWorker.last.terminated, true);

const encrypt = (options) =>
  client.encrypt({ phrase: PHRASE, passwordRepeat: options.password, ...options });
// Every error rejects the promise, the checks of the arguments included: none is thrown.
const refusals = [
  [() => client.encrypt({ phrase: PHRASE, password: "p" }), { code: "PASSWORDS_DIFFER" }],
  [
    () => client.encrypt({ phrase: PHRASE, password: "p", passwordRepeat: "p", sameLength: "yes" }),
    TypeError,
  ],
  [
    () => client.encrypt({ phrase: PHRASE, password: "p", passwordRepeat: "P" }),
    { code: "PASSWORDS_DIFFER" },
  ],
  [
    () =>
      client.encrypt({ phrase: PHRASE, password: password, passwordRepeat: new Uint8Array(20) }),
    { code: "PASSWORDS_DIFFER" },
  ],
  [() => encrypt({ password: "a\uD800" }), { code: "INVALID_PASSWORD_TEXT" }],
  [() => encrypt({ password: "p", memoryLevel: 1 }), { code: "MEMORY_LEVEL_NOT_SUPPORTED_HERE" }],
  [() => encrypt({ password: "p", pim: 1024 }), { code: "INVALID_PIM" }],
  [() => encrypt({ password: "" }), { code: "EMPTY_PASSWORD" }],
  [() => encrypt({ password: "p", onUnverified: "show" }), TypeError],
  [() => client.encrypt(), TypeError],
  [
    () => client.decrypt({ container: "c", password: "p", words: 13 }),
    { code: "INVALID_WORD_COUNT" },
  ],
  [() => client.readPhrase(42), TypeError],
  [() => client.readContainer(), TypeError],
];
for (const [call, expected] of refusals) {
  let result;
  assert.doesNotThrow(() => {
    result = call();
  }, "a refusal is a rejected promise, not an exception");
  assert.ok(result instanceof Promise);
  await assert.rejects(result, expected);
}

// A check that fails after the container was shown rejects, so the page can mark it as wrong.
const shown = [];
const failing = encrypt({ password: "p", onUnverified: ({ container }) => shown.push(container) });
StandInWorker.last.reply({ type: "unverified", container: "c" });
StandInWorker.last.reply({
  type: "error",
  error: { code: "VERIFICATION_FAILED", message: "wrong" },
});
await assert.rejects(failing, { code: "VERIFICATION_FAILED" });
assert.deepEqual(shown, ["c"]);
await assert.rejects(client.check({ container: "c", password: "p", reference: { words: 24 } }), {
  code: "INVALID_WORD_COUNT",
});

// A callback of the page that throws stops the operation: the worker ends, the promise rejects
// with CALLBACK_FAILED and the page's error as the cause, and later messages of that worker are
// ignored.
for (const [name, message] of [
  ["onProgress", { type: "progress", round: 1, rounds: 24 }],
  ["onUnverified", { type: "unverified", container: "c" }],
]) {
  const pageError = new Error(`page bug in ${name}`);
  const calls = [];
  const broken = encrypt({
    password: "p",
    onProgress: () => {
      calls.push("progress");
      if (name === "onProgress") throw pageError;
    },
    onUnverified: () => {
      calls.push("unverified");
      if (name === "onUnverified") throw pageError;
    },
  });
  const brokenWorker = StandInWorker.last;
  brokenWorker.reply(message);
  brokenWorker.reply({ type: "progress", round: 2, rounds: 24 });
  brokenWorker.reply({ type: "result", result: { container: "c" } });
  await assert.rejects(
    broken,
    (error) => error.code === "CALLBACK_FAILED" && error.cause === pageError,
  );
  assert.equal(brokenWorker.terminated, true, `the worker stops when ${name} throws`);
  assert.equal(
    calls.length,
    1,
    `nothing of the stopped operation reaches the page after ${name} threw`,
  );
}

// An async callback fails by rejecting its promise. While the operation runs, that stops it as a
// throw does.
for (const [name, message] of [
  ["onProgress", { type: "progress", round: 1, rounds: 24 }],
  ["onUnverified", { type: "unverified", container: "c" }],
]) {
  const pageError = new Error(`async page bug in ${name}`);
  const broken = encrypt({
    password: "p",
    [name]: async () => {
      throw pageError;
    },
  });
  const brokenWorker = StandInWorker.last;
  brokenWorker.reply(message);
  await assert.rejects(
    broken,
    (error) => error.code === "CALLBACK_FAILED" && error.cause === pageError,
  );
  assert.equal(brokenWorker.terminated, true, `the worker stops when async ${name} rejects`);
}

// A callback's promise that rejects after its operation has ended stops nothing; the rejection
// stays the page's own unhandled one instead of disappearing inside the client.
{
  const lateError = new Error("late async page bug");
  let rejectLate;
  const unhandled = [];
  const recordUnhandled = (error) => unhandled.push(error);
  process.on("unhandledRejection", recordUnhandled);
  const finished = encrypt({
    password: "p",
    onProgress: () =>
      new Promise((_, reject) => {
        rejectLate = reject;
      }),
  });
  StandInWorker.last.reply({ type: "progress", round: 1, rounds: 24 });
  StandInWorker.last.reply({ type: "result", result: { container: "c" } });
  assert.deepEqual(await finished, { container: "c" });
  rejectLate(lateError);
  // Node reports unhandled rejections after the microtasks of the current turn have run.
  await new Promise((resolve) => setTimeout(resolve, 0));
  process.off("unhandledRejection", recordUnhandled);
  assert.deepEqual(unhandled, [lateError]);
}

// Exactly one reference: with several, the check would silently use only one of them.
const conflicting = [
  { address: "bc1q", fingerprint: "00000000" },
  { fingerprint: "00000000", words: 12 },
  { words: 12, path: "m/84'/0'/0'/0/0" },
  { address: "bc1q", path: 5 },
  {},
  null,
];
for (const reference of conflicting) {
  await assert.rejects(
    client.check({ container: "c", password: "p", reference }),
    TypeError,
    JSON.stringify(reference),
  );
}

// The client's byte copies of secrets are wiped when an operation cannot start. The stand-in
// encoder keeps a reference to every copy of the two public test secrets it makes.
const TEST_PASSWORD = "public test password";
const TEST_PASSPHRASE = "public test passphrase";
const copies = [];
const RealTextEncoder = globalThis.TextEncoder;
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSWORD || text === TEST_PASSPHRASE) copies.push(bytes);
    return bytes;
  }
};
const fingerprintCheck = (options) =>
  client.check({
    container: "c",
    password: TEST_PASSWORD,
    reference: { fingerprint: "00000000" },
    passphrase: TEST_PASSPHRASE,
    ...options,
  });
await assert.rejects(fingerprintCheck({ pim: -1 }), { code: "INVALID_PIM" });
assert.equal(copies.length, 0, "settings are checked before any secret is copied");
globalThis.Worker = class {
  constructor() {
    throw new Error("refused by the stand-in");
  }
};
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
assert.equal(copies.length, 2, "the password and the passphrase were copied");
assert.ok(
  copies.every((bytes) => bytes.every((byte) => byte === 0)),
  "both copies are wiped when the worker does not start",
);
globalThis.Worker = StandInWorker;
globalThis.TextEncoder = RealTextEncoder;
const afterFailure = client.readContainer("donate");
StandInWorker.last.reply({ type: "result", result: { container: "donate" } });
assert.deepEqual(await afterFailure, { container: "donate" }, "the client is usable again");
console.log("The client passes its checks with a stand-in worker.");

// The threaded build keeps its lane workers alive; end the process explicitly.
process.exit(0);
