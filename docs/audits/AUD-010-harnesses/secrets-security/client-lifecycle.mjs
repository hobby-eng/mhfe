// AUD-010 secrets-security probe (CHECK-SEC-005, AUD-009-SEC001 and the secret half of
// AUD-009-API001): the byte copies of secrets that the browser package's classes make on the page,
// on every exit path.
//
// Loads web/runtime.js and the classes web/client.js, web/passwords.js and web/wallet.js from
// source, with a stand-in Worker that answers the startup check and then follows each case's
// script. Every Uint8Array that TextEncoder.encode or Uint8Array.prototype.slice makes during a
// case is recorded; after the case each must be either transferred to the worker (detached, length
// 0) or all zeros. A message posted to the worker is cloned with its transfer list, as a browser
// does, and every secret field of the page's message must then be detached: a field missing from
// the transfer list would leave a page copy behind. Public synthetic values only.
//
// Exits 1 when any case fails.
//
//   node docs/audits/AUD-010-harnesses/secrets-security/client-lifecycle.mjs
import { readFileSync } from "node:fs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const runtimeUrl = "data:text/javascript;base64," + Buffer.from(read("web/runtime.js")).toString("base64");
async function loadClass(path) {
  const source = read(path).replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl));
  return import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
}
const { MhfeClient } = await loadClass("web/client.js");
const { MhfePasswords } = await loadClass("web/passwords.js");
const { MhfeWallet } = await loadClass("web/wallet.js");
const { WorkerJob, CompiledModule } = await import(runtimeUrl);

/** The fields of a request or answer that hold secrets (web/runtime.js SECRET_FIELDS). */
const SECRET_FIELDS = [
  "password",
  "passwordRepeat",
  "passphrase",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
];
const CORE_PARAMETERS = {
  maxPim: 1023,
  maxMemoryLevel: 21,
  highestBrowserMemoryLevel: 0,
  wordCounts: [12, 15, 18, 21, 24],
  repairWordCounts: [2, 4, 6, 8],
};
/** Every secret text the cases pass, all public and synthetic: a page copy of one must not stay. */
const SECRETS = new Set([
  "public sentinel",
  "public passphrase",
  "public main passphrase",
  "public hidden one",
  "public hidden two",
  "public three",
  "public new",
  "public p",
  "pub",
  "11111 11112 11113 11114 11115",
]);
const tick = () => new Promise((resolve) => setImmediate(resolve));
const settle = async () => {
  for (let i = 0; i < 5; i += 1) await tick();
};

// Recording of the page's byte copies.
let recording = null;
const originalEncode = TextEncoder.prototype.encode;
TextEncoder.prototype.encode = function encode(...args) {
  const bytes = originalEncode.apply(this, args);
  recording?.push(bytes);
  return bytes;
};
const originalSlice = Uint8Array.prototype.slice;
Uint8Array.prototype.slice = function slice(...args) {
  const bytes = originalSlice.apply(this, args);
  if (bytes.constructor === Uint8Array) recording?.push(bytes);
  return bytes;
};

// The stand-in worker.
const failures = [];
const workers = [];
let scenario = () => {};
let refuseWorker = false;
let refusePost = false;
globalThis.Worker = class FakeWorker {
  constructor(url, options) {
    if (refuseWorker) throw new Error("synthetic Worker refusal");
    this.url = url;
    this.options = options;
    this.terminated = false;
    workers.push(this);
  }
  postMessage(message, transfer = []) {
    if (refusePost) throw new DOMException("synthetic clone refusal", "DataCloneError");
    const clone = structuredClone(message, { transfer });
    for (const holder of [message, message?.value]) {
      for (const field of SECRET_FIELDS) {
        const bytes = holder?.[field];
        if (bytes instanceof Uint8Array && bytes.byteLength !== 0) {
          failures.push(`${message.operation ?? message.type}: ${field} was not transferred`);
        }
      }
    }
    setImmediate(() => {
      if (!this.terminated) this.#respond(clone);
    });
  }
  terminate() {
    this.terminated = true;
  }
  emit(data) {
    this.onmessage?.({ data });
  }
  #respond(message) {
    if (message.compiled !== undefined) this.emit({ type: "ready", buildId: "development" });
    if (message.operation === "selfCheck") {
      const report = { version: "0.5.0", tier: message.tier, passed: true, ids: [], components: [] };
      if (message.module === "core") report.parameters = CORE_PARAMETERS;
      this.emit({ type: "result", result: report });
      return;
    }
    scenario(this, message);
  }
};

/** Bytes the caller owns, made before any recording: the classes must copy, not take them. */
const CALLER_NEW_PASSWORD = new TextEncoder().encode("public new");
const wasm = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const source = { workerSource: "stand-in worker" };
const client = new MhfeClient({ ...source, wasm, argon2Threaded: "a", argon2SingleThreaded: "b" });
const passwords = new MhfePasswords({ ...source, wasm });
const wallet = new MhfeWallet({ ...source, wasm });
await client.startupCheck({ argon2: false });
await passwords.startupCheck();
await wallet.startupCheck();

/** Runs `body`, then requires every page copy made meanwhile to be transferred or wiped. */
async function testCase(name, body) {
  recording = [];
  const before = failures.length;
  let note = "";
  try {
    note = (await body()) ?? "";
  } catch (error) {
    failures.push(`${name}: the probe itself failed: ${error.stack}`);
  }
  await settle();
  const made = recording;
  recording = null;
  // Copies of other text, such as the worker scripts that Node's Blob encodes, are not secrets.
  const left = made.filter(
    (bytes) => bytes.byteLength > 0 && SECRETS.has(new TextDecoder().decode(bytes)),
  );
  if (left.length > 0) {
    const texts = left.map((bytes) => JSON.stringify(new TextDecoder().decode(bytes)));
    failures.push(
      `${name}: ${left.length} of ${made.length} page copies left unwiped: ${texts.join(", ")}`,
    );
  }
  const ok = failures.length === before;
  console.log(`${ok ? "pass" : "FAIL"} ${name}: ${made.length} page copies made${note ? `; ${note}` : ""}`);
  for (const failure of failures.slice(before)) console.log(`     ${failure}`);
}

/** The error code a promise rejects with, or "resolved". */
async function outcome(promise) {
  try {
    await promise;
    return "resolved";
  } catch (error) {
    return error.code ?? error.name;
  }
}

function expect(condition, message) {
  if (!condition) failures.push(message);
}

// AUD-009-SEC001: a refused repetition after the first copy was made.
await testCase("passwords.review, repetition of another type", async () => {
  const code = await outcome(passwords.review({ password: "public sentinel", passwordRepeat: 5 }));
  expect(code === "TypeError", `review rejected with ${code}`);
  return `rejected with ${code}`;
});
await testCase("passwords.review, repetition with a lone surrogate", async () => {
  const code = await outcome(passwords.review({ password: "public sentinel", passwordRepeat: "a\uD800" }));
  expect(code === "INVALID_PASSWORD_TEXT", `review rejected with ${code}`);
  return `rejected with ${code}`;
});
await testCase("wallet.drawPhrase, repetition of another type", async () => {
  const code = await outcome(
    wallet.drawPhrase({ passphrase: "public sentinel", passphraseRepeat: 7, walletCheck: false }),
  );
  expect(code === "TypeError", `drawPhrase rejected with ${code}`);
  return `rejected with ${code}`;
});
await testCase("wallet.drawPhrase, repetition with a lone surrogate", async () => {
  const code = await outcome(
    wallet.drawPhrase({
      passphrase: Uint8Array.of(0x70, 0x75, 0x62),
      passphraseRepeat: "p\uD800",
      walletCheck: false,
    }),
  );
  expect(code === "INVALID_PASSWORD_TEXT", `drawPhrase rejected with ${code}`);
  return `rejected with ${code}`;
});
await testCase("client.check, passphrase of another type after the password was copied", async () => {
  const code = await outcome(
    client.check({
      container: "public container",
      password: "public sentinel",
      passphrase: 5,
      reference: { fingerprint: "00000000" },
    }),
  );
  expect(code === "TypeError", `check rejected with ${code}`);
  scenario = (worker) => worker.emit({ type: "result", result: { matches: false, path: null } });
  const next = await outcome(
    client.check({ container: "c", password: "public p", reference: { fingerprint: "00000000" } }),
  );
  expect(next === "resolved", `the next operation gave ${next}: the slot was not freed`);
  return `rejected with ${code}; the next operation ${next}`;
});

// AUD-009-API001, the secret half: the worker cannot be started.
const originalCreateObjectURL = URL.createObjectURL;
const originalBlob = globalThis.Blob;
const startFailures = {
  "URL.createObjectURL throws": () => {
    URL.createObjectURL = () => {
      throw new Error("synthetic Blob URL refusal");
    };
  },
  "Blob throws": () => {
    globalThis.Blob = class {
      constructor() {
        throw new Error("synthetic Blob refusal");
      }
    };
  },
  "Worker throws": () => {
    refuseWorker = true;
  },
  "postMessage throws": () => {
    refusePost = true;
  },
};
for (const [failure, install] of Object.entries(startFailures)) {
  await testCase(`passwords.strength, ${failure}`, async () => {
    install();
    let code;
    try {
      code = await outcome(passwords.strength({ password: "public sentinel" }));
    } finally {
      URL.createObjectURL = originalCreateObjectURL;
      globalThis.Blob = originalBlob;
      refuseWorker = false;
      refusePost = false;
    }
    expect(code === "WORKER_FAILED", `strength rejected with ${code}`);
    return `rejected with ${code}`;
  });
  await testCase(`client.decrypt, ${failure}`, async () => {
    install();
    let code;
    try {
      code = await outcome(client.decrypt({ container: "public container", password: "public sentinel" }));
    } finally {
      URL.createObjectURL = originalCreateObjectURL;
      globalThis.Blob = originalBlob;
      refuseWorker = false;
      refusePost = false;
    }
    expect(code === "WORKER_FAILED", `decrypt rejected with ${code}`);
    scenario = (worker) => worker.emit({ type: "result", result: { kind: "phrase", candidates: [] } });
    const next = await outcome(client.decrypt({ container: "c", password: "public p" }));
    expect(next === "resolved", `the next operation gave ${next}: the slot was not freed`);
    return `rejected with ${code}; the next operation ${next}`;
  });
}
await testCase("WorkerJob, createObjectURL throws, caller-supplied message", async () => {
  URL.createObjectURL = () => {
    throw new Error("synthetic Blob URL refusal");
  };
  const bytes = new TextEncoder().encode("public sentinel");
  const job = new WorkerJob(["stand-in"]);
  let code;
  try {
    code = await outcome(job.run({ password: bytes }, [], new CompiledModule(wasm, "wasm")));
  } finally {
    URL.createObjectURL = originalCreateObjectURL;
  }
  expect(code === "WORKER_FAILED" && job.ended, `run gave ${code}, ended ${job.ended}`);
  return `rejected with ${code}, ended ${job.ended}`;
});

// Cancellation and a late answer.
await testCase("client.decrypt cancelled, then a late result", async () => {
  scenario = () => {};
  const running = outcome(client.decrypt({ container: "public container", password: "public sentinel" }));
  await settle();
  const worker = workers.at(-1);
  client.cancel();
  const code = await running;
  worker.emit({ type: "result", result: { kind: "phrase", candidates: [{ phrase: "late" }] } });
  await settle();
  expect(code === "CANCELLED", `decrypt gave ${code}`);
  expect(worker.terminated, "the worker was not terminated");
  scenario = (next) => next.emit({ type: "result", result: { kind: "phrase", candidates: [] } });
  const next = await outcome(client.decrypt({ container: "c", password: "public p" }));
  expect(next === "resolved", `the next operation gave ${next}`);
  return `cancelled with ${code}, worker terminated ${worker.terminated}, late result ignored`;
});

// Every secret of every long operation reaches the worker by transfer only.
await testCase("client.encrypt, rekey and check transfer every secret", async () => {
  scenario = () => {};
  const cases = [
    outcome(client.encrypt({
      phrase: "public phrase",
      password: "public sentinel",
      passwordRepeat: "public sentinel",
      walletHasPassphrase: false,
    })),
  ];
  await settle();
  client.cancel();
  cases.push(
    outcome(client.rekey({
      container: "public container",
      password: "public sentinel",
      otherWalletsMoved: true,
      newPassword: CALLER_NEW_PASSWORD,
      newPasswordRepeat: "public new",
      confirmation: { fingerprint: "00000000" },
      passphrase: "public passphrase",
    })),
  );
  await settle();
  client.cancel();
  cases.push(
    outcome(client.check({
      container: "public container",
      password: "public sentinel",
      passphrase: "public passphrase",
      reference: { walletCheck: true },
    })),
  );
  await settle();
  client.cancel();
  const codes = await Promise.all(cases);
  // The caller's own bytes are copied, never transferred or wiped (web/runtime.js encodeSecret).
  expect(
    new TextDecoder().decode(CALLER_NEW_PASSWORD) === "public new",
    "the caller's own password bytes were changed",
  );
  expect(codes.every((code) => code === "CANCELLED"), `codes ${codes}`);
  return `codes ${codes.join(", ")}`;
});
await testCase("passwords.make from dice and wallet.drawPhrase on two workers", async () => {
  scenario = (worker, message) => {
    if (message.operation === "make") worker.emit({ type: "result", result: { password: "x" } });
  };
  const made = await outcome(passwords.make({ kind: "checkWord", dice: "11111 11112 11113 11114 11115" }));
  const drawing = outcome(wallet.drawPhrase({
    passphrase: "public passphrase",
    passphraseRepeat: "public passphrase",
    walletCheck: true,
    workers: 2,
  }));
  await settle();
  wallet.cancel();
  const drawn = await drawing;
  expect(made === "resolved" && drawn === "CANCELLED", `make ${made}, draw ${drawn}`);
  return `make ${made}, draw ${drawn}`;
});

// Hidden wallets: the passwords of each wallet and the main passphrase, a close during an open.
await testCase("client.openHiddenWallets: open, open cancelled by close, open after close", async () => {
  let holdNextOpen = false;
  scenario = (worker, message) => {
    if (message.operation === "hiddenWallets") {
      worker.emit({ type: "ask", question: "ready", value: null });
      return;
    }
    if (message.type !== "answer") return;
    if (message.value?.close === true) {
      worker.emit({ type: "result", result: { closed: true } });
    } else if (!holdNextOpen) {
      worker.emit({ type: "ask", question: "opened", value: { phrase: "public wallet", words: 24 } });
    }
  };
  const handle = await client.openHiddenWallets({
    container: "public container",
    mainPassphrase: "public main passphrase",
  });
  const first = await outcome(
    handle.open({ password: "public hidden one", passwordRepeat: "public hidden one" }),
  );
  holdNextOpen = true;
  const second = outcome(
    handle.open({ password: "public hidden two", passwordRepeat: "public hidden two" }),
  );
  await settle();
  const worker = workers.at(-1);
  await handle.close();
  const secondCode = await second;
  const afterRecording = recording.length;
  const third = await outcome(handle.open({ password: "public three", passwordRepeat: "public three" }));
  expect(first === "resolved", `first open ${first}`);
  expect(secondCode === "CANCELLED", `open during close ${secondCode}`);
  expect(worker.terminated, "the session's worker was not terminated");
  expect(third === "SESSION_CLOSED", `open after close ${third}`);
  expect(recording.length === afterRecording, "an open after close copied its password");
  return `open ${first}; open during close ${secondCode}; open after close ${third}`;
});

if (failures.length > 0) {
  console.log(`FAILED: ${failures.length} failures.`);
  process.exit(1);
}
console.log("PASSED: every page copy of a secret was transferred to its worker or wiped.");
