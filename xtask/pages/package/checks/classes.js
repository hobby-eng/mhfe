// Part 4: the page-side classes, with a stand-in worker.
// The classes are ES modules that import "../runtime/runtime.js"; each is imported as text with
// that import pointed at the runtime's text.
const runtimeUrl = moduleUrl(read("dist/runtime/runtime.js"));
const importClass = (path) => {
  const text = read(path).toString().replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`);
  return import(moduleUrl(text));
};
// A page that inlines the package joins the runtime and its classes into one module, as
// xtask/src/browser/page.rs does; their top-level names must not collide.
await import(moduleUrl(JOINED_CLASSES)).catch((error) => {
  throw new Error(`The classes do not join into one module: ${error.message}`);
});
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

// The client's own limits, checked before any secret is copied, equal the core's.
const clientText = read("dist/core/client.js").toString();
const clientConstant = (name) =>
  JSON.parse(new RegExp(`^const ${name} = (.+);$`, "mu").exec(clientText)[1]);
assert.equal(clientConstant("MAX_PIM"), parameters.maxPim);
assert.equal(clientConstant("MAX_MEMORY_LEVEL"), parameters.maxMemoryLevel);
assert.equal(clientConstant("HIGHEST_BROWSER_MEMORY_LEVEL"), parameters.highestBrowserMemoryLevel);
assert.deepEqual(clientConstant("WORD_COUNTS"), parameters.wordCounts);
assert.deepEqual(clientConstant("REPAIR_WORD_COUNTS"), [0, ...parameters.repairWordCounts]);
assert.deepEqual(clientConstant("BUILT_IN_CHECK_WORD_COUNTS"), parameters.builtInCheckWordCounts);
assert.equal(clientConstant("DECOY_SCAN_GAP"), parameters.decoyScanGap);
assert.deepEqual(
  [clientConstant("ARGON2_PART"), clientConstant("ARGON2_SIZES_PART")],
  parameters.argon2Parts,
);
// A real compiled module, so that the classes' compilation succeeds; the stand-in ignores it.
const wasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const sources = {
  workerSource: "worker source",
  wasm,
  argon2Threaded: "threaded source",
  argon2SingleThreaded: "single-threaded source",
};

/** The operations of the self-checks, which a stand-in worker answers by itself. */
const SELF_CHECK_OPERATIONS = ["selfCheck", "selfCheckArgon2"];
/** Counts the events of the stand-in workers, so that their order can be compared. */
let workerEvents = 0;

class StandInWorker {
  static last = null;
  static started = [];
  /** The workers of the classes' self-checks, in the order they were asked. */
  static checks = [];
  /** How a self-check is answered: by default as the package's worker would; see below. */
  static serveCheck = null;
  /**
   * Whether a worker says it has loaded the WebAssembly as soon as it has its first request, as
   * the package's worker does; a test of a worker still loading turns it off.
   */
  static loads = true;
  constructor(url) {
    this.script = resolveObjectURL(url);
    this.terminated = false;
    this.messages = [];
    /**
     * The transfer list of each message as the page gave it: each buffer with its size before the
     * transfer, which empties it.
     */
    this.transfers = [];
    this.createdAt = workerEvents += 1;
    StandInWorker.last = this;
    StandInWorker.started.push(this);
    this.received = new Promise((resolve) => {
      this.firstMessage = resolve;
    });
  }
  postMessage(message, transfer = []) {
    this.transfers.push(transfer.map((buffer) => ({ buffer, byteLength: buffer.byteLength })));
    // structuredClone with a transfer list empties the sender's buffers, as a real worker does.
    this.messages.push(structuredClone(message, { transfer }));
    this.firstMessage();
    if (this.messages.length === 1 && SELF_CHECK_OPERATIONS.includes(message.operation)) {
      this.selfCheck = true;
      StandInWorker.checks.push(this);
      setTimeout(() => this.#serveCheck(), 0);
    } else if (this.messages.length === 1 && StandInWorker.loads) {
      setTimeout(() => {
        if (!this.terminated) this.reply({ type: "ready", buildId: BUILD_ID });
      }, 0);
    }
  }
  async #serveCheck() {
    try {
      const result = await StandInWorker.serveCheck(this.messages[0], this);
      if (!this.terminated && result !== undefined) this.reply({ type: "result", result });
    } catch (error) {
      if (!this.terminated) this.reply({ type: "error", error: describeWorkerError(error) });
    }
  }
  reply(data) {
    this.onmessage({ data });
  }
  terminate() {
    this.terminated = true;
    this.terminatedAt ??= workerEvents += 1;
  }
}
globalThis.Worker = StandInWorker;

/** An error as the worker posts it: "CODE: message" from the WebAssembly. */
function describeWorkerError(error) {
  const [, code, message] = /^([A-Z_]+): (.*)$/su.exec(error.message);
  return { code, message };
}

/**
 * Answers a self-check as the package's worker does, with the package's WebAssembly in this
 * process: ready with this build, each part as it starts and ends, then the report; Argon2 by the
 * single-threaded build, whichever build the class placed in front.
 */
function servedByTheWebAssembly(message, worker) {
  worker.reply({ type: "ready", buildId: BUILD_ID });
  const onStart = (id, label) => worker.reply({ type: "componentStart", value: { id, label } });
  const onResult = (json) => worker.reply({ type: "component", value: JSON.parse(json) });
  const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
  const { tier, skip } = message;
  const argon2 = message.argon2 === false ? undefined : realArgon2;
  const run = {
    "repair.selfCheck": () => bindings.selfCheckRepair(tier, skip, onStart, onResult),
    "passwords.selfCheck": () => bindings.selfCheckPasswords(tier, skip, random, onStart, onResult),
    "wallet.selfCheck": () => bindings.selfCheckWallet(tier, skip, random, onStart, onResult),
    "core.selfCheck": () => bindings.selfCheckCore(tier, skip, argon2, onStart, onResult),
    "core.selfCheckArgon2": () => bindings.selfCheckArgon2(tier, skip, argon2, onStart, onResult),
  }[`${message.module}.${message.operation}`];
  const report = JSON.parse(run());
  return message.module === "core" && message.operation === "selfCheck"
    ? { ...report, parameters }
    : report;
}
StandInWorker.serveCheck = servedByTheWebAssembly;

/**
 * The worker of the call just made, once its request has been sent to it: the latest running one
 * that is not a self-check's, and whose request `matches` accepts when several run.
 */
async function started(matches = () => true) {
  for (let tries = 0; tries < 50; tries += 1) {
    const worker = StandInWorker.started.findLast(
      (each) => !each.selfCheck && each.messages.length > 0 && matches(each.messages[0]),
    );
    if (worker !== undefined && !worker.terminated) return worker;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("no worker received its request");
}

const client = new MhfeClient(sources);
assert.equal(client.mode(), "standard");
assert.equal(client.maxSupportedMemLevel(), 0);

const progress = [];
const password = encode("public test password");
const pending = client.encrypt({
  phrase: PHRASE,
  password,
  passwordRepeat: password.slice(),
  repairWordCount: 4,
  walletHasPassphrase: false,
  onProgress: (step) => progress.push(`${step.stage} ${step.round}/${step.rounds}`),
  onUnverified: ({ container }) => progress.push(`unverified ${container}`),
});
let worker = await started();
assert.equal(await worker.script.text(), "single-threaded source\n;\nworker source");
assert.equal(worker.messages[0].argon2Script, null);
assert.equal(worker.messages[0].sameLength, false, "24 words unless the page asks otherwise");
assert.equal(worker.messages[0].repairWordCount, 4);
assert.equal(worker.messages[0].walletHasPassphrase, false, "the page's answer goes to the worker");
assert.equal(worker.messages[0].module, "core");
assert.ok(
  worker.messages[0].compiled instanceof WebAssembly.Module,
  "compiled once, not per worker",
);
assert.deepEqual([...worker.messages[0].password], [...password], "the worker gets the password");
assert.equal(password.length, 20, "the caller's array is copied, not emptied");
// The phrase goes as bytes too, transferred with the passwords, so that the worker and the
// WebAssembly wipe it (AUD-010); the non-secret request carries none of the secrets.
assert.ok(worker.messages[0].phrase instanceof Uint8Array, "the phrase goes as bytes");
assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE);
assert.deepEqual(
  worker.transfers[0].map(({ byteLength }) => byteLength),
  [PHRASE.length, 20, 20],
  "the phrase and both passwords are transferred, in buffers of their own",
);
worker.reply({ type: "progress", value: { stage: "encrypt", round: 12, rounds: 24 } });
worker.reply({ type: "unverified", value: { container: "c", containerFingerprint: "00000000" } });
worker.reply({ type: "progress", value: { stage: "check", round: 13, rounds: 24 } });
worker.reply({ type: "result", result: { container: "c" } });
assert.deepEqual(await pending, { container: "c" });
assert.deepEqual(progress, ["encrypt 12/24", "unverified c", "check 13/24"]);
assert.equal(worker.terminated, true, "each worker ends with its operation");

// Without an answer, left out or null, the client sends none, and the core names any passphrase
// of the wallet in what to keep.
for (const [description, options] of [
  ["left out", {}],
  ["null", { walletHasPassphrase: null }],
]) {
  const unanswered = client.encrypt({
    phrase: PHRASE,
    password: "p",
    passwordRepeat: "p",
    ...options,
  });
  worker = await started();
  assert.equal(
    worker.messages[0].walletHasPassphrase,
    options.walletHasPassphrase,
    `encrypt with walletHasPassphrase ${description} sends no answer to the worker`,
  );
  worker.reply({ type: "result", result: { container: "c" } });
  assert.deepEqual(await unanswered, { container: "c" });
}

globalThis.crossOriginIsolated = true;
assert.equal(client.mode(), "fast");
const fast = client.decrypt({ container: "c", password: "public test password" });
await assert.rejects(client.decrypt({ container: "c", password: "x" }), { code: "BUSY" });
worker = await started();
assert.equal(await worker.script.text(), "threaded source\n;\nworker source");
assert.equal(await worker.messages[0].argon2Script.text(), "threaded source");
worker.reply({
  type: "error",
  error: { code: "VERIFIER_MISMATCH", message: "the password or the settings are wrong" },
});
// The core's message becomes a sentence that a page can show as it is.
await assert.rejects(fast, {
  code: "VERIFIER_MISMATCH",
  message: "The password or the settings are wrong",
});
delete globalThis.crossOriginIsolated;

// Reading words starts a worker with the core only, and never waits for a long operation.
const long = client.check({ container: "c", password: "p", reference: { words: 12 } });
const reading = client.readContainer("DONA stov");
worker = await started(({ operation }) => operation === "describeContainer");
assert.equal(await worker.script.text(), "worker source");
assert.equal(worker.messages[0].operation, "describeContainer");
assert.equal(worker.messages[0].password, undefined);
worker.reply({ type: "result", result: { container: "donate stove" } });
assert.deepEqual(await reading, { container: "donate stove" });
client.cancel();
await assert.rejects(long, (error) => error instanceof MhfeCancelledError);

// A search with the decoy wallet sends no password and one with the owner's wallet does; both pass
// the worker's progress on, and a reference that does not belong to the search is a TypeError.
const decoyProgress = [];
const decoySearch = client.searchDecoy({
  container: "c ?",
  reference: { fingerprint: "487a156e" },
  onProgress: (value) => decoyProgress.push(value),
});
worker = await started(({ operation }) => operation === "searchDecoy");
assert.equal(worker.messages[0].password, undefined);
assert.deepEqual(
  [worker.messages[0].referenceKind, worker.messages[0].reference],
  ["fingerprint", "487a156e"],
);
worker.reply({ type: "progress", value: { stage: "search", candidate: 8, candidates: 8 } });
worker.reply({ type: "result", result: { found: false } });
assert.deepEqual(await decoySearch, { found: false });
assert.deepEqual(decoyProgress, [{ stage: "search", candidate: 8, candidates: 8 }]);
const walletSearch = client.searchWallet({
  container: "c ?",
  password: "p",
  reference: { builtInCheck: true },
});
worker = await started(({ operation }) => operation === "searchWallet");
assert.equal(worker.messages[0].referenceKind, "builtInCheck");
assert.ok(worker.messages[0].password instanceof Uint8Array, "the password goes as bytes");
worker.reply({ type: "result", result: { found: false } });
assert.deepEqual(await walletSearch, { found: false });
await assert.rejects(
  client.searchDecoy({ container: "c ?", reference: { walletCheck: true } }),
  TypeError,
);
await assert.rejects(
  client.searchWallet({ container: "c ?", password: "p", reference: { builtInCheck: "yes" } }),
  TypeError,
);

const encrypt = (options) =>
  client.encrypt({
    phrase: PHRASE,
    passwordRepeat: options.password,
    walletHasPassphrase: false,
    ...options,
  });
/** A rekey of the stand-in's container, with what its checks of the confirmation need. */
const rekeyWith = (options) =>
  client.rekey({
    container: "c",
    password: "p",
    newPassword: "n",
    newPasswordRepeat: "n",
    ...options,
  });
/** The TypeError of a walletHasPassphrase that is not a boolean, with its exact message. */
const walletPassphraseRequired = { name: "TypeError", message: WALLET_PASSPHRASE_REQUIRED };
/** The TypeError of a passphrase with the built-in check or the owner, with its exact message. */
const passphraseOnlyWithReference = { name: "TypeError", message: PASSPHRASE_ONLY_WITH_REFERENCE };
// Every error rejects the promise, the checks of the arguments included: none is thrown.
const refusals = [
  // encrypt may be given no answer, but one given is a boolean.
  ...[...NOT_BOOLEAN_ANSWERS, "yes"].map((walletHasPassphrase) => [
    () => encrypt({ password: "p", walletHasPassphrase }),
    walletPassphraseRequired,
  ]),
  [() => encrypt({ password: "p", sameLength: "yes" }), TypeError],
  [() => encrypt({ password: "p", repairWordCount: 3 }), { code: "INVALID_REPAIR_WORDS" }],
  [() => encrypt({ password: "p", passwordRepair: { repair: "3" } }), TypeError],
  [() => encrypt({ password: "a\uD800" }), { code: "INVALID_PASSWORD_TEXT" }],
  [
    () => encrypt({ password: "p", memoryLevel: 1 }),
    {
      code: "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      message: LIBRARY_MESSAGES.MEMORY_LEVEL_NOT_SUPPORTED_HERE,
    },
  ],
  [() => encrypt({ password: "p", pim: 1024 }), { code: "INVALID_PIM" }],
  [() => encrypt({ password: "p", onUnverified: "show" }), TypeError],
  [() => client.encrypt(), TypeError],
  [
    () => client.decrypt({ container: "c", password: "p", words: 13 }),
    { code: "INVALID_WORD_COUNT" },
  ],
  [
    () => client.check({ container: "c", password: "p", reference: { words: 24 } }),
    { code: "INVALID_WORD_COUNT", message: LIBRARY_MESSAGES.NO_BUILT_IN_CHECK_AT_24 },
  ],
  [
    () =>
      client.rekey({
        container: "c",
        password: "p",
        newPassword: "n",
        newPasswordRepeat: "n",
        confirmation: { words: 12 },
      }),
    TypeError,
  ],
  // A rekey's answer may be left out, but when given it is a boolean: null is not.
  ...["yes", ...NOT_BOOLEAN_ANSWERS, null].map((walletHasPassphrase) => [
    () => rekeyWith({ confirmation: { builtInCheck: true }, walletHasPassphrase }),
    walletPassphraseRequired,
  ]),
  [
    () =>
      rekeyWith({
        confirmation: { builtInCheck: true },
        walletHasPassphrase: false,
        onConfirmAgain: "again",
      }),
    TypeError,
  ],
  // A passphrase, as text or bytes, belongs only to an address or a fingerprint.
  ...[{ builtInCheck: true }, { owner: () => true }].flatMap((confirmation) =>
    ["TREZOR", encode("TREZOR")].map((passphrase) => [
      () => rekeyWith({ confirmation, passphrase, walletHasPassphrase: true }),
      passphraseOnlyWithReference,
    ]),
  ),
  [() => client.openHiddenWallets({ container: "c" }), TypeError],
  [() => client.readPhrase(42), TypeError],
  [() => client.readContainer(), TypeError],
  // A password of another type than a string or a Uint8Array is a TypeError, also when it is given
  // twice: the two entries do not differ, they are not passwords (AUD-010). The types are checked
  // before the entries are compared. A repetition left out still differs.
  ...[new Uint16Array([112]), new ArrayBuffer(1), new Uint8ClampedArray([112]), 5, null].flatMap(
    (value) => [
      [
        () => encrypt({ password: value, passwordRepeat: value }),
        { name: "TypeError", message: "password must be a string or a Uint8Array." },
      ],
      [
        () => encrypt({ password: value, passwordRepeat: undefined }),
        { name: "TypeError", message: "password must be a string or a Uint8Array." },
      ],
      [
        () => encrypt({ password: "p", passwordRepeat: value }),
        { name: "TypeError", message: "repeated password must be a string or a Uint8Array." },
      ],
      [
        () =>
          rekeyWith({
            confirmation: { builtInCheck: true },
            walletHasPassphrase: false,
            newPassword: value,
            newPasswordRepeat: value,
          }),
        { name: "TypeError", message: "new password must be a string or a Uint8Array." },
      ],
      [
        () =>
          rekeyWith({
            confirmation: { builtInCheck: true },
            walletHasPassphrase: false,
            newPasswordRepeat: value,
          }),
        {
          name: "TypeError",
          message: "repeated new password must be a string or a Uint8Array.",
        },
      ],
    ],
  ),
  [
    () => encrypt({ password: undefined, passwordRepeat: "p" }),
    { name: "TypeError", message: "password must be a string or a Uint8Array." },
  ],
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
worker = await started();
worker.reply({ type: "unverified", value: { container: "c", containerFingerprint: "0" } });
worker.reply({ type: "error", error: { code: "VERIFICATION_FAILED", message: "wrong" } });
await assert.rejects(failing, { code: "VERIFICATION_FAILED" });
assert.deepEqual(shown, ["c"]);

// A callback of the page that throws stops the operation: the worker ends, the promise rejects
// with CALLBACK_FAILED and the page's error as the cause, and later messages are ignored.
for (const [name, message] of [
  ["onProgress", { type: "progress", value: { stage: "encrypt", round: 1, rounds: 24 } }],
  ["onUnverified", { type: "unverified", value: { container: "c", containerFingerprint: "0" } }],
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
  const brokenWorker = await started();
  brokenWorker.reply(message);
  brokenWorker.reply({ type: "progress", value: { stage: "encrypt", round: 2, rounds: 24 } });
  brokenWorker.reply({ type: "result", result: { container: "c" } });
  await assert.rejects(
    broken,
    (error) => error.code === "CALLBACK_FAILED" && error.cause === pageError,
  );
  assert.equal(brokenWorker.terminated, true, `the worker stops when ${name} throws`);
  assert.equal(calls.length, 1, `nothing of the stopped operation reaches the page after ${name}`);
}

// A rekey asks the owner in the middle and sends the answer back. The callback gets the check as
// the worker gives it, with the length stated where the built-in check found another.
const ownerChecks = [];
const rekeying = client.rekey({
  container: "c",
  words: 15,
  password: "old",
  newPassword: "new",
  newPasswordRepeat: "new",
  confirmation: {
    owner: (check) => {
      ownerChecks.push(check);
      return check.words === 12;
    },
  },
  walletHasPassphrase: true,
});
worker = await started();
assert.equal(worker.messages[0].confirmKind, "owner");
assert.equal(worker.messages[0].walletHasPassphrase, true, "the page's answer goes to the worker");
const shownToOwner = {
  phrase: "p",
  words: 12,
  statedWords: 15,
  fingerprintWithoutPassphrase: "00000000",
};
worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(ownerChecks, [shownToOwner]);
assert.deepEqual(worker.messages[1], { type: "answer", value: true });
worker.reply({ type: "result", result: { container: "n" } });
assert.deepEqual(await rekeying, { container: "n" });
// After a refusal that allows another confirmation the worker asks the page (AUD-017-UI002): the
// page gets the refusal as an MhfeError with the owner's lengths, and its answer goes back with
// its passphrase as bytes, or with the length the owner compares; the owner callback of the
// answer is the one asked then. Without onConfirmAgain the worker is told not to ask.
const confirmAgainCalls = [];
const answers = [
  { fingerprint: PHRASE_TREZOR_FINGERPRINT, passphrase: "TREZOR" },
  { owner: (check) => confirmAgainCalls.push(["owner", check]) > 0 },
];
const confirmingAgain = rekeyWith({
  words: 15,
  confirmation: { builtInCheck: true },
  walletHasPassphrase: true,
  onConfirmAgain: (refusal) => {
    confirmAgainCalls.push(["refusal", refusal]);
    return answers.shift();
  },
});
worker = await started();
assert.equal(worker.messages[0].confirmsAgain, true);
const lengthDiffers = { code: "LENGTH_DIFFERS", message: "the check finds 12", ownerLengths: [15] };
worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
await new Promise((resolve) => setTimeout(resolve, 0));
const [, firstRefusal] = confirmAgainCalls[0];
assert.ok(firstRefusal.error instanceof MhfeError);
assert.deepEqual(
  [firstRefusal.error.code, firstRefusal.error.message, firstRefusal.ownerLengths],
  ["LENGTH_DIFFERS", "The check finds 12", [15]],
);
assert.deepEqual(
  fieldsOf(worker.messages[1].value, ["confirmKind", "reference", "coin", "path", "words"]),
  {
    confirmKind: "fingerprint",
    reference: PHRASE_TREZOR_FINGERPRINT,
    coin: "",
    path: "",
    words: 0,
  },
);
assert.equal(new TextDecoder().decode(worker.messages[1].value.passphrase), "TREZOR");
worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(fieldsOf(worker.messages[2].value, ["confirmKind", "words"]), {
  confirmKind: "owner",
  words: 15,
});
worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(confirmAgainCalls.at(-1), ["owner", shownToOwner]);
assert.deepEqual(worker.messages[3], { type: "answer", value: true });
worker.reply({ type: "result", result: { container: "n" } });
assert.deepEqual(await confirmingAgain, { container: "n" });
const notAsking = rekeyWith({ confirmation: { builtInCheck: true }, walletHasPassphrase: false });
worker = await started();
assert.equal(worker.messages[0].confirmsAgain, false);
worker.reply({ type: "result", result: { container: "n" } });
await notAsking;
// A null answer ends the rekey with the refusal, as the worker throws it; an answer the client
// refuses stops the rekey with CALLBACK_FAILED, its TypeError as the cause.
const stopsAgain = rekeyWith({
  confirmation: { builtInCheck: true },
  walletHasPassphrase: false,
  onConfirmAgain: () => null,
});
worker = await started();
worker.reply({ type: "ask", question: "confirmAgain", value: lengthDiffers });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(worker.messages[1], { type: "answer", value: null });
worker.reply({ type: "error", error: { code: "LENGTH_DIFFERS", message: "the check finds 12" } });
await assert.rejects(stopsAgain, { code: "LENGTH_DIFFERS" });
for (const [answer, ownerLengths, message] of [
  [{ owner: () => true, words: 12 }, [15], "words must name the reading the owner compares: 15."],
  [
    { owner: () => true },
    [],
    "the owner cannot confirm this phrase: give an address or the fingerprint.",
  ],
  [{ owner: () => true }, [12, 21], "words must name the reading the owner compares: 12 or 21."],
  [{ fingerprint: "00000000", words: 15 }, [15], "words belongs only to the owner's confirmation."],
  [{ owner: () => true, passphrase: "TREZOR" }, [15], PASSPHRASE_ONLY_WITH_REFERENCE],
  [
    { walletCheck: true },
    [15],
    "a rekey is confirmed by an address or a fingerprint, not by the wallet check.",
  ],
]) {
  const refused = rekeyWith({
    confirmation: { builtInCheck: true },
    walletHasPassphrase: false,
    onConfirmAgain: () => answer,
  });
  worker = await started();
  worker.reply({
    type: "ask",
    question: "confirmAgain",
    value: { ...lengthDiffers, ownerLengths },
  });
  await assert.rejects(
    refused,
    (error) =>
      error.code === "CALLBACK_FAILED" &&
      error.cause instanceof TypeError &&
      error.cause.message === message,
    message,
  );
  assert.equal(worker.terminated, true, `${message}: the worker stops`);
}
// Whether a left-out answer is enough is the core's to judge, from the reference's passphrase:
// the client sends it as it is, undefined, with the passphrase as bytes.
const byFingerprint = rekeyWith({
  confirmation: { fingerprint: PHRASE_TREZOR_FINGERPRINT },
  passphrase: "TREZOR",
});
worker = await started();
assert.deepEqual(
  fieldsOf(worker.messages[0], ["confirmKind", "reference", "walletHasPassphrase"]),
  {
    confirmKind: "fingerprint",
    reference: PHRASE_TREZOR_FINGERPRINT,
    walletHasPassphrase: undefined,
  },
);
assert.equal(new TextDecoder().decode(worker.messages[0].passphrase), "TREZOR");
worker.reply({ type: "result", result: { container: "n" } });
assert.deepEqual(await byFingerprint, { container: "n" });
// An empty passphrase is none, so the built-in check takes it.
const emptyPassphrase = rekeyWith({
  confirmation: { builtInCheck: true },
  passphrase: "",
  walletHasPassphrase: false,
});
worker = await started();
assert.deepEqual(fieldsOf(worker.messages[0], ["confirmKind", "walletHasPassphrase"]), {
  confirmKind: "builtInCheck",
  walletHasPassphrase: false,
});
assert.equal(worker.messages[0].passphrase.length, 0);
worker.reply({ type: "result", result: { container: "n" } });
assert.deepEqual(await emptyPassphrase, { container: "n" });
