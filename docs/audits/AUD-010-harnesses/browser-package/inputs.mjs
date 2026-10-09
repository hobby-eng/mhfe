// AUD-010 browser-package probe of the call contracts (CHECK-API-001): the public classes of web/
// called with runtime values outside their declared types (undefined, null, wrong enums, wrong
// typed arrays, extra fields, missing callbacks), and the Rust translators of src/wasm_api/ called
// directly through the package's real WebAssembly (dist/runtime/mhfe.wasm) with an Argon2 stand-in
// that refuses every call, so that no Argon2 work runs: a request that gets as far as Argon2 was
// accepted. Public test data only. Exits non-zero when a check fails.
//
//   node docs/audits/AUD-010-harnesses/browser-package/inputs.mjs
import { readFileSync } from "node:fs";
import { Checks, StandInWorker, loadPackage, packageModule, standInSources, tick } from "./lib.mjs";

const checks = new Checks("AUD-010 browser-package: call contracts");
globalThis.Worker = StandInWorker;
const pkg = await loadPackage("web");
const { MhfeClient } = pkg.core;
const { MhfeRepair } = pkg.repair;
const { MhfePasswords } = pkg.passwords;
const { MhfeWallet } = pkg.wallet;
const { encodeSecret, secretBuffers } = pkg.runtime;

/** The public BIP39 test phrase and its first BIP84 receiving address (BIP84 test vector). */
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const PHRASE_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/** No method of a class throws when called: every refusal is a rejection. */
async function refused(call, expected, label) {
  let threw = false;
  let value;
  try {
    value = call();
  } catch (error) {
    threw = true;
    value = Promise.reject(error);
  }
  value?.catch?.(() => {});
  checks.ok(!threw, `${label}: returns a promise, does not throw`);
  return checks.rejects(value, expected, label);
}

// --- Part 1: the classes, with a stand-in worker --------------------------------------------
const operationsStarted = () => StandInWorker.instances.filter((w) => !w.isSelfCheck).length;
const client = new MhfeClient(standInSources());
await client.startupCheck({ argon2: false });
const base = {
  phrase: PHRASE,
  password: "synthetic-test",
  passwordRepeat: "synthetic-test",
  walletHasPassphrase: false,
};
const before = operationsStarted();
for (const [label, options, expected] of [
  ["encrypt without options", undefined, TypeError],
  ["encrypt with null", null, TypeError],
  ['walletHasPassphrase "false"', { ...base, walletHasPassphrase: "false" }, TypeError],
  ["walletHasPassphrase left out", { ...base, walletHasPassphrase: undefined }, TypeError],
  ['sameLength "true"', { ...base, sameLength: "true" }, TypeError],
  ["repairWordCount 3", { ...base, repairWordCount: 3 }, "INVALID_REPAIR_WORDS"],
  ['repairWordCount "4"', { ...base, repairWordCount: "4" }, "INVALID_REPAIR_WORDS"],
  ["pim -1", { ...base, pim: -1 }, "INVALID_PIM"],
  ["pim 1.5", { ...base, pim: 1.5 }, "INVALID_PIM"],
  ["pim null", { ...base, pim: null }, "INVALID_PIM"],
  ['pim "0"', { ...base, pim: "0" }, "INVALID_PIM"],
  ["memoryLevel 1", { ...base, memoryLevel: 1 }, "MEMORY_LEVEL_NOT_SUPPORTED_HERE"],
  ["memoryLevel 22", { ...base, memoryLevel: 22 }, "INVALID_MEMORY_LEVEL"],
  [
    "password as Uint16Array",
    { ...base, password: new Uint16Array([1]), passwordRepeat: new Uint16Array([1]) },
    TypeError,
  ],
  [
    "password as ArrayBuffer",
    { ...base, password: new ArrayBuffer(4), passwordRepeat: new ArrayBuffer(4) },
    TypeError,
  ],
  [
    "password as Uint8ClampedArray",
    { ...base, password: new Uint8ClampedArray([65]), passwordRepeat: new Uint8ClampedArray([65]) },
    TypeError,
  ],
  ['passwordRepair "Corrected"', { ...base, passwordRepair: "Corrected" }, TypeError],
  ["passwordRepair { repair: 0 }", { ...base, passwordRepair: { repair: 0 } }, TypeError],
  ['passwordRepair { repair: "1" }', { ...base, passwordRepair: { repair: "1" } }, TypeError],
  ["onProgress not a function", { ...base, onProgress: 5 }, TypeError],
  ["onUnverified not a function", { ...base, onUnverified: "x" }, TypeError],
  ["phrase as a number", { ...base, phrase: 12 }, TypeError],
]) {
  await refused(() => client.encrypt(options), expected, `encrypt: ${label}`);
}
// A password of a type that is not text or bytes, given twice: refused, under which code.
const numeric = await client
  .encrypt({ ...base, password: 5, passwordRepeat: 5 })
  .catch((error) => error);
checks.note(
  `encrypt with password 5 and passwordRepeat 5 rejects with ${numeric?.constructor?.name} ${numeric?.code ?? ""}`,
);
checks.ok(operationsStarted() === before, "no refused encrypt reached a worker");

for (const [label, options, expected] of [
  ["words 13", { container: "x", password: "p", words: 13 }, "INVALID_WORD_COUNT"],
  ['words "12"', { container: "x", password: "p", words: "12" }, "INVALID_WORD_COUNT"],
  ["container as a number", { container: 5, password: "p" }, TypeError],
]) {
  await refused(() => client.decrypt(options), expected, `decrypt: ${label}`);
}

const checkBase = { container: "x", password: "synthetic-test" };
for (const [label, reference, expected, extra = {}] of [
  ["no reference", undefined, TypeError],
  ["an empty reference", {}, TypeError],
  [
    "address and fingerprint",
    { address: ADDRESS, coin: "bitcoin", fingerprint: "73c5da0a" },
    TypeError,
  ],
  ["address without coin", { address: ADDRESS }, TypeError],
  ["fingerprint with coin", { fingerprint: "73c5da0a", coin: "bitcoin" }, TypeError],
  ["words 24", { words: 24 }, "INVALID_WORD_COUNT"],
  ['walletCheck "yes"', { walletCheck: "yes" }, TypeError],
  ["coin as a number", { address: ADDRESS, coin: 5 }, TypeError],
  ["passphrase null", { fingerprint: "73c5da0a" }, TypeError, { passphrase: null }],
]) {
  await refused(
    () => client.check({ ...checkBase, reference, ...extra }),
    expected,
    `check: ${label}`,
  );
}

const rekeyBase = {
  container: "x",
  words: 24,
  password: "synthetic-old",
  otherWalletsMoved: true,
  newPassword: "synthetic-new",
  newPasswordRepeat: "synthetic-new",
  walletHasPassphrase: false,
  confirmation: { builtInCheck: true },
};
for (const [label, options, expected] of [
  [
    "builtInCheck and owner",
    { confirmation: { builtInCheck: true, owner: () => true } },
    TypeError,
  ],
  ['owner "yes"', { confirmation: { owner: "yes" } }, TypeError],
  ["words as confirmation", { confirmation: { words: 12 } }, TypeError],
  ["walletCheck as confirmation", { confirmation: { walletCheck: true } }, TypeError],
  ['otherWalletsMoved "true"', { otherWalletsMoved: "true" }, "OTHER_WALLETS_NOT_CONFIRMED"],
  ["walletHasPassphrase null", { walletHasPassphrase: null }, TypeError],
  ["passphrase with builtInCheck", { passphrase: "synthetic" }, TypeError],
  ["newPim 1.5", { newPim: 1.5 }, "INVALID_PIM"],
  ["newMemoryLevel 1", { newMemoryLevel: 1 }, "MEMORY_LEVEL_NOT_SUPPORTED_HERE"],
  ["words 13", { words: 13 }, "INVALID_WORD_COUNT"],
  ["newPasswordRepeat that differs", { newPasswordRepeat: "other" }, "PASSWORDS_DIFFER"],
]) {
  await refused(() => client.rekey({ ...rekeyBase, ...options }), expected, `rekey: ${label}`);
}
for (const [label, options] of [
  ["without mainPassphrase", { container: "x" }],
  ["mainPassphrase null", { container: "x", mainPassphrase: null }],
]) {
  await refused(() => client.openHiddenWallets(options), TypeError, `openHiddenWallets: ${label}`);
}
await refused(() => client.startupCheck({ argon2: "no" }), TypeError, 'startupCheck: argon2 "no"');
await refused(() => client.fullCheck({ onProgress: 1 }), TypeError, "fullCheck: onProgress 1");
checks.ok(operationsStarted() === before, "no refused core call reached an operation worker");

// What reaches the worker for extra fields: they are dropped, not passed on.
client
  .check({ ...checkBase, reference: { fingerprint: "73c5da0a", extra: "field" } })
  .catch(() => {});
const extraWorker = await StandInWorker.operation((m) => m.operation === "check");
checks.ok(
  extraWorker.messages[0].referenceKind === "fingerprint" && !("extra" in extraWorker.messages[0]),
  "an extra field of a reference is dropped; the kind stays the one given",
);
client.cancel();
await tick();

const repair = new MhfeRepair(standInSources());
await refused(
  () => repair.repairWords({ container: "x", count: "4" }),
  TypeError,
  'repairWords: count "4"',
);
await refused(() => repair.repairWords({ container: "x" }), TypeError, "repairWords: no count");
await refused(() => repair.repairPlate({ plate: 5, card: "x" }), TypeError, "repairPlate: plate 5");

const passwords = new MhfePasswords(standInSources());
await refused(() => passwords.review({ password: null }), TypeError, "review: password null");
await refused(
  () => passwords.strength({ password: "x", passwordRepair: "bad" }),
  TypeError,
  'strength: passwordRepair "bad"',
);
await refused(() => passwords.make({ kind: 5 }), TypeError, "make: kind 5");
await refused(() => passwords.make({ count: 1.5 }), TypeError, "make: count 1.5");
await refused(() => passwords.make({ count: null }), TypeError, "make: count null");
await refused(() => passwords.make({ dice: 12345 }), TypeError, "make: dice 12345");

const wallet = new MhfeWallet(standInSources());
await refused(() => wallet.walletCheck({ phrase: 5 }), TypeError, "walletCheck: phrase 5");
await refused(
  () => wallet.fingerprint({ phrase: PHRASE, passphrase: null }),
  TypeError,
  "fingerprint: passphrase null",
);
await refused(
  () => wallet.describeAddress({ address: ADDRESS }),
  TypeError,
  "describeAddress: no coin",
);
await refused(
  () => wallet.describeAddress({ address: ADDRESS, coin: "bitcoin", path: null }),
  TypeError,
  "describeAddress: path null",
);
await refused(
  () =>
    wallet.drawPhrase({ passphrase: "p", passphraseRepeat: "p", walletCheck: true, workers: 0 }),
  TypeError,
  "drawPhrase: workers 0",
);
await refused(
  () => wallet.drawPhrase({ passphrase: "p", passphraseRepeat: "p", walletCheck: "yes" }),
  TypeError,
  'drawPhrase: walletCheck "yes" with a passphrase',
);
await refused(
  () => wallet.drawPhrase({ passphrase: "", walletCheck: true }),
  "WALLET_CHECK_NEEDS_PASSPHRASE",
  "drawPhrase: walletCheck without a passphrase",
);
// A page's own choice of workers has no upper bound.
StandInWorker.instances.length = 0;
const many = wallet.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 64,
});
many.catch(() => {});
for (let i = 0; i < 20 && operationsStarted() < 64; i += 1) await tick();
checks.note(
  `drawPhrase({ workers: 64 }) starts ${operationsStarted()} workers (no upper bound; the default is at most 8)`,
);
wallet.cancel();
await tick();

// --- Part 2: the page's byte copies of secrets ("a caller's own array is copied, never emptied")
{
  const plain = new TextEncoder().encode("synthetic-test");
  const copy = encodeSecret(plain, "password", false);
  checks.ok(copy.buffer !== plain.buffer, "a Uint8Array is copied into a buffer of its own");
  // Node's Buffer is a Uint8Array whose slice() returns a view of the same memory.
  const buffer = Buffer.from("synthetic-test");
  const fromBuffer = encodeSecret(buffer, "password", false);
  const shared = fromBuffer.buffer === buffer.buffer;
  checks.ok(
    !shared,
    "a Uint8Array subclass (Node's Buffer) is copied into a buffer of its own",
    "encodeSecret returns a view of the caller's own memory: its buffer goes into the transfer list",
  );
  if (shared) {
    const message = { password: fromBuffer };
    const transfer = secretBuffers(message);
    checks.note(
      `the transfer list then holds the caller's ArrayBuffer of ${transfer[0].byteLength} bytes ` +
        `(Node's Buffer pool), not a ${buffer.length}-byte copy`,
    );
    // A browser-style Buffer (one ArrayBuffer per Buffer, as the 'buffer' package allocates).
    class ViewSlicingArray extends Uint8Array {
      slice(start, end) {
        return this.subarray(start, end);
      }
    }
    const callers = ViewSlicingArray.from(new TextEncoder().encode("synthetic-test"));
    const viaClass = encodeSecret(callers, "password", false);
    for (const each of secretBuffers({ password: viaClass })) {
      structuredClone(each, { transfer: [each] });
    }
    checks.ok(
      callers.length !== 0,
      "the caller's own array still holds its bytes after the request is transferred",
      `after the transfer the caller's array has length ${callers.length}`,
    );
  }
}

// --- Part 3: the Rust translators, through the package's real WebAssembly ------------------
const worker = readFileSync("dist/runtime/worker.js", "utf8");
const glue = worker.slice(0, worker.indexOf("// The bridge from the Rust core"));
const mhfe = new Function(`${glue}\nreturn mhfe;`)();
mhfe.initSync({ module: packageModule() });
/** An Argon2 build that refuses every call: reaching it means the request was accepted. */
const noArgon2 = {
  derive() {
    throw new Error("ARGON2_FAILED: the audit's stand-in Argon2 refuses every call");
  },
  reserve() {
    throw new Error("ARGON2_FAILED: the audit's stand-in Argon2 refuses every call");
  },
};
const noop = () => {};
const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
const utf8 = (text) => new TextEncoder().encode(text);
/** Calls a binding; resolves to its error code, or "accepted" when it reached Argon2 or returned. */
function outcome(call) {
  try {
    const value = call();
    return { code: "returned", value };
  } catch (error) {
    const match = /^([A-Z][A-Z0-9_]+): (.*)$/su.exec(error?.message ?? "");
    const code = match?.[1] ?? "UNPARSED";
    // The stand-in's refusal surfaces as ARGON2_FAILED or, from the known answer, SELF_CHECK_FAILED.
    const reachedArgon2 =
      /stand-in Argon2/u.test(error?.message ?? "") ||
      ["ARGON2_FAILED", "SELF_CHECK_FAILED"].includes(code);
    return { code: reachedArgon2 ? "reached Argon2" : code, message: match?.[2] ?? error?.message };
  }
}
function translator(label, call, expected) {
  const result = outcome(call);
  checks.ok(
    result.code === expected,
    `wasm ${label} -> ${result.code}`,
    `expected ${expected}: ${result.message ?? JSON.stringify(result.value)}`,
  );
  return result;
}
const pw = () => utf8("synthetic-test");
const encrypt = (overrides) => {
  const a = {
    phrase: PHRASE,
    choice: "",
    position: 0,
    pim: 0,
    memoryLevel: 0,
    sameLength: false,
    repair: 0,
    answer: false,
    ...overrides,
  };
  return () =>
    mhfe.encrypt(
      a.phrase,
      pw(),
      pw(),
      a.choice,
      a.position,
      a.pim,
      a.memoryLevel,
      a.sameLength,
      a.repair,
      a.answer,
      noArgon2,
      noop,
      noop,
    );
};
translator('encrypt walletHasPassphrase "true"', encrypt({ answer: "true" }), "INVALID_REQUEST");
translator(
  "encrypt walletHasPassphrase undefined",
  encrypt({ answer: undefined }),
  "INVALID_REQUEST",
);
translator("encrypt walletHasPassphrase 1", encrypt({ answer: 1 }), "INVALID_REQUEST");
translator('encrypt choice "Corrected"', encrypt({ choice: "Corrected" }), "INVALID_REQUEST");
translator("encrypt pim 1.5", encrypt({ pim: 1.5 }), "INVALID_PIM");
translator("encrypt pim 2^32", encrypt({ pim: 2 ** 32 }), "INVALID_PIM");
translator("encrypt pim NaN", encrypt({ pim: Number.NaN }), "INVALID_PIM");
translator("encrypt pim -1", encrypt({ pim: -1 }), "INVALID_PIM");
translator(
  "encrypt memory level 1",
  encrypt({ memoryLevel: 1 }),
  "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
);
translator("encrypt repair words 3", encrypt({ repair: 3 }), "INVALID_REPAIR_WORDS");
translator("encrypt repair words 4.5", encrypt({ repair: 4.5 }), "INVALID_REPAIR_WORDS");
translator(
  "encrypt same length of 24 words",
  encrypt({ phrase: PHRASE_24, sameLength: true }),
  "SAME_LENGTH_NEEDS_SHORT_PHRASE",
);
translator(
  "encrypt of a valid request (stops at Argon2's known answer)",
  encrypt({}),
  "reached Argon2",
);

const decrypt = (words) => () => mhfe.decrypt(PHRASE_24, pw(), "", 0, 0, 0, words, noArgon2, noop);
translator("decrypt words 13", decrypt(13), "INVALID_WORD_COUNT");
translator("decrypt words 12.5", decrypt(12.5), "INVALID_WORD_COUNT");

const check =
  (kind, reference, coin, path, passphrase = "") =>
  () =>
    mhfe.check(
      PHRASE_24,
      pw(),
      "",
      0,
      0,
      0,
      kind,
      reference,
      coin,
      path,
      utf8(passphrase),
      noArgon2,
      noop,
    );
translator('check kind "seed"', check("seed", "", "", ""), "INVALID_REQUEST");
translator('check kind "Address"', check("Address", ADDRESS, "bitcoin", ""), "INVALID_REQUEST");
translator('check coin ""', check("address", ADDRESS, "", ""), "INVALID_COIN");
const btc = translator('check coin "BTC"', check("address", ADDRESS, "BTC", ""), "INVALID_COIN");
translator(
  'check path "m/x"',
  check("address", ADDRESS, "bitcoin", "m/x"),
  "INVALID_DERIVATION_PATH",
);
translator('check words "12.0"', check("words", "12.0", "", ""), "INVALID_WORD_COUNT");
translator(
  "check walletCheck without a passphrase",
  check("walletCheck", "", "", ""),
  "WALLET_CHECK_NEEDS_PASSPHRASE",
);
const lenient = outcome(check("address", ADDRESS, " Bitcoin ", ""));
checks.note(
  `check coin " Bitcoin " (spaces, capital) -> ${lenient.code}: the coin id is trimmed and lower-cased`,
);
checks.note(`the INVALID_COIN message names every coin: "${btc.message}"`);

translator(
  "RekeySession without the yes about other wallets",
  () => new mhfe.RekeySession(PHRASE_24, 24, pw(), "", 0, 0, 0, false, noArgon2),
  "OTHER_WALLETS_NOT_CONFIRMED",
);
translator(
  "RekeySession words 13",
  () => new mhfe.RekeySession(PHRASE_24, 13, pw(), "", 0, 0, 0, true, noArgon2),
  "INVALID_WORD_COUNT",
);
{
  const session = new mhfe.RekeySession(PHRASE_24, 24, pw(), "", 0, 0, 0, true, noArgon2);
  translator(
    "RekeySession recover before setNew",
    () => session.recover("builtInCheck", "", "", "", utf8(""), false, noop),
    "INVALID_REQUEST",
  );
  session.free();
}
const rekeyAt = (kind, passphrase, answer) => () => {
  const session = new mhfe.RekeySession(PHRASE_24, 24, pw(), "", 0, 0, 0, true, noArgon2);
  try {
    session.setNew(utf8("synthetic-new"), utf8("synthetic-new"), "", 0, 0, 0, 0);
    return session.recover(
      kind,
      kind === "fingerprint" ? "73c5da0a" : "",
      "",
      "",
      utf8(passphrase),
      answer,
      noop,
    );
  } finally {
    session.free();
  }
};
translator(
  'rekey recover kind "walletCheck"',
  rekeyAt("walletCheck", "", false),
  "INVALID_REQUEST",
);
translator('rekey recover kind "words"', rekeyAt("words", "", false), "INVALID_REQUEST");
translator(
  "rekey recover owner with a passphrase",
  rekeyAt("owner", "synthetic", false),
  "INVALID_REQUEST",
);
translator('rekey recover answer "yes"', rekeyAt("fingerprint", "", "yes"), "INVALID_REQUEST");
translator(
  "HiddenWalletSession on a 12-word container",
  () => new mhfe.HiddenWalletSession(PHRASE, 0, 0, utf8(""), noArgon2),
  "INVALID_CONTAINER",
);
translator(
  "HiddenWalletSession memory level 1",
  () => new mhfe.HiddenWalletSession(PHRASE_24, 0, 1, utf8(""), noArgon2),
  "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
);
translator(
  'selfCheckRepair tier "Startup"',
  () => mhfe.selfCheckRepair("Startup", [], noop, noop),
  "INVALID_REQUEST",
);
const unknownSkip = outcome(() =>
  JSON.parse(mhfe.selfCheckRepair("startup", ["no-such-part"], noop, noop)),
);
checks.note(
  `selfCheckRepair with an unknown part to skip -> ${unknownSkip.code} (unknown ids are ignored)`,
);

translator("repairWords count 3", () => mhfe.repairWords(PHRASE_24, 3), "INVALID_REPAIR_WORDS");
translator("repairWords count 4.5", () => mhfe.repairWords(PHRASE_24, 4.5), "INVALID_REPAIR_WORDS");
translator(
  'makePassword kind "Words"',
  () => mhfe.makePassword("Words", undefined, utf8(""), random),
  "INVALID_REQUEST",
);
translator(
  "makePassword 0 words",
  () => mhfe.makePassword("words", 0, utf8(""), random),
  "INVALID_PASSWORD_SIZE",
);
translator(
  "makePassword 33 words",
  () => mhfe.makePassword("words", 33, utf8(""), random),
  "INVALID_PASSWORD_SIZE",
);
translator(
  "makePassword characters from dice",
  () => mhfe.makePassword("characters", 16, utf8("11111"), random),
  "INVALID_REQUEST",
);
const checkWordSeven = outcome(() =>
  JSON.parse(mhfe.makePassword("checkWord", 7, utf8(""), random)),
);
const sevenWords = checkWordSeven.value?.password?.split(" ").length;
checks.ok(
  checkWordSeven.code !== "returned",
  'makePassword "checkWord" with count 7 is refused, as the command line refuses --check-word with --words',
  `it returned ${sevenWords} words (five and the check word), ${checkWordSeven.value?.bits} bits; count was ignored`,
);
const browserWithCount = await (async () => {
  StandInWorker.instances.length = 0;
  const call = passwords.make({ kind: "checkWord", count: 7 });
  call.catch(() => {});
  const sent = await StandInWorker.operation((m) => m.operation === "make");
  return sent.messages[0];
})();
checks.note(
  `MhfePasswords.make({ kind: "checkWord", count: 7 }) sends count ${browserWithCount.count} to the worker unrefused`,
);
translator(
  'passwordStrength choice "bogus"',
  () => mhfe.passwordStrength(pw(), "bogus", 0),
  "INVALID_REQUEST",
);
translator(
  "reviewPassword with a repetition that differs",
  () => mhfe.reviewPassword(pw(), utf8("other"), true),
  "PASSWORDS_DIFFER",
);
translator(
  'describeAddress coin "BTC"',
  () => mhfe.describeAddress(ADDRESS, "BTC", ""),
  "INVALID_COIN",
);
translator(
  "drawPhrase with the check and no passphrase",
  () => mhfe.drawPhrase(utf8(""), true, random, noop),
  "WALLET_CHECK_NEEDS_PASSPHRASE",
);
translator(
  "walletCheck of 12 words",
  () => mhfe.walletCheck(PHRASE, utf8("synthetic")),
  "INVALID_WORD_COUNT",
);
const fingerprint = outcome(() => mhfe.walletFingerprint(PHRASE, utf8("")));
checks.ok(
  fingerprint.value === "73c5da0a",
  "walletFingerprint of the public test phrase is 73c5da0a",
);

checks.finish();
setTimeout(() => process.exit(), 50);
