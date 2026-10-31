const PASSWORD = encode(TEST_PASSWORD);
const NEW_PASSWORD = encode("another public test password");
/** Four Argon2 lanes need at least 32 KiB; 256 KiB and one pass match the native test. */
const REDUCED_MEMORY_KIB = 256;
const REDUCED_PASSES = 1;
/** The master key fingerprint of PHRASE without a passphrase (BIP32 test vectors). */
const PHRASE_FINGERPRINT = "73c5da0a";
/** The same with the BIP39 test passphrase "TREZOR" (src/wallet.rs). */
const PHRASE_TREZOR_FINGERPRINT = "b4e3f5ed";
/** BIP84's first address of PHRASE with the passphrase "TREZOR" (src/wallet.rs). */
const PHRASE_TREZOR_ADDRESS = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";
// The core's refusals of the answer whether the wallet has a BIP39 passphrase, exactly as the
// WebAssembly throws them: the answer not given where nothing shows the passphrase, given against
// the reference's passphrase, or not a boolean (src/rekey.rs, src/wasm_api/core.rs).
const PASSPHRASE_UNSTATED =
  "INVALID_REQUEST: invalid request: say whether the wallet has a BIP39 passphrase";
const PASSPHRASE_CONTRADICTED =
  "INVALID_REQUEST: invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows";
/** A reference without the passphrase for a wallet stated to have one (src/rekey.rs). */
const PASSPHRASE_NOT_COMPARED =
  "INVALID_REQUEST: invalid request: the reference must be compared with the wallet's BIP39 passphrase, which it has";
const PASSPHRASE_ANSWER_NOT_BOOLEAN =
  "INVALID_REQUEST: invalid request: walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase";
/** A rekey's refusal of a passphrase with the built-in check or the owner (src/wasm_api/core.rs). */
const PASSPHRASE_WITHOUT_REFERENCE =
  "INVALID_REQUEST: invalid request: a passphrase belongs to an address or fingerprint confirmation";
/** A length without a built-in check confirmed by the built-in check (src/error.rs). */
const REFERENCE_REQUIRED =
  "REFERENCE_REQUIRED: the built-in check alone does not confirm this recovery: a 24-word original seed phrase, a same-length container and a detected length need a receiving address or the master key fingerprint of the wallet, or the owner's comparison with the backup, before the phrase is encrypted again";
/**
 * The client's TypeError for a walletHasPassphrase given but not a boolean, where encrypt takes
 * undefined and null as no answer and a rekey only undefined (web/client.js).
 */
const WALLET_PASSPHRASE_REQUIRED =
  "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
/** The client's TypeError for a passphrase with the built-in check or the owner (web/client.js). */
const PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address or fingerprint confirmation.";
/** Values that are not a boolean, which no answer whether the wallet has a passphrase may be. */
const NOT_BOOLEAN_ANSWERS = ["no", "true", 1, 0, {}];
/** The self-test's fault where a round's published input gave another key (src/self_test.rs). */
const argon2KeyFault = (round) => ({
  kind: "argon2-key",
  round,
  message:
    `first wrong round ${round} of 24: Argon2id returned another key for the published input, so the fault is in Argon2id`,
});
/** The error of an operation whose Argon2 build gave another answer (src/error.rs). */
const argon2Refused = (detail) =>
  `SELF_CHECK_FAILED: the self-test failed: Argon2id: ${detail}. `
  + "Do not use this program on this computer";
const SUITE_3 = "MHFE-BIP39-256-EXPERIMENTAL-3";
const SUITE_4 = "MHFE-BIP39-LP-EXPERIMENTAL-4";
const VERSION = /^version = "([^"]+)"/mu.exec(read("Cargo.toml").toString())[1];

function expectCode(code, action) {
  assert.throws(action, (error) => error.message.startsWith(`${code}: `), code);
}

/** Like expectCode, for the whole message, "CODE: message" as the WebAssembly throws it. */
function expectMessage(message, action, description = message) {
  assert.throws(action, { message }, description);
}

/** The round callback of a refusal that must come before any Argon2 round. */
function noRoundExpected(stage, round) {
  throw new Error(`the refusal came after ${stage} round ${round} had started`);
}

/** The named fields of an object, to compare them without the others. */
function fieldsOf(object, names) {
  return Object.fromEntries(names.map((name) => [name, object[name]]));
}

// The package's wasm-bindgen glue defines `mhfe`, the bindings of every module.
const bindings = new Function(`${GLUE}\nreturn mhfe;`)();
const coreMemory = bindings.initSync({ module: read("dist/runtime/mhfe.wasm") }).memory;
const packageWasm = read("dist/runtime/mhfe.wasm");
/** A new instance of the package's bindings over `wasm`, apart from the one above. */
function bindingsOver(wasm) {
  const fresh = new Function(`${GLUE}\nreturn mhfe;`)();
  fresh.initSync({ module: wasm });
  return fresh;
}

// Part 1: the core module and the Argon2 bridge.
const core = bindings;
const argon2Engine = new Function(`${read("web/argon2-engine.js")}\nreturn argon2Engine;`)();

const parameters = JSON.parse(core.suiteParameters());
assert.equal(parameters.version, VERSION);
assert.equal(core.packageVersion(), VERSION);
assert.equal(parameters.apiVersion, undefined, "the release version replaced the API counter");
assert.equal(parameters.suiteId, SUITE_3);
assert.equal(parameters.sameLengthSuiteId, SUITE_4);
assert.equal(parameters.highestBrowserMemoryLevel, 0);
assert.deepEqual(parameters.wordCounts, [12, 15, 18, 21, 24]);
assert.deepEqual(parameters.repairWordCounts, [2, 4, 6, 8]);
assert.deepEqual(parameters.repairCapacities[1], { count: 4, unreadable: 4, wrong: 2 });
assert.ok(
  parameters.hiddenWalletRefusals.includes("PASSWORD_ALREADY_USED")
    && parameters.hiddenWalletRefusals.includes("HIDDEN_WALLET_PASSES_CHECK"),
  "the core names the refusals that keep a session of hidden wallets open",
);

/**
 * The positional arguments of the core's operations, from named ones. encrypt's phrase goes as its
 * UTF-8 bytes, as the worker passes it. encrypt's walletHasPassphrase is false only when the
 * options leave it out: one given as undefined or null reaches the core as it is, which then names
 * any passphrase of the wallet in what to keep.
 */
const operations = {
  encrypt: (phrase, password, argon2, options = {}) =>
    JSON.parse(
      core.encrypt(
        encode(phrase),
        password,
        options.repeat ?? password.slice(),
        options.choice ?? "",
        options.position ?? 0,
        options.pim ?? 0,
        options.memoryLevel ?? 0,
        options.sameLength ?? false,
        options.repairWordCount ?? 0,
        Object.hasOwn(options, "walletHasPassphrase") ? options.walletHasPassphrase : false,
        argon2,
        options.onRound ?? (() => {}),
        options.onUnverified ?? (() => {}),
      ),
    ),
  decrypt: (container, password, argon2, options = {}) =>
    JSON.parse(
      core.decrypt(
        container,
        password,
        options.choice ?? "",
        options.position ?? 0,
        options.pim ?? 0,
        options.memoryLevel ?? 0,
        options.words ?? 0,
        encode(options.passphrase ?? ""),
        argon2,
        options.onRound ?? (() => {}),
      ),
    ),
  // The worker's check: one recovery in a session, then the comparison.
  check: (container, password, argon2, kind, reference, options = {}) => {
    const coin = options.coin ?? "";
    const path = options.path ?? "";
    const passphrase = options.passphrase ?? noBytes();
    const copy = passphrase.slice();
    const session = new core.CheckSession(
      container,
      password,
      "",
      0,
      options.pim ?? 0,
      0,
      kind,
      reference,
      coin,
      path,
      passphrase,
      argon2,
      options.onRound ?? (() => {}),
    );
    try {
      return JSON.parse(session.compare(kind, reference, coin, path, copy));
    } finally {
      session.free();
    }
  },
};

const builds = {
  threaded: argon2Build("dist/core/argon2-mt.js", "createArgon2Mt"),
  "single-threaded": argon2Build("dist/core/argon2-st.js", "createArgon2St"),
};

// The Argon2 builds alone, with the reference code's own interface.
const KEY_BYTES = 32;
const LANES = 4;
const tagSalt = encode("0123456789abcdef");

// The Argon2id tags of PASSWORD and the salt above, 4 lanes and 32 bytes, computed with
// OpenSSL through Python cryptography 46.0.5 (an independent implementation).
const knownTags = [
  {
    memoryKib: 1024,
    passes: 1,
    tag: "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2",
  },
  {
    memoryKib: 65536,
    passes: 3,
    tag: "a3931f5728b235c605c02522f3302a8e90d0509a0c3db63ab4d2fcf75f345b5b",
  },
  {
    memoryKib: 262144,
    passes: 2,
    tag: "4a4a094750f2c17fc6507d38825ec9eac65e10fb2de9e9bf5e801d2af53f1efe",
  },
];

const hexOf = (bytes) => Buffer.from(bytes).toString("hex");

// Minimal caller of argon2id_hash_raw: copy the inputs into the C heap, run, read the tag.
function argon2id(argon2, memoryKib, passes) {
  const passwordPtr = argon2._malloc(PASSWORD.length) >>> 0;
  const saltPtr = argon2._malloc(tagSalt.length) >>> 0;
  const keyPtr = argon2._malloc(KEY_BYTES) >>> 0;
  try {
    argon2.HEAPU8.set(PASSWORD, passwordPtr);
    argon2.HEAPU8.set(tagSalt, saltPtr);
    const code = argon2._argon2id_hash_raw(
      passes,
      memoryKib,
      LANES,
      passwordPtr,
      PASSWORD.length,
      saltPtr,
      tagSalt.length,
      keyPtr,
      KEY_BYTES,
    );
    if (code !== 0) throw new Error(`Argon2 returned error code ${code}`);
    return hexOf(argon2.HEAPU8.subarray(keyPtr, keyPtr + KEY_BYTES));
  } finally {
    argon2._free(passwordPtr);
    argon2._free(saltPtr);
    argon2._free(keyPtr);
  }
}

for (const [name, createModule] of Object.entries(builds)) {
  const argon2 = await createModule();
  for (const { memoryKib, passes, tag } of knownTags) {
    const actual = argon2id(argon2, memoryKib, passes);
    assert.equal(actual, tag, `${name} build, ${memoryKib} KiB, ${passes} passes`);
  }
  console.log(`The ${name} build matches all ${knownTags.length} known Argon2id tags.`);
}

for (const [name, createModule] of Object.entries(builds)) {
  await checkArgon2Build(name, createModule);
}
