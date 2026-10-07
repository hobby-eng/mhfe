// Checks the browser package in dist/ with Node.js. Build it first with scripts/build-wasm.sh.
//
//   node scripts/verify-browser-package.mjs          fast checks, a few seconds
//   node scripts/verify-browser-package.mjs --full   also one full-size encryption (2 GiB)
//
// Part 1 runs the core module of the package's WebAssembly and the real Argon2 bridge with both
// Emscripten builds. To stay fast it lowers the Argon2 cost in a test wrapper, which lets only the
// known answer of the Argon2 build (1 MiB, one pass) through unchanged; the result must equal the
// container that the native engine gives at the same cost (REDUCED_COST_CONTAINER in src/mhfe.rs).
// It also gives the core Argon2 builds that fail their known answer, and the self-test the
// published round keys in place of Argon2 at full size, to check the fault it names. Part 2 runs
// the repair, passwords and wallet modules of the same WebAssembly with public vectors, then the
// self-check of every module at both tiers, with a WebAssembly whose vectors were damaged, and the
// package's worker.js in this process, with Argon2 builds that do not start or are of another
// build. Part 3 checks the package's manifest, versions and scripts, that its WebAssembly names no
// folder of the machine that built it, and its build against another one.
// Part 4 checks the page-side classes against a stand-in worker, whose self-checks run the real
// WebAssembly in this process. The real worker runs in a browser test
// (scripts/verify-browsers.mjs).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolveObjectURL } from "node:buffer";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { bundleClasses } from "./bundle-browser-classes.mjs";

const require = createRequire(import.meta.url);
const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const encode = (text) => new TextEncoder().encode(text);
const noBytes = () => new Uint8Array();

const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD = encode("public test password");
const NEW_PASSWORD = encode("another public test password");
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
/** The same phrase and password at full size: the public vector zero-12. */
const FULL_SIZE_CONTAINER =
  "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
/** The master key fingerprint of PHRASE without a passphrase (BIP32 test vectors). */
const PHRASE_FINGERPRINT = "73c5da0a";
/** The same with the BIP39 test passphrase "TREZOR" (src/wallet.rs). */
const PHRASE_TREZOR_FINGERPRINT = "b4e3f5ed";
/** BIP84's published first address of PHRASE without a passphrase. */
const PHRASE_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/** BIP84's first address of PHRASE with the passphrase "TREZOR" (src/wallet.rs). */
const PHRASE_TREZOR_ADDRESS = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";
// The core's refusals of the answer whether the wallet has a BIP39 passphrase, exactly as the
// WebAssembly throws them: the answer not given where nothing shows the passphrase, given against
// the reference's passphrase, or not a boolean (src/rekey.rs, src/wasm_api/core.rs).
const PASSPHRASE_UNSTATED =
  "INVALID_REQUEST: invalid request: say whether the wallet has a BIP39 passphrase";
const PASSPHRASE_CONTRADICTED =
  "INVALID_REQUEST: invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows";
const PASSPHRASE_ANSWER_NOT_BOOLEAN =
  "INVALID_REQUEST: invalid request: walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase";
/** A rekey's refusal of a passphrase with the built-in check or the owner (src/wasm_api/core.rs). */
const PASSPHRASE_WITHOUT_REFERENCE =
  "INVALID_REQUEST: invalid request: a passphrase belongs to an address or fingerprint confirmation";
/** A length without a built-in check confirmed by the built-in check (src/error.rs). */
const REFERENCE_REQUIRED =
  "REFERENCE_REQUIRED: a 24-word original or a same-length container has no built-in check, so a receiving address or the master key fingerprint of the wallet must confirm the recovery before it is encrypted again";
/** The client's TypeError for a missing or non-boolean walletHasPassphrase (web/client.js). */
const WALLET_PASSPHRASE_REQUIRED =
  "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
/** The client's TypeError for a passphrase with the built-in check or the owner (web/client.js). */
const PASSPHRASE_ONLY_WITH_REFERENCE =
  "passphrase belongs only to an address or fingerprint confirmation.";
/** Values that are not a boolean, which no answer whether the wallet has a passphrase may be. */
const NOT_BOOLEAN_ANSWERS = ["no", "true", 1, 0, {}];
/**
 * The cost of the known answer of the page's Argon2 build, which every Argon2 operation runs before
 * its first round and after its last (src/engine/known_answers.rs), and of its larger ones at 64
 * and 256 MiB in the full self-check: these reach the real build unchanged.
 */
const KNOWN_ANSWER_COSTS = ["1024/1", "65536/3", "262144/2"];
/** The self-test's fault where a round's published input gave another key (src/self_test.rs). */
const argon2KeyFault = (round) => ({
  kind: "argon2-key",
  round,
  message: `first wrong round ${round} of 24: Argon2id returned another key for the published input, so the fault is in Argon2id`,
});
/** The error of an operation whose Argon2 build gave another answer (src/error.rs). */
const argon2Refused = (detail) =>
  `SELF_CHECK_FAILED: the self-test failed: Argon2id: ${detail}. ` +
  "Do not use this program on this computer";
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

// The package's wasm-bindgen glue defines the global `mhfe`, the bindings of every module.
vm.runInThisContext(read("target/wasm-bindgen/mhfe.js").toString(), { filename: "mhfe.js" });
const bindings = vm.runInThisContext("mhfe");
const coreMemory = bindings.initSync({ module: read("dist/runtime/mhfe.wasm") }).memory;
const glue = read("target/wasm-bindgen/mhfe.js").toString();
const packageWasm = read("dist/runtime/mhfe.wasm");
/** A new instance of the package's bindings over `wasm`, apart from the one above. */
function bindingsOver(wasm) {
  const fresh = new Function(`${glue}\nreturn mhfe;`)();
  fresh.initSync({ module: wasm });
  return fresh;
}

// Part 1: the core module and the Argon2 bridge.
const core = bindings;
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");

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

/**
 * The positional arguments of the core's operations, from named ones. encrypt's phrase goes as its
 * UTF-8 bytes, as the worker passes it. encrypt's walletHasPassphrase is false only when the
 * options leave it out: one given as undefined or null reaches the core as it is, which must
 * refuse it.
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
        argon2,
        options.onRound ?? (() => {}),
      ),
    ),
  check: (container, password, argon2, kind, reference, options = {}) =>
    JSON.parse(
      core.check(
        container,
        password,
        "",
        0,
        options.pim ?? 0,
        0,
        kind,
        reference,
        options.coin ?? "",
        options.path ?? "",
        options.passphrase ?? noBytes(),
        argon2,
        options.onRound ?? (() => {}),
      ),
    ),
};

const builds = {
  threaded: require("../dist/core/argon2-mt.js"),
  "single-threaded": require("../dist/core/argon2-st.js"),
};
for (const [name, createModule] of Object.entries(builds)) {
  const engine = argon2Engine(await createModule());
  // What reached the engine, in order: "known answer" or "round".
  const derives = [];
  const reduced = {
    derive: (password, salt, memoryKib, passes, key) => {
      if (KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)) {
        derives.push("known answer");
        engine.derive(password, salt, memoryKib, passes, key);
        return;
      }
      assert.deepEqual(
        [memoryKib, passes],
        [2097152, 12],
        "the core asks for the suite 3 defaults",
      );
      derives.push("round");
      engine.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key);
    },
    reserve: (memoryKib) => assert.equal(memoryKib, 2097152, "a session reserves 2 GiB"),
  };
  const steps = [];
  const onRound = (round, rounds, stage) => steps.push(`${stage} ${round}/${rounds}`);
  const created = operations.encrypt(PHRASE, PASSWORD, reduced, {
    onRound,
    repairWordCount: 4,
    onUnverified: (json) => steps.push(`unverified ${JSON.parse(json).container}`),
  });
  assert.equal(created.container, REDUCED_COST_CONTAINER, `${name}: same container as native`);
  // The build gives its known answer before the first round and again after the last.
  assert.deepEqual(derives, [
    "known answer",
    ...Array.from({ length: 24 }, () => "round"),
    "known answer",
  ]);
  assert.equal(created.suiteId, SUITE_3);
  assert.equal(created.builtInCheck, true, "a 12-word phrase in 24 words has a built-in check");
  assert.deepEqual(created.otherLengths, []);
  assert.equal(created.repairWords.split(" ").length, 4);
  assert.equal(created.repairProfile, "MHFE-REPAIR-1");
  assert.deepEqual(created.keep, [
    { item: "containerWords", words: 24 },
    { item: "password" },
    { item: "repairWords" },
  ]);
  // Twelve rounds of encryption, the unchecked container, then twelve more that check it.
  const expected = Array.from(
    { length: 24 },
    (_, index) => `${index < 12 ? "encrypt" : "check"} ${index + 1}/24`,
  );
  expected.splice(12, 0, `unverified ${REDUCED_COST_CONTAINER}`);
  assert.deepEqual(steps, expected);
  steps.length = 0;
  // A wallet with a BIP39 passphrase keeps it after the password and before the repair words.
  const withPassphrase = operations.encrypt(PHRASE, PASSWORD, reduced, {
    repairWordCount: 2,
    walletHasPassphrase: true,
  });
  assert.equal(withPassphrase.container, REDUCED_COST_CONTAINER);
  assert.deepEqual(withPassphrase.keep, [
    { item: "containerWords", words: 24 },
    { item: "password" },
    { item: "passphrase" },
    { item: "repairWords" },
  ]);
  // The answer is a boolean and nothing else, refused before any Argon2 round: no other value is
  // read as a truth value, and undefined or null is no answer.
  for (const value of [...NOT_BOOLEAN_ANSWERS, undefined, null]) {
    expectMessage(PASSPHRASE_ANSWER_NOT_BOOLEAN, () =>
      operations.encrypt(PHRASE, PASSWORD, reduced, { walletHasPassphrase: value, onRound }),
    );
  }
  assert.deepEqual(steps, [], "encrypt refuses an answer that is not a boolean before Argon2");

  const recovery = operations.decrypt(created.container, PASSWORD, reduced, { onRound });
  assert.deepEqual(
    steps,
    Array.from({ length: 12 }, (_, index) => `recover ${index + 1}/12`),
  );
  assert.deepEqual(recovery, {
    kind: "phrase",
    candidates: [
      {
        words: 12,
        verified: true,
        status: "verified",
        phrase: PHRASE,
        suiteId: SUITE_3,
        fingerprintWithoutPassphrase: PHRASE_FINGERPRINT,
        passesWalletCheckWithoutPassphrase: null,
      },
    ],
  });
  const wrong = operations.decrypt(created.container, encode("wrong"), reduced);
  assert.deepEqual(
    [wrong.candidates[0].words, wrong.candidates[0].status],
    [24, "readAs24"],
    "a wrong password reads as 24 words, not verified",
  );
  assert.equal(typeof wrong.candidates[0].passesWalletCheckWithoutPassphrase, "boolean");

  steps.length = 0;
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "words", "12", { onRound }).matches,
    true,
  );
  assert.deepEqual(steps.slice(-2), ["recover 12/12", "compare 12/12"]);
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT)
      .matches,
    true,
  );
  assert.deepEqual(
    operations.check(created.container, PASSWORD, reduced, "address", PHRASE_ADDRESS, {
      coin: "bitcoin",
    }),
    { matches: true, path: "m/84'/0'/0'/0/0" },
  );
  // An Ethereum address of the same wallet, on Ethereum's path.
  assert.deepEqual(
    operations.check(
      created.container,
      PASSWORD,
      reduced,
      "address",
      "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
      { coin: "ethereum" },
    ),
    { matches: true, path: "m/44'/60'/0'/0/0" },
  );
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT, {
      passphrase: encode("TREZOR"),
    }).matches,
    false,
  );
  expectCode("INVALID_COIN", () =>
    operations.check(created.container, PASSWORD, reduced, "address", "bc1q", { coin: "doge" }),
  );
  // The library's refusal, before any round: the binding has none of its own.
  expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
    operations.check(created.container, PASSWORD, reduced, "walletCheck", "", {
      onRound: noRoundExpected,
    }),
  );

  // Refusals happen before any Argon2 call.
  expectCode("MEMORY_LEVEL_NOT_SUPPORTED_HERE", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { memoryLevel: 1 }),
  );
  expectCode("INVALID_PIM", () => operations.encrypt(PHRASE, PASSWORD, reduced, { pim: 1024 }));
  expectCode("INVALID_PHRASE", () => operations.encrypt("abandon about", PASSWORD, reduced));
  expectCode("INVALID_REPAIR_WORDS", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { repairWordCount: 3 }),
  );
  expectCode("PASSWORDS_DIFFER", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, { repeat: encode("other") }),
  );
  // Numbers the raw API gets straight from JavaScript are refused unless they are whole numbers
  // in range; a u32 parameter would have turned 2^32 into 0 and -1 into 4294967295.
  for (const value of [2 ** 32, 2 ** 32 + 1, -1, 0.5, NaN, Infinity]) {
    expectCode("INVALID_PIM", () => operations.encrypt(PHRASE, PASSWORD, reduced, { pim: value }));
    expectCode("INVALID_MEMORY_LEVEL", () =>
      operations.decrypt(created.container, PASSWORD, reduced, { memoryLevel: value }),
    );
    expectCode("INVALID_WORD_COUNT", () =>
      operations.decrypt(created.container, PASSWORD, reduced, { words: value }),
    );
  }
  // A refused password must not leave the separately given BIP39 passphrase in the core's memory.
  const sentinel = encode("public sentinel passphrase 7f3a9c");
  expectCode("EMPTY_PASSWORD", () =>
    operations.check(created.container, noBytes(), reduced, "fingerprint", PHRASE_FINGERPRINT, {
      passphrase: sentinel.slice(),
    }),
  );
  assert.equal(
    Buffer.from(coreMemory.buffer).indexOf(Buffer.from(sentinel)),
    -1,
    "the passphrase was wiped",
  );
  // The words are read back written out, whatever case and short forms were typed.
  const typed = created.container
    .toUpperCase()
    .split(" ")
    .map((word) => word.slice(0, 4))
    .join("  ");
  const facts = JSON.parse(core.describeContainer(typed));
  assert.equal(facts.container, created.container);
  assert.deepEqual(facts.phraseLengths, [12, 15, 18, 21, 24]);
  assert.equal(facts.confirmationFor["12"], "builtInCheck");
  assert.equal(facts.confirmationFor["24"], "walletOrOwner");
  assert.equal(facts.hiddenWallets, true);
  assert.equal(facts.offersWalletCheck, true);
  const phraseFacts = JSON.parse(
    core.describePhrase(encode(PHRASE.toUpperCase().replaceAll(" ", "\t"))),
  );
  assert.equal(phraseFacts.phrase, PHRASE);
  assert.deepEqual(phraseFacts.otherLengths, []);
  assert.deepEqual(phraseFacts.containers, [
    { sameLength: false, words: 24, wrongWordPassesOneIn: 256 },
    { sameLength: true, words: 12, wrongWordPassesOneIn: 16 },
  ]);
  // A public 12-word phrase whose packed state also passes the 21-word check (src/packing.rs).
  assert.deepEqual(JSON.parse(core.describePhrase(encode(AMBIGUOUS_12_WORDS))).otherLengths, [21]);
  expectCode("UNASSIGNED_CHARACTER", () => core.checkPassword(encode("a͸")));
  expectCode("INVALID_PASSWORD_UTF8", () => core.checkPassword(new Uint8Array([0xff])));
  expectCode("CONTROL_CHARACTER_IN_PASSWORD", () => core.checkPassword(encode("first\r\nsecond")));
  // A progress callback that throws stops the operation.
  expectCode("CANCELLED", () =>
    operations.encrypt(PHRASE, PASSWORD, reduced, {
      onRound: () => {
        throw new Error("stop");
      },
    }),
  );
  // A container of the phrase's own length, only when asked for.
  const sameLength = operations.encrypt(PHRASE, PASSWORD, reduced, { sameLength: true });
  assert.equal(sameLength.container, REDUCED_COST_SAME_LENGTH_CONTAINER);
  assert.equal(sameLength.suiteId, SUITE_4);
  assert.equal(sameLength.builtInCheck, false);
  assert.deepEqual(
    operations.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced).candidates[0].status,
    "noBuiltInCheck",
  );
  expectCode("NO_BUILT_IN_CHECK", () =>
    operations.check(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, "words", "12"),
  );
  // A same-length container has no wallet check, with a passphrase or without one: the library's
  // order, the same as through the command line, puts this refusal before the empty passphrase's.
  for (const passphrase of [encode("TREZOR"), noBytes()]) {
    expectCode("NO_WALLET_CHECK", () =>
      operations.check(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, "walletCheck", "", {
        passphrase,
        onRound: noRoundExpected,
      }),
    );
  }
  expectCode("SAME_LENGTH_NEEDS_SHORT_PHRASE", () =>
    operations.encrypt(ZERO_24, PASSWORD, reduced, { sameLength: true }),
  );
  expectCode("LENGTH_CHOICE_NOT_APPLICABLE", () =>
    operations.decrypt(REDUCED_COST_SAME_LENGTH_CONTAINER, PASSWORD, reduced, { words: 15 }),
  );

  // A password with a check word, typed with one word forgotten, is repaired before Argon2.
  const checkWordPassword = "jovial trailing chokehold pavilion cresting ninth";
  const withCheckWord = operations.encrypt(PHRASE, encode(checkWordPassword), reduced);
  const repaired = operations.decrypt(
    withCheckWord.container,
    encode("jovial trailing ? pavilion cresting ninth"),
    reduced,
    { choice: "repair", position: 3 },
  );
  assert.equal(repaired.candidates[0].phrase, PHRASE, "the restored word opens the container");
  expectCode("PASSWORD_REPAIR_NOT_OFFERED", () =>
    operations.decrypt(withCheckWord.container, encode(checkWordPassword), reduced, {
      choice: "repair",
      position: 2,
    }),
  );

  // A rekey: recovered with the built-in check (rounds 1-12 of 36), sealed again (13-36).
  steps.length = 0;
  const rekey = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, true, reduced);
  rekey.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  assert.deepEqual(
    JSON.parse(rekey.recover("builtInCheck", "", "", "", noBytes(), false, onRound)),
    { ownerCheck: null },
  );
  const rekeyed = JSON.parse(rekey.seal(onRound, () => {}));
  rekey.free();
  assert.deepEqual(steps.slice(0, 1), ["recover 1/36"]);
  assert.deepEqual(steps.slice(-1), ["check 36/36"]);
  assert.equal(
    operations.decrypt(rekeyed.container, NEW_PASSWORD, reduced).candidates[0].phrase,
    PHRASE,
  );
  assert.deepEqual(
    rekeyed.keep,
    [{ item: "containerWords", words: 24 }, { item: "password" }],
    "a wallet stated to have no BIP39 passphrase keeps none",
  );
  // Stated to have one, the wallet keeps its passphrase after the password, before the repair
  // words.
  const stated = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, true, reduced);
  stated.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 2);
  stated.recover("builtInCheck", "", "", "", noBytes(), true, () => {});
  assert.deepEqual(
    JSON.parse(
      stated.seal(
        () => {},
        () => {},
      ),
    ).keep,
    [
      { item: "containerWords", words: 24 },
      { item: "password" },
      { item: "passphrase" },
      { item: "repairWords" },
    ],
  );
  stated.free();

  // The confirmations of the rekeys below: the built-in check of the 12-word phrase in the 24-word
  // container, its owner reading it as 24 words, and wallet references of PHRASE that match the
  // same-length container, with the BIP39 passphrase "TREZOR" or with an empty one.
  const builtInCheck = { container: created.container, words: 12, kind: "builtInCheck" };
  const ownerCheck = { container: created.container, words: 24, kind: "owner" };
  const onSameLength = { container: REDUCED_COST_SAME_LENGTH_CONTAINER, words: 0 };
  const trezorFingerprint = {
    ...onSameLength,
    kind: "fingerprint",
    reference: PHRASE_TREZOR_FINGERPRINT,
    passphrase: "TREZOR",
  };
  const trezorAddress = {
    ...onSameLength,
    kind: "address",
    reference: PHRASE_TREZOR_ADDRESS,
    coin: "bitcoin",
    passphrase: "TREZOR",
  };
  const plainFingerprint = { ...onSameLength, kind: "fingerprint", reference: PHRASE_FINGERPRINT };
  const plainAddress = {
    ...onSameLength,
    kind: "address",
    reference: PHRASE_ADDRESS,
    coin: "bitcoin",
  };
  /** A rekey of the confirmation's container, ready for its recovery with the answer `answer`. */
  const recoverAs = (confirmation, answer, onRecoverRound = () => {}) => {
    const { container, words, kind, reference = "", coin = "", passphrase = "" } = confirmation;
    const session = new core.RekeySession(container, words, PASSWORD, "", 0, 0, 0, true, reduced);
    session.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
    const recover = () =>
      session.recover(kind, reference, coin, "", encode(passphrase), answer, onRecoverRound);
    return { session, recover };
  };
  const describe = ({ words, kind, passphrase = "" }, answer) =>
    `${kind} of ${words} words, passphrase ${JSON.stringify(passphrase)}, ` +
    `answer ${String(JSON.stringify(answer))}`;

  // Sealed again, a same-length rekey gives what encrypt gives with the new password; its keep list
  // tells what the answer became.
  const sameLengthWithNew = operations.encrypt(PHRASE, NEW_PASSWORD, reduced, { sameLength: true });
  const KEEP_SAME_LENGTH = [{ item: "containerWords", words: 12 }, { item: "password" }];
  const KEEP_SAME_LENGTH_AND_PASSPHRASE = [...KEEP_SAME_LENGTH, { item: "passphrase" }];
  const sameLengthKeep = (confirmation, answer) => {
    const { session, recover } = recoverAs(confirmation, answer);
    try {
      assert.deepEqual(JSON.parse(recover()), { ownerCheck: null });
      const sealed = JSON.parse(
        session.seal(
          () => {},
          () => {},
        ),
      );
      assert.equal(sealed.container, sameLengthWithNew.container, describe(confirmation, answer));
      return sealed.keep;
    } finally {
      session.free();
    }
  };
  // Only a reference compared with a non-empty passphrase shows that the wallet has one: the
  // answer may be left out (undefined or null, none) or be true, and the passphrase is kept.
  for (const confirmation of [trezorFingerprint, trezorAddress]) {
    for (const answer of [undefined, null, true]) {
      assert.deepEqual(
        sameLengthKeep(confirmation, answer),
        KEEP_SAME_LENGTH_AND_PASSPHRASE,
        describe(confirmation, answer),
      );
    }
  }
  // An empty passphrase matches the phrase's wallet without one and proves nothing about funds
  // under a passphrase, so the answer decides: true keeps the passphrase, false does not.
  for (const confirmation of [plainFingerprint, plainAddress]) {
    for (const [answer, keep] of [
      [true, KEEP_SAME_LENGTH_AND_PASSPHRASE],
      [false, KEEP_SAME_LENGTH],
    ]) {
      assert.deepEqual(sameLengthKeep(confirmation, answer), keep, describe(confirmation, answer));
    }
  }

  // Everything else is refused before any Argon2 round, and the refusal ends the rekey.
  const rekeyRefusals = [
    // Nothing shows the passphrase: not the built-in check, not the owner, not a reference with an
    // empty passphrase, which matches even here. undefined and null are no answer.
    ...[undefined, null].flatMap((answer) =>
      [builtInCheck, ownerCheck, plainFingerprint, plainAddress].map((confirmation) => ({
        confirmation,
        answer,
        message: PASSPHRASE_UNSTATED,
      })),
    ),
    // An answer against the passphrase that the reference was compared with.
    ...[trezorFingerprint, trezorAddress].map((confirmation) => ({
      confirmation,
      answer: false,
      message: PASSPHRASE_CONTRADICTED,
    })),
    // Not a boolean, where the answer is required and where it may be left out alike.
    ...NOT_BOOLEAN_ANSWERS.flatMap((answer) =>
      [builtInCheck, plainFingerprint, trezorFingerprint].map((confirmation) => ({
        confirmation,
        answer,
        message: PASSPHRASE_ANSWER_NOT_BOOLEAN,
      })),
    ),
    // A passphrase belongs only to an address or a fingerprint, whatever the answer.
    ...[true, false].flatMap((answer) =>
      [builtInCheck, ownerCheck].map((confirmation) => ({
        confirmation: { ...confirmation, passphrase: "TREZOR" },
        answer,
        message: PASSPHRASE_WITHOUT_REFERENCE,
      })),
    ),
    // A length without a built-in check refuses that check first, before the answer is judged:
    // the 24-word reading and the same-length container's own length.
    ...[undefined, null, true, false].flatMap((answer) =>
      [
        { ...builtInCheck, words: 24 },
        { ...onSameLength, kind: "builtInCheck" },
      ].map((confirmation) => ({ confirmation, answer, message: REFERENCE_REQUIRED })),
    ),
  ];
  for (const { confirmation, answer, message } of rekeyRefusals) {
    const description = describe(confirmation, answer);
    steps.length = 0;
    const { session, recover } = recoverAs(confirmation, answer, onRound);
    expectMessage(message, recover, description);
    assert.deepEqual(steps, [], `${description}: refused before any Argon2 round`);
    expectMessage(
      "INVALID_REQUEST: invalid request: a rekey step out of its order",
      () =>
        session.seal(
          () => {},
          () => {},
        ),
      `${description}: the refusal ended the rekey`,
    );
    session.free();
  }
  expectCode(
    "OTHER_WALLETS_NOT_CONFIRMED",
    () => new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, false, reduced),
  );
  const same = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, true, reduced);
  expectCode("NEW_PASSWORD_SAME_AS_OLD", () =>
    same.setNew(PASSWORD, PASSWORD.slice(), "", 0, 0, 0, 0),
  );
  expectCode("INVALID_REQUEST", () =>
    same.seal(
      () => {},
      () => {},
    ),
  );
  same.free();
  // The owner confirms a 24-word phrase by comparing it; a no ends the rekey.
  const owner = new core.RekeySession(created.container, 24, PASSWORD, "", 0, 0, 0, true, reduced);
  owner.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  const shown = JSON.parse(owner.recover("owner", "", "", "", noBytes(), false, () => {}));
  assert.equal(shown.ownerCheck.words, 24);
  expectCode("NOT_CONFIRMED_BY_OWNER", () => owner.ownerAnswer(false));
  owner.free();

  // Hidden wallets: each password opens its own wallet, none twice. The session's start and each
  // wallet run the build's known answer, a wallet before and after its rounds.
  derives.length = 0;
  const wallets = new core.HiddenWalletSession(created.container, 0, 0, noBytes(), reduced);
  const hidden = JSON.parse(wallets.open(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, () => {}));
  assert.deepEqual(derives, [
    "known answer",
    "known answer",
    ...Array.from({ length: 12 }, () => "round"),
    "known answer",
  ]);
  assert.equal(hidden.words, 24);
  assert.equal(
    hidden.phrase,
    operations.decrypt(created.container, NEW_PASSWORD, reduced, { words: 24 }).candidates[0]
      .phrase,
    "a hidden wallet is the container read as 24 words with that password",
  );
  expectCode("PASSWORD_ALREADY_USED", () =>
    wallets.open(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, () => {}),
  );
  wallets.free();
  expectCode(
    "INVALID_CONTAINER",
    () =>
      new core.HiddenWalletSession(REDUCED_COST_SAME_LENGTH_CONTAINER, 0, 0, noBytes(), reduced),
  );

  // The self-test runs both vectors in two stages; at a lowered cost they cannot match, and the
  // first round's key already differs from the published one, for the published input.
  steps.length = 0;
  assert.deepEqual(JSON.parse(core.selfTest(reduced, onRound)), {
    passed: false,
    suite3: { vector: "zero-12", asPublished: false },
    suite4: { vector: "same-length-zero-12", asPublished: false },
    firstWrongRound: 1,
    fault: argon2KeyFault(1),
  });
  assert.deepEqual(
    [steps[0], steps[12], steps[23]],
    ["encrypt 1/24", "recover 13/24", "recover 24/24"],
  );
  console.log(`The ${name} build gives the native container and passes the core's checks.`);
}

if (process.argv.includes("--full")) {
  const engine = argon2Engine(await builds.threaded());
  const created = operations.encrypt(PHRASE, PASSWORD, engine);
  assert.equal(created.container, FULL_SIZE_CONTAINER);
  console.log("A full-size encryption with the threaded build gives the native container.");
}

// An Argon2 build that does not give its known answer is refused before any round: a bridge that
// leaves the key as it was or writes zeros, as a stale view of the WebAssembly's memory would, and
// a build that gives another tag. Nothing secret reaches it, and the self-check names it.
const realArgon2 = argon2Engine(await builds["single-threaded"]());
const noop = () => {};
const unwrittenKey = "Argon2id could not run: the Argon2 engine returned without writing the key";
const faultyBuilds = [
  ["leaves the key as it was", () => {}, unwrittenKey],
  ["writes zeros", (key) => key.fill(0), unwrittenKey],
  ["gives another tag", (key) => (key[0] ^= 1), "the page's Argon2 build gives another tag"],
];
for (const [fault, spoil, detail] of faultyBuilds) {
  const rounds = [];
  const faulty = {
    derive: (password, salt, memoryKib, passes, key) => {
      if (fault !== "leaves the key as it was") {
        realArgon2.derive(password, salt, memoryKib, passes, key);
      }
      spoil(key);
    },
    reserve: noop,
  };
  const report = JSON.parse(core.selfCheckCore("startup", [], faulty, noop, noop));
  assert.equal(report.passed, false, fault);
  assert.deepEqual(report.components[1], {
    id: "argon2",
    label: "Argon2id",
    outcome: "failed",
    detail,
  });
  assert.ok(
    report.components.every((part) => part.id === "argon2" || part.outcome === "passed"),
    `${fault}: only Argon2 fails`,
  );
  expectMessage(argon2Refused(detail), () =>
    operations.encrypt(PHRASE, PASSWORD, faulty, {
      onRound: (round) => rounds.push(round),
    }),
  );
  expectMessage(
    argon2Refused(detail),
    () => new core.HiddenWalletSession(ZERO_24, 0, 0, noBytes(), faulty),
  );
  assert.deepEqual(rounds, [], `${fault}: refused before round 1`);
}
// A build that goes wrong during the work fails its known answer after the last round: the result
// is dropped, although every round ran and the container was shown as not yet verified.
let knownAnswers = 0;
const failsLater = {
  derive: (password, salt, memoryKib, passes, key) => {
    if (memoryKib === 1024) {
      knownAnswers += 1;
      realArgon2.derive(password, salt, memoryKib, passes, key);
      if (knownAnswers === 2) key[31] ^= 0x80;
      return;
    }
    realArgon2.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key);
  },
  reserve: noop,
};
const lateRounds = [];
const shownUnverified = [];
expectMessage(argon2Refused("the page's Argon2 build gives another tag"), () =>
  operations.encrypt(PHRASE, PASSWORD, failsLater, {
    onRound: (round) => lateRounds.push(round),
    onUnverified: (json) => shownUnverified.push(JSON.parse(json).container),
  }),
);
assert.equal(lateRounds.length, 24, "every round ran before the known answer failed");
assert.deepEqual(shownUnverified, [REDUCED_COST_CONTAINER]);
assert.equal(knownAnswers, 2);

// The reference code wipes its work area before it frees it, and the bridge its copies of the
// password, salt and key: after the 1 MiB known answer, a fresh single-threaded build's memory holds
// about 2 KiB more non-zero bytes than before (allocator records and the stack of the last block
// computation), where a work area left as it was would add 1 MiB. Fragile by nature: it depends
// on where the allocator puts things, so its bound is generous.
const WIPED_RESIDUE_BYTES = 16 * 1024;
const freshArgon2 = await builds["single-threaded"]();
const nonZeroBytes = (heap) => heap.reduce((count, byte) => count + (byte === 0 ? 0 : 1), 0);
const nonZeroBefore = nonZeroBytes(freshArgon2.HEAPU8);
assert.equal(
  JSON.parse(core.selfCheckArgon2("startup", [], argon2Engine(freshArgon2), noop, noop)).passed,
  true,
);
const residue = nonZeroBytes(freshArgon2.HEAPU8) - nonZeroBefore;
assert.ok(residue < WIPED_RESIDUE_BYTES, `the Argon2 memory was wiped: ${residue} bytes remain`);
console.log(
  `Argon2 builds that fail their known answer are refused before round 1 and after the last; ` +
    `${residue} non-zero bytes remain after a known answer.`,
);

// The self-test tells where it first left the published path, and how. Argon2 at full size takes
// minutes and 2 GiB, so a test-only engine stands in for it: it answers each published input, the
// password after NFKD and a round's salt as the public vectors record them, with the recorded key,
// and any other input with a hash of it, as Argon2id gives some key for any input. The known
// answers reach the real build. It gives the published results, with no fault; a key changed in
// one round is a fault in Argon2id at that round; an input that is not published, here the
// password of the built-in suite 3 vector with one letter changed, is a fault before Argon2id at
// the first round; and a result that differs when every input and key was as published, here the
// built-in suite 3 container with one letter changed, is a fault after the last Argon2id call.
const PUBLISHED_VECTOR_FILES = {
  suite3: "tests/fixtures/suite3-vectors/zero-12.json",
  suite4: "tests/fixtures/suite4-vectors/same-length-zero-12.json",
};
const publishedKeys = new Map();
for (const path of Object.values(PUBLISHED_VECTOR_FILES)) {
  const vector = JSON.parse(read(path).toString());
  for (const round of [...vector.encryption.rounds, ...vector.decryption.rounds]) {
    publishedKeys.set(
      `${vector.inputs.password_nfkd_utf8_hex}/${round.salt_hex}`,
      round.argon2_key_hex,
    );
  }
}
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
/** The stand-in for Argon2 at full size; `spoil(round, key)` may change the key of a round. */
function publishedRounds(spoil = noop) {
  let rounds = 0;
  return {
    derive: (password, salt, memoryKib, passes, key) => {
      if (KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)) {
        realArgon2.derive(password, salt, memoryKib, passes, key);
        return;
      }
      assert.deepEqual([memoryKib, passes], [2097152, 12], "the self-test asks for 2 GiB");
      rounds += 1;
      const recorded = publishedKeys.get(`${hexOf(password)}/${hexOf(salt)}`);
      key.set(
        recorded === undefined
          ? createHash("sha256").update(password).update(salt).digest()
          : Buffer.from(recorded, "hex"),
      );
      spoil(rounds, key);
    },
    reserve: noop,
  };
}
/**
 * The package's WebAssembly with the last letter of `text` changed in the built-in copy of the
 * public vector `path` alone, which include_str! keeps byte for byte: the start of a JSON field,
 * whose value stays a string.
 */
function damagedVector(path, text) {
  const bytes = Buffer.from(packageWasm);
  const vector = read(path);
  const start = bytes.indexOf(vector);
  assert.ok(start !== -1 && bytes.indexOf(vector, start + 1) === -1, `one copy of ${path}`);
  const at = vector.indexOf(Buffer.from(text));
  assert.ok(at !== -1 && vector.indexOf(Buffer.from(text), at + 1) === -1, `one ${text}`);
  bytes[start + at + Buffer.byteLength(text) - 1] ^= 1;
  return bytes;
}
const selfTestOf = (instance, argon2) => JSON.parse(instance.selfTest(argon2, noop));
const vectors = (suite3, suite4) => ({
  suite3: { vector: "zero-12", asPublished: suite3 },
  suite4: { vector: "same-length-zero-12", asPublished: suite4 },
});
assert.deepEqual(selfTestOf(core, publishedRounds()), {
  passed: true,
  ...vectors(true, true),
  firstWrongRound: null,
  fault: null,
});
for (const [round, suite3, suite4] of [
  [5, false, true],
  [17, true, false],
]) {
  const spoiled = publishedRounds((at, key) => {
    if (at === round) key[0] ^= 1;
  });
  assert.deepEqual(selfTestOf(core, spoiled), {
    passed: false,
    ...vectors(suite3, suite4),
    firstWrongRound: round,
    fault: argon2KeyFault(round),
  });
}
assert.deepEqual(
  selfTestOf(
    bindingsOver(damagedVector(PUBLISHED_VECTOR_FILES.suite3, '"password": "public test password')),
    publishedRounds(),
  ),
  {
    passed: false,
    ...vectors(false, true),
    firstWrongRound: 1,
    fault: {
      kind: "argon2-input",
      round: 1,
      message:
        "first wrong round 1 of 24: Argon2id was given an input that the published vector does not have, so the fault is before Argon2id, in this round's password or salt or in the state before it",
    },
  },
);
assert.deepEqual(
  selfTestOf(
    bindingsOver(
      damagedVector(PUBLISHED_VECTOR_FILES.suite3, `"container": "${FULL_SIZE_CONTAINER}`),
    ),
    publishedRounds(),
  ),
  {
    passed: false,
    ...vectors(false, true),
    firstWrongRound: null,
    fault: {
      kind: "after-argon2",
      round: null,
      message:
        "every Argon2id input and key as published, so the fault is after the last Argon2id call of an operation",
    },
  },
);
console.log(
  "The self-test passes with the published round keys and names a fault in Argon2id, before it " +
    "and after it.",
);

// Part 2: the modules without Argon2.
const repair = bindings;
assert.equal(JSON.parse(repair.repairParameters()).version, VERSION);
assert.equal(repair.packageVersion(), VERSION);
// Vectors of an independent implementation (src/repair.rs).
assert.deepEqual(JSON.parse(repair.repairWords(FULL_SIZE_CONTAINER, 4)), {
  profile: "MHFE-REPAIR-1",
  words: "shaft pupil patient jewel",
  repairsUnreadable: 4,
  repairsWrong: 2,
});
const plate = FULL_SIZE_CONTAINER.split(" ");
plate[2] = "?";
plate[16] = "?";
const repairedPlate = JSON.parse(repair.repairPlate(plate.join(" "), "shaft pupil patient jewel"));
assert.equal(repairedPlate.container, FULL_SIZE_CONTAINER);
assert.deepEqual(repairedPlate.plateWords, [3, 17]);
assert.equal(repairedPlate.unchanged, false);
assert.equal(repairedPlate.changes[0].read, null);
expectCode("INVALID_REPAIR_WORDS", () => repair.repairWords(FULL_SIZE_CONTAINER, 3));
console.log("The repair module passes its checks.");

const passwords = bindings;
assert.equal(JSON.parse(passwords.passwordParameters()).version, VERSION);
// The specification's vector: an erased third word is recovered as chokehold.
const review = JSON.parse(
  passwords.reviewPassword(encode("jovial trailing ? pavilion cresting ninth"), noBytes(), false),
);
assert.equal(review.reading, "restorable");
assert.deepEqual(review.repairs, [{ position: 3, word: "chokehold", typed: null }]);
assert.equal(review.repairsFirst, true);
expectCode("PASSWORDS_DIFFER", () =>
  passwords.reviewPassword(encode("jovial"), encode("Jovial"), true),
);
// An empty repetition differs; it is not a missing one.
expectCode("PASSWORDS_DIFFER", () => passwords.reviewPassword(encode("jovial"), noBytes(), true));
assert.equal(
  JSON.parse(
    passwords.reviewPassword(
      encode("JOVIAL Trailing chokehold pavilion cresting ninth"),
      noBytes(),
      false,
    ),
  ).correction,
  "capitals",
);
assert.equal(JSON.parse(passwords.passwordStrength(encode("password"), "", 0)).weak, true);
// A deterministic stand-in for crypto.getRandomValues.
let counter = 0;
const testRandom = {
  fill: (bytes) => {
    for (let index = 0; index < bytes.length; index += 1) {
      counter = (counter * 1664525 + 1013904223) >>> 0;
      bytes[index] = counter >>> 24;
    }
  },
};
// Without a count, as many words or characters as the command-line tool makes.
assert.equal(
  JSON.parse(passwords.makePassword("words", undefined, noBytes(), testRandom)).password.split(" ")
    .length,
  5,
);
assert.equal(
  JSON.parse(passwords.makePassword("characters", undefined, noBytes(), testRandom)).password
    .length,
  16,
);
const made = JSON.parse(passwords.makePassword("checkWord", undefined, noBytes(), testRandom));
assert.equal(made.password.split(" ").length, 6);
assert.equal(made.checkWord, true);
assert.equal(made.bits, 64.625, "five words and their check word");
// The check word takes no count, as `mhfe password` refuses --check-word with --words: a page
// that asked for seven words never gets five instead. Five, the count it makes, is refused too, and
// so is a count with dice.
for (const [count, rolls] of [
  [7, noBytes()],
  [5, noBytes()],
  [5, encode("11111 11112 11113 11114 11115")],
]) {
  expectMessage(
    "INVALID_REQUEST: invalid request: checkWord takes no count: it always makes five words and " +
      "their check word",
    () => passwords.makePassword("checkWord", count, rolls, testRandom),
    `checkWord with count ${count} is refused`,
  );
}
// null is no count, as undefined: wasm-bindgen reads both as none.
assert.equal(
  JSON.parse(passwords.makePassword("checkWord", null, noBytes(), testRandom)).password.split(" ")
    .length,
  6,
);
assert.equal(
  JSON.parse(passwords.reviewPassword(encode(made.password), noBytes(), false)).reading,
  "fits",
  "a generated check word fits",
);
assert.equal(
  JSON.parse(passwords.makePassword("words", 2, encode("11111 66666"), testRandom)).password,
  "abacus zoom",
);
expectCode("RANDOM_FAILED", () =>
  passwords.makePassword("words", 5, noBytes(), { fill: () => {} }),
);
expectCode("INVALID_PASSWORD_SIZE", () =>
  passwords.makePassword("characters", 65, noBytes(), testRandom),
);
console.log("The passwords module passes its checks.");

const wallet = bindings;
assert.equal(JSON.parse(wallet.walletParameters()).coins.length, 12);
assert.equal(wallet.walletFingerprint(encode(PHRASE), noBytes()), PHRASE_FINGERPRINT);
assert.equal(wallet.walletFingerprint(encode(PHRASE), encode("TREZOR")), PHRASE_TREZOR_FINGERPRINT);
// "abandon" 21 times and "above proof fatigue" passes the wallet check with "TREZOR"
// (TREZOR_COUNTER in src/wallet_check.rs).
const checkedPhrase = `${"abandon ".repeat(21)}above proof fatigue`;
assert.equal(wallet.walletCheck(encode(checkedPhrase), encode("TREZOR")), true);
assert.equal(wallet.walletCheck(encode(checkedPhrase), encode("trezor")), false);
expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
  wallet.walletCheck(encode(checkedPhrase), noBytes()),
);
expectCode("INVALID_WORD_COUNT", () => wallet.walletCheck(encode(PHRASE), encode("TREZOR")));
const search = JSON.parse(wallet.describeAddress(PHRASE_ADDRESS, "bitcoin", ""));
assert.equal(search.onlyPath, false);
assert.ok(search.addresses > 1);
const drawn = JSON.parse(wallet.drawPhrase(noBytes(), false, testRandom, () => {}));
assert.equal(drawn.words, 24);
assert.equal(drawn.walletCheck, false);
expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
  wallet.drawPhrase(noBytes(), true, testRandom, () => {}),
);
expectCode("RANDOM_FAILED", () =>
  wallet.drawPhrase(noBytes(), false, { fill: () => {} }, () => {}),
);
console.log("The wallet module passes its checks.");

// Phrases reach the WebAssembly as UTF-8 bytes, which the bindings wipe (SecretText in
// src/wasm_api/mod.rs), as they wipe passwords: wasm-bindgen's own copy of a text argument stays
// in the module's memory after the call (AUD-010). Each case runs in a fresh instance with the
// phrase as a person may type it, in capitals with two spaces between the words, a form the
// library never writes itself, so that a copy found can only be the argument's. None may be left,
// whether the call succeeds or is refused.
const typedForm = (phrase) => phrase.toUpperCase().split(" ").join("  ");
/** Twelve words whose checksum fails: an invalid phrase as long as a valid one. */
const INVALID_CHECKSUM = `${"abandon ".repeat(11)}abandon`;
/**
 * The allocator of the WebAssembly writes its own records over the first bytes of a block it
 * frees, so a copy left in a freed block is sought by the rest of the text.
 */
const FREED_BLOCK_RECORD_BYTES = 16;
/**
 * Runs `call(instance, bytes, copies)` with the UTF-8 bytes of `text` in a fresh instance of the
 * package's bindings and returns what it returned or threw and the copies of `text` left in its
 * memory; `copies()` counts them during the call.
 */
function copiesLeftBy(text, call) {
  const instance = new Function(`${glue}\nreturn mhfe;`)();
  const { memory } = instance.initSync({ module: packageWasm });
  const needle = Buffer.from(text).subarray(FREED_BLOCK_RECORD_BYTES);
  assert.ok(needle.length >= FREED_BLOCK_RECORD_BYTES, `${JSON.stringify(text)} is long enough`);
  const copies = () => {
    // The memory may have grown during the call, which replaces its buffer.
    const heap = Buffer.from(memory.buffer);
    let found = 0;
    for (let at = heap.indexOf(needle); at !== -1; at = heap.indexOf(needle, at + 1)) found += 1;
    return found;
  };
  assert.equal(copies(), 0, `a fresh instance holds no copy of ${JSON.stringify(text)}`);
  let outcome;
  try {
    outcome = call(instance, encode(text), copies);
  } catch (error) {
    outcome = error;
  }
  return { outcome, copies: copies() };
}
/** The core's Argon2 at the reduced cost of part 1, its known answers unchanged. */
const reducedArgon2 = {
  derive: (password, salt, memoryKib, passes, key) =>
    KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)
      ? realArgon2.derive(password, salt, memoryKib, passes, key)
      : realArgon2.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key),
  reserve: noop,
};
const encryptBytes = (instance, phrase, repeat = PASSWORD.slice(), onRound = noop) =>
  JSON.parse(
    instance.encrypt(
      phrase,
      PASSWORD.slice(),
      repeat,
      "",
      0,
      0,
      0,
      false,
      0,
      false,
      reducedArgon2,
      onRound,
      noop,
    ),
  );
const refusedWith = (code) => (outcome) => outcome?.message?.startsWith(`${code}: `);
const phraseCases = [
  {
    name: "describePhrase",
    text: typedForm(PHRASE),
    call: (instance, bytes) => JSON.parse(instance.describePhrase(bytes)).phrase,
    expected: (outcome) => outcome === PHRASE,
  },
  {
    name: "describePhrase, refused",
    text: typedForm(INVALID_CHECKSUM),
    call: (instance, bytes) => instance.describePhrase(bytes),
    expected: refusedWith("INVALID_PHRASE"),
  },
  {
    name: "walletFingerprint",
    text: typedForm(PHRASE),
    call: (instance, bytes) => instance.walletFingerprint(bytes, encode("TREZOR")),
    expected: (outcome) => outcome === PHRASE_TREZOR_FINGERPRINT,
  },
  {
    name: "walletFingerprint, its passphrase refused",
    text: typedForm(PHRASE),
    call: (instance, bytes) => instance.walletFingerprint(bytes, new Uint8Array([0xff])),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  {
    name: "walletCheck",
    text: typedForm(checkedPhrase),
    call: (instance, bytes) => instance.walletCheck(bytes, encode("TREZOR")),
    expected: (outcome) => outcome === true,
  },
  {
    name: "walletCheck, refused without a passphrase",
    text: typedForm(checkedPhrase),
    call: (instance, bytes) => instance.walletCheck(bytes, noBytes()),
    expected: refusedWith("WALLET_CHECK_NEEDS_PASSPHRASE"),
  },
  {
    name: "encrypt",
    text: typedForm(PHRASE),
    // The measure finds the phrase while the binding holds it, from the first round's callback:
    // its absence afterwards is the wipe, not a copy the measure cannot see.
    call: (instance, bytes, copies) => {
      let during = null;
      const { container } = encryptBytes(instance, bytes, PASSWORD.slice(), (round) => {
        if (round === 1) during = copies();
      });
      return { container, during };
    },
    expected: ({ container, during }) => container === REDUCED_COST_CONTAINER && during === 1,
  },
  {
    name: "encrypt, refused before the phrase is read",
    text: typedForm(PHRASE),
    call: (instance, bytes) => encryptBytes(instance, bytes, encode("another password")),
    expected: refusedWith("PASSWORDS_DIFFER"),
  },
  {
    name: "encrypt, its phrase refused",
    text: typedForm(INVALID_CHECKSUM),
    call: (instance, bytes) => encryptBytes(instance, bytes),
    expected: refusedWith("INVALID_PHRASE"),
  },
];
for (const { name, text, call, expected } of phraseCases) {
  const { outcome, copies } = copiesLeftBy(text, call);
  assert.ok(expected(outcome), `${name}: ${outcome?.message ?? JSON.stringify(outcome)}`);
  assert.equal(copies, 0, `${name}: the phrase was wiped`);
}
// A phrase that is not UTF-8 is an invalid phrase, before any other work.
const PHRASE_NOT_UTF8 =
  "INVALID_PHRASE: the seed phrase is not a valid English BIP39 phrase: it is not UTF-8 text";
const notUtf8 = () => new Uint8Array([0x61, 0xff]);
expectMessage(PHRASE_NOT_UTF8, () => core.describePhrase(notUtf8()));
expectMessage(PHRASE_NOT_UTF8, () => wallet.walletFingerprint(notUtf8(), noBytes()));
expectMessage(PHRASE_NOT_UTF8, () => wallet.walletCheck(notUtf8(), encode("TREZOR")));
expectMessage(PHRASE_NOT_UTF8, () => encryptBytes(core, notUtf8()));
console.log("Phrases reach the WebAssembly as bytes, and no copy of them stays in its memory.");

// Each draw probes the page's source itself, before anything is drawn: two blocks of 32 bytes,
// which must differ and not be zero (src/random.rs), and the browser's own error is kept.
expectMessage(
  "RANDOM_FAILED: the random generator failed: it gave bytes that cannot be random",
  () => passwords.makePassword("words", 5, noBytes(), { fill: (bytes) => bytes.fill(7) }),
);
const refusingSource = {
  fill: () => {
    throw new Error("QuotaExceededError: the browser refused");
  },
};
for (const draw of [
  () => passwords.makePassword("checkWord", undefined, noBytes(), refusingSource),
  () => wallet.drawPhrase(noBytes(), false, refusingSource, () => {}),
]) {
  expectMessage(
    "RANDOM_FAILED: the random generator failed: the page's random source failed: " +
      "QuotaExceededError: the browser refused",
    draw,
  );
}
// Two distinct non-zero probe blocks, then the bytes of the specification's first check word
// vector, whose dice rolls are all index 0 to 4 (src/new_password/known_answers.rs).
const probeBlocks = Array.from({ length: 64 }, (_, index) => index + 1);
const scripted = (bytes) => {
  let position = 0;
  return {
    fill: (buffer) => {
      for (let index = 0; index < buffer.length; index += 1) buffer[index] = bytes[position++];
    },
  };
};
assert.equal(
  JSON.parse(
    passwords.makePassword(
      "checkWord",
      undefined,
      noBytes(),
      scripted([...probeBlocks, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4]),
    ),
  ).password,
  "abacus abdomen abdominal abide abiding aids",
);

// Part 2b: the self-check of each module, as its class runs it in a worker: exact parts and
// outcomes at both tiers, each part reported as it starts and ends.
const REPAIR_PARTS = ["bip39-words", "repair-words"];
const PASSWORD_PARTS = [
  "password-unicode",
  "password-check-word",
  "password-generator",
  "random-source",
];
const WALLET_PARTS = [
  "bip39-words",
  "wallet-hashes",
  "bip39-seed",
  "bip32",
  "addresses",
  "address-search",
  "wallet-check",
  "random-source",
];
const CORE_PARTS = [
  "cipher-hashes",
  "argon2",
  "cipher-rounds",
  "formats",
  "container-facts",
  "keep-advice",
  "password-unicode",
  "bip39-words",
  "repair-words",
  "password-check-word",
  "wallet-hashes",
  "bip39-seed",
  "bip32",
  "addresses",
  "wallet-check",
  "hidden-wallets",
  "rekey",
  "rehearsal",
];
/** The name of each part as a person reads it, as the library defines it. */
const LABELS = {
  "cipher-hashes": "Cipher hashes",
  argon2: "Argon2id",
  "argon2-sizes": "Argon2id at 64 and 256 MiB",
  "cipher-rounds": "Cipher rounds",
  formats: "Formats",
  "container-facts": "Container facts",
  "keep-advice": "Keep advice",
  "password-unicode": "Passwords (Unicode 17)",
  "bip39-words": "BIP39 words",
  "repair-words": "Repair words (MHFE-REPAIR-1)",
  "password-check-word": "Password check word (MHFE-PASSWORD-CHECK-1)",
  "wallet-hashes": "Wallet hashes",
  "bip39-seed": "BIP39 seeds",
  bip32: "BIP32 keys",
  addresses: "Address encodings",
  "address-search": "Address search",
  "wallet-check": "Wallet check (MHFE-WALLET-CHECK-SEED-1)",
  "hidden-wallets": "Hidden wallets",
  rekey: "Rekey",
  rehearsal: "Rehearsal",
  "password-generator": "Password generator",
  "random-source": "Random source",
};
const ARGON2_LEFT_OUT = "this check leaves Argon2 out";
/** Every report of this part, for the check of their texts in part 3. */
const reports = [];

/** Runs a self-check binding and returns its report and the events of its parts, in order. */
function runCheck(check) {
  const events = [];
  const report = JSON.parse(
    check(
      (id, label) => events.push(`start ${id} ${label}`),
      (json) => {
        const part = JSON.parse(json);
        events.push(`end ${part.id} ${part.outcome}`);
      },
    ),
  );
  reports.push(report);
  return { report, events };
}

/** A passed part, or one with another outcome and its detail. */
function part(id, outcome = "passed", detail = undefined) {
  return detail === undefined
    ? { id, label: LABELS[id], outcome }
    : { id, label: LABELS[id], outcome, detail };
}

/** The exact report of a run in which `parts` ran, with the outcomes `other` of some. */
function expectReport({ report, events }, tier, parts, ids, other = {}) {
  const expected = parts.map((id) => (other[id] === undefined ? part(id) : other[id]));
  assert.deepEqual(report, {
    version: VERSION,
    tier,
    passed: expected.every((each) => each.outcome !== "failed"),
    ids,
    components: expected,
  });
  assert.deepEqual(
    events,
    expected.flatMap((each) => [
      `start ${each.id} ${each.label}`,
      `end ${each.id} ${each.outcome}`,
    ]),
  );
}

// A live source that counts its calls: the startup tier tries scripted sources only.
let liveCalls = 0;
const liveRandom = {
  fill: (bytes) => {
    liveCalls += 1;
    globalThis.crypto.getRandomValues(bytes);
  },
};
for (const tier of ["startup", "full"]) {
  const timed = (name, check) => {
    const started = performance.now();
    const ran = runCheck(check);
    console.log(`  ${name} at ${tier}: ${(performance.now() - started).toFixed(1)} ms`);
    return ran;
  };
  liveCalls = 0;
  expectReport(
    timed("repair", (start, end) => bindings.selfCheckRepair(tier, [], start, end)),
    tier,
    REPAIR_PARTS,
    REPAIR_PARTS,
  );
  expectReport(
    timed("passwords", (start, end) =>
      bindings.selfCheckPasswords(tier, [], liveRandom, start, end),
    ),
    tier,
    PASSWORD_PARTS,
    PASSWORD_PARTS,
  );
  expectReport(
    timed("wallet", (start, end) => bindings.selfCheckWallet(tier, [], liveRandom, start, end)),
    tier,
    WALLET_PARTS,
    WALLET_PARTS,
  );
  // Two probes and the spread for each of the two modules that draw.
  assert.equal(liveCalls, tier === "startup" ? 0 : 6, `the live source at ${tier}`);
  expectReport(
    timed("core without Argon2", (start, end) =>
      bindings.selfCheckCore(tier, [], undefined, start, end),
    ),
    tier,
    CORE_PARTS,
    CORE_PARTS,
    { argon2: part("argon2", "notRun", ARGON2_LEFT_OUT) },
  );
}
// Through each real Argon2 build: its known answer at startup, and at 64 and 256 MiB in the full
// tier only.
for (const [name, createModule] of Object.entries(builds)) {
  const engine = argon2Engine(await createModule());
  expectReport(
    runCheck((start, end) => bindings.selfCheckCore("startup", [], engine, start, end)),
    "startup",
    CORE_PARTS,
    CORE_PARTS,
  );
  expectReport(
    runCheck((start, end) => bindings.selfCheckArgon2("startup", [], engine, start, end)),
    "startup",
    ["argon2"],
    ["argon2", "argon2-sizes"],
  );
  const started = performance.now();
  expectReport(
    runCheck((start, end) => bindings.selfCheckArgon2("full", [], engine, start, end)),
    "full",
    ["argon2", "argon2-sizes"],
    ["argon2", "argon2-sizes"],
  );
  console.log(
    `  ${name} Argon2 at 1, 64 and 256 MiB: ${(performance.now() - started).toFixed(0)} ms`,
  );
}
// A browser that cannot give the memory makes the larger sizes not available, not failed.
const refusingMemory = {
  derive: (password, salt, memoryKib, passes, key) => {
    if (memoryKib > 1024) {
      throw new Error("MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory");
    }
    realArgon2.derive(password, salt, memoryKib, passes, key);
  },
  reserve: noop,
};
expectReport(
  runCheck((start, end) => bindings.selfCheckArgon2("full", [], refusingMemory, start, end)),
  "full",
  ["argon2", "argon2-sizes"],
  ["argon2", "argon2-sizes"],
  { "argon2-sizes": part("argon2-sizes", "notAvailable", "the browser could not give 64 MiB") },
);
// Parts that another module of the page passed are skipped, an unknown one ignored; the order of
// the whole set comes with the report.
expectReport(
  runCheck((start, end) =>
    bindings.selfCheckWallet(
      "startup",
      ["bip39-words", "addresses", "unknown"],
      liveRandom,
      start,
      end,
    ),
  ),
  "startup",
  WALLET_PARTS.filter((id) => id !== "bip39-words" && id !== "addresses"),
  WALLET_PARTS,
);
// A stuck source passes the startup tier, which does not call it, and fails the full one.
const stuck = { fill: (bytes) => bytes.fill(0x2a) };
expectReport(
  runCheck((start, end) => bindings.selfCheckPasswords("startup", [], stuck, start, end)),
  "startup",
  PASSWORD_PARTS,
  PASSWORD_PARTS,
);
expectReport(
  runCheck((start, end) => bindings.selfCheckWallet("full", [], stuck, start, end)),
  "full",
  WALLET_PARTS,
  WALLET_PARTS,
  {
    "random-source": part(
      "random-source",
      "failed",
      "the source gives bytes that cannot be random",
    ),
  },
);
// Only "startup" and "full" are tiers, refused before any part runs.
for (const [tier, check] of [
  ["nightly", (start) => bindings.selfCheckRepair("nightly", [], start, noop)],
  ["Startup", (start) => bindings.selfCheckCore("Startup", [], undefined, start, noop)],
  ["", (start) => bindings.selfCheckArgon2("", [], realArgon2, start, noop)],
]) {
  const started = [];
  expectMessage(
    `INVALID_REQUEST: invalid request: a self-check tier is "startup" or "full", not "${tier}"`,
    () => check((id) => started.push(id)),
  );
  assert.deepEqual(started, [], `no part runs for the tier "${tier}"`);
}

// A WebAssembly whose vectors were damaged, as a fault of the download, the disk or the memory
// would damage them: one letter of a repair card of MHFE-REPAIR-1, then of BIP84's published
// address, then of what an address check states it searches. Each must fail its own part, named
// by its place only.
/** The package's WebAssembly with the last letter of every copy of `text` changed. */
function damaged(text) {
  const bytes = Buffer.from(packageWasm);
  const needle = Buffer.from(text);
  let copies = 0;
  for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) {
    bytes[at + needle.length - 1] ^= 1;
    copies += 1;
  }
  assert.ok(copies > 0, `the WebAssembly holds ${text}`);
  return bytes;
}
const damagedCard = bindingsOver(damaged("shaft pupil patient jewel"));
const cardFailed = (detail) => ({ "repair-words": part("repair-words", "failed", detail) });
expectReport(
  runCheck((start, end) => damagedCard.selfCheckRepair("startup", [], start, end)),
  "startup",
  REPAIR_PARTS,
  REPAIR_PARTS,
  cardFailed("card 1 of 1 gives other words"),
);
expectReport(
  runCheck((start, end) => damagedCard.selfCheckRepair("full", [], start, end)),
  "full",
  REPAIR_PARTS,
  REPAIR_PARTS,
  cardFailed("card 1 of 4 gives other words"),
);
const damagedAddress = bindingsOver(damaged(PHRASE_ADDRESS));
expectReport(
  runCheck((start, end) => damagedAddress.selfCheckWallet("startup", [], liveRandom, start, end)),
  "startup",
  WALLET_PARTS,
  WALLET_PARTS,
  {
    addresses: part("addresses", "failed", "address 3 of 18 stops with INVALID_ADDRESS"),
    // The search an address check states starts from the same address.
    "address-search": part("address-search", "failed", "search 1 of 5 stops with INVALID_ADDRESS"),
  },
);
// The search an address check states, which describeAddress shows before it runs: the first known
// answer with one account fewer, "0'-9'" read as "0'-8'" after the damage, fails the wallet's
// startup check.
const damagedSearch = bindingsOver(damaged("m/84'/0'/0'-9'/0-1/0-99"));
expectReport(
  runCheck((start, end) => damagedSearch.selfCheckWallet("startup", [], liveRandom, start, end)),
  "startup",
  WALLET_PARTS,
  WALLET_PARTS,
  { "address-search": part("address-search", "failed", "search 1 of 5 is stated otherwise") },
);
console.log("Every module's self-check passes at both tiers and fails on a damaged vector.");

// Part 2c: the package's worker.js in this process, its `self` a stand-in that collects what it
// posts: the build handshake, the self-checks of the worker's tables, and a WebAssembly that stops.
const workerScript = read("dist/runtime/worker.js").toString();
const compiledPackage = new WebAssembly.Module(packageWasm);
const BUILD_ID = JSON.parse(read("dist/modules.json").toString()).buildId;
/**
 * The worker's PACKAGE_MISMATCH message for `file` of build `build`, as it posts it. It starts
 * with a word, not the file's path, which the page's sentence() would capitalize.
 */
const workerMismatch = (file, build) =>
  `the file ${file} is of build ${build} and runtime/worker.js of build ${BUILD_ID}: ` +
  "take every file of the package from one build.";
/**
 * Runs worker `script` with `globals` (such as an Argon2 build in front of it) and returns `send`,
 * which delivers a message as the page would and resolves to what the worker posted for it.
 * `isolated` stands for a cross-origin isolated page.
 */
function inProcessWorker(script, globals = {}, { isolated = false } = {}) {
  const posted = [];
  const workerSelf = {
    postMessage: (message) => posted.push(structuredClone(message)),
    crypto: globalThis.crypto,
    crossOriginIsolated: isolated,
  };
  new Function("self", ...Object.keys(globals), script)(workerSelf, ...Object.values(globals));
  return async (message) => {
    posted.length = 0;
    await workerSelf.onmessage({ data: message });
    return [...posted];
  };
}
/** The messages of a self-check: a start and an end for each part, then the result. */
function selfCheckMessages(parts, report) {
  return [
    ...parts.flatMap(({ id, label, outcome, detail }) => [
      { type: "componentStart", value: { id, label } },
      {
        type: "component",
        value: detail === undefined ? { id, label, outcome } : { id, label, outcome, detail },
      },
    ]),
    { type: "result", result: report },
  ];
}
const repairWorker = inProcessWorker(workerScript);
const repairRequest = { module: "repair", operation: "selfCheck", tier: "startup", skip: [] };
const repairReport = {
  version: VERSION,
  tier: "startup",
  passed: true,
  ids: REPAIR_PARTS,
  components: REPAIR_PARTS.map((id) => part(id)),
};
assert.deepEqual(await repairWorker({ ...repairRequest, compiled: compiledPackage }), [
  { type: "ready", buildId: BUILD_ID },
  ...selfCheckMessages(repairReport.components, repairReport),
]);
// The core through the single-threaded Argon2 build in front of the worker, with the core's
// limits. Each Argon2 build carries its stamped build, which the worker compares with its own.
const coreRequest = {
  module: "core",
  operation: "selfCheck",
  tier: "startup",
  skip: [],
  argon2: true,
};
const singleThreadedBuild = {
  createArgon2St: builds["single-threaded"],
  ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID,
};
const threadedBuild = { createArgon2Mt: builds.threaded, ARGON2_THREADED_BUILD_ID: BUILD_ID };
const withArgon2 = await inProcessWorker(
  workerScript,
  singleThreadedBuild,
)({
  ...coreRequest,
  compiled: compiledPackage,
});
assert.deepEqual(withArgon2.at(-1).result.parameters, parameters);
assert.deepEqual(
  withArgon2.at(-1).result.components.map(({ id, outcome }) => `${id} ${outcome}`),
  CORE_PARTS.map((id) => `${id} passed`),
);
/** What the worker posts for the core's self-check whose Argon2 part is `argon2`. */
function coreCheckMessages(argon2) {
  const components = CORE_PARTS.map((id) => (id === "argon2" ? argon2 : part(id)));
  const report = {
    version: VERSION,
    tier: "startup",
    passed: argon2.outcome !== "failed",
    ids: CORE_PARTS,
    components,
  };
  return [
    { type: "ready", buildId: BUILD_ID },
    ...selfCheckMessages(components, { ...report, parameters }),
  ];
}
const coreCheckWith = (globals, options) =>
  inProcessWorker(workerScript, globals, options)({ ...coreRequest, compiled: compiledPackage });
// An Argon2 build that does not start gave no wrong answer: Argon2 is not available, with the
// cause, and the report passes. A wrong answer of a build that started still fails it.
const refusedStart = () => Promise.reject(new Error("the browser refused its memory"));
assert.deepEqual(
  await coreCheckWith({ ...singleThreadedBuild, createArgon2St: refusedStart }),
  coreCheckMessages(
    part(
      "argon2",
      "notAvailable",
      "Argon2id could not run: the single-threaded Argon2 build did not start: the browser " +
        "refused its memory",
    ),
  ),
);
// On a fast-mode page the single-threaded build follows the threaded one. When the threaded one
// does not start, here because the page is not cross-origin isolated or its lane workers do not
// start, the check runs the single-threaded build instead and says so.
const notIsolated =
  "the threaded Argon2 build did not start: the page is not cross-origin isolated, so the build " +
  "cannot share its memory with its lane workers";
const fellBack = "; the check ran the single-threaded build of the standard mode instead";
assert.deepEqual(
  await coreCheckWith({ ...threadedBuild, ...singleThreadedBuild }),
  coreCheckMessages(part("argon2", "warning", `${notIsolated}${fellBack}`)),
);
const noLanes = () => Promise.reject(new Error("the lane workers did not start"));
const lanesFailed = "the threaded Argon2 build did not start: the lane workers did not start";
assert.deepEqual(
  await coreCheckWith(
    { ...threadedBuild, createArgon2Mt: noLanes, ...singleThreadedBuild },
    { isolated: true },
  ),
  coreCheckMessages(part("argon2", "warning", `${lanesFailed}${fellBack}`)),
);
const wrongTag = async () => {
  const module = await builds["single-threaded"]();
  const realHash = module._argon2id_hash_raw;
  module._argon2id_hash_raw = (...args) => {
    const code = realHash(...args);
    module.HEAPU8[args[7]] ^= 1;
    return code;
  };
  return module;
};
assert.deepEqual(
  await coreCheckWith(
    { ...threadedBuild, createArgon2Mt: noLanes, ...singleThreadedBuild, createArgon2St: wrongTag },
    { isolated: true },
  ),
  coreCheckMessages(
    part(
      "argon2",
      "failed",
      `${lanesFailed}${fellBack}; the page's Argon2 build gives another tag`,
    ),
  ),
);
assert.deepEqual(
  await coreCheckWith(
    {
      ...threadedBuild,
      createArgon2Mt: noLanes,
      ...singleThreadedBuild,
      createArgon2St: refusedStart,
    },
    { isolated: true },
  ),
  coreCheckMessages(
    part(
      "argon2",
      "notAvailable",
      `Argon2id could not run: ${lanesFailed}; the single-threaded Argon2 build did not start: ` +
        "the browser refused its memory",
    ),
  ),
);
// The check of one build at 64 and 256 MiB, as the full self-check runs it for each build.
const sizesRequest = {
  module: "core",
  operation: "selfCheckArgon2",
  tier: "full",
  skip: ["argon2"],
  compiled: compiledPackage,
};
const sizesNotStarted = await inProcessWorker(
  workerScript,
  { ...threadedBuild, createArgon2Mt: noLanes },
  { isolated: true },
)(sizesRequest);
const sizesPart = part("argon2-sizes", "notAvailable", `Argon2id could not run: ${lanesFailed}`);
assert.deepEqual(sizesNotStarted, [
  { type: "ready", buildId: BUILD_ID },
  ...selfCheckMessages([sizesPart], {
    version: VERSION,
    tier: "full",
    passed: true,
    ids: ["argon2", "argon2-sizes"],
    components: [sizesPart],
  }),
]);
// No build in front is the page's mistake, not a fault of the computer.
assert.deepEqual(await coreCheckWith({}), [
  { type: "ready", buildId: BUILD_ID },
  {
    type: "error",
    error: {
      code: "INTERNAL_ERROR",
      message: "this operation needs an Argon2 build in front of the worker",
    },
  },
]);
// An Argon2 build of another build, or one that was not stamped, is refused before it runs, for
// a check and for the self-test, which waits for no check, alike. Part 4b gives the page the
// worker's refusals as it posts them.
const workerRefusals = [];
for (const [file, globals, build] of [
  [
    "core/argon2-st.js",
    { ...singleThreadedBuild, ARGON2_SINGLE_THREADED_BUILD_ID: "0123456789abcdef" },
    "0123456789abcdef",
  ],
  ["core/argon2-st.js", { createArgon2St: builds["single-threaded"] }, "development"],
  [
    "core/argon2-mt.js",
    { ...threadedBuild, ARGON2_THREADED_BUILD_ID: "0123456789abcdef", ...singleThreadedBuild },
    "0123456789abcdef",
  ],
]) {
  const mismatch = {
    type: "error",
    error: { code: "PACKAGE_MISMATCH", message: workerMismatch(file, build) },
  };
  for (const request of [coreRequest, { module: "core", operation: "selfTest" }]) {
    const posted = await inProcessWorker(workerScript, globals, { isolated: true })({
      ...request,
      compiled: compiledPackage,
    });
    assert.deepEqual(
      posted,
      [{ type: "ready", buildId: BUILD_ID }, mismatch],
      `${file} of build ${build}: ${request.operation}`,
    );
    workerRefusals.push({ file, build, error: posted[1].error });
  }
}
// The full tier of the passwords module tries the worker's own crypto.getRandomValues.
const passwordsFull = await inProcessWorker(workerScript)({
  module: "passwords",
  operation: "selfCheck",
  tier: "full",
  skip: [],
  compiled: compiledPackage,
});
assert.deepEqual(
  passwordsFull.at(-1).result.components,
  PASSWORD_PARTS.map((id) => part(id)),
);

// The worker serves the operations of its tables only. A name every object inherits from
// Object.prototype is no operation: it is refused like any other unknown name, rather than called
// with the request, whose secrets it would post back (AUD-010). The worker wipes the request's
// secrets either way.
for (const [module, operation] of [
  ["core", "constructor"],
  ["repair", "toString"],
  ["passwords", "hasOwnProperty"],
  ["wallet", "__proto__"],
  ["__proto__", "constructor"],
  ["constructor", "keys"],
  ["toString", "call"],
  ["core", "encrypt "],
  ["Core", "encrypt"],
]) {
  const request = { module, operation, password: encode("public test password") };
  assert.deepEqual(
    await inProcessWorker(workerScript)({ ...request, compiled: compiledPackage }),
    [
      { type: "ready", buildId: BUILD_ID },
      {
        type: "error",
        error: { code: "INVALID_REQUEST", message: `unknown operation ${module}.${operation}` },
      },
    ],
    `${module}.${operation} is refused`,
  );
}
const inheritedRequest = {
  module: "core",
  operation: "constructor",
  password: encode("public test password"),
  compiled: compiledPackage,
};
await inProcessWorker(workerScript)(inheritedRequest);
assert.ok(
  inheritedRequest.password.every((byte) => byte === 0),
  "the worker wipes the secrets of a refused request",
);
// A phrase goes to the worker as bytes, which it hands to the WebAssembly and then wipes, with the
// passphrase, as it wipes passwords.
const phraseRequests = [
  [{ module: "wallet", operation: "fingerprint", passphrase: encode("TREZOR") }, PHRASE],
  [{ module: "wallet", operation: "walletCheck", passphrase: encode("TREZOR") }, checkedPhrase],
  [{ module: "core", operation: "describePhrase" }, typedForm(PHRASE)],
];
const phraseResults = [];
for (const [request, phrase] of phraseRequests) {
  const sent = { ...request, phrase: encode(phrase), compiled: compiledPackage };
  const posted = await inProcessWorker(workerScript)(sent);
  assert.equal(posted.at(-1).type, "result", `${request.operation}: ${JSON.stringify(posted)}`);
  phraseResults.push(posted.at(-1).result);
  assert.ok(
    sent.phrase.every((byte) => byte === 0),
    `${request.operation}: the phrase is wiped`,
  );
  assert.ok(
    (sent.passphrase ?? noBytes()).every((byte) => byte === 0),
    `${request.operation}: the passphrase is wiped`,
  );
}
assert.deepEqual(phraseResults.slice(0, 2), [PHRASE_TREZOR_FINGERPRINT, true]);
assert.equal(phraseResults[2].phrase, PHRASE);

// The build handshake. scripts/stamp-build-id.mjs ends the WebAssembly with the custom section
// "mhfe-build": id 0, 27 bytes, the 10-byte name, the 16 hex digits of the build (part 3 derives
// them again).
const stamp = Buffer.concat([Buffer.from([0, 27, 10]), Buffer.from(`mhfe-build${BUILD_ID}`)]);
assert.deepEqual(packageWasm.subarray(-stamp.length), stamp, "the WebAssembly ends with its stamp");
const unstamped = packageWasm.subarray(0, -stamp.length);
assert.deepEqual(unstamped, read("target/wasm-bindgen/mhfe_bg.wasm"));
// A WebAssembly of another build, or not stamped at all, is refused before it runs: no "ready".
for (const [build, wasm] of [
  [
    "0123456789abcdef",
    Buffer.concat([unstamped, stamp.subarray(0, 13), Buffer.from("0123456789abcdef")]),
  ],
  ["development", unstamped],
]) {
  const posted = await inProcessWorker(workerScript)({
    ...repairRequest,
    compiled: new WebAssembly.Module(wasm),
  });
  assert.deepEqual(posted, [
    {
      type: "error",
      error: { code: "PACKAGE_MISMATCH", message: workerMismatch("runtime/mhfe.wasm", build) },
    },
  ]);
  workerRefusals.push({ file: "runtime/mhfe.wasm", build, error: posted[0].error });
}

// A WebAssembly that stops inside a part (a trap, such as a Rust panic, which a release build
// turns into "unreachable") fails that part with what came before, instead of the worker. The
// worker's runtime and the repair module's table, unstamped, run over a stand-in of the bindings.
const trapping = inProcessWorker(
  `${read("web/worker-runtime.js")}\n${read("web/repair-worker.js")}\n` +
    "serveOperations(mhfe, { repair: REPAIR_OPERATIONS });",
  {
    mhfe: {
      initSync: noop,
      packageVersion: () => VERSION,
      selfCheckRepair: (tier, skip, onStart, onResult) => {
        onStart("bip39-words", LABELS["bip39-words"]);
        onResult(JSON.stringify(part("bip39-words")));
        onStart("repair-words", LABELS["repair-words"]);
        throw new WebAssembly.RuntimeError("unreachable");
      },
    },
  },
);
const stoppedReport = {
  version: VERSION,
  tier: "startup",
  passed: false,
  components: [part("bip39-words"), part("repair-words", "failed", "the WebAssembly stopped")],
};
reports.push(stoppedReport);
// An unstamped module, as the unstamped worker runtime expects.
const emptyModule = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
assert.deepEqual(await trapping({ ...repairRequest, compiled: emptyModule }), [
  { type: "ready", buildId: "development" },
  { type: "componentStart", value: { id: "bip39-words", label: LABELS["bip39-words"] } },
  { type: "component", value: part("bip39-words") },
  { type: "componentStart", value: { id: "repair-words", label: LABELS["repair-words"] } },
  { type: "component", value: part("repair-words", "failed", "the WebAssembly stopped") },
  { type: "result", result: stoppedReport },
]);
console.log(
  "The worker serves every self-check, names a part that stops, and refuses other builds.",
);

// Part 3: the manifest, the versions, and no network code.
const manifest = JSON.parse(read("dist/modules.json").toString());
assert.equal(manifest.version, VERSION);
const hash = (path) => createHash("sha256").update(read(path)).digest("hex");
for (const [name, file] of Object.entries(manifest.runtime.files)) {
  assert.equal(hash(`dist/runtime/${name}`), file, `runtime/${name}`);
}
for (const [module, { files, requires }] of Object.entries(manifest.modules)) {
  assert.deepEqual(requires, ["runtime"], `${module} needs no other module`);
  for (const [name, file] of Object.entries(files)) {
    assert.equal(hash(`dist/${module}/${name}`), file, `${module}/${name}`);
  }
}
// The WebAssembly names no folder of the machine that built it (AUD-010): scripts/build-wasm.sh
// remaps the checkout, CARGO_HOME and RUSTUP_HOME to the relative names mhfe, cargo and rustup
// with packaging/remap-builder-paths.sh, as every native build does, so that the panic locations
// of the dependencies carry no account name or folder layout. Neither
// this machine's folders nor any absolute source path but those rustc writes for its own sources
// may appear, whatever machine built it.
const wasmText = packageWasm.toString("latin1");
for (const path of [
  "/home/",
  fileURLToPath(root).replace(/\/$/u, ""),
  process.env.CARGO_HOME ?? join(homedir(), ".cargo"),
  process.env.RUSTUP_HOME ?? join(homedir(), ".rustup"),
]) {
  const at = wasmText.indexOf(path);
  assert.equal(
    at,
    -1,
    `runtime/mhfe.wasm names ${path} of the machine that built it, in ` +
      JSON.stringify(wasmText.slice(Math.max(at, 0), at + 160)),
  );
}
/** Where rustc puts the standard library's sources and its dependencies' itself. */
const REMAPPED_BY_RUSTC = ["/rustc/", "/rust/deps/"];
// A source path is a run of printable bytes ending in a Rust or C file name; it is absolute when
// it starts with a slash that no other printable byte precedes.
const sourcePaths = [
  ...wasmText.matchAll(/(?<![\x21-\x7e])\/[\x21-\x7e]{5,}?\.(?:rs|c|h)(?![A-Za-z0-9_])/gu),
].map(([path]) => path);
assert.ok(sourcePaths.length > 0, "the WebAssembly's panic locations are found");
assert.deepEqual(
  sourcePaths.filter((path) => !REMAPPED_BY_RUSTC.some((prefix) => path.startsWith(prefix))),
  [],
  "runtime/mhfe.wasm names no absolute source path but rustc's own",
);
assert.match(
  wasmText,
  /(?<![\x21-\x7e])cargo\/registry\/src\/[^/]+\/bip39-/u,
  "the dependencies' paths are there, remapped from CARGO_HOME to cargo/",
);
// No script of the package contains code that could reach the network, not even code that never
// runs (scripts/remove-network-code.mjs removes the loaders the tools emit).
const scriptsOf = (folder, files) =>
  Object.keys(files)
    .filter((name) => name.endsWith(".js"))
    .map((name) => `${folder}/${name}`);
const scripts = [
  ...scriptsOf("runtime", manifest.runtime.files),
  ...Object.entries(manifest.modules).flatMap(([module, { files }]) => scriptsOf(module, files)),
];
assert.ok(scripts.includes("runtime/worker.js"), "the worker is checked too");
for (const script of scripts) {
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
// No script names a coin: the coins live in the WebAssembly only, so that a page for one coin
// carries no other coin's name (the wallet tools' Dash edition refuses any other in its page).
const coinNames = JSON.parse(wallet.walletParameters()).coins.flatMap(({ id, name }) => [id, name]);
const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
for (const script of scripts) {
  const text = read(`dist/${script}`).toString();
  for (const coin of coinNames) {
    const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
    assert.equal(pattern.test(text), false, `${script} names the coin ${coin}`);
  }
}
// Nor does any script carry the vectors of the wallet's or the rehearsal's checks, which name
// coins' addresses: they stay in the WebAssembly, whose text the Dash edition does not read.
// A vector is a string of those files of 8 or more characters that has a digit and no space (an
// address, a digest, a seed or a path) or 12 words or more (a phrase); the names, identifiers and
// details of the parts are not vectors.
/** The string literals of a Rust file, with their escapes resolved. */
function rustStrings(path) {
  const source = read(path).toString();
  const strings = [];
  let index = 0;
  while (index < source.length) {
    if (source.startsWith("//", index)) {
      index = source.indexOf("\n", index);
      if (index === -1) break;
    } else if (source[index] === '"') {
      let text = "";
      index += 1;
      while (source[index] !== '"') {
        if (source[index] === "\\") {
          const next = source[index + 1];
          if (next === "\n") {
            // A line continuation: the line break and the next line's indentation are left out.
            index += 2;
            while (/\s/u.test(source[index])) index += 1;
            continue;
          }
          if (next === "u") {
            const end = source.indexOf("}", index);
            text += String.fromCodePoint(parseInt(source.slice(index + 3, end), 16));
            index = end + 1;
            continue;
          }
          text += { n: "\n", t: "\t", 0: "\0" }[next] ?? next;
          index += 2;
        } else {
          text += source[index];
          index += 1;
        }
      }
      strings.push(text);
      index += 1;
    } else {
      index += 1;
    }
  }
  return strings;
}
const vectorTexts = [
  ...new Set(
    ["src/wallet/known_answers.rs", "src/rehearsal/known_answers.rs"]
      .flatMap(rustStrings)
      .filter(
        (text) =>
          text.length >= 8 &&
          ((/[0-9]/u.test(text) && !text.includes(" ")) || text.split(" ").length >= 12),
      ),
  ),
];
assert.ok(vectorTexts.includes(PHRASE_ADDRESS), "the strings of the Rust files are read");
assert.ok(vectorTexts.includes(PHRASE), "a string over several lines is read whole");
for (const script of scripts) {
  const text = read(`dist/${script}`).toString();
  for (const vector of vectorTexts) {
    assert.equal(text.includes(vector), false, `${script} carries the vector text ${vector}`);
  }
}
// The labels and details of every self-check report, failures included, name no coin and carry
// no vector.
const reportTexts = reports.flatMap((report) =>
  report.components.flatMap(({ label, detail }) => [label, detail ?? ""]),
);
assert.ok(reportTexts.includes("address 3 of 18 stops with INVALID_ADDRESS"));
for (const text of reportTexts) {
  for (const coin of coinNames) {
    const pattern = new RegExp(`\\b${escaped(coin)}\\b`, "iu");
    assert.equal(pattern.test(text), false, `the report text "${text}" names the coin ${coin}`);
  }
  for (const vector of vectorTexts) {
    assert.equal(text.includes(vector), false, `the report text "${text}" carries ${vector}`);
  }
}

// One build: modules.json, the WebAssembly's section and every stamped part name the same.
assert.equal(manifest.buildId, BUILD_ID);
assert.match(BUILD_ID, /^[0-9a-f]{16}$/u);
assert.deepEqual(
  WebAssembly.Module.customSections(compiledPackage, "mhfe-build").map((section) =>
    new TextDecoder().decode(section),
  ),
  [BUILD_ID],
);
/** Every script a page loads, with its build constant; the Argon2 builds end with theirs. */
const STAMPED_SCRIPTS = new Map([
  ["runtime/runtime.js", "export const BUILD_ID"],
  ["runtime/worker.js", "const WORKER_BUILD_ID"],
  ["core/client.js", "const CLIENT_BUILD_ID"],
  ["core/argon2-mt.js", "const ARGON2_THREADED_BUILD_ID"],
  ["core/argon2-st.js", "const ARGON2_SINGLE_THREADED_BUILD_ID"],
  ["repair/repair.js", "const REPAIR_BUILD_ID"],
  ["passwords/passwords.js", "const PASSWORDS_BUILD_ID"],
  ["wallet/wallet.js", "const WALLET_BUILD_ID"],
]);
for (const [file, constant] of STAMPED_SCRIPTS) {
  const text = read(`dist/${file}`).toString();
  assert.equal(text.split(`${constant} = "${BUILD_ID}";`).length, 2, `${file} is stamped once`);
  assert.equal(text.includes('BUILD_ID = "development"'), false, `${file} has no unstamped build`);
}
for (const [file, constant] of [...STAMPED_SCRIPTS].filter(([file]) => file.includes("argon2"))) {
  assert.ok(
    read(`dist/${file}`).toString().endsWith(`\n${constant} = "${BUILD_ID}";\n`),
    `${file} ends with its build`,
  );
}
// The build is derived from every file a page loads before any was stamped: the first 16 hex
// digits of the SHA-256 of their list, one line per file in this order, its SHA-256, two spaces
// and its path, as sha256sum prints it. Here it is derived again from the files with their stamps
// taken out.
const BUILD_FILES = [
  "runtime/mhfe.wasm",
  "runtime/runtime.js",
  "runtime/worker.js",
  "core/client.js",
  "core/argon2-mt.js",
  "core/argon2-st.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
/** The build of `files`, a map from each of BUILD_FILES to its bytes before stamping. */
const buildOf = (files) =>
  sha256(BUILD_FILES.map((path) => `${sha256(files.get(path))}  ${path}\n`).join("")).slice(0, 16);
const unstampedFiles = new Map([
  ["runtime/mhfe.wasm", unstamped],
  ...[...STAMPED_SCRIPTS].map(([file, constant]) => [
    file,
    Buffer.from(
      read(`dist/${file}`)
        .toString()
        .replace(`${constant} = "${BUILD_ID}";`, `${constant} = "development";`),
    ),
  ]),
]);
assert.deepEqual(
  [...unstampedFiles.keys()].sort(),
  [...BUILD_FILES].sort(),
  "every file is derived from",
);
assert.equal(buildOf(unstampedFiles), BUILD_ID);
// Two builds that differ in one script alone have different builds, so that their files are not
// used together: the files of this package, unstamped, with a comment added to repair/repair.js,
// stamped again by the build's own script in a folder of their own. Then every file of that build
// carries the other build: its WebAssembly is refused by this worker, its Argon2 build too, and
// part 4b gives its class file this runtime.
const otherBuildDir = fileURLToPath(new URL("target/build-id-check/", root));
/** Writes `files` into the other build's folder, as scripts/build-wasm.sh leaves them. */
function writeBuildFiles(files) {
  rmSync(otherBuildDir, { recursive: true, force: true });
  for (const [path, bytes] of files) {
    mkdirSync(join(otherBuildDir, dirname(path)), { recursive: true });
    writeFileSync(join(otherBuildDir, path), bytes);
  }
}
const stampBuild = () =>
  execFileSync(process.execPath, ["scripts/stamp-build-id.mjs", otherBuildDir], {
    cwd: fileURLToPath(root),
    stdio: "pipe",
  }).toString();
const otherFiles = new Map(unstampedFiles);
otherFiles.set(
  "repair/repair.js",
  Buffer.concat([unstampedFiles.get("repair/repair.js"), Buffer.from("// another build\n")]),
);
writeBuildFiles(otherFiles);
const OTHER_BUILD_ID = buildOf(otherFiles);
assert.notEqual(OTHER_BUILD_ID, BUILD_ID, "a script alone changes the build");
assert.equal(stampBuild(), `Stamped build ${OTHER_BUILD_ID} into the package.\n`);
const readOtherBuild = (path) => readFileSync(join(otherBuildDir, path));
for (const [file, constant] of STAMPED_SCRIPTS) {
  assert.ok(
    readOtherBuild(file).toString().includes(`${constant} = "${OTHER_BUILD_ID}";`),
    `${file} of the other build carries it`,
  );
}
const otherWasm = readOtherBuild("runtime/mhfe.wasm");
assert.deepEqual(otherWasm.subarray(0, unstamped.length), unstamped, "the same WebAssembly");
assert.deepEqual(
  await inProcessWorker(workerScript)({
    ...repairRequest,
    compiled: new WebAssembly.Module(otherWasm),
  }),
  [
    {
      type: "error",
      error: {
        code: "PACKAGE_MISMATCH",
        message: workerMismatch("runtime/mhfe.wasm", OTHER_BUILD_ID),
      },
    },
  ],
  "the other build's WebAssembly, the same bytes but for its build, is refused",
);
// The other build's single-threaded Argon2 build, the very file, in front of this worker.
assert.deepEqual(
  await inProcessWorker(`${readOtherBuild("core/argon2-st.js")}\n;\n${workerScript}`)({
    module: "core",
    operation: "selfTest",
    compiled: compiledPackage,
  }),
  [
    { type: "ready", buildId: BUILD_ID },
    {
      type: "error",
      error: {
        code: "PACKAGE_MISMATCH",
        message: workerMismatch("core/argon2-st.js", OTHER_BUILD_ID),
      },
    },
  ],
);
// The stamped package is not stamped again, and a script without its build constant, such as an
// Argon2 build that scripts/build-wasm.sh did not give one, stops the build.
assert.throws(stampBuild, (error) =>
  error.stderr
    .toString()
    .includes(`${join(otherBuildDir, "runtime/mhfe.wasm")} is stamped already; build it again.`),
);
const withoutConstant = new Map(unstampedFiles);
withoutConstant.set(
  "core/argon2-st.js",
  Buffer.from(
    unstampedFiles
      .get("core/argon2-st.js")
      .toString()
      .replace('\nconst ARGON2_SINGLE_THREADED_BUILD_ID = "development";\n', ""),
  ),
);
writeBuildFiles(withoutConstant);
assert.throws(stampBuild, (error) =>
  error.stderr
    .toString()
    .includes(
      `${join(otherBuildDir, "core/argon2-st.js")} holds 0 build constants instead of one.`,
    ),
);
writeBuildFiles(otherFiles);
stampBuild();
console.log(
  "The manifest matches the files, one build derived from every file a page loads is stamped " +
    "into each, another build is refused, and no script of the package contains network code, " +
    "names a coin or carries a wallet vector.",
);

// Part 4: the page-side classes, with a stand-in worker.
// The classes are ES modules that import "../runtime/runtime.js". The nearest package.json, the
// repository's tooling, cannot declare "type": "module" (the Emscripten builds are CommonJS), so
// each is imported as text with that import pointed at the runtime's text.
const runtimeUrl = `data:text/javascript;base64,${read("dist/runtime/runtime.js").toString("base64")}`;
const importClass = (path) => {
  const text = read(path).toString().replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`);
  return import(`data:text/javascript;base64,${Buffer.from(text).toString("base64")}`);
};
// A page that inlines the package joins the runtime and its classes into one module, as
// scripts/bundle-browser-classes.mjs does; their top-level names must not collide.
const joined = bundleClasses(root, [
  "core/client.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
]);
await import(`data:text/javascript;base64,${Buffer.from(joined).toString("base64")}`).catch(
  (error) => {
    throw new Error(`The classes do not join into one module: ${error.message}`);
  },
);
const { MhfeClient, MhfeCancelledError } = await importClass("dist/core/client.js");
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
    otherWalletsMoved: true,
    newPassword: "n",
    newPasswordRepeat: "n",
    ...options,
  });
/** The TypeError of a missing or non-boolean walletHasPassphrase, with its exact message. */
const walletPassphraseRequired = { name: "TypeError", message: WALLET_PASSPHRASE_REQUIRED };
/** The TypeError of a passphrase with the built-in check or the owner, with its exact message. */
const passphraseOnlyWithReference = { name: "TypeError", message: PASSPHRASE_ONLY_WITH_REFERENCE };
// Every error rejects the promise, the checks of the arguments included: none is thrown.
const refusals = [
  [
    () => client.encrypt({ phrase: PHRASE, password: "p", walletHasPassphrase: false }),
    { code: "PASSWORDS_DIFFER" },
  ],
  [
    () => client.encrypt({ phrase: PHRASE, password: "p", passwordRepeat: "p" }),
    walletPassphraseRequired,
  ],
  [() => encrypt({ password: "p", walletHasPassphrase: undefined }), walletPassphraseRequired],
  [() => encrypt({ password: "p", walletHasPassphrase: "no" }), walletPassphraseRequired],
  [() => encrypt({ password: "p", walletHasPassphrase: null }), walletPassphraseRequired],
  [() => encrypt({ password: "p", walletHasPassphrase: 0 }), walletPassphraseRequired],
  [() => encrypt({ password: "p", sameLength: "yes" }), TypeError],
  [() => encrypt({ password: "p", repairWordCount: 3 }), { code: "INVALID_REPAIR_WORDS" }],
  [() => encrypt({ password: "p", passwordRepair: { repair: "3" } }), TypeError],
  [
    () =>
      client.encrypt({
        phrase: PHRASE,
        password: password,
        passwordRepeat: new Uint8Array(20),
        walletHasPassphrase: false,
      }),
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
  [
    () => client.rekey({ container: "c", password: "p", otherWalletsMoved: false }),
    { code: "OTHER_WALLETS_NOT_CONFIRMED" },
  ],
  [
    () =>
      client.rekey({
        container: "c",
        password: "p",
        otherWalletsMoved: true,
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
  [
    () => encrypt({ password: password, passwordRepeat: undefined }),
    { code: "PASSWORDS_DIFFER", message: "The password and its repetition differ." },
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

// A rekey asks the owner in the middle and sends the answer back.
const rekeying = client.rekey({
  container: "c",
  words: 24,
  password: "old",
  otherWalletsMoved: true,
  newPassword: "new",
  newPasswordRepeat: "new",
  confirmation: { owner: ({ words }) => words === 24 },
  walletHasPassphrase: true,
});
worker = await started();
assert.equal(worker.messages[0].confirmKind, "owner");
assert.equal(worker.messages[0].walletHasPassphrase, true, "the page's answer goes to the worker");
worker.reply({ type: "ask", question: "ownerCheck", value: { phrase: "p", words: 24 } });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(worker.messages[1], { type: "answer", value: true });
worker.reply({ type: "result", result: { container: "n" } });
assert.deepEqual(await rekeying, { container: "n" });
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

// A session of hidden wallets: ready, a wallet per password, refusals keep it open, close ends it.
const opening = client.openHiddenWallets({ container: "c", mainPassphrase: "" });
worker = await started();
worker.reply({ type: "ask", question: "ready", value: null });
const session = await opening;
await assert.rejects(client.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
const first = session.open({ password: "one", passwordRepeat: "one" });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(new TextDecoder().decode(worker.messages[1].value.password), "one");
worker.reply({ type: "ask", question: "opened", value: { phrase: "w", words: 24 } });
assert.deepEqual(await first, { phrase: "w", words: 24 });
const again = session.open({ password: "one", passwordRepeat: "one" });
await new Promise((resolve) => setTimeout(resolve, 0));
worker.reply({
  type: "ask",
  question: "refused",
  value: { code: "PASSWORD_ALREADY_USED", message: "this password was already used here" },
});
await assert.rejects(again, { code: "PASSWORD_ALREADY_USED" });
await assert.rejects(session.open({ password: "a", passwordRepeat: "b" }), {
  code: "PASSWORDS_DIFFER",
});
// A password of another type is a TypeError there too, before the entries are compared.
for (const value of [new Uint16Array([112]), new ArrayBuffer(1), 5]) {
  await assert.rejects(session.open({ password: value, passwordRepeat: value }), {
    name: "TypeError",
    message: "password must be a string or a Uint8Array.",
  });
}
assert.equal(worker.messages.length, 3, "no refused password reached the worker");
// The worker waits for the page, so closing asks it to free the session, which wipes it.
const closing = session.close();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(worker.messages.at(-1), { type: "answer", value: { close: true } });
await assert.rejects(session.open({ password: "x", passwordRepeat: "x" }), {
  code: "SESSION_CLOSED",
});
worker.reply({ type: "result", result: { closed: true } });
await closing;
assert.equal(worker.terminated, true, "closing the session ends its worker");

// Closed while a wallet opens, the session stops its worker at once.
const reopening = client.openHiddenWallets({ container: "c", mainPassphrase: "" });
worker = await started();
worker.reply({ type: "ask", question: "ready", value: null });
const busySession = await reopening;
const interrupted = busySession.open({ password: "one", passwordRepeat: "one" });
await new Promise((resolve) => setTimeout(resolve, 0));
await busySession.close();
assert.equal(worker.terminated, true, "a close during an open stops the worker");
await assert.rejects(interrupted, (error) => error instanceof MhfeCancelledError);

// The client's byte copies of secrets are wiped when an operation cannot start.
const TEST_PASSWORD = "public test password";
const TEST_PASSPHRASE = "public test passphrase";
const copies = [];
const RealTextEncoder = globalThis.TextEncoder;
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSWORD || text === TEST_PASSPHRASE || text === PHRASE) copies.push(bytes);
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
// A browser that refuses the Blob URL ends the operation the same way, and frees its slot.
const realCreateObjectURL = URL.createObjectURL;
URL.createObjectURL = () => {
  throw new Error("refused by the stand-in");
};
copies.length = 0;
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" });
await assert.rejects(fingerprintCheck({}), { code: "WORKER_FAILED" }, "not BUSY: the slot is free");
assert.equal(copies.length, 4);
assert.ok(
  copies.every((bytes) => bytes.every((byte) => byte === 0)),
  "the copies are wiped when the Blob URL is refused",
);
// The phrase's copy is wiped with the passwords' when an encryption cannot start.
copies.length = 0;
await assert.rejects(
  client.encrypt({
    phrase: PHRASE,
    password: TEST_PASSWORD,
    passwordRepeat: TEST_PASSWORD,
    walletHasPassphrase: false,
  }),
  { code: "WORKER_FAILED" },
);
assert.deepEqual(
  copies.map((bytes) => bytes.length),
  [PHRASE.length, TEST_PASSWORD.length, TEST_PASSWORD.length],
  "the phrase and both passwords were copied",
);
assert.ok(
  copies.every((bytes) => bytes.every((byte) => byte === 0)),
  "the phrase's copy is wiped too",
);
URL.createObjectURL = realCreateObjectURL;
globalThis.TextEncoder = RealTextEncoder;

// A caller's array is copied into a plain Uint8Array of the package's own, which alone is
// transferred and wiped, whatever the array's own slice() gives (AUD-010). Node's Buffer, and the
// Buffer that bundlers add to a page, slice into views of the caller's memory, here of Node's
// shared pool of small buffers. The caller's array keeps its length and bytes after an operation
// and after every refusal, and the same array may be given as the password and its repetition.
class ViewSlicing extends Uint8Array {
  slice(start, end) {
    return this.subarray(start, end);
  }
}
const callerArrays = {
  "a Uint8Array whose slice() gives a view": (text) => ViewSlicing.from(encode(text)),
  "Node's Buffer": (text) => Buffer.from(text),
};
for (const [kind, arrayOf] of Object.entries(callerArrays)) {
  const given = arrayOf(TEST_PASSWORD);
  const passphraseGiven = arrayOf(TEST_PASSPHRASE);
  const keeps = (array, text, when) => {
    assert.equal(array.length, text.length, `${kind} keeps its length ${when}`);
    assert.equal(new TextDecoder().decode(array), text, `${kind} keeps its bytes ${when}`);
  };
  const operation = client.encrypt({
    phrase: PHRASE,
    password: given,
    passwordRepeat: given,
    walletHasPassphrase: false,
  });
  worker = await started();
  const transferred = worker.transfers[0];
  assert.ok(
    transferred.every(
      ({ buffer }) =>
        buffer !== given.buffer && Object.getPrototypeOf(buffer) === ArrayBuffer.prototype,
    ),
    `${kind}: only the package's own buffers are transferred`,
  );
  assert.equal(
    new Set(transferred.map(({ buffer }) => buffer)).size,
    transferred.length,
    `${kind}: no buffer twice`,
  );
  assert.deepEqual(
    transferred.map(({ byteLength }) => byteLength),
    [PHRASE.length, TEST_PASSWORD.length, TEST_PASSWORD.length],
    `${kind}: copies of the exact size, not the caller's whole buffer`,
  );
  for (const field of ["password", "passwordRepeat"]) {
    assert.equal(
      Object.getPrototypeOf(worker.messages[0][field]),
      Uint8Array.prototype,
      `${kind}: the worker gets a plain Uint8Array as ${field}`,
    );
    assert.equal(new TextDecoder().decode(worker.messages[0][field]), TEST_PASSWORD);
  }
  keeps(given, TEST_PASSWORD, "after the transfer");
  worker.reply({ type: "result", result: { container: "c" } });
  await operation;
  keeps(given, TEST_PASSWORD, "after the operation");
  // Refused: the repetition differs (its comparison copies are wiped), and the worker does not
  // start (the request's copies are wiped).
  const otherGiven = arrayOf("another public test password");
  await assert.rejects(
    client.encrypt({
      phrase: PHRASE,
      password: given,
      passwordRepeat: otherGiven,
      walletHasPassphrase: false,
    }),
    { code: "PASSWORDS_DIFFER" },
  );
  keeps(given, TEST_PASSWORD, "after its repetition was refused");
  keeps(otherGiven, "another public test password", "as a repetition that was refused");
  globalThis.Worker = class {
    constructor() {
      throw new Error("refused by the stand-in");
    }
  };
  await assert.rejects(
    client.check({
      container: "c",
      password: given,
      reference: { fingerprint: "00000000" },
      passphrase: passphraseGiven,
    }),
    { code: "WORKER_FAILED" },
  );
  globalThis.Worker = StandInWorker;
  keeps(given, TEST_PASSWORD, "after the worker did not start");
  keeps(passphraseGiven, TEST_PASSPHRASE, "as a passphrase after the worker did not start");
}
console.log("The core client passes its checks with a stand-in worker.");

// The quick modules: each call in a worker of its own, terminated afterwards.
const repairClient = new MhfeRepair({ workerSource: "repair worker", wasm });
const card = repairClient.repairWords({ container: "c", count: 4 });
worker = await started();
assert.equal(await worker.script.text(), "repair worker");
assert.equal(worker.messages[0].module, "repair");
assert.equal(worker.messages[0].operation, "repairWords");
worker.reply({ type: "result", result: { words: "w" } });
assert.deepEqual(await card, { words: "w" });
assert.equal(worker.terminated, true);
await assert.rejects(repairClient.repairWords({ container: "c", count: "4" }), TypeError);

const passwordsClient = new MhfePasswords({ workerSource: "passwords worker", wasm });
const reviewing = passwordsClient.review({
  password: "secret words",
  passwordRepeat: "secret words",
});
worker = await started();
assert.equal(worker.messages[0].module, "passwords");
assert.equal(worker.messages[0].operation, "review");
assert.equal(worker.messages[0].repeated, true);
assert.equal(new TextDecoder().decode(worker.messages[0].password), "secret words");
worker.reply({ type: "result", result: { reading: "notThisShape" } });
assert.deepEqual(await reviewing, { reading: "notThisShape" });
// The check word takes no count, refused before any worker starts, as the WebAssembly refuses it
// and `mhfe password` refuses --check-word with --words (AUD-010). Without one, the class sends
// none.
const workersBeforeCount = StandInWorker.started.length;
for (const count of [7, 5, 0]) {
  await assert.rejects(passwordsClient.make({ kind: "checkWord", count }), {
    name: "TypeError",
    message:
      'count belongs only to the kinds "words" and "characters": "checkWord" always gives five ' +
      "words and their check word.",
  });
}
assert.equal(StandInWorker.started.length, workersBeforeCount, "no worker was started");
const makingCheckWord = passwordsClient.make({ kind: "checkWord" });
worker = await started();
assert.deepEqual(fieldsOf(worker.messages[0], ["operation", "kind", "count"]), {
  operation: "make",
  kind: "checkWord",
  count: undefined,
});
worker.reply({ type: "result", result: { checkWord: true } });
assert.deepEqual(await makingCheckWord, { checkWord: true });

const walletClient = new MhfeWallet({ workerSource: "wallet worker", wasm });
// A phrase goes to the wallet's worker as bytes, transferred with the passphrase, so that the
// worker and the WebAssembly wipe it (AUD-010).
for (const [method, operation] of [
  ["fingerprint", "fingerprint"],
  ["walletCheck", "walletCheck"],
]) {
  const asked = walletClient[method]({ phrase: PHRASE, passphrase: "TREZOR" });
  worker = await started(({ operation: sent }) => sent === operation);
  assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE, method);
  assert.equal(new TextDecoder().decode(worker.messages[0].passphrase), "TREZOR", method);
  assert.deepEqual(
    worker.transfers[0].map(({ byteLength }) => byteLength),
    [PHRASE.length, "TREZOR".length],
    `${method}: the phrase and the passphrase are transferred`,
  );
  worker.reply({ type: "result", result: "73c5da0a" });
  assert.equal(await asked, "73c5da0a");
}
// A passphrase of another type is a TypeError before the phrase is copied; one with a lone
// surrogate leaves no copy of the phrase behind.
const phraseCopies = [];
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === PHRASE) phraseCopies.push(bytes);
    return bytes;
  }
};
await assert.rejects(walletClient.fingerprint({ phrase: PHRASE, passphrase: 5 }), {
  name: "TypeError",
  message: "passphrase must be a string or a Uint8Array.",
});
assert.equal(phraseCopies.length, 0, "the phrase was not copied");
await assert.rejects(walletClient.walletCheck({ phrase: PHRASE, passphrase: "a\uD800" }), {
  code: "INVALID_PASSWORD_TEXT",
});
globalThis.TextEncoder = RealTextEncoder;
assert.equal(phraseCopies.length, 1);
assert.ok(
  phraseCopies[0].every((byte) => byte === 0),
  "the phrase's copy is wiped",
);
await assert.rejects(
  walletClient.drawPhrase({ passphrase: "p", passphraseRepeat: "p" }),
  TypeError,
);
await assert.rejects(
  walletClient.drawPhrase({ passphrase: "p", passphraseRepeat: "q", walletCheck: true }),
  { code: "PASSPHRASES_DIFFER" },
);
StandInWorker.started.length = 0;
const draws = [];
const drawing = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 3,
  onProgress: ({ draws: count }) => draws.push(count),
});
await started();
await new Promise((resolve) => setTimeout(resolve, 0));
const drawWorkers = StandInWorker.started.filter((each) => !each.selfCheck);
assert.equal(drawWorkers.length, 3, "a checked phrase is drawn on several workers");
assert.ok(drawWorkers.every((each) => each.messages[0].module === "wallet"));
drawWorkers[0].reply({ type: "draws", value: 1024 });
drawWorkers[1].reply({ type: "draws", value: 1024 });
drawWorkers[2].reply({ type: "result", result: { phrase: "found", words: 24 } });
assert.deepEqual(await drawing, { phrase: "found", words: 24, workers: 3 });
assert.deepEqual(draws, [1024, 2048]);
assert.ok(
  drawWorkers.every((each) => each.terminated),
  "the other workers stop",
);
const cancelledDraw = walletClient.drawPhrase();
walletClient.cancel();
await assert.rejects(cancelledDraw, (error) => error instanceof MhfeCancelledError);
// A refused repetition leaves no copy of the first entry behind.
const firstCopies = [];
globalThis.TextEncoder = class extends RealTextEncoder {
  encode(text) {
    const bytes = super.encode(text);
    if (text === TEST_PASSWORD || text === TEST_PASSPHRASE) firstCopies.push(bytes);
    return bytes;
  }
};
await assert.rejects(
  passwordsClient.review({ password: TEST_PASSWORD, passwordRepeat: 5 }),
  TypeError,
);
await assert.rejects(
  walletClient.drawPhrase({
    passphrase: TEST_PASSPHRASE,
    passphraseRepeat: "\uD800",
    walletCheck: true,
  }),
  { code: "INVALID_PASSWORD_TEXT" },
);
globalThis.TextEncoder = RealTextEncoder;
assert.equal(firstCopies.length, 2);
assert.ok(
  firstCopies.every((bytes) => bytes.every((byte) => byte === 0)),
  "the first entry's copy is wiped when its repetition is refused",
);

// A progress callback whose promise rejects stops every drawing worker.
StandInWorker.started.length = 0;
const failingDraw = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 2,
  onProgress: () => Promise.reject(new Error("the page failed")),
});
await started();
await new Promise((resolve) => setTimeout(resolve, 0));
const failingWorkers = StandInWorker.started.filter((each) => !each.selfCheck);
failingWorkers[0].reply({ type: "draws", value: 1024 });
await assert.rejects(failingDraw, { code: "CALLBACK_FAILED" });
assert.ok(
  failingWorkers.every((each) => each.terminated),
  "every drawing worker stops",
);
console.log("The repair, passwords and wallet classes pass their checks with a stand-in worker.");

// Part 4b: the self-checks of the classes. Each test gives its classes a WebAssembly object of
// their own, so that it starts with no part passed on the page.
const ownWasm = () => new Uint8Array(wasm);
/** A part the page checks itself. */
const pagePart = (id, outcome = "passed", detail = undefined) => {
  const label = {
    "browser-features": "Browser features",
    "package-parts": "Package parts",
    "page-encoding": "Text encoding of the page",
  }[id];
  return detail === undefined ? { id, label, outcome } : { id, label, outcome, detail };
};
const PAGE_PARTS_OF_SECRETS = ["browser-features", "package-parts", "page-encoding"].map((id) =>
  pagePart(id),
);
/** The self-check workers started from here on. */
const checksFrom = (start) => StandInWorker.checks.slice(start);
const firstMessages = (workers) =>
  workers.map(({ messages: [message] }) =>
    fieldsOf(message, ["module", "operation", "tier", "skip"]),
  );

// Each class runs its parts once per page, the page's own first; a part that another class passed
// with the same WebAssembly is not run again but listed as that class found it.
const sharedWasm = ownWasm();
let checksBefore = StandInWorker.checks.length;
const walletFirst = new MhfeWallet({ workerSource: "wallet worker", wasm: sharedWasm });
const walletStartup = await walletFirst.startupCheck();
assert.deepEqual(walletStartup, {
  passed: true,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  components: [...PAGE_PARTS_OF_SECRETS, ...WALLET_PARTS.map((id) => part(id))],
});
assert.equal(await walletFirst.startupCheck(), walletStartup, "made once");
const repairSecond = new MhfeRepair({ workerSource: "repair worker", wasm: sharedWasm });
assert.deepEqual(await repairSecond.startupCheck(), {
  passed: true,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  // No secrets, so no check of their encoding.
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    ...REPAIR_PARTS.map((id) => part(id)),
  ],
});
const passwordsThird = new MhfePasswords({ workerSource: "passwords worker", wasm: sharedWasm });
await passwordsThird.startupCheck();
const coreFourth = new MhfeClient({ ...sources, wasm: sharedWasm });
const withoutArgon2 = await coreFourth.startupCheck({ argon2: false });
assert.deepEqual(withoutArgon2.components, [
  ...PAGE_PARTS_OF_SECRETS,
  ...CORE_PARTS.map((id) => (id === "argon2" ? part(id, "notRun", ARGON2_LEFT_OUT) : part(id))),
]);
// The core's check with Argon2 runs Argon2 alone: every other part has passed on this page.
const withArgon2Report = await coreFourth.startupCheck();
assert.deepEqual(withArgon2Report.components[4], part("argon2"));
assert.ok(withArgon2Report.passed);
const startupChecks = checksFrom(checksBefore);
assert.deepEqual(firstMessages(startupChecks), [
  { module: "wallet", operation: "selfCheck", tier: "startup", skip: [] },
  { module: "repair", operation: "selfCheck", tier: "startup", skip: WALLET_PARTS },
  {
    module: "passwords",
    operation: "selfCheck",
    tier: "startup",
    skip: [...WALLET_PARTS, "repair-words"],
  },
  {
    module: "core",
    operation: "selfCheck",
    tier: "startup",
    skip: [
      ...WALLET_PARTS,
      "repair-words",
      ...PASSWORD_PARTS.filter((id) => id !== "random-source"),
    ],
  },
  {
    module: "core",
    operation: "selfCheck",
    tier: "startup",
    skip: [
      ...WALLET_PARTS,
      "repair-words",
      ...PASSWORD_PARTS.filter((id) => id !== "random-source"),
      ...CORE_PARTS.filter(
        (id) =>
          !WALLET_PARTS.includes(id) &&
          !PASSWORD_PARTS.includes(id) &&
          id !== "repair-words" &&
          id !== "argon2",
      ),
    ],
  },
]);
assert.deepEqual(
  startupChecks.map(({ messages: [message] }) => message.argon2),
  [undefined, undefined, undefined, false, true],
);
assert.equal(
  await startupChecks[3].script.text(),
  "worker source",
  "no Argon2 build without Argon2",
);
assert.equal(await startupChecks[4].script.text(), "single-threaded source\n;\nworker source");
// The startup check is not the rehearsal check, which only check() runs.
assert.ok(StandInWorker.checks.every(({ messages: [message] }) => message.operation !== "check"));
await assert.rejects(coreFourth.startupCheck({ argon2: "yes" }), TypeError);

// The first operation of a class waits for its startup check, without Argon2 for the core.
checksBefore = StandInWorker.checks.length;
const gatedClient = new MhfeClient({ ...sources, wasm: ownWasm() });
const gatedReading = gatedClient.readPhrase(PHRASE);
worker = await started(({ operation }) => operation === "describePhrase");
assert.deepEqual(
  checksFrom(checksBefore).map(({ messages: [message] }) => [message.operation, message.argon2]),
  [["selfCheck", false]],
  "the check ran first",
);
assert.ok(checksFrom(checksBefore)[0].terminatedAt < worker.createdAt);
// The phrase is copied into bytes only after the check, and transferred (AUD-010).
assert.equal(new TextDecoder().decode(worker.messages[0].phrase), PHRASE);
assert.deepEqual(
  worker.transfers[0].map(({ byteLength }) => byteLength),
  [PHRASE.length],
);
worker.reply({ type: "result", result: { phrase: PHRASE } });
assert.deepEqual(await gatedReading, { phrase: PHRASE });

// A part that fails closes the class for good: every operation rejects with SELF_CHECK_FAILED and
// the report, without a worker, while parameters(), the checks and selfTest() still run.
StandInWorker.serveCheck = (message, worker) =>
  message.module === "repair"
    ? JSON.parse(
        damagedCard.selfCheckRepair(
          message.tier,
          message.skip,
          (id, label) => worker.reply({ type: "componentStart", value: { id, label } }),
          (json) => worker.reply({ type: "component", value: JSON.parse(json) }),
        ),
      )
    : servedByTheWebAssembly(message, worker);
const brokenRepair = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
const brokenReport = await brokenRepair.startupCheck();
const cardRefused = part("repair-words", "failed", "card 1 of 1 gives other words");
assert.deepEqual(brokenReport, {
  passed: false,
  tier: "startup",
  version: VERSION,
  buildId: BUILD_ID,
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    part("bip39-words"),
    cardRefused,
  ],
});
const SELF_CHECK_FAILED_MESSAGE =
  "The self-test failed: Repair words (MHFE-REPAIR-1): card 1 of 1 gives other words. " +
  "Do not use this program on this computer";
let workersBefore = StandInWorker.started.length;
checksBefore = StandInWorker.checks.length;
for (const call of [
  () => brokenRepair.repairWords({ container: FULL_SIZE_CONTAINER, count: 4 }),
  () => brokenRepair.repairPlate({ plate: FULL_SIZE_CONTAINER, card: "labor extra" }),
]) {
  await assert.rejects(call(), (error) => {
    assert.equal(error.code, "SELF_CHECK_FAILED");
    assert.equal(error.message, SELF_CHECK_FAILED_MESSAGE);
    assert.equal(error.report, brokenReport);
    return true;
  });
}
assert.equal(StandInWorker.started.length, workersBefore, "a closed class starts no worker");
const brokenParameters = brokenRepair.parameters();
worker = await started(({ operation }) => operation === "parameters");
worker.reply({ type: "result", result: { profile: "MHFE-REPAIR-1" } });
assert.deepEqual(await brokenParameters, { profile: "MHFE-REPAIR-1" });
const brokenFull = await brokenRepair.fullCheck();
assert.deepEqual(
  brokenFull.components.at(-1),
  part("repair-words", "failed", "card 1 of 4 gives other words"),
);
StandInWorker.serveCheck = servedByTheWebAssembly;
// A failed full self-check closes a class too.
const fullyBroken = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
assert.ok((await fullyBroken.startupCheck()).passed);
StandInWorker.serveCheck = (message, worker) =>
  message.tier === "full"
    ? {
        ...servedByTheWebAssembly(message, worker),
        passed: false,
        components: [part("bip39-words", "failed", "case 3 of 24 differs")],
      }
    : servedByTheWebAssembly(message, worker);
assert.equal((await fullyBroken.fullCheck()).passed, false);
StandInWorker.serveCheck = servedByTheWebAssembly;
await assert.rejects(fullyBroken.repairWords({ container: "c", count: 4 }), {
  code: "SELF_CHECK_FAILED",
  message:
    "The self-test failed: BIP39 words: case 3 of 24 differs. Do not use this program on this computer",
});

// A worker that fails gives no report and closes nothing: the next call checks again.
const retried = new MhfeRepair({ workerSource: "repair worker", wasm: ownWasm() });
StandInWorker.serveCheck = (message, worker) => {
  worker.onerror({ preventDefault: noop, message: "The stand-in worker stopped." });
};
await assert.rejects(retried.repairWords({ container: "c", count: 4 }), {
  code: "WORKER_FAILED",
  message: "The stand-in worker stopped.",
});
StandInWorker.serveCheck = servedByTheWebAssembly;
const retriedCard = retried.repairWords({ container: "c", count: 4 });
worker = await started(({ operation }) => operation === "repairWords");
worker.reply({ type: "result", result: { words: "w" } });
assert.deepEqual(await retriedCard, { words: "w" });
// A worker that never says it is ready is given up after a minute (the timer fires at once here).
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (callback, delay, ...rest) =>
  delay === 60_000
    ? realSetTimeout(callback, 0, ...rest)
    : realSetTimeout(callback, delay, ...rest);
StandInWorker.serveCheck = () => new Promise(noop);
const silent = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
await assert.rejects(silent.startupCheck(), {
  code: "WORKER_FAILED",
  message: "The worker did not start within a minute.",
});
globalThis.setTimeout = realSetTimeout;
// A worker of another build is refused when it says it is ready; nothing is kept either.
StandInWorker.serveCheck = (message, worker) => {
  worker.reply({ type: "ready", buildId: "0123456789abcdef" });
  return servedByTheWebAssembly(message, worker);
};
await assert.rejects(silent.fingerprint({ phrase: PHRASE }), {
  code: "PACKAGE_MISMATCH",
  message:
    "The file runtime/worker.js is of build 0123456789abcdef and runtime/runtime.js of build " +
    `${BUILD_ID}: take every file of the package from one build.`,
});
StandInWorker.serveCheck = servedByTheWebAssembly;
assert.ok((await silent.startupCheck()).passed, "checked again once the parts match");
// A core whose limits are not this client's comes from another build.
StandInWorker.serveCheck = (message, worker) => ({
  ...servedByTheWebAssembly(message, worker),
  parameters: { ...parameters, maxPim: parameters.maxPim + 1 },
});
await assert.rejects(new MhfeClient({ ...sources, wasm: ownWasm() }).startupCheck(), {
  code: "PACKAGE_MISMATCH",
  message:
    "The files core/client.js and runtime/mhfe.wasm have different limits: take every file of " +
    "the package from one build.",
});
StandInWorker.serveCheck = servedByTheWebAssembly;
// A class file of another build than the runtime: the other build of part 3, which differs from
// this one in that file alone.
const { MhfeRepair: OtherBuildRepair } = await import(
  `data:text/javascript;base64,${Buffer.from(
    readOtherBuild("repair/repair.js")
      .toString()
      .replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`),
  ).toString("base64")}`
);
await assert.rejects(new OtherBuildRepair({ workerSource: "w", wasm: ownWasm() }).startupCheck(), {
  code: "PACKAGE_MISMATCH",
  message:
    `The file repair/repair.js is of build ${OTHER_BUILD_ID} and runtime/runtime.js of build ` +
    `${BUILD_ID}: take every file of the package from one build.`,
});
// The worker's own refusals of parts of another build reach the page as sentences that keep the
// paths as the package spells them: the first word is capitalized, never the folder of a path, as
// in "Runtime/mhfe.wasm" (AUD-010).
assert.equal(workerRefusals.length, 8);
for (const { file, build, error } of workerRefusals) {
  StandInWorker.serveCheck = (message, worker) => {
    worker.reply({ type: "error", error });
  };
  await assert.rejects(new MhfeRepair({ workerSource: "w", wasm: ownWasm() }).startupCheck(), {
    code: "PACKAGE_MISMATCH",
    message:
      `The file ${file} is of build ${build} and runtime/worker.js of build ${BUILD_ID}: ` +
      "take every file of the package from one build.",
  });
}
StandInWorker.serveCheck = servedByTheWebAssembly;

// cancel() while an operation waits for the startup check stops it at once and frees the slot.
StandInWorker.serveCheck = () => new Promise(noop);
const checksBeforeCancel = StandInWorker.checks.length;
const waitingClient = new MhfeClient({ ...sources, wasm: ownWasm() });
const waitingDecrypt = waitingClient.decrypt({ container: "c", password: "p" });
await assert.rejects(waitingClient.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
waitingClient.cancel();
await assert.rejects(waitingDecrypt, (error) => error instanceof MhfeCancelledError);
const waitingWallet = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
const waitingDraw = waitingWallet.drawPhrase();
await assert.rejects(waitingWallet.drawPhrase(), { code: "BUSY" });
waitingWallet.cancel();
await assert.rejects(waitingDraw, (error) => error instanceof MhfeCancelledError);
// A cancel() just after the startup check settled, before the operation took over from the wait,
// stops it too: here the check has passed long ago, and the page awaits a refusal in between.
const lateDraw = walletClient.drawPhrase({
  passphrase: "p",
  passphraseRepeat: "p",
  walletCheck: true,
  workers: 1,
});
await assert.rejects(walletClient.drawPhrase(), { code: "BUSY" });
walletClient.cancel();
await assert.rejects(lateDraw, (error) => error instanceof MhfeCancelledError);
const lateDecrypt = client.decrypt({ container: "c", password: "p" });
await assert.rejects(client.decrypt({ container: "c", password: "p" }), { code: "BUSY" });
client.cancel();
await assert.rejects(lateDecrypt, (error) => error instanceof MhfeCancelledError);
// The two checks that were waited for keep running in their workers, unanswered here.
while (StandInWorker.checks.length < checksBeforeCancel + 2) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
StandInWorker.serveCheck = servedByTheWebAssembly;

// The page's encoding of secrets: a TextEncoder that gives other bytes, and a page that lets a
// lone surrogate through, fail it before any worker runs.
checksBefore = StandInWorker.checks.length;
const RealEncoder = globalThis.TextEncoder;
globalThis.TextEncoder = class extends RealEncoder {
  encode(text) {
    return super.encode(text.normalize("NFC"));
  }
};
const otherBytes = new MhfePasswords({ workerSource: "passwords worker", wasm: ownWasm() });
assert.deepEqual(await otherBytes.startupCheck(), {
  passed: false,
  tier: "startup",
  version: null,
  buildId: BUILD_ID,
  components: [
    pagePart("browser-features"),
    pagePart("package-parts"),
    pagePart("page-encoding", "failed", "the page encodes text into other UTF-8 bytes"),
  ],
});
globalThis.TextEncoder = RealEncoder;
await assert.rejects(otherBytes.review({ password: "p" }), { code: "SELF_CHECK_FAILED" });
const realIsWellFormed = String.prototype.isWellFormed;
String.prototype.isWellFormed = () => true;
const acceptsSurrogates = new MhfeWallet({ workerSource: "wallet worker", wasm: ownWasm() });
assert.deepEqual(
  (await acceptsSurrogates.startupCheck()).components[2],
  pagePart("page-encoding", "failed", "a lone surrogate is accepted instead of refused"),
);
String.prototype.isWellFormed = realIsWellFormed;
assert.equal(StandInWorker.checks.length, checksBefore, "no worker ran for a page that failed");

// A browser without WebAssembly, or whose WebAssembly does not compile (as under a
// Content-Security-Policy without 'wasm-unsafe-eval'), gets a report instead of an exception.
const RealWebAssembly = globalThis.WebAssembly;
delete globalThis.WebAssembly;
const noWebAssembly = new MhfeClient({ ...sources, wasm: ownWasm() });
const noWebAssemblyReport = await noWebAssembly.startupCheck();
globalThis.WebAssembly = RealWebAssembly;
assert.deepEqual(
  noWebAssemblyReport.components[0],
  pagePart("browser-features", "failed", "the browser lacks WebAssembly"),
);
assert.equal(noWebAssemblyReport.passed, false);
await assert.rejects(noWebAssembly.readContainer("c"), { code: "SELF_CHECK_FAILED" });
const notCompiling = await new MhfeRepair({
  workerSource: "repair worker",
  wasm: new Uint8Array([0, 97, 115, 109, 9, 0, 0, 0]),
}).startupCheck();
assert.equal(notCompiling.components[0].outcome, "failed");
assert.ok(
  notCompiling.components[0].detail.startsWith(
    "the WebAssembly does not compile here, as when the page's Content-Security-Policy lacks 'wasm-unsafe-eval': ",
  ),
);
assert.equal(StandInWorker.checks.length, checksBefore, "no worker ran for either");

// The full self-check of the core: every part at the full tier, then Argon2 at 64 and 256 MiB with
// each build in turn, each worker ended before the next starts, then the parts not run here.
const NOT_RUN_HERE = [
  {
    id: "published-vectors",
    label: "Published vectors",
    outcome: "notRun",
    detail: "they take minutes and 2 GiB: selfTest() runs them",
  },
  {
    id: "memory-locking",
    label: "Locked memory",
    outcome: "notAvailable",
    detail: "a web page cannot keep its memory out of swap",
  },
  {
    id: "core-dumps",
    label: "Core dumps",
    outcome: "notAvailable",
    detail: "the browser keeps its own crash reports, which a page cannot turn off",
  },
  {
    id: "isolation",
    label: "Isolation",
    outcome: "notAvailable",
    detail: "a web page cannot sandbox itself or prove that it is offline",
  },
  {
    id: "hidden-input",
    label: "Hidden input",
    outcome: "notAvailable",
    detail: "a web page has no terminal whose echo it could read back",
  },
];
const SIZES_SINGLE = {
  id: "argon2-sizes-single-threaded",
  label: "Argon2id at 64 and 256 MiB, single-threaded build",
};
const SIZES_THREADED = {
  id: "argon2-sizes-threaded",
  label: "Argon2id at 64 and 256 MiB, threaded build",
};
for (const fast of [false, true]) {
  if (fast) globalThis.crossOriginIsolated = true;
  checksBefore = StandInWorker.checks.length;
  const fullClient = new MhfeClient({ ...sources, wasm: ownWasm() });
  const progressEvents = [];
  const started = performance.now();
  const fullReport = await fullClient.fullCheck({
    onProgress: ({ id, running, outcome }) =>
      progressEvents.push(running ? `start ${id}` : `end ${id} ${outcome}`),
  });
  console.log(
    `  MhfeClient.fullCheck() in ${fast ? "fast" : "standard"} mode: ${(performance.now() - started).toFixed(0)} ms`,
  );
  const threadedRow = fast
    ? { ...SIZES_THREADED, outcome: "passed" }
    : { ...SIZES_THREADED, outcome: "notRun", detail: "the page is not cross-origin isolated" };
  assert.deepEqual(fullReport, {
    passed: true,
    tier: "full",
    version: VERSION,
    buildId: BUILD_ID,
    components: [
      ...PAGE_PARTS_OF_SECRETS,
      ...CORE_PARTS.map((id) => part(id)),
      { ...SIZES_SINGLE, outcome: "passed" },
      threadedRow,
      ...NOT_RUN_HERE,
    ],
  });
  const ran = [...CORE_PARTS, SIZES_SINGLE.id, ...(fast ? [SIZES_THREADED.id] : [])];
  assert.deepEqual(
    progressEvents,
    ran.flatMap((id) => [`start ${id}`, `end ${id} passed`]),
  );
  const fullChecks = checksFrom(checksBefore);
  assert.deepEqual(firstMessages(fullChecks), [
    { module: "core", operation: "selfCheck", tier: "full", skip: [] },
    { module: "core", operation: "selfCheckArgon2", tier: "full", skip: ["argon2"] },
    ...(fast
      ? [{ module: "core", operation: "selfCheckArgon2", tier: "full", skip: ["argon2"] }]
      : []),
  ]);
  assert.deepEqual(await Promise.all(fullChecks.map((each) => each.script.text())), [
    // On an isolated page the single-threaded build follows the threaded one, for the check to
    // fall back to when the threaded one does not start.
    `${fast ? "threaded source\n;\nsingle-threaded" : "single-threaded"} source\n;\nworker source`,
    "single-threaded source\n;\nworker source",
    ...(fast ? ["threaded source\n;\nworker source"] : []),
  ]);
  for (let index = 1; index < fullChecks.length; index += 1) {
    assert.ok(
      fullChecks[index - 1].terminatedAt < fullChecks[index].createdAt,
      "never two at once",
    );
  }
  assert.equal(fullChecks.at(-1).messages[0].argon2Script === null, !fast);
  delete globalThis.crossOriginIsolated;
}

// An Argon2 build that does not start gave no wrong answer (the worker's side is checked in part
// 2c): the report passes with Argon2 not available, or with a warning where the check fell back to
// the single-threaded build. Such a report is not kept and closes nothing: the next call checks
// again, and an operation goes to its worker and gets its own error.
const ARGON2_NOT_STARTED = {
  notAvailable:
    "Argon2id could not run: the single-threaded Argon2 build did not start: the browser " +
    "refused its memory",
  warning:
    "the threaded Argon2 build did not start: the lane workers did not start; the check ran " +
    "the single-threaded build of the standard mode instead",
};
/** Serves the self-checks, the Argon2 part of the core's as `argon2` when it runs Argon2. */
const servedWithArgon2 = (argon2) => (message, worker) => {
  const report = servedByTheWebAssembly(message, worker);
  if (message.argon2 !== true) return report;
  const components = report.components.map((component) =>
    component.id === "argon2" ? argon2 : component,
  );
  return {
    ...report,
    passed: components.every(({ outcome }) => outcome !== "failed"),
    components,
  };
};
for (const [outcome, detail] of Object.entries(ARGON2_NOT_STARTED)) {
  StandInWorker.serveCheck = servedWithArgon2(part("argon2", outcome, detail));
  checksBefore = StandInWorker.checks.length;
  const unstarted = new MhfeClient({ ...sources, wasm: ownWasm() });
  const first = await unstarted.startupCheck();
  assert.deepEqual(first, {
    passed: true,
    tier: "startup",
    version: VERSION,
    buildId: BUILD_ID,
    components: [
      ...PAGE_PARTS_OF_SECRETS,
      ...CORE_PARTS.map((id) => (id === "argon2" ? part(id, outcome, detail) : part(id))),
    ],
  });
  const again = await unstarted.startupCheck();
  assert.notEqual(again, first, `${outcome}: the report is not kept`);
  assert.deepEqual(again, first);
  assert.deepEqual(
    firstMessages(checksFrom(checksBefore)).map(({ skip }) => skip),
    [[], CORE_PARTS.filter((id) => id !== "argon2")],
    `${outcome}: the second check runs Argon2 alone`,
  );
  const decryption = unstarted.decrypt({ container: "c", password: "p" });
  worker = await started(({ operation }) => operation === "decrypt");
  worker.reply({
    type: "error",
    error: { code: "INTERNAL_ERROR", message: "the browser refused its memory" },
  });
  await assert.rejects(decryption, {
    code: "INTERNAL_ERROR",
    message: "The browser refused its memory",
  });
}
// The threaded build's sizes in the full self-check, when that build does not start.
globalThis.crossOriginIsolated = true;
const threadedSizesNotStarted =
  "Argon2id could not run: the threaded Argon2 build did not start: the lane workers did not start";
StandInWorker.serveCheck = (message, worker) => {
  const report = servedByTheWebAssembly(message, worker);
  const threaded = message.operation === "selfCheckArgon2" && message.argon2Script !== null;
  return threaded
    ? { ...report, components: [part("argon2-sizes", "notAvailable", threadedSizesNotStarted)] }
    : report;
};
const threadedNotStarted = await new MhfeClient({ ...sources, wasm: ownWasm() }).fullCheck();
assert.equal(threadedNotStarted.passed, true);
assert.deepEqual(threadedNotStarted.components.at(-NOT_RUN_HERE.length - 1), {
  ...SIZES_THREADED,
  outcome: "notAvailable",
  detail: threadedSizesNotStarted,
});
delete globalThis.crossOriginIsolated;
// A wrong answer of Argon2 still closes the client for good.
StandInWorker.serveCheck = servedWithArgon2(
  part("argon2", "failed", "the page's Argon2 build gives another tag"),
);
const wrongArgon2 = new MhfeClient({ ...sources, wasm: ownWasm() });
const wrongArgon2Report = await wrongArgon2.startupCheck();
assert.equal(wrongArgon2Report.passed, false);
assert.equal(await wrongArgon2.startupCheck(), wrongArgon2Report, "a failed report is kept");
await assert.rejects(wrongArgon2.readPhrase(PHRASE), (error) => {
  assert.equal(error.code, "SELF_CHECK_FAILED");
  assert.equal(
    error.message,
    "The self-test failed: Argon2id: the page's Argon2 build gives another tag. " +
      "Do not use this program on this computer",
  );
  assert.equal(error.report, wrongArgon2Report);
  return true;
});
StandInWorker.serveCheck = servedByTheWebAssembly;
console.log("The classes check themselves before their first operation and close on a failure.");

// The threaded build keeps its lane workers alive; end the process explicitly.
process.exit(0);
