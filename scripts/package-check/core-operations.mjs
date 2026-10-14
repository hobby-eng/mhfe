// Part 1 of the checks of the browser package (scripts/verify-browser-package.mjs): the core
// module of the package's WebAssembly through the page's Argon2 bridge with each Emscripten build.
// To stay fast, a test wrapper lowers the cost of every round and lets only the known answers of
// the Argon2 build through unchanged; the result must equal the container that the native engine
// gives at the same cost. The rekey's checks are in core-rekey.mjs.
import assert from "node:assert/strict";

import {
  AMBIGUOUS_12_WORDS,
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_CONTAINER,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
  ZERO_24,
} from "../public-test-data.mjs";
import { checkRekey } from "./core-rekey.mjs";
import { expectCode, expectMessage, fieldsOf, noRoundExpected, sorted } from "./expect.mjs";
import {
  VERSION,
  argon2Engine,
  bindings,
  builds,
  coreMemory,
  operations,
  parameters,
  read,
} from "./package.mjs";
import {
  CHECKED_PHRASE,
  KNOWN_ANSWER_COSTS,
  NEW_PASSWORD,
  NOT_BOOLEAN_ANSWERS,
  PASSPHRASE_ANSWER_NOT_BOOLEAN,
  PASSWORD,
  PHRASE_ADDRESS,
  PHRASE_FINGERPRINT,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  SEARCH_PASSPHRASE_WITHOUT_REFERENCE,
  SUITE_3,
  SUITE_4,
  argon2KeyFault,
  encode,
  noBytes,
} from "./test-values.mjs";

/** The core module's bindings: the bindings of the package's one WebAssembly. */
const core = bindings;

/** The core's facts, and the copies that the page's runtime and the worker cannot avoid. */
export function checkPackageFacts() {
  assert.equal(parameters.version, VERSION);
  assert.equal(core.packageVersion(), VERSION);
  assert.equal(parameters.apiVersion, undefined, "the release version replaced the API counter");
  assert.equal(parameters.suiteId, SUITE_3);
  assert.equal(parameters.sameLengthSuiteId, SUITE_4);
  assert.equal(parameters.highestBrowserMemoryLevel, 0);
  assert.deepEqual(parameters.wordCounts, [12, 15, 18, 21, 24]);
  assert.deepEqual(parameters.repairWordCounts, [2, 4, 6, 8]);
  assert.deepEqual(parameters.repairCapacities[1], { count: 4, unreadable: 4, wrong: 2 });
  // The page's runtime and the worker keep two copies that a worker script, which imports nothing,
  // cannot avoid: the fields that hold secrets, and the advice of PACKAGE_MISMATCH.
  {
    const source = (file) => read(`web/${file}`).toString();
    const owners = (text) =>
      text
        .split("// SECRET_OWNERS_BEGIN\n")[1]
        .split("// SECRET_OWNERS_END")[0]
        .replaceAll("export class ", "class ");
    assert.equal(
      owners(source("runtime.js")),
      owners(source("worker-runtime.js")),
      "the page and the worker use the same secret owners",
    );
    const advice = ": take every file of the package from one build.";
    for (const file of ["runtime.js", "worker-runtime.js"]) {
      assert.ok(source(file).includes(advice), `${file} gives the advice of PACKAGE_MISMATCH`);
    }
    // The news the page passes to its handlers is the news the worker scripts post, so that no
    // other message name reaches a handler (AUD-015-SEC007).
    const news = JSON.parse(/const WORKER_NEWS = (\[[^\]]*\])/u.exec(source("runtime.js"))[1]);
    const workers = [
      "worker-runtime.js",
      "core-worker.js",
      "repair-worker.js",
      "passwords-worker.js",
      "wallet-worker.js",
    ]
      .map(source)
      .join("\n");
    const posted = new Set([
      ...[...workers.matchAll(/postMessage\(\{ type: "(\w+)"/gu)].map((match) => match[1]),
      ...[...workers.matchAll(/host\.post\("(\w+)"/gu)].map((match) => match[1]),
    ]);
    for (const own of ["ready", "result", "error", "ask"]) posted.delete(own);
    assert.deepEqual(sorted(posted), sorted(news), "the page knows the news workers post");
  }
  assert.ok(
    parameters.hiddenWalletRefusals.includes("PASSWORD_ALREADY_USED") &&
      parameters.hiddenWalletRefusals.includes("HIDDEN_WALLET_PASSES_CHECK"),
    "the core names the refusals that keep a session of hidden wallets open",
  );
}

/**
 * The core's checks through the Argon2 build `name`, whose instances `createModule` starts, at the
 * reduced cost.
 */
export async function checkCoreThroughBuild(name, createModule) {
  const run = reducedRun(argon2Engine(await createModule()));
  run.created = checkEncrypt(run, name);
  checkDecrypt(run);
  checkCheck(run);
  checkSearchCandidates();
  checkSearchWallet(run);
  checkWalletReferences(run);
  checkRefusalsBeforeArgon2(run);
  checkDescriptions(run);
  checkCancelAndSameLength(run);
  checkPasswordRepair(run);
  checkRekey(run);
  checkHiddenWallets(run);
  checkReducedSelfTest(run);
  console.log(`The ${name} build gives the native container and passes the core's checks.`);
}

/**
 * What the checks through one Argon2 build share: `reduced`, the engine at the reduced cost, which
 * lets the known answers through unchanged; `derives`, what reached the engine, in order ("known
 * answer" or "round"); `steps`, what `onRound` was told; and `created`, the container of PHRASE
 * once encrypted.
 */
function reducedRun(engine) {
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
  return { reduced, derives, steps, onRound, created: undefined };
}

/** An encryption at the reduced cost: the native container, its rounds and what to keep. */
function checkEncrypt({ reduced, derives, steps, onRound }, name) {
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
    { item: "repairWords", apart: true },
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
    { item: "repairWords", apart: true },
  ]);
  // Without an answer, undefined or null, what to keep names any passphrase of the wallet in its
  // place: a page need not ask.
  for (const value of [undefined, null]) {
    const unknown = operations.encrypt(PHRASE, PASSWORD, reduced, {
      repairWordCount: 2,
      walletHasPassphrase: value,
    });
    assert.equal(unknown.container, REDUCED_COST_CONTAINER);
    assert.deepEqual(
      unknown.keep,
      [
        { item: "containerWords", words: 24 },
        { item: "password" },
        { item: "passphraseIfAny" },
        { item: "repairWords", apart: true },
      ],
      `encrypt with walletHasPassphrase ${value} names any passphrase of the wallet`,
    );
  }
  // An answer given is a boolean and nothing else, refused before any Argon2 round: no other value
  // is read as a truth value.
  for (const value of NOT_BOOLEAN_ANSWERS) {
    expectMessage(PASSPHRASE_ANSWER_NOT_BOOLEAN, () =>
      operations.encrypt(PHRASE, PASSWORD, reduced, { walletHasPassphrase: value, onRound }),
    );
  }
  assert.deepEqual(steps, [], "encrypt refuses an answer that is not a boolean before Argon2");
  return created;
}

/** A recovery: the phrase, the length rules and the wallet check of every 24-word reading. */
function checkDecrypt({ reduced, steps, onRound, created }) {
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
        walletCheck: null,
        statedWords: null,
        otherLengths: [],
      },
    ],
  });
  // The length rules of recovery (AUD-015-FUN001): a check that passes takes precedence over a
  // stated length, which the reading names; 24 stated words give both readings, the checked one
  // first; a stated short length that no check passes is refused.
  const statedOther = operations.decrypt(created.container, PASSWORD, reduced, { words: 15 });
  assert.deepEqual(
    [statedOther.kind, statedOther.candidates[0].words, statedOther.candidates[0].statedWords],
    ["phrase", 12, 15],
  );
  assert.equal(statedOther.candidates[0].phrase, PHRASE);
  const stated24 = operations.decrypt(created.container, PASSWORD, reduced, { words: 24 });
  assert.deepEqual(
    stated24.candidates.map(({ words, verified, statedWords }) => [words, verified, statedWords]),
    [
      [12, true, 24],
      [24, false, null],
    ],
  );
  assert.equal(stated24.kind, "ambiguous");
  expectMessage(
    "VERIFIER_MISMATCH: the recovered phrase passes no built-in check: the password, PIM, " +
      "memory level or container is probably wrong, or the original seed phrase has 24 words",
    () => operations.decrypt(created.container, encode("wrong"), reduced, { words: 12 }),
  );
  const wrong = operations.decrypt(created.container, encode("wrong"), reduced);
  assert.deepEqual(
    [wrong.candidates[0].words, wrong.candidates[0].status],
    [24, "readAs24"],
    "a wrong password reads as 24 words, not verified",
  );
  assert.equal(typeof wrong.candidates[0].walletCheck, "boolean");
  // Every 24-word reading gets the 16-bit source check with the passphrase given, or none: the
  // published wallet-check phrase ("abandon" 21 times, "above proof fatigue") passes with
  // "TREZOR" and fails without a passphrase.
  const checkedContainer = operations.encrypt(CHECKED_PHRASE, PASSWORD, reduced).container;
  const readWith = (passphrase) =>
    operations.decrypt(checkedContainer, PASSWORD, reduced, { passphrase }).candidates[0];
  assert.deepEqual(
    [readWith("TREZOR").words, readWith("TREZOR").walletCheck, readWith("").walletCheck],
    [24, true, false],
  );
}

/** The worker's check of a container against the words, a fingerprint or an address. */
function checkCheck({ reduced, steps, onRound, created }) {
  steps.length = 0;
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "words", "12", { onRound }).outcome,
    "matches",
  );
  assert.deepEqual(steps.slice(-2), ["recover 12/12", "compare 12/12"]);
  // A check at a stated length that the built-in check contradicts matches at the length found,
  // which the evidence names (AUD-015-FUN001).
  const checkedOther = operations.check(created.container, PASSWORD, reduced, "words", "15");
  assert.deepEqual([checkedOther.outcome, checkedOther.evidence.builtInCheck], ["matches", 12]);
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT)
      .outcome,
    "matches",
  );
  assert.deepEqual(
    operations.check(created.container, PASSWORD, reduced, "address", PHRASE_ADDRESS, {
      coin: "bitcoin",
    }),
    {
      outcome: "matches",
      path: "m/84'/0'/0'/0/0",
      evidence: {
        builtInCheck: 12,
        matchingLengths: [12],
        passed: [{ check: "builtInCheck", words: 12 }],
        walletCheck: null,
      },
    },
  );
  // The length detected: the 12-word original passes its own checks, and one recovery is
  // compared again, as a page that asks for the length when detection finds none compares it.
  assert.deepEqual(operations.check(created.container, PASSWORD, reduced, "words", "0"), {
    outcome: "matches",
    path: null,
    evidence: {
      builtInCheck: 12,
      matchingLengths: [12],
      passed: [{ check: "builtInCheck", words: 12 }],
      walletCheck: null,
    },
  });
  const checkSession = new core.CheckSession(
    created.container,
    PASSWORD,
    "",
    0,
    0,
    0,
    "words",
    "0",
    "",
    "",
    noBytes(),
    reduced,
    () => {},
  );
  // A stated length the built-in check contradicts matches at the length found (AUD-015-FUN001);
  // a fingerprint of another wallet does not.
  const atFifteen = JSON.parse(checkSession.compare("words", "15", "", "", noBytes()));
  assert.deepEqual([atFifteen.outcome, atFifteen.evidence.builtInCheck], ["matches", 12]);
  assert.equal(
    JSON.parse(checkSession.compare("fingerprint", "00000000", "", "", noBytes())).outcome,
    "doesNotMatch",
  );
  assert.equal(
    JSON.parse(checkSession.compare("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes())).outcome,
    "matches",
    "a recovery is compared again without its rounds",
  );
  checkSession.free();

  const unverified = operations.encrypt(ZERO_24, PASSWORD, reduced).container;
  const afterDetection = new core.CheckSession(
    unverified,
    PASSWORD,
    "",
    0,
    0,
    0,
    "words",
    "0",
    "",
    "",
    noBytes(),
    reduced,
    () => {},
  );
  try {
    assert.equal(
      JSON.parse(afterDetection.compare("words", "0", "", "", noBytes())).outcome,
      "notVerified",
    );
    assert.equal(afterDetection.asksLength(), true, "the library requests the follow-up");
    for (const [kind, reference, passphrase] of [
      ["words", "0", noBytes()],
      ["walletCheck", "", encode("TREZOR")],
    ]) {
      expectMessage(
        "INVALID_REQUEST: invalid request: a follow-up after detection needs a stated short length, an address or a fingerprint",
        () => afterDetection.compare(kind, reference, "", "", passphrase),
      );
    }
    for (const words of [12, 15, 18, 21]) {
      assert.equal(
        JSON.parse(afterDetection.compare("words", String(words), "", "", noBytes())).outcome,
        "doesNotMatch",
      );
    }
    assert.equal(
      JSON.parse(afterDetection.compare("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes()))
        .outcome,
      "doesNotMatch",
    );
    assert.equal(
      JSON.parse(
        afterDetection.compare("address", PHRASE_ADDRESS, "bitcoin", "m/84'/0'/0'/0/0", noBytes()),
      ).outcome,
      "doesNotMatch",
    );
  } finally {
    afterDetection.free();
  }
}

/** The reduced-cost container of PHRASE with its last word missing, for the searches. */
const MISSING_LAST = REDUCED_COST_CONTAINER.split(" ")
  .map((word, index) => (index === 23 ? "?" : word))
  .join(" ");

/** The candidates of a search for missing words, and the decoy wallet's search without Argon2. */
function checkSearchCandidates() {
  assert.deepEqual(JSON.parse(core.searchCandidates(MISSING_LAST)), {
    missing: [24],
    candidates: 8,
    offersWalletSearch: true,
    offersOwnChecks: true,
  });
  // Two missing words leave only the decoy search; a same-length container has no own checks.
  const twoMarked = MISSING_LAST.replace(/^\w+/u, "?");
  assert.deepEqual(
    fieldsOf(JSON.parse(core.searchCandidates(twoMarked)), ["missing", "offersWalletSearch"]),
    { missing: [1, 24], offersWalletSearch: false },
  );
  assert.equal(JSON.parse(core.searchCandidates(twoMarked)).offersOwnChecks, false);
  const sameLengthMissing = REDUCED_COST_SAME_LENGTH_CONTAINER.replace(/\w+$/u, "?");
  assert.deepEqual(
    fieldsOf(JSON.parse(core.searchCandidates(sameLengthMissing)), [
      "offersWalletSearch",
      "offersOwnChecks",
    ]),
    { offersWalletSearch: true, offersOwnChecks: false },
  );
  const decoyFingerprint = core.walletFingerprint(encode(REDUCED_COST_CONTAINER), noBytes());
  const decoyFound = JSON.parse(
    core.searchDecoy(
      MISSING_LAST,
      "fingerprint",
      decoyFingerprint,
      "",
      "",
      noBytes(),
      20,
      () => {},
    ),
  );
  assert.equal(decoyFound.container, REDUCED_COST_CONTAINER);
  assert.deepEqual(decoyFound.words, [{ position: 24, word: "sweet" }]);
  const decoyMissed = JSON.parse(
    core.searchDecoy(MISSING_LAST, "fingerprint", "00000000", "", "", noBytes(), 20, () => {}),
  );
  assert.deepEqual([decoyMissed.found, decoyMissed.container], [false, null]);
}

/** The search of the owner's wallet, each candidate recovered at the reduced cost. */
function checkSearchWallet({ reduced }) {
  // The owner's fingerprint, and the original seed phrase's own checks without and with its
  // passphrase: a 12-word phrase passes its built-in check either way.
  for (const [kind, reference, passphrase] of [
    ["fingerprint", PHRASE_FINGERPRINT, ""],
    ["builtInCheck", "", ""],
    ["walletCheck", "", "TREZOR"],
  ]) {
    const seen = [];
    const searched = JSON.parse(
      core.searchWallet(
        MISSING_LAST,
        PASSWORD,
        "",
        0,
        0,
        0,
        kind,
        reference,
        "",
        "",
        encode(passphrase),
        reduced,
        (candidate, candidates) => seen.push(`${candidate}/${candidates}`),
        () => {},
      ),
    );
    assert.equal(searched.container, REDUCED_COST_CONTAINER, `searchWallet with ${kind}`);
    assert.equal(seen[0], "1/8", `searchWallet with ${kind} tells each candidate`);
  }
  const twoMissing = MISSING_LAST.replace(/^\S+/, "?");
  expectCode("TOO_MANY_MISSING_WORDS", () =>
    core.searchWallet(
      twoMissing,
      PASSWORD,
      "",
      0,
      0,
      0,
      "fingerprint",
      PHRASE_FINGERPRINT,
      "",
      "",
      noBytes(),
      reduced,
      () => {},
      () => {},
    ),
  );
  // The built-in check compares no passphrase: one given is refused, not dropped (AUD-023-API001).
  expectMessage(SEARCH_PASSPHRASE_WITHOUT_REFERENCE, () =>
    core.searchWallet(
      MISSING_LAST,
      PASSWORD,
      "",
      0,
      0,
      0,
      "builtInCheck",
      "",
      "",
      "",
      encode("TREZOR"),
      reduced,
      () => {},
      () => {},
    ),
  );
  expectCode("INVALID_REQUEST", () => core.searchCandidates(REDUCED_COST_CONTAINER));
}

/** The other references of a check: an Ethereum address, a passphrase, a coin, the wallet check. */
function checkWalletReferences({ reduced, created }) {
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
    {
      outcome: "matches",
      path: "m/44'/60'/0'/0/0",
      evidence: {
        builtInCheck: 12,
        matchingLengths: [12],
        passed: [{ check: "builtInCheck", words: 12 }],
        walletCheck: null,
      },
    },
  );
  assert.equal(
    operations.check(created.container, PASSWORD, reduced, "fingerprint", PHRASE_FINGERPRINT, {
      passphrase: encode("TREZOR"),
    }).outcome,
    "doesNotMatch",
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
}

/** Refusals before any Argon2 call, and a refused password that leaves no passphrase behind. */
function checkRefusalsBeforeArgon2({ reduced, created }) {
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
}

/** What a container and a phrase are, as typed, and the password's own rules. */
function checkDescriptions({ created }) {
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
  // With the length detected, the wallet or its owner confirms a rekey, whatever length is found:
  // a 24-word original may pass a short check by chance (AUD-017-FUN001).
  assert.equal(facts.confirmationFor["0"], "walletOrOwner");
  assert.equal(facts.hiddenWallets, true);
  assert.equal(facts.offersWalletCheck, true);
  const phraseFacts = JSON.parse(
    core.describePhrase(encode(PHRASE.toUpperCase().replaceAll(" ", "\t"))),
  );
  assert.equal(phraseFacts.phrase, PHRASE);
  assert.deepEqual(phraseFacts.otherLengths, []);
  assert.deepEqual(phraseFacts.containers, [
    { sameLength: false, words: 24, wrongWordPassesOneIn: 256, otherLengths: [] },
    { sameLength: true, words: 12, wrongWordPassesOneIn: 16, otherLengths: [] },
  ]);
  // A public 12-word phrase whose packed state also passes the 21-word check (src/packing.rs):
  // a 24-word container of it can be misread, a same-length one cannot, as the command-line tool
  // warns only for the first.
  const ambiguous = JSON.parse(core.describePhrase(encode(AMBIGUOUS_12_WORDS)));
  assert.deepEqual(ambiguous.otherLengths, [21]);
  assert.deepEqual(
    ambiguous.containers.map((choice) => choice.otherLengths),
    [[21], []],
  );
  expectCode("UNASSIGNED_CHARACTER", () => core.checkPassword(encode("a͸")));
  expectCode("INVALID_PASSWORD_UTF8", () => core.checkPassword(new Uint8Array([0xff])));
  expectCode("CONTROL_CHARACTER_IN_PASSWORD", () => core.checkPassword(encode("first\r\nsecond")));
}

/** A progress callback that cancels, and a container of the phrase's own length. */
function checkCancelAndSameLength({ reduced }) {
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
}

/** A password with a check word, typed with one word forgotten, repaired before Argon2. */
function checkPasswordRepair({ reduced }) {
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
}

/** Hidden wallets: each password opens its own wallet, none twice. */
function checkHiddenWallets({ reduced, derives, created }) {
  // The session's start and each wallet run the build's known answer, a wallet before and after
  // its rounds.
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
    "NO_HIDDEN_WALLETS",
    () =>
      new core.HiddenWalletSession(REDUCED_COST_SAME_LENGTH_CONTAINER, 0, 0, noBytes(), reduced),
  );
}

/** The self-test at the reduced cost, where the first round already differs. */
function checkReducedSelfTest({ reduced, steps, onRound }) {
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
}

/** One full-size encryption with the threaded build, 2 GiB, when --full asks for it. */
export async function checkFullSizeEncryption() {
  const engine = argon2Engine(await builds.threaded());
  const created = operations.encrypt(PHRASE, PASSWORD, engine);
  assert.equal(created.container, FULL_SIZE_CONTAINER);
  console.log("A full-size encryption with the threaded build gives the native container.");
}
