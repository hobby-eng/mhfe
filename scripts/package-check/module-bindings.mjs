// Part 2 of the checks of the browser package (scripts/verify-browser-package.mjs): the repair,
// passwords and wallet modules of the package's WebAssembly with public vectors, the refusals the
// classes give early in the library's words, and the probe of the page's random source.
import assert from "node:assert/strict";

import { FULL_SIZE_CONTAINER, PHRASE } from "../public-test-data.mjs";
import { expectCode, expectMessage, fieldsOf } from "./expect.mjs";
import {
  VERSION,
  argon2Engine,
  bindings,
  builds,
  drawWithoutWishes,
  noop,
  operations,
  testRandom,
} from "./package.mjs";
import {
  CHECKED_PHRASE,
  CHECK_WORD_TAKES_NO_COUNT,
  KNOWN_ANSWER_COSTS,
  PHRASE_ADDRESS,
  PHRASE_FINGERPRINT,
  PHRASE_TREZOR_FINGERPRINT,
  encode,
  noBytes,
} from "./test-values.mjs";

// Each module's bindings are the bindings of the package's one WebAssembly.
const core = bindings;
const repair = bindings;
const passwords = bindings;
const wallet = bindings;

/** The repair module: a card of repair words, a repaired container and what a typed one is. */
export function checkRepairModule() {
  assert.equal(JSON.parse(repair.repairParameters()).version, VERSION);
  assert.equal(repair.packageVersion(), VERSION);
  // Vectors of an independent implementation (src/repair.rs).
  assert.deepEqual(JSON.parse(repair.repairWords(FULL_SIZE_CONTAINER, 4)), {
    profile: "MHFE-REPAIR-1",
    words: "shaft pupil patient jewel",
    repairsUnreadable: 4,
    repairsWrong: 2,
  });
  const damagedWords = FULL_SIZE_CONTAINER.split(" ");
  damagedWords[2] = "?";
  damagedWords[16] = "?";
  const repairedContainer = JSON.parse(
    repair.repairContainer(damagedWords.join(" "), "shaft pupil patient jewel"),
  );
  assert.equal(repairedContainer.container, FULL_SIZE_CONTAINER);
  assert.deepEqual(repairedContainer.containerWords, [3, 17]);
  assert.equal(repairedContainer.unchanged, false);
  assert.equal(repairedContainer.changes[0].read, null);
  expectCode("INVALID_REPAIR_WORDS", () => repair.repairWords(FULL_SIZE_CONTAINER, 3));
  // What a container phrase as typed is: each kind, from the same words.
  const inspected = (words) => JSON.parse(repair.inspectContainer(words));
  assert.deepEqual(inspected(FULL_SIZE_CONTAINER), {
    reading: "container",
    wordCount: 24,
    unreadable: [],
  });
  assert.deepEqual(inspected(damagedWords.join(" ")), {
    reading: "marked",
    wordCount: 24,
    unreadable: [3, 17],
  });
  const typo = FULL_SIZE_CONTAINER.split(" ");
  typo[8] = "towr";
  assert.deepEqual(inspected(typo.join(" ")), {
    reading: "notAContainer",
    wordCount: 24,
    unreadable: [],
  });
  assert.deepEqual(inspected(damagedWords.slice(1).join(" ")), {
    reading: "wrongLength",
    wordCount: 23,
    unreadable: [],
  });
  console.log("The repair module passes its checks.");
}

/** The passwords module: the specification's vector, its refusals and the passwords it makes. */
export function checkPasswordsModule() {
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
  // Without a count, as many words or characters as the command-line tool makes.
  assert.equal(
    JSON.parse(passwords.makePassword("words", undefined, noBytes(), testRandom)).password.split(
      " ",
    ).length,
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
  // that asked for seven words never gets five instead. Five, the count it makes, is refused too,
  // and so is a count with dice.
  for (const { count, rolls } of [
    { count: 7, rolls: noBytes() },
    { count: 5, rolls: noBytes() },
    { count: 5, rolls: encode("11111 11112 11113 11114 11115") },
  ]) {
    expectMessage(
      `INVALID_REQUEST: invalid request: ${CHECK_WORD_TAKES_NO_COUNT}`,
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
}

/** The wallet module: fingerprints, the wallet check, draws, chosen words and word hints. */
export function checkWalletModule() {
  checkWalletFacts();
  checkWordWishes();
  checkWordHints();
  console.log("The wallet module passes its checks.");
}

/** The wallet's facts, fingerprints, wallet check, address search and draws without wishes. */
function checkWalletFacts() {
  const walletFacts = JSON.parse(wallet.walletParameters());
  assert.equal(walletFacts.coins.length, 12);
  // The owner's limits of chosen words (src/word_wishes.rs).
  assert.deepEqual(
    fieldsOf(walletFacts, ["maxChosenWords", "maxNeverUseWords", "recommendedRandomBits"]),
    { maxChosenWords: 1, maxNeverUseWords: 1, recommendedRandomBits: 240 },
  );
  assert.equal(wallet.walletFingerprint(encode(PHRASE), noBytes()), PHRASE_FINGERPRINT);
  assert.equal(
    wallet.walletFingerprint(encode(PHRASE), encode("TREZOR")),
    PHRASE_TREZOR_FINGERPRINT,
  );
  // "abandon" 21 times and "above proof fatigue" passes the wallet check with "TREZOR"
  // (TREZOR_COUNTER in src/wallet_check.rs).
  assert.equal(wallet.walletCheck(encode(CHECKED_PHRASE), encode("TREZOR")), true);
  assert.equal(wallet.walletCheck(encode(CHECKED_PHRASE), encode("trezor")), false);
  expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
    wallet.walletCheck(encode(CHECKED_PHRASE), noBytes()),
  );
  expectCode("INVALID_WORD_COUNT", () => wallet.walletCheck(encode(PHRASE), encode("TREZOR")));
  const search = JSON.parse(wallet.describeAddress(PHRASE_ADDRESS, "bitcoin", "", 0));
  assert.equal(search.onlyPath, false);
  assert.equal(search.addresses, 2000);
  // A scan gap states the decoy search of two missing words: the first account, 20 of each chain.
  assert.equal(JSON.parse(wallet.describeAddress(PHRASE_ADDRESS, "bitcoin", "", 20)).addresses, 40);
  const drawn = JSON.parse(drawWithoutWishes(wallet, noBytes(), noBytes(), false, testRandom));
  assert.equal(drawn.words, 24);
  assert.equal(drawn.walletCheck, false);
  expectCode("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
    drawWithoutWishes(wallet, noBytes(), noBytes(), true, testRandom),
  );
  expectCode("RANDOM_FAILED", () =>
    drawWithoutWishes(wallet, noBytes(), noBytes(), false, { fill: () => {} }),
  );
  // A passphrase is typed twice, and the binding compares the two, whatever the page did before.
  expectCode("PASSPHRASES_DIFFER", () =>
    drawWithoutWishes(wallet, encode("TREZOR"), encode("trezor"), false, testRandom),
  );
  const drawnWithPassphrase = JSON.parse(
    drawWithoutWishes(wallet, encode("TREZOR"), encode("TREZOR"), false, testRandom),
  );
  assert.equal(drawnWithPassphrase.walletCheck, false);
}

/** What a chosen word costs before the draw, and a draw that meets it. */
function checkWordWishes() {
  // A chosen word: what it costs before the draw, as the library rates it (src/word_wishes.rs), and
  // a draw that meets it. One chosen word and one word never to use at most; a word at a fixed
  // position, a word never to use and the wallet check keep 228.98 bits, the least they can keep.
  // Each word after a line break of its own, as the class sends them (AUD-024-API009).
  const entries = (list) => list.map((word) => `\n${word}`).join("");
  const describeDraw = (words, places, neverUse, walletCheck) =>
    JSON.parse(
      wallet.describeDraw(
        encode(entries(words)),
        Float64Array.from(places),
        entries(neverUse),
        walletCheck,
      ),
    );
  assert.deepEqual(describeDraw([], [], [], false), {
    randomBits: 256,
    randomness: "full",
    expectedDraws: 1,
    recognisable: false,
    fixedPosition: false,
  });
  assert.deepEqual(describeDraw([], [], [], true), {
    randomBits: 240,
    randomness: "ample",
    expectedDraws: 65536,
    recognisable: false,
    fixedPosition: false,
  });
  // A word never to use with the check is rated as the check alone (AUD-015-UI003).
  const neverUseChecked = describeDraw([], [], ["abandon"], true);
  assert.equal(neverUseChecked.randomness, "ample");
  assert.ok(neverUseChecked.randomBits > 239.98 && neverUseChecked.randomBits < 239.99);
  assert.equal(describeDraw(["happy"], [0], [], true).fixedPosition, false);
  // A chosen word makes the phrase recognisable to someone who learns or guesses it; a word never
  // to use alone does not.
  const worst = describeDraw(["happy"], [1], ["abandon"], true);
  assert.equal(worst.randomness, "notRecommended");
  assert.equal(worst.recognisable, true);
  assert.equal(worst.fixedPosition, true);
  assert.ok(worst.randomBits > 228.98 && worst.randomBits < 228.99, `${worst.randomBits}`);
  assert.equal(describeDraw([], [], ["abandon"], false).recognisable, false);
  assert.equal(describeDraw(["zoo"], [24], [], false).expectedDraws, 256);
  expectMessage(
    "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: the chosen word is not an " +
      "English BIP39 word",
    () => describeDraw(["notaword"], [1], [], false),
  );
  expectMessage(
    "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: choose at most 1 word",
    () => describeDraw(["happy", "zoo"], [1, 2], [], false),
  );
  expectMessage(
    "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: name at most 1 word never " +
      "to use",
    () => describeDraw([], [], ["abandon", "zoo"], false),
  );
  expectCode("INVALID_WORD_WISH", () => describeDraw(["happy"], [25], [], false));
  expectCode("INVALID_REQUEST", () => describeDraw(["happy", "zoo"], [1], [], false));
  // An empty or blank entry stays an entry, which the library refuses (AUD-024-API009); a place
  // that is not a whole number from 0, and a walletCheck that is not a boolean, are refused, not
  // converted (AUD-024-API022).
  for (const [words, places, neverUse] of [
    [[""], [1], []],
    [[" "], [0], []],
    [[], [], ["", "abandon"]],
    [["happy"], [Number.NaN], []],
    [["happy"], [1.5], []],
    [["happy"], [2 ** 32], []],
  ]) {
    expectCode("INVALID_WORD_WISH", () => describeDraw(words, places, neverUse, false));
  }
  for (const walletCheck of ["true", 1, undefined]) {
    expectCode("INVALID_REQUEST", () => describeDraw([], [], [], walletCheck));
  }
  /** A phrase drawn without a passphrase that meets `words` at `places` and avoids `neverUse`. */
  const drawnWith = (words, places, neverUse) =>
    JSON.parse(
      wallet.drawPhrase(
        noBytes(),
        noBytes(),
        encode(entries(words)),
        Float64Array.from(places),
        entries(neverUse),
        false,
        testRandom,
        noop,
      ),
    ).phrase.split(" ");
  const atTheEnd = drawnWith(["ZOO"], [24], ["abandon"]);
  assert.equal(atTheEnd.length, 24);
  assert.equal(atTheEnd[23], "zoo", "a chosen word at its position");
  assert.ok(!atTheEnd.includes("abandon"), "no word never to use");
  assert.ok(drawnWith(["happ"], [0], []).includes("happy"), "a chosen word anywhere");
}

/** The hints below a line of words being typed. */
function checkWordHints() {
  // The hints below a line of words being typed (src/word_hints.rs), from either list, as the
  // command-line tool shows them.
  const hintsOf = (list, typed) => JSON.parse(wallet.wordHints(list, encode(typed)));
  assert.deepEqual(hintsOf("bip39", "abandon z"), {
    hint: "count",
    count: 4,
    words: [],
    completion: { letters: "", wordEnds: false },
  });
  assert.deepEqual(hintsOf("bip39", "abandon ZO"), {
    hint: "words",
    count: 2,
    words: ["zone", "zoo"],
    completion: { letters: "", wordEnds: false },
  });
  assert.deepEqual(hintsOf("bip39", "abou").completion, { letters: "t", wordEnds: true });
  assert.equal(hintsOf("bip39", "xq").hint, "noWord");
  assert.equal(hintsOf("bip39", "zoo").hint, "nothing");
  // A run of letters longer than any list word still begins no word (AUD-015-UI004).
  assert.equal(hintsOf("eff", "zookeepers").hint, "noWord");
  assert.equal(hintsOf("bip39", "toolongforanyword").hint, "noWord");
  assert.equal(hintsOf("eff", "y").count, 27);
  assert.deepEqual(hintsOf("eff", "yo-").words, ["yo-yo"]);
  expectCode("INVALID_REQUEST", () => wallet.wordHints("BIP39", encode("ab")));
  expectCode("INVALID_REQUEST", () => wallet.wordHints("bip39", new Uint8Array([0xff])));
}

/**
 * The message a page reads for a refusal of the WebAssembly: its text after the code, begun with a
 * capital letter as sentence() in web/runtime.js writes it.
 */
export function pageMessageOf(code, action, description = code) {
  let message = "";
  assert.throws(
    action,
    (error) => {
      message = error.message;
      return message.startsWith(`${code}: `);
    },
    description,
  );
  const text = message.slice(code.length + 2);
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** A refusal-test engine: known answers execute, while any cipher round is a failure. */
export async function knownAnswersOnly() {
  /** An Argon2 engine for refusals: the known answer that a call checks first, and no round. */
  const knownAnswerEngine = argon2Engine(await builds["single-threaded"]());
  return {
    derive: (password, salt, memoryKib, passes, key) => {
      if (!KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)) {
        assert.fail("a refusal came after the first round started");
      }
      knownAnswerEngine.derive(password, salt, memoryKib, passes, key);
    },
  };
}

/**
 * The library's refusals that the classes give early, before a secret reaches a worker, with the
 * library's code and in its words, as the command-line tool gives them; part 4 compares the
 * classes' with these.
 */
export async function checkLibraryMessages() {
  checkRekeyRefusalOrder();
  const noArgon2 = await knownAnswersOnly();
  /**
   * The library's refusal, with `code`, of the new settings `newPim` and `newMemoryLevel` of a
   * rekey.
   */
  function newSettingsMessage(code, newPim, newMemoryLevel) {
    return pageMessageOf(code, () => {
      const session = new core.RekeySession(
        FULL_SIZE_CONTAINER,
        0,
        encode("p"),
        "",
        0,
        0,
        0,
        noArgon2,
      );
      try {
        session.setNew(encode("n"), encode("n"), "", 0, newPim, newMemoryLevel, 0);
      } finally {
        session.free();
      }
    });
  }
  const LIBRARY_MESSAGES = {
    MEMORY_LEVEL_NOT_SUPPORTED_HERE: pageMessageOf("MEMORY_LEVEL_NOT_SUPPORTED_HERE", () =>
      operations.encrypt(PHRASE, encode("p"), noArgon2, { memoryLevel: 1 }),
    ),
    WALLET_CHECK_NEEDS_PASSPHRASE: pageMessageOf("WALLET_CHECK_NEEDS_PASSPHRASE", () =>
      drawWithoutWishes(wallet, noBytes(), noBytes(), true, testRandom),
    ),
    PASSPHRASES_DIFFER: pageMessageOf("PASSPHRASES_DIFFER", () =>
      drawWithoutWishes(wallet, encode("p"), encode("q"), true, testRandom),
    ),
    NO_BUILT_IN_CHECK_AT_24: pageMessageOf("INVALID_WORD_COUNT", () =>
      operations.check(FULL_SIZE_CONTAINER, encode("p"), noArgon2, "words", "24"),
    ),
    // The settings, word counts and repair word counts the client refuses before any worker, in the
    // library's words for the same value (AUD-023-UI001).
    INVALID_PIM: pageMessageOf("INVALID_PIM", () =>
      operations.encrypt(PHRASE, encode("p"), noArgon2, { pim: 1024 }),
    ),
    INVALID_MEMORY_LEVEL: pageMessageOf("INVALID_MEMORY_LEVEL", () =>
      operations.encrypt(PHRASE, encode("p"), noArgon2, { memoryLevel: 22 }),
    ),
    INVALID_WORD_COUNT: pageMessageOf("INVALID_WORD_COUNT", () =>
      operations.decrypt(FULL_SIZE_CONTAINER, encode("p"), noArgon2, { words: 13 }),
    ),
    INVALID_REPAIR_WORDS: pageMessageOf("INVALID_REPAIR_WORDS", () =>
      operations.encrypt(PHRASE, encode("p"), noArgon2, { repairWordCount: 3 }),
    ),
    NEW_PIM: newSettingsMessage("INVALID_PIM", 1024, 0),
    NEW_MEMORY_LEVEL: newSettingsMessage("INVALID_MEMORY_LEVEL", 0, 22),
  };
  assert.equal(
    LIBRARY_MESSAGES.INVALID_PIM,
    "The PIM must be a whole number from 0 to 1023, not 1024",
  );
  assert.equal(
    LIBRARY_MESSAGES.NEW_PIM,
    "The new PIM must be a whole number from 0 to 1023, not 1024",
  );
  return LIBRARY_MESSAGES;
}

/** Binding confirmation refusals precede even an Argon2 engine whose known answer would fail. */
function checkRekeyRefusalOrder() {
  let derives = 0;
  const faulty = {
    derive: () => {
      derives += 1;
      throw new Error("the Argon2 known answer failed");
    },
  };
  const session = new core.RekeySession(FULL_SIZE_CONTAINER, 0, encode("p"), "", 0, 0, 0, faulty);
  try {
    session.setNew(encode("n"), encode("n"), "", 0, 0, 0, 0);
    expectCode("REFERENCE_REQUIRED", () =>
      session.recover("builtInCheck", "", "", "", noBytes(), false, noop),
    );
    assert.equal(derives, 0, "confirmation was refused before the engine's known answer");
  } finally {
    session.free();
  }
}

/**
 * Each draw probes the page's source itself, before anything is drawn: two blocks of 32 bytes,
 * which must differ and not be zero (src/random.rs), and the browser's own error is kept.
 */
export function checkRandomSourceProbes() {
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
    () => drawWithoutWishes(wallet, noBytes(), noBytes(), false, refusingSource),
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
}
