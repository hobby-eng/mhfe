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

const passwords = bindings;
assert.equal(JSON.parse(passwords.passwordParameters()).version, VERSION);
// The specification's vector: an erased third word is recovered as chokehold.
const review = JSON.parse(
  passwords.reviewPassword(encode("jovial trailing ? pavilion cresting ninth"), noBytes(), false),
);
assert.equal(review.reading, "restorable");
assert.deepEqual(review.repairs, [{ position: 3, word: "chokehold", typed: null }]);
assert.equal(review.repairsFirst, true);
expectCode(
  "PASSWORDS_DIFFER",
  () => passwords.reviewPassword(encode("jovial"), encode("Jovial"), true),
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
for (
  const [count, rolls] of [
    [7, noBytes()],
    [5, noBytes()],
    [5, encode("11111 11112 11113 11114 11115")],
  ]
) {
  expectMessage(
    "INVALID_REQUEST: invalid request: checkWord takes no count: it always makes five words and "
      + "their check word",
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
expectCode(
  "RANDOM_FAILED",
  () => passwords.makePassword("words", 5, noBytes(), { fill: () => {} }),
);
expectCode(
  "INVALID_PASSWORD_SIZE",
  () => passwords.makePassword("characters", 65, noBytes(), testRandom),
);
console.log("The passwords module passes its checks.");

const wallet = bindings;
/**
 * drawPhrase of the WebAssembly with no chosen words, no places and no words never to use, as a
 * draw without wishes passes them.
 */
const drawWithoutWishes = (instance, passphrase, repeat, walletCheck, random, onDraws = noop) =>
  instance.drawPhrase(
    passphrase,
    repeat,
    noBytes(),
    new Uint32Array(),
    "",
    walletCheck,
    random,
    onDraws,
  );
const walletFacts = JSON.parse(wallet.walletParameters());
assert.equal(walletFacts.coins.length, 12);
// The owner's limits of chosen words (src/word_wishes.rs).
assert.deepEqual(
  fieldsOf(walletFacts, ["maxChosenWords", "maxNeverUseWords", "recommendedRandomBits"]),
  { maxChosenWords: 1, maxNeverUseWords: 1, recommendedRandomBits: 240 },
);
assert.equal(wallet.walletFingerprint(encode(PHRASE), noBytes()), PHRASE_FINGERPRINT);
assert.equal(wallet.walletFingerprint(encode(PHRASE), encode("TREZOR")), PHRASE_TREZOR_FINGERPRINT);
// "abandon" 21 times and "above proof fatigue" passes the wallet check with "TREZOR"
// (TREZOR_COUNTER in src/wallet_check.rs).
const checkedPhrase = `${"abandon ".repeat(21)}above proof fatigue`;
assert.equal(wallet.walletCheck(encode(checkedPhrase), encode("TREZOR")), true);
assert.equal(wallet.walletCheck(encode(checkedPhrase), encode("trezor")), false);
expectCode(
  "WALLET_CHECK_NEEDS_PASSPHRASE",
  () => wallet.walletCheck(encode(checkedPhrase), noBytes()),
);
expectCode("INVALID_WORD_COUNT", () => wallet.walletCheck(encode(PHRASE), encode("TREZOR")));
const search = JSON.parse(wallet.describeAddress(BIP84_ADDRESS, "bitcoin", "", 0));
assert.equal(search.onlyPath, false);
assert.equal(search.addresses, 2000);
// A scan gap states the decoy search of two missing words: the first account, 20 of each chain.
assert.equal(JSON.parse(wallet.describeAddress(BIP84_ADDRESS, "bitcoin", "", 20)).addresses, 40);
const drawn = JSON.parse(drawWithoutWishes(wallet, noBytes(), noBytes(), false, testRandom));
assert.equal(drawn.words, 24);
assert.equal(drawn.walletCheck, false);
expectCode(
  "WALLET_CHECK_NEEDS_PASSPHRASE",
  () => drawWithoutWishes(wallet, noBytes(), noBytes(), true, testRandom),
);
expectCode(
  "RANDOM_FAILED",
  () => drawWithoutWishes(wallet, noBytes(), noBytes(), false, { fill: () => {} }),
);
// A passphrase is typed twice, and the binding compares the two, whatever the page did before.
expectCode(
  "PASSPHRASES_DIFFER",
  () => drawWithoutWishes(wallet, encode("TREZOR"), encode("trezor"), false, testRandom),
);
const drawnWithPassphrase = JSON.parse(
  drawWithoutWishes(wallet, encode("TREZOR"), encode("TREZOR"), false, testRandom),
);
assert.equal(drawnWithPassphrase.walletCheck, false);

// A chosen word: what it costs before the draw, as the library rates it (src/word_wishes.rs), and
// a draw that meets it. One chosen word and one word never to use at most; a word at a fixed
// position, a word never to use and the wallet check keep 228.98 bits, the least they can keep.
const describeDraw = (words, places, neverUse, walletCheck) =>
  JSON.parse(wallet.describeDraw(encode(words), Uint32Array.from(places), neverUse, walletCheck));
assert.deepEqual(describeDraw("", [], "", false), {
  randomBits: 256,
  randomness: "full",
  expectedDraws: 1,
  recognisable: false,
  fixedPosition: false,
});
assert.deepEqual(describeDraw("", [], "", true), {
  randomBits: 240,
  randomness: "ample",
  expectedDraws: 65536,
  recognisable: false,
  fixedPosition: false,
});
// A word never to use with the check is rated as the check alone (AUD-015-UI003).
const neverUseChecked = describeDraw("", [], "abandon", true);
assert.equal(neverUseChecked.randomness, "ample");
assert.ok(neverUseChecked.randomBits > 239.98 && neverUseChecked.randomBits < 239.99);
assert.equal(describeDraw("happy", [0], "", true).fixedPosition, false);
// A chosen word makes the phrase recognisable to someone who learns or guesses it; a word never
// to use alone does not.
const worst = describeDraw("happy", [1], "abandon", true);
assert.equal(worst.randomness, "notRecommended");
assert.equal(worst.recognisable, true);
assert.equal(worst.fixedPosition, true);
assert.ok(worst.randomBits > 228.98 && worst.randomBits < 228.99, `${worst.randomBits}`);
assert.equal(describeDraw("", [], "abandon", false).recognisable, false);
assert.equal(describeDraw("zoo", [24], "", false).expectedDraws, 256);
expectMessage(
  "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: the chosen word is not an "
    + "English BIP39 word",
  () => describeDraw("notaword", [1], "", false),
);
expectMessage(
  "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: choose at most 1 word",
  () => describeDraw("happy zoo", [1, 2], "", false),
);
expectMessage(
  "INVALID_WORD_WISH: the wishes for the new phrase cannot be used: name at most 1 word never "
    + "to use",
  () => describeDraw("", [], "abandon zoo", false),
);
expectCode("INVALID_WORD_WISH", () => describeDraw("happy", [25], "", false));
expectCode("INVALID_REQUEST", () => describeDraw("happy zoo", [1], "", false));
/** A phrase drawn without a passphrase that meets `words` at `places` and avoids `neverUse`. */
const drawnWith = (words, places, neverUse) =>
  JSON.parse(
    wallet.drawPhrase(
      noBytes(),
      noBytes(),
      encode(words),
      Uint32Array.from(places),
      neverUse,
      false,
      testRandom,
      noop,
    ),
  ).phrase.split(" ");
const atTheEnd = drawnWith("ZOO", [24], "abandon");
assert.equal(atTheEnd.length, 24);
assert.equal(atTheEnd[23], "zoo", "a chosen word at its position");
assert.ok(!atTheEnd.includes("abandon"), "no word never to use");
assert.ok(drawnWith("happ", [0], "").includes("happy"), "a chosen word anywhere");
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
console.log("The wallet module passes its checks.");

const noArgon2 = knownAnswersOnly(argon2Engine(await builds["single-threaded"]()));
// The classes give these refusals of the library early, before a secret reaches a worker; they
// must give them with the library's code and in its words, as the command-line tool does.
const LIBRARY_MESSAGES = {
  MEMORY_LEVEL_NOT_SUPPORTED_HERE: pageMessageOf(
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    () => operations.encrypt(PHRASE, encode("p"), noArgon2, { memoryLevel: 1 }),
  ),
  WALLET_CHECK_NEEDS_PASSPHRASE: pageMessageOf(
    "WALLET_CHECK_NEEDS_PASSPHRASE",
    () => drawWithoutWishes(wallet, noBytes(), noBytes(), true, testRandom),
  ),
  PASSPHRASES_DIFFER: pageMessageOf(
    "PASSPHRASES_DIFFER",
    () => drawWithoutWishes(wallet, encode("p"), encode("q"), true, testRandom),
  ),
  NO_BUILT_IN_CHECK_AT_24: pageMessageOf(
    "INVALID_WORD_COUNT",
    () => operations.check(FULL_SIZE_CONTAINER, encode("p"), noArgon2, "words", "24"),
  ),
};

// Phrases reach the WebAssembly as UTF-8 bytes, which the bindings wipe (SecretText in
// src/wasm_api.rs), as they wipe passwords: wasm-bindgen's own copy of a text argument stays
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
  const instance = new Function(`${GLUE}\nreturn mhfe;`)();
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
  // The two passphrases of a new phrase are both held for wiping before either is read: a first
  // one that is not UTF-8 leaves no copy of its repetition (AUD-013-SEC001), and the other way
  // round.
  {
    name: "drawPhrase, its passphrase refused before its repetition is read",
    text: "public test passphrase repeated for the draw",
    call: (instance, bytes) =>
      drawWithoutWishes(instance, new Uint8Array([0xff]), bytes, true, testRandom),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  {
    name: "drawPhrase, its repetition refused",
    text: "public test passphrase typed first for the draw",
    call: (instance, bytes) =>
      drawWithoutWishes(instance, bytes, new Uint8Array([0xff]), true, testRandom),
    expected: refusedWith("INVALID_PASSPHRASE"),
  },
  // A line for a hint may be part of a password or a seed phrase: wiped, and so is the result's
  // buffer, which tells its last letters.
  {
    name: "wordHints, its line",
    text: "public test line typed for a hint below it",
    // The words that begin with "it", which the result's wiped buffer held.
    call: (instance, bytes) => JSON.parse(instance.wordHints("eff", bytes)).hint,
    expected: (outcome) => outcome === "words",
  },
  // A chosen word is part of the new phrase: wiped after a description, a draw and a refusal,
  // also when the passphrase is refused before it is read. The padding makes the text long enough
  // to be sought; the word is read without the spaces around it.
  {
    name: "describeDraw, its chosen word",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      JSON.parse(instance.describeDraw(bytes, Uint32Array.from([1]), "", false)).randomness,
    expected: (outcome) => outcome === "ample",
  },
  {
    name: "drawPhrase, its chosen word",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      JSON.parse(
        instance.drawPhrase(
          noBytes(),
          noBytes(),
          bytes,
          Uint32Array.from([1]),
          "",
          false,
          testRandom,
          noop,
        ),
      ).words,
    expected: (outcome) => outcome === 24,
  },
  {
    name: "drawPhrase, its chosen word refused",
    text: "Notaword".padStart(40),
    call: (instance, bytes) =>
      instance.drawPhrase(
        noBytes(),
        noBytes(),
        bytes,
        Uint32Array.from([1]),
        "",
        false,
        testRandom,
        noop,
      ),
    expected: refusedWith("INVALID_WORD_WISH"),
  },
  {
    name: "drawPhrase, its chosen word after a refused passphrase",
    text: "Happy".padStart(40),
    call: (instance, bytes) =>
      instance.drawPhrase(
        new Uint8Array([0xff]),
        noBytes(),
        bytes,
        Uint32Array.from([1]),
        "",
        false,
        testRandom,
        noop,
      ),
    expected: refusedWith("INVALID_PASSPHRASE"),
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
for (
  const draw of [
    () => passwords.makePassword("checkWord", undefined, noBytes(), refusingSource),
    () => drawWithoutWishes(wallet, noBytes(), noBytes(), false, refusingSource),
  ]
) {
  expectMessage(
    "RANDOM_FAILED: the random generator failed: the page's random source failed: "
      + "QuotaExceededError: the browser refused",
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
