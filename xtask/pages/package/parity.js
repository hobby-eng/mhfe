// The package's side of `cargo xtask parity`: for each public case it prints, as one line of JSON,
// how to run the command-line tool and what the package says the tool must give, from the package's
// WebAssembly in this worker, without any full-cost Argon2 work.
// The package's wasm-bindgen glue defines `mhfe`, the bindings of every module.
const mhfe = new Function(`${GLUE}\nreturn mhfe;`)();
mhfe.initSync({ module: read("dist/runtime/mhfe.wasm") });
const argon2Engine = new Function(`${read("web/argon2-engine.js")}\nreturn argon2Engine;`)();
const engine = argon2Engine(await argon2Build("dist/core/argon2-st.js", "createArgon2St")());
const knownAnswers = knownAnswersOnly(engine);
const noRound = () => {};

/** One run of the program and what the package says it must give: `cargo xtask parity` runs it. */
const expect = (what, args, lines, expected) =>
  console.log(JSON.stringify({ what, args, lines, expected }));

/** Both refuse with the same words; the program may add what it did not do after them. */
const sameRefusal = (what, args, lines, code, packageCall) =>
  expect(what, args, lines, { refuses: pageMessageOf(code, packageCall, what) });

// Repair words, at every count, and a count no card has.
for (const count of JSON.parse(mhfe.repairParameters()).repairWordCounts) {
  expect(
    `repair-words --count ${count}`,
    ["repair-words", "--stdin", "--count", String(count)],
    [FULL_SIZE_CONTAINER],
    { prints: JSON.parse(mhfe.repairWords(FULL_SIZE_CONTAINER, count)).words },
  );
}
sameRefusal(
  "repair-words --count 3",
  ["repair-words", "--stdin", "--count", "3"],
  [FULL_SIZE_CONTAINER],
  "INVALID_REPAIR_WORDS",
  () => mhfe.repairWords(FULL_SIZE_CONTAINER, 3),
);

// A repair of two unreadable words with the card, and one with nothing to repair.
const card = JSON.parse(mhfe.repairWords(FULL_SIZE_CONTAINER, 4)).words;
const damaged = FULL_SIZE_CONTAINER.split(" ");
damaged[2] = "?";
damaged[16] = "?";
for (
  const [what, typed, expected] of [
    ["two unreadable words", damaged.join(" "), FULL_SIZE_CONTAINER],
    ["nothing to repair", FULL_SIZE_CONTAINER, ""],
  ]
) {
  const repaired = JSON.parse(mhfe.repairContainer(typed, card));
  const prints = repaired.unchanged ? "" : repaired.container;
  assert.equal(prints, expected, what);
  expect(`repair, ${what}`, ["repair", "--stdin"], [typed, card], { prints });
}

// Refusals before any round, word for word.
sameRefusal(
  "check --words 24",
  ["check", "--stdin", "--words", "24"],
  [FULL_SIZE_CONTAINER],
  "INVALID_WORD_COUNT",
  () =>
    new mhfe.CheckSession(
      FULL_SIZE_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      "words",
      "24",
      "",
      "",
      noBytes(),
      knownAnswers,
      noRound,
    ),
);
sameRefusal(
  "check --words 12 of a same-length container",
  ["check", "--stdin", "--words", "12"],
  [REDUCED_COST_SAME_LENGTH_CONTAINER],
  "NO_BUILT_IN_CHECK",
  () =>
    new mhfe.CheckSession(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      "words",
      "12",
      "",
      "",
      noBytes(),
      knownAnswers,
      noRound,
    ),
);
sameRefusal(
  "decrypt --words 15 of a same-length container",
  ["decrypt", "--stdin", "--words", "15"],
  [REDUCED_COST_SAME_LENGTH_CONTAINER],
  "LENGTH_CHOICE_NOT_APPLICABLE",
  () =>
    mhfe.decrypt(
      REDUCED_COST_SAME_LENGTH_CONTAINER,
      encode("p"),
      "",
      0,
      0,
      0,
      15,
      new Uint8Array(),
      knownAnswers,
      noRound,
    ),
);
/** The raw encryption of the package, with the repetition and the same-length choice given. */
const encrypt = (phrase, password, repeat, sameLength) => () =>
  mhfe.encrypt(
    encode(phrase),
    encode(password),
    encode(repeat),
    "",
    0,
    0,
    0,
    sameLength,
    0,
    false,
    knownAnswers,
    noRound,
    () => {},
  );
sameRefusal(
  "encrypt --same-length of a 24-word phrase",
  ["encrypt", "--stdin", "--same-length"],
  [ZERO_24],
  "SAME_LENGTH_NEEDS_SHORT_PHRASE",
  encrypt(ZERO_24, TEST_PASSWORD, TEST_PASSWORD, true),
);
// The password's own rules come before its repetition is compared, in both.
sameRefusal(
  "encrypt with a tab in the password and another repetition",
  ["encrypt", "--stdin"],
  [PHRASE, "a\tb", "a\tc"],
  "CONTROL_CHARACTER_IN_PASSWORD",
  encrypt(PHRASE, "a\tb", "a\tc", false),
);
sameRefusal(
  "encrypt with another repetition",
  ["encrypt", "--stdin"],
  [PHRASE, TEST_PASSWORD, "other"],
  "PASSWORDS_DIFFER",
  encrypt(PHRASE, TEST_PASSWORD, "other", false),
);

// The other lengths detection could read: warned of for a 24-word container, as the first
// container of readPhrase() lists them, and not for a same-length one, as the second does not.
const facts = JSON.parse(mhfe.describePhrase(encode(AMBIGUOUS_12_WORDS)));
for (
  const [args, choice] of [
    [["encrypt", "--stdin"], facts.containers[0]],
    [["encrypt", "--stdin", "--same-length"], facts.containers[1]],
  ]
) {
  // Standard input ends at the password: the warning comes before it.
  expect(`mhfe ${args.join(" ")}`, args, [AMBIGUOUS_12_WORDS], { warns: choice.otherLengths });
}
assert.deepEqual(
  facts.containers.map((choice) => choice.otherLengths),
  [[21], []],
);
