async function checkRepair(repair) {
  group("MhfeRepair");
  expectThrownTypeError(
    () => new MhfeRepair({ wasm: bytes(WASM_BASE64) }),
    "workerSource must be the text of runtime/worker.js.",
    "a repair module without its worker is refused",
  );
  expectThrownTypeError(
    () => new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: [0, 97, 115, 109] }),
    "wasm must be a Uint8Array or a WebAssembly.Module.",
    "a wasm that is neither bytes nor a compiled module is refused",
  );
  const fromBytes = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: bytes(WASM_BASE64) });
  expectEqual(
    await fromBytes.parameters(),
    {
      version: VERSION,
      profile: REPAIR_PROFILE,
      repairWordCounts: [2, 4, 6, 8],
      recommendedRepairWords: 4,
      repairCapacities: [
        { count: 2, unreadable: 2, wrong: 1 },
        { count: 4, unreadable: 4, wrong: 2 },
        { count: 6, unreadable: 6, wrong: 3 },
        { count: 8, unreadable: 8, wrong: 4 },
      ],
    },
    "parameters gives every fixed value; the module also takes the WebAssembly as bytes",
  );
  for (const count of REPAIR_WORD_CHOICES) {
    expectEqual(
      await repair.repairWords({ container: FULL_SIZE_CONTAINER, count }),
      {
        profile: REPAIR_PROFILE,
        words: FULL_SIZE_REPAIR_WORDS[count],
        repairsUnreadable: count,
        repairsWrong: count / 2,
      },
      `${count} repair words are the published card`,
    );
  }
  await expectRejection(
    repair.repairWords({ container: FULL_SIZE_CONTAINER, count: 3 }),
    "INVALID_REPAIR_WORDS",
    "three repair words are refused",
  );
  // Which counts a card has is the library's rule (INVALID_REPAIR_WORDS above); the page refuses
  // only what is no whole number at all, without a copy of the list (web/repair.js).
  await expectExactTypeError(
    repair.repairWords({ container: FULL_SIZE_CONTAINER, count: "4" }),
    "count must be a whole number.",
    "a count that is not a number is refused",
  );
  await checkRepairContainer(repair);
}

/** MhfeRepair.repairContainer with the published card and its refusals, and inspectContainer. */
async function checkRepairContainer(repair) {
  const card = FULL_SIZE_REPAIR_WORDS[4];
  const containerWith = (changes) => {
    const words = FULL_SIZE_CONTAINER.split(" ");
    for (const [position, word] of Object.entries(changes)) words[position - 1] = word;
    return words.join(" ");
  };
  const repaired = (containerWords, cardWords, changes) => ({
    container: FULL_SIZE_CONTAINER,
    containerFingerprint: FINGERPRINTS.fullSizeContainer,
    unchanged: changes.length === 0,
    containerWords,
    cardWords,
    changes,
  });
  expectEqual(
    await repair.repairContainer({ container: FULL_SIZE_CONTAINER, card }),
    repaired([], [], []),
    "an intact container phrase and card are unchanged, with every field",
  );
  const shortForms = (text) =>
    text
      .split(" ")
      .map((word) => word.slice(0, 4).toUpperCase())
      .join(" ");
  expectEqual(
    await repair.repairContainer({
      container: shortForms(FULL_SIZE_CONTAINER),
      card: shortForms(card),
    }),
    repaired([], [], []),
    "a container phrase and card typed in capitals and four-letter forms are read in full",
  );
  expectEqual(
    await repair.repairContainer({ container: containerWith({ 3: "?" }), card }),
    repaired([3], [], [{ onCard: false, position: 3, read: null, word: "tower" }]),
    "the repair module repairs an unreadable word",
  );
  expectEqual(
    await repair.repairContainer({ container: containerWith({ 5: "zoo", 20: "abandon" }), card }),
    repaired(
      [5, 20],
      [],
      [
        { onCard: false, position: 5, read: "zoo", word: "iron" },
        { onCard: false, position: 20, read: "abandon", word: "heart" },
      ],
    ),
    "two wrong words are repaired and reported with what was read",
  );
  expectEqual(
    await repair.repairContainer({
      container: containerWith({ 1: "?", 9: "legal" }),
      card: "MHFE-REPAIR-1 1/4 shaft 2/4 ? 3/4 patient 4/4 jewel",
    }),
    repaired(
      [1, 9],
      [2],
      [
        { onCard: false, position: 1, read: null, word: "donate" },
        { onCard: false, position: 9, read: "legal", word: "roof" },
        { onCard: true, position: 2, read: null, word: "pupil" },
      ],
    ),
    "a card typed with its profile and numbers, one word unreadable, is read and repaired",
  );
  const damagedCard = await repair.repairContainer({
    container: containerWith({ 2: "abandon", 11: "zoo", 23: "legal" }),
    card: "appear include vicious move uphold abandon song satoshi",
  });
  expectEqual(
    fieldsOf(damagedCard, ["container", "containerWords", "cardWords", "unchanged"]),
    {
      container: FULL_SIZE_CONTAINER,
      containerWords: [2, 11, 23],
      cardWords: [6],
      unchanged: false,
    },
    "a wrong word on an eight-word card is repaired with three wrong container words",
  );
  expectEqual(
    fieldsOf(
      await repair.repairContainer({ container: FULL_SIZE_CONTAINER, card: "zoo extra" }),
      ["containerWords", "cardWords", "unchanged"],
    ),
    { containerWords: [], cardWords: [1], unchanged: false },
    "a wrong card word alone is repaired too",
  );
  await expectRejection(
    repair.repairContainer({
      container: containerWith({ 1: "?", 2: "?", 3: "?" }),
      card: FULL_SIZE_REPAIR_WORDS[2],
    }),
    "REPAIR_NOT_POSSIBLE",
    "three unreadable words are beyond two repair words",
  );
  await expectRejection(
    repair.repairContainer({ container: FULL_SIZE_CONTAINER, card: "abandon abandon abandon" }),
    "INVALID_REPAIR_WORDS",
    "a card of three words is refused",
  );
  await expectRejection(
    repair.repairContainer({
      container: FULL_SIZE_CONTAINER.split(" ").slice(1).join(" "),
      card,
    }),
    "INVALID_CONTAINER",
    "a container phrase of 23 words is refused",
  );

  // What a container phrase as typed is, before it is used: the page asks for the card when it
  // is "marked" and offers it when it is "notAContainer".
  for (
    const [typed, reading, wordCount, unreadable, description] of [
      [FULL_SIZE_CONTAINER, "container", 24, [], "a valid container phrase"],
      [containerWith({ 3: "?", 17: "?" }), "marked", 24, [3, 17], "words marked with ?"],
      [containerWith({ 3: "?", 9: "towr" }), "marked", 24, [3, 9], "a ? and a word not listed"],
      [containerWith({ 9: "towr" }), "notAContainer", 24, [], "a word not listed alone"],
      [FULL_SIZE_CONTAINER.split(" ").slice(1).join(" "), "wrongLength", 23, [], "23 words"],
    ]
  ) {
    expectEqual(
      await repair.inspectContainer({ container: typed }),
      { reading, wordCount, unreadable },
      `inspectContainer reads ${description} as ${reading}`,
    );
  }
  await expectTypeError(
    repair.inspectContainer({}),
    "container must be a string.",
    "inspectContainer without a container is refused",
  );
}
