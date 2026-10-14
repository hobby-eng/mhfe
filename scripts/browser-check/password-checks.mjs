// The page's checks of MhfePasswords (page code, scripts/browser-check/harness.mjs).

/** MhfePasswords: its construction, its review, the strength and the passwords it makes. */
export async function checkPasswords(passwords) {
  group("MhfePasswords");
  await checkPasswordParameters(passwords);
  await checkPasswordReview(passwords);
  await checkPasswordCorrections(passwords);
  await checkPasswordStrength(passwords);
  await checkMadePasswords(passwords);
  await checkMadePasswordRefusals(passwords);
}

/** What passwords.review gives for a password of the check-word profile, with `fields` as given. */
export function review(fields) {
  return {
    profile: "MHFE-PASSWORD-CHECK-1",
    correction: null,
    correctionText: null,
    offersCorrection: false,
    repairsFirst: false,
    repairs: [],
    ...fields,
  };
}

/** Its construction, a hint below a password, and its fixed values. */
export async function checkPasswordParameters(passwords) {
  expectThrownTypeError(
    () => new MhfePasswords({ workerSource: "", wasm: bytes(WASM_BASE64) }),
    "workerSource must be the text of runtime/worker.js.",
    "a passwords module without its worker is refused",
  );
  const effHint = await passwords.wordHints({ typed: "jovial trailing y" });
  expect(
    effHint.hint === "count" && effHint.count === 27,
    "the hint below a password counts the EFF words that begin with one letter",
  );
  expectEqual(
    await passwords.parameters(),
    {
      version: VERSION,
      checkWordProfile: "MHFE-PASSWORD-CHECK-1",
      defaultWords: 5,
      recommendedWords: 4,
      mostWords: 32,
      defaultCharacters: 16,
      recommendedCharacters: 12,
      mostCharacters: 64,
      weakBelowBits: 50,
    },
    "parameters gives every fixed value",
  );
}

/** A review: a password that fits, a repetition that differs, and the repairs it offers. */
export async function checkPasswordReview(passwords) {
  expectEqual(
    await passwords.review({
      password: CHECK_WORD_PASSWORD,
      passwordRepeat: CHECK_WORD_PASSWORD,
    }),
    review({ reading: "fits" }),
    "a check-word password typed twice fits",
  );
  await expectRejection(
    passwords.review({ password: CHECK_WORD_PASSWORD, passwordRepeat: CHECK_WORD_CAPITALS }),
    "PASSWORDS_DIFFER",
    "a repetition that differs is refused",
  );
  await expectRejection(
    passwords.review({ password: CHECK_WORD_PASSWORD, passwordRepeat: "" }),
    "PASSWORDS_DIFFER",
    "an empty repetition differs; it is not a missing one",
  );
  const restored = await passwords.review({
    password: "jovial trailing ? pavilion cresting ninth",
  });
  expect(
    restored.repairs[0].word === "chokehold",
    "the passwords module restores a forgotten word",
  );
  expectEqual(
    restored,
    review({
      reading: "restorable",
      repairsFirst: true,
      repairs: [{ position: 3, word: "chokehold", typed: null }],
    }),
    "a word typed as ? is restorable, its repair offered first",
  );
  // The six repairs follow from the profile alone: the check word is the EFF list word at
  // (d1 + 5 d2 + 7 d3 + 11 d4 + 13 d5) mod 7776 for the list indexes d of the five words
  // (src/check_word.rs), and each repair solves that for the word at its place. They were
  // computed so from vendor/eff-large-wordlist, independently of mhfe.
  expectEqual(
    await passwords.review({
      password: encode("abacus abdomen abdominal zoom abiding aids"),
    }),
    review({
      reading: "mismatch",
      repairs: [
        { position: 1, word: "activate", typed: "abacus" },
        { position: 2, word: "daylong", typed: "abdomen" },
        { position: 3, word: "encrust", typed: "abdominal" },
        { position: 4, word: "abide", typed: "zoom" },
        { position: 5, word: "excretory", typed: "abiding" },
        { position: 6, word: "affected", typed: "aids" },
      ],
    }),
    "a wrong word is a mismatch with a repair at each of the six places; bytes are read",
  );
}

/** The corrections of a review, another shape of password, and its refusals. */
export async function checkPasswordCorrections(passwords) {
  expectEqual(
    await passwords.review({ password: CHECK_WORD_CAPITALS }),
    review({
      reading: "fits",
      correction: "capitals",
      correctionText: "capitals made small",
      offersCorrection: true,
      repairsFirst: true,
    }),
    "capitals are corrected, and the corrected password is offered first",
  );
  expectEqual(
    await passwords.review({ password: " jovial trailing ? pavilion  cresting ninth " }),
    review({
      reading: "restorable",
      correction: "extraSpaces",
      correctionText: "extra spaces removed",
      repairsFirst: true,
      repairs: [{ position: 3, word: "chokehold", typed: null }],
    }),
    "extra spaces are removed before the review",
  );
  const both = await passwords.review({
    password: "  Jovial trailing chokehold pavilion cresting ninth",
  });
  expect(
    both.correction === "spacesAndCapitals" &&
      both.correctionText === "spaces and capitals corrected",
    "spaces and capitals are corrected together",
  );
  expectEqual(
    await passwords.review({ password: "correct horse battery staple" }),
    review({ reading: "notThisShape" }),
    "another password is not of the profile's shape",
  );
  await expectRejection(
    passwords.review({ password: "" }),
    "EMPTY_PASSWORD",
    "an empty password is refused",
  );
  await expectRejection(
    passwords.review({ password: "a\tb" }),
    "CONTROL_CHARACTER_IN_PASSWORD",
    "a password with a TAB is refused",
  );
}

/** The strength of a password, after its repair or correction. */
export async function checkPasswordStrength(passwords) {
  // 12.925 bits for each different word of the EFF list (src/eff.rs).
  expectEqual(
    await passwords.strength({ password: "abacus zoom yearbook zipfile" }),
    { bits: 51.7, weak: false },
    "four different list words are 51.7 bits",
  );
  expectEqual(
    await passwords.strength({ password: encode("password") }),
    { bits: 12.925, weak: true },
    '"password" is one word of the EFF list, 12.925 bits, weak; bytes are read',
  );
  expectEqual(
    await passwords.strength({ password: CHECK_WORD_MISSING, passwordRepair: { repair: 3 } }),
    { bits: 64.625, weak: false },
    "the strength is of the password after its repair: five drawn words and their check word",
  );
  expectEqual(
    await passwords.strength({ password: CHECK_WORD_CAPITALS, passwordRepair: "corrected" }),
    { bits: 64.625, weak: false },
    "the strength is of the corrected password: five drawn words and their check word",
  );
  await expectRejection(
    passwords.strength({ password: CHECK_WORD_MISSING, passwordRepair: { repair: 2 } }),
    "PASSWORD_REPAIR_NOT_OFFERED",
    "a repair the review did not offer is refused",
  );
}

/** Passwords made of words, characters and a check word, from randomness or dice. */
export async function checkMadePasswords(passwords) {
  const listWords = (password) => password.split(" ").every((word) => /^[a-z-]+$/u.test(word));
  // The bits of a made password are counted in thousandths of a bit, which add up exactly
  // (src/new_password.rs): 12.925 for each drawn word of the EFF list (log2 7,776, rounded) and
  // 5.833 for each character of the 57 (log2 57, rounded).
  const made = await passwords.make();
  expect(
    made.password.split(" ").length === 5 &&
      listWords(made.password) &&
      sameValue(fieldsOf(made, ["bits", "weak", "checkWord"]), {
        bits: 64.625,
        weak: false,
        checkWord: false,
      }),
    "make() makes five words, 64.625 bits",
  );
  const words = await passwords.make({ kind: "words" });
  expect(
    words.password.split(" ").length === 5 && words.bits === 64.625,
    'kind "words" without a count makes five words',
  );
  expectEqual(
    fieldsOf(await passwords.make({ kind: "words", count: 3 }), ["bits", "weak"]),
    { bits: 38.775, weak: true },
    "three words are 38.775 bits, weak",
  );
  const characters = await passwords.make({ kind: "characters" });
  expect(
    /^[2-9A-HJ-NP-Za-km-z]{16}$/u.test(characters.password) &&
      sameValue(fieldsOf(characters, ["bits", "weak", "checkWord"]), {
        bits: 93.328,
        weak: false,
        checkWord: false,
      }),
    'kind "characters" makes 16 characters without those easily confused, 93.328 bits',
  );
  const elevenCharacters = await passwords.make({ kind: "characters", count: 11 });
  expect(
    elevenCharacters.password.length === 11 &&
      elevenCharacters.bits === 64.163 &&
      elevenCharacters.weak,
    "eleven characters are 64.163 bits, weak",
  );
  const checkWord = await passwords.make({ kind: "checkWord" });
  const checkWordReview = await passwords.review({ password: checkWord.password });
  expect(
    checkWord.checkWord &&
      checkWord.password.split(" ").length === 6 &&
      checkWord.bits === 64.625 &&
      !checkWord.weak &&
      checkWordReview.reading === "fits",
    "the passwords module makes a check-word password from the browser's randomness",
  );
  expectEqual(
    await passwords.make({ kind: "words", count: 2, dice: "11111 66666" }),
    { password: "abacus zoom", bits: 25.85, weak: true, checkWord: false },
    "two words from dice are the first and last of the list",
  );
  expectEqual(
    await passwords.make({ kind: "checkWord", dice: encode(CHECK_WORD_DICE) }),
    { password: CHECK_WORD_PASSWORD, bits: 64.625, weak: false, checkWord: true },
    "the published dice give the published check-word password; dice as bytes are read",
  );
}

/** The kinds, counts and dice that make() refuses. */
export async function checkMadePasswordRefusals(passwords) {
  await expectRefusal(
    passwords.make({ kind: "characters", dice: "11111" }),
    "INVALID_REQUEST",
    "a character password cannot come from dice",
    "characters cannot come from dice",
  );
  await expectExactTypeError(
    passwords.make({ kind: "checkWord", count: 7 }),
    'count belongs only to the kinds "words" and "characters": "checkWord" always gives 5 ' +
      "words and their check word.",
    "the check word takes no count, as mhfe password refuses --check-word with --words",
  );
  await expectRejection(
    passwords.make({ kind: "words", count: 2, dice: "11111 66667" }),
    "INVALID_DICE_ROLLS",
    "a 7 is no die",
  );
  await expectRejection(
    passwords.make({ kind: "words", count: 2, dice: "11111" }),
    "INVALID_REQUEST",
    "dice for one word of two are refused as a count, not as digits (AUD-024-API015)",
  );
  await expectRejection(
    passwords.make({ kind: "words", count: 0 }),
    "INVALID_PASSWORD_SIZE",
    "no words are refused",
  );
  await expectRejection(
    passwords.make({ kind: "words", count: 33 }),
    "INVALID_PASSWORD_SIZE",
    "33 words are refused",
  );
  await expectRejection(
    passwords.make({ kind: "characters", count: 65 }),
    "INVALID_PASSWORD_SIZE",
    "65 characters are refused",
  );
  await expectRefusal(
    passwords.make({ kind: "emoji" }),
    "INVALID_REQUEST",
    "unknown password kind emoji",
    "an unknown kind is refused",
  );
  await expectTypeError(
    passwords.make({ count: 2.5 }),
    "count must be a whole number.",
    "a count that is not whole is refused",
  );
}
