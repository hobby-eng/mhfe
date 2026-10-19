// Part 1 of the checks of the browser package, continued: the core's rekey through one Argon2
// build at the reduced cost, which core-operations.mjs runs for each build. A rekey recovers the
// phrase (rounds 1-12 of 36), is confirmed by the built-in check, a wallet reference or the owner,
// and seals it again (rounds 13-36). Input and confirmation-admission refusals precede the rounds;
// refusals based on the recovered phrase or length follow recovery, before replacement sealing.
import assert from "node:assert/strict";

import {
  AMBIGUOUS_12_WORDS,
  PHRASE,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
} from "../public-test-data.mjs";
import { expectCode, expectMessage, noRoundExpected } from "./expect.mjs";
import { bindings, operations, readWipedJson } from "./package.mjs";
import {
  NEW_PASSWORD,
  NOT_BOOLEAN_ANSWERS,
  NOTHING_TO_ASK,
  PASSPHRASE_ANSWER_NOT_BOOLEAN,
  PASSPHRASE_CONTRADICTED,
  PASSPHRASE_NOT_COMPARED,
  PASSPHRASE_UNSTATED,
  PASSWORD,
  PHRASE_ADDRESS,
  PHRASE_FINGERPRINT,
  PHRASE_TREZOR_ADDRESS,
  PHRASE_TREZOR_FINGERPRINT,
  REFERENCE_REQUIRED,
  REKEY_PASSPHRASE_WITHOUT_REFERENCE,
  encode,
  noBytes,
} from "./test-values.mjs";

/** The core module's bindings: the bindings of the package's one WebAssembly. */
const core = bindings;

/**
 * The rekey's checks through the build of `run` (core-operations.mjs): its recovery, the lengths
 * it is confirmed at, its confirmations and refusals, and the owner's answer.
 */
export function checkRekey(run) {
  checkBuiltInCheckRekey(run);
  checkContradictedLength(run);
  checkOwnerComparesAgain(run);
  checkEndsAfterRefusal(run);
  checkSeveralLengths(run);
  const confirmations = confirmationsOf(run);
  checkSameLengthRekeys(run, confirmations);
  checkRekeyRefusals(run, confirmations);
  checkNewPasswordAndOwner(run);
}

/** A rekey confirmed by the built-in check, and what a wallet keeps, with a passphrase or not. */
function checkBuiltInCheckRekey({ reduced, steps, onRound, created }) {
  // A rekey: recovered with the built-in check (rounds 1-12 of 36), sealed again (13-36).
  steps.length = 0;
  const rekey = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, reduced);
  rekey.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  assert.deepEqual(
    JSON.parse(rekey.recover("builtInCheck", "", "", "", noBytes(), false, onRound)),
    NOTHING_TO_ASK,
  );
  const rekeyed = readWipedJson(rekey.seal(onRound, () => {}));
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
  const stated = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, reduced);
  stated.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 2);
  stated.recover("builtInCheck", "", "", "", noBytes(), true, () => {});
  const withPassphrase = readWipedJson(
    stated.seal(
      () => {},
      () => {},
    ),
  );
  assert.equal(withPassphrase.repairWords.split(" ").length, 2);
  assert.deepEqual(withPassphrase.keep, [
    { item: "containerWords", words: 24 },
    { item: "password" },
    { item: "passphrase" },
    { item: "repairWords", apart: true },
  ]);
  stated.free();
}

/** A rekey of the 12-word phrase's 24-word container with `words` stated, 0 to detect it. */
function rekeyStating({ reduced, created }, words) {
  const session = new core.RekeySession(created.container, words, PASSWORD, "", 0, 0, 0, reduced);
  session.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  return session;
}

/** A rekey with 15 words stated, which the built-in check of the 12-word phrase contradicts. */
const contradicted = (run) => rekeyStating(run, 15);

/** A stated length the built-in check contradicts, confirmed again by the fingerprint. */
function checkContradictedLength(run) {
  const { reduced, steps, onRound } = run;
  // A stated length that the built-in check contradicts (AUD-015-FUN001): the built-in check alone
  // is refused once the recovery has run, and the fingerprint confirms the 12-word reading.
  const refusedLength = contradicted(run);
  expectMessage(
    "LENGTH_DIFFERS: the built-in check finds a 12-word original seed phrase, not the 15 words " +
      "stated: confirm it with a receiving address or the master key fingerprint of the wallet",
    () => refusedLength.recover("builtInCheck", "", "", "", noBytes(), false, () => {}),
  );
  // The refusal keeps the recovery (AUD-017-UI002): the owner may compare at the stated length,
  // and the fingerprint confirms the reading on the same recovery, without its rounds again.
  assert.equal(refusedLength.ownerLengths(), "[15]");
  steps.length = 0;
  assert.deepEqual(
    JSON.parse(
      refusedLength.confirmAgain("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes(), 0, onRound),
    ),
    NOTHING_TO_ASK,
  );
  assert.deepEqual(steps, ["compare 12/36"], "confirmed again without a round");
  assert.equal(refusedLength.ownerLengths(), "null", "confirmed, it waits for no other");
  const confirmedAgain = JSON.parse(
    refusedLength.seal(
      () => {},
      () => {},
    ),
  );
  assert.equal(
    operations.decrypt(confirmedAgain.container, NEW_PASSWORD, reduced).candidates[0].phrase,
    PHRASE,
  );
  refusedLength.free();
}

/** The owner compares the reading at the stated length; what to keep of the old container. */
function checkOwnerComparesAgain(run) {
  // The owner compares the reading the check found at the stated length; the built-in check again
  // is refused again and keeps the recovery, and the answer about the passphrase holds.
  const ownerAgain = contradicted(run);
  expectCode("LENGTH_DIFFERS", () =>
    ownerAgain.recover("builtInCheck", "", "", "", noBytes(), true, () => {}),
  );
  expectCode("LENGTH_DIFFERS", () =>
    ownerAgain.confirmAgain("builtInCheck", "", "", "", noBytes(), 0, noRoundExpected),
  );
  assert.deepEqual(
    JSON.parse(ownerAgain.confirmAgain("owner", "", "", "", noBytes(), 15, noRoundExpected))
      .ownerCheck,
    {
      phrase: PHRASE,
      words: 12,
      statedWords: 15,
      fingerprintWithoutPassphrase: PHRASE_FINGERPRINT,
    },
  );
  ownerAgain.ownerAnswer(true, noBytes());
  const resealed = JSON.parse(
    ownerAgain.seal(
      () => {},
      () => {},
    ),
  );
  assert.deepEqual(
    resealed.keep,
    [{ item: "containerWords", words: 24 }, { item: "password" }, { item: "passphrase" }],
    "the wallet stated with the first confirmation to have a passphrase keeps it",
  );
  assert.deepEqual(
    resealed.rehearsal,
    { kind: "builtInCheck" },
    "a short phrase is rehearsed with its built-in check",
  );
  // What to keep of a rekey's old container: a PIM or memory level only where it is not 0
  // (AUD-023-ARC016).
  const oldKept = [{ item: "oldContainer" }, { item: "oldPasswords" }];
  for (const [pim, level, settings] of [
    [0, 0, []],
    [3, 0, [{ item: "pim", value: 3 }]],
    [0, 2, [{ item: "memoryLevel", value: 2 }]],
    [
      3,
      2,
      [
        { item: "pim", value: 3 },
        { item: "memoryLevel", value: 2 },
      ],
    ],
  ]) {
    assert.deepEqual(JSON.parse(core.keepOldContainer(pim, level)), [...oldKept, ...settings]);
  }
  ownerAgain.free();
}

/** What ends a rekey after a refusal, and that nothing is confirmed again before one. */
function checkEndsAfterRefusal(run) {
  // What ends a rekey after a refusal: a length the owner cannot confirm, a length with another
  // kind, a reference that does not match. Before a refusal there is nothing to confirm again.
  const endsAfterRefusal = [
    {
      confirm: (session) => session.confirmAgain("owner", "", "", "", noBytes(), 12, () => {}),
      message:
        "INVALID_REQUEST: invalid request: the owner confirms a reading of [15] words here, not 12",
    },
    {
      confirm: (session) =>
        session.confirmAgain("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes(), 15, () => {}),
      message: "INVALID_REQUEST: invalid request: only the owner's confirmation states a length",
    },
    {
      confirm: (session) =>
        session.confirmAgain("fingerprint", "00000000", "", "", noBytes(), 0, () => {}),
      code: "REFERENCE_MISMATCH",
    },
  ];
  for (const { confirm, message, code } of endsAfterRefusal) {
    const session = contradicted(run);
    expectCode("LENGTH_DIFFERS", () =>
      session.recover("builtInCheck", "", "", "", noBytes(), false, () => {}),
    );
    if (message === undefined) expectCode(code, () => confirm(session));
    else expectMessage(message, () => confirm(session));
    assert.equal(session.ownerLengths(), "null", `${message ?? code}: the rekey ended`);
    expectMessage("INVALID_REQUEST: invalid request: a rekey step out of its order", () =>
      session.confirmAgain("builtInCheck", "", "", "", noBytes(), 0, () => {}),
    );
    session.free();
  }
  const defaultOwner = rekeyStating(run, 15);
  expectCode("LENGTH_DIFFERS", () =>
    defaultOwner.recover("builtInCheck", "", "", "", noBytes(), false, () => {}),
  );
  const defaultShown = JSON.parse(
    defaultOwner.confirmAgain("owner", "", "", "", noBytes(), 0, () => {}),
  );
  assert.equal(
    defaultShown.ownerCheck.statedWords,
    15,
    "the library defaults to the only owner length",
  );
  defaultOwner.free();
  const notRefused = rekeyStating(run, 12);
  assert.equal(notRefused.ownerLengths(), "null");
  expectMessage("INVALID_REQUEST: invalid request: a rekey step out of its order", () =>
    notRefused.confirmAgain("builtInCheck", "", "", "", noBytes(), 0, noRoundExpected),
  );
  notRefused.free();
}

/** Several lengths that pass by accident, and the lengths a reference or the owner confirms. */
function checkSeveralLengths(run) {
  const { reduced } = run;
  // Several lengths that pass by accident: the owner states the one to compare among those the
  // library leaves, here both readings, and is shown it.
  const ambiguousContainer = operations.encrypt(AMBIGUOUS_12_WORDS, PASSWORD, reduced).container;
  const several = new core.RekeySession(ambiguousContainer, 12, PASSWORD, "", 0, 0, 0, reduced);
  several.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  expectCode("AMBIGUOUS_LENGTH", () =>
    several.recover("builtInCheck", "", "", "", noBytes(), false, () => {}),
  );
  assert.equal(several.ownerLengths(), "[12,21]");
  const shownOfSeveral = JSON.parse(
    several.confirmAgain("owner", "", "", "", noBytes(), 21, () => {}),
  );
  assert.equal(
    shownOfSeveral.ownerCheck.words,
    21,
    "the owner is shown the reading of the stated length",
  );
  several.free();
  const confirmedLength = contradicted(run);
  assert.deepEqual(
    JSON.parse(
      confirmedLength.recover(
        "fingerprint",
        PHRASE_FINGERPRINT,
        "",
        "",
        noBytes(),
        false,
        () => {},
      ),
    ),
    NOTHING_TO_ASK,
  );
  confirmedLength.free();
  // The owner of a contradicted length is shown the reading the check found, with the length
  // stated, which the page names before the owner compares.
  const ownerOfContradicted = contradicted(run);
  assert.deepEqual(
    JSON.parse(ownerOfContradicted.recover("owner", "", "", "", noBytes(), false, () => {}))
      .ownerCheck,
    {
      phrase: PHRASE,
      words: 12,
      statedWords: 15,
      fingerprintWithoutPassphrase: PHRASE_FINGERPRINT,
    },
  );
  ownerOfContradicted.free();
  // The length detected: the fingerprint confirms the 12-word reading that detection finds; the
  // built-in check alone is refused before any work (below).
  const detectedLength = rekeyStating(run, 0);
  assert.deepEqual(
    JSON.parse(
      detectedLength.recover("fingerprint", PHRASE_FINGERPRINT, "", "", noBytes(), false, () => {}),
    ),
    NOTHING_TO_ASK,
  );
  detectedLength.free();
}

/**
 * The confirmations of the rekeys below: the built-in check of the 12-word phrase in the 24-word
 * container, its owner reading it as 24 words, and wallet references of PHRASE that match the
 * same-length container, with the BIP39 passphrase "TREZOR" or with an empty one.
 */
function confirmationsOf({ created }) {
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
  return {
    builtInCheck,
    ownerCheck,
    onSameLength,
    trezorFingerprint,
    trezorAddress,
    plainFingerprint,
    plainAddress,
  };
}

/** A rekey of the confirmation's container, ready for its recovery with the answer `answer`. */
function recoverAs({ reduced }, confirmation, answer, onRecoverRound = () => {}) {
  const { container, words, kind, reference = "", coin = "", passphrase = "" } = confirmation;
  const session = new core.RekeySession(container, words, PASSWORD, "", 0, 0, 0, reduced);
  session.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  const recover = () =>
    session.recover(kind, reference, coin, "", encode(passphrase), answer, onRecoverRound);
  return { session, recover };
}
/** A confirmation and an answer as a failed assertion names them. */
const describe = ({ words, kind, passphrase = "" }, answer) =>
  `${kind} of ${words} words, passphrase ${JSON.stringify(passphrase)}, ` +
  `answer ${String(JSON.stringify(answer))}`;

/** The same-length rekeys that pass: what they seal, and what their keep lists tell. */
function checkSameLengthRekeys(run, confirmations) {
  const { reduced } = run;
  const { trezorFingerprint, trezorAddress, plainFingerprint, plainAddress } = confirmations;
  // Sealed again, a same-length rekey gives what encrypt gives with the new password; its keep list
  // tells what the answer became.
  const sameLengthWithNew = operations.encrypt(PHRASE, NEW_PASSWORD, reduced, { sameLength: true });
  const KEEP_SAME_LENGTH = [{ item: "containerWords", words: 12 }, { item: "password" }];
  const KEEP_SAME_LENGTH_AND_PASSPHRASE = [...KEEP_SAME_LENGTH, { item: "passphrase" }];
  const sameLengthKeep = (confirmation, answer) => {
    const { session, recover } = recoverAs(run, confirmation, answer);
    try {
      assert.deepEqual(JSON.parse(recover()), NOTHING_TO_ASK);
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
  // under a passphrase: it confirms only a wallet stated to have none (the specification's
  // re-encryption rules); a wallet with one is compared with it, and true is refused below.
  for (const confirmation of [plainFingerprint, plainAddress]) {
    assert.deepEqual(
      sameLengthKeep(confirmation, false),
      KEEP_SAME_LENGTH,
      describe(confirmation, false),
    );
  }
}

/** Everything else is refused before any Argon2 round, and the refusal ends the rekey. */
function checkRekeyRefusals(run, confirmations) {
  const { steps, onRound } = run;
  const {
    builtInCheck,
    ownerCheck,
    onSameLength,
    trezorFingerprint,
    trezorAddress,
    plainFingerprint,
    plainAddress,
  } = confirmations;
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
    // A wallet said to have a passphrase, but a reference compared without it.
    ...[plainFingerprint, plainAddress].map((confirmation) => ({
      confirmation,
      answer: true,
      message: PASSPHRASE_NOT_COMPARED,
    })),
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
        message: REKEY_PASSPHRASE_WITHOUT_REFERENCE,
      })),
    ),
    // A length without a built-in check refuses that check first, before the answer is judged:
    // the 24-word reading, the same-length container's own length, and the length detected on a
    // 24-word container, where a 24-word original may pass a short check by chance
    // (AUD-017-FUN001).
    ...[undefined, null, true, false].flatMap((answer) =>
      [
        { ...builtInCheck, words: 24 },
        { ...onSameLength, kind: "builtInCheck" },
        { ...builtInCheck, words: 0 },
      ].map((confirmation) => ({ confirmation, answer, message: REFERENCE_REQUIRED })),
    ),
  ];
  for (const { confirmation, answer, message } of rekeyRefusals) {
    const description = describe(confirmation, answer);
    steps.length = 0;
    const { session, recover } = recoverAs(run, confirmation, answer, onRound);
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
}

/** A new password that is the old one, and the owner's comparison and answer. */
function checkNewPasswordAndOwner({ reduced, created }) {
  const same = new core.RekeySession(created.container, 12, PASSWORD, "", 0, 0, 0, reduced);
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
  // The owner confirms a phrase by comparing it; a no ends the rekey. With the length detected
  // nothing was stated, so the check names no stated length.
  const owner = new core.RekeySession(created.container, 0, PASSWORD, "", 0, 0, 0, reduced);
  owner.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  const shown = JSON.parse(owner.recover("owner", "", "", "", noBytes(), false, () => {}));
  assert.deepEqual(shown.ownerCheck, {
    phrase: PHRASE,
    words: 12,
    fingerprintWithoutPassphrase: PHRASE_FINGERPRINT,
  });
  expectCode("NOT_CONFIRMED_BY_OWNER", () => owner.ownerAnswer(false, noBytes()));
  owner.free();
  // Only the value true is a yes, never 1, "1" or [1], which a bool of the ABI would take, and
  // nothing is sealed before the answer (the specification's re-encryption rules).
  const askedOwner = () => {
    const asked = new core.RekeySession(created.container, 0, PASSWORD, "", 0, 0, 0, reduced);
    asked.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
    asked.recover("owner", "", "", "", noBytes(), false, () => {});
    return asked;
  };
  const unanswered = askedOwner();
  expectMessage(
    "INVALID_REQUEST: invalid request: a rekey step out of its order",
    () =>
      unanswered.seal(
        () => {},
        () => {},
      ),
    "a rekey waiting for the owner seals nothing",
  );
  unanswered.free();
  for (const notTrue of [1, "1", [1], "true", {}]) {
    const asked = askedOwner();
    expectCode("NOT_CONFIRMED_BY_OWNER", () => asked.ownerAnswer(notTrue, noBytes()));
    asked.free();
  }
  // 24 words stated for this 12-word phrase: the owner cannot tell the two readings apart, and
  // only an address or the fingerprint confirms it (AUD-015-FUN001).
  const ownerOf24 = new core.RekeySession(created.container, 24, PASSWORD, "", 0, 0, 0, reduced);
  ownerOf24.setNew(NEW_PASSWORD, NEW_PASSWORD.slice(), "", 0, 0, 0, 0);
  expectCode("LENGTH_DIFFERS", () =>
    ownerOf24.recover("owner", "", "", "", noBytes(), false, () => {}),
  );
  assert.equal(ownerOf24.ownerLengths(), "[]", "only an address or the fingerprint is left");
  expectMessage(
    "INVALID_REQUEST: invalid request: the owner cannot confirm this phrase: an address or the " +
      "fingerprint does",
    () => ownerOf24.confirmAgain("owner", "", "", "", noBytes(), 24, () => {}),
  );
  ownerOf24.free();
}
