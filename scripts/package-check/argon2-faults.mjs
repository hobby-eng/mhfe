// Part 1 of the checks of the browser package, continued: Argon2 builds that fail their known
// answer, before the first round or after the last, the wipe of the Argon2 memory, and the faults
// the self-test names, with the published round keys in place of Argon2 at full size.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_CONTAINER,
  ZERO_24,
} from "../public-test-data.mjs";
import { expectMessage } from "./expect.mjs";
import {
  argon2Engine,
  bindings,
  bindingsOver,
  builds,
  noop,
  operations,
  packageWasm,
  read,
  realArgon2,
} from "./package.mjs";
import {
  KNOWN_ANSWER_COSTS,
  PASSWORD,
  REDUCED_MEMORY_KIB,
  REDUCED_PASSES,
  argon2KeyFault,
  argon2Refused,
  noBytes,
} from "./test-values.mjs";

/** The core module's bindings: the bindings of the package's one WebAssembly. */
const core = bindings;

/** Argon2 builds that fail their known answer are refused, and the Argon2 memory is wiped. */
export async function checkArgon2Faults() {
  checkFaultyBuilds();
  checkLateFault();
  const residue = await checkArgon2Wipe();
  console.log(
    `Argon2 builds that fail their known answer are refused before round 1 and after the last; ` +
      `${residue} non-zero bytes remain after a known answer.`,
  );
}

/**
 * An Argon2 build that does not give its known answer is refused before any round: a bridge that
 * leaves the key as it was or writes zeros, as a stale view of the WebAssembly's memory would, and
 * a build that gives another tag. Nothing secret reaches it, and the self-check names it.
 */
function checkFaultyBuilds() {
  const unwrittenKey = "Argon2id could not run: the Argon2 engine returned without writing the key";
  const faultyBuilds = [
    { fault: "leaves the key as it was", spoil: () => {}, detail: unwrittenKey },
    { fault: "writes zeros", spoil: (key) => key.fill(0), detail: unwrittenKey },
    {
      fault: "gives another tag",
      spoil: (key) => (key[0] ^= 1),
      detail: "the page's Argon2 build gives another tag",
    },
  ];
  for (const { fault, spoil, detail } of faultyBuilds) {
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
}

/**
 * A build that goes wrong during the work fails its known answer after the last round: the result
 * is dropped, although every round ran and the container was shown as not yet verified.
 */
function checkLateFault() {
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
}

/**
 * The reference code wipes its work area before it frees it, and the bridge its copies of the
 * password, salt and key: after the 1 MiB known answer, a fresh single-threaded build's memory
 * holds about 2 KiB more non-zero bytes than before (allocator records and the stack of the last
 * block computation), where a work area left as it was would add 1 MiB. Fragile by nature: it
 * depends on where the allocator puts things, so its bound is generous. Gives what remains.
 */
async function checkArgon2Wipe() {
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
  return residue;
}

// Argon2 at full size takes minutes and 2 GiB, so a test-only engine stands in for it in the
// self-test: it answers each published input, the password after NFKD and a round's salt as the
// public vectors record them, with the recorded key, and any other input with a hash of it, as
// Argon2id gives some key for any input. The known answers reach the real build.

/** The public vectors whose round keys stand in for Argon2 at full size. */
const PUBLISHED_VECTOR_FILES = {
  suite3: "tests/fixtures/suite3-vectors/zero-12.json",
  suite4: "tests/fixtures/suite4-vectors/same-length-zero-12.json",
};
/** The key of each published round, by the round's password after NFKD and its salt, in hex. */
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
/** The bytes as hex digits. */
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
/** The self-test's result in `instance` of the bindings, with `argon2` in place of Argon2. */
const selfTestOf = (instance, argon2) => JSON.parse(instance.selfTest(argon2, noop));
/** Whether each built-in vector came out as published. */
const vectors = (suite3, suite4) => ({
  suite3: { vector: "zero-12", asPublished: suite3 },
  suite4: { vector: "same-length-zero-12", asPublished: suite4 },
});

/**
 * The self-test tells where it first left the published path, and how. With the published round
 * keys it gives the published results, with no fault; a key changed in one round is a fault in
 * Argon2id at that round; an input that is not published, here the password of the built-in suite
 * 3 vector with one letter changed, is a fault before Argon2id at the first round; and a result
 * that differs when every input and key was as published, here the built-in suite 3 container with
 * one letter changed, is a fault after the last Argon2id call.
 */
export function checkSelfTestFaults() {
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
      bindingsOver(
        damagedVector(PUBLISHED_VECTOR_FILES.suite3, '"password": "public test password'),
      ),
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
}
