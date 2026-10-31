if (FULL) {
  const engine = argon2Engine(await builds.threaded());
  const created = operations.encrypt(PHRASE, PASSWORD, engine);
  assert.equal(created.container, FULL_SIZE_CONTAINER);
  console.log("A full-size encryption with the threaded build gives the native container.");
}

// The bridge's deliberate copy of ARGON2_MEMORY_ALLOCATION_ERROR (web/argon2-engine.js) is the
// value in argon2.h: the reference code returns it when the browser cannot give the Argon2 memory,
// and the bridge reports it as MEMORY_ALLOCATION_FAILED.
{
  const header = read("vendor/phc-winner-argon2/include/argon2.h").toString();
  const code = Number(/^\s*ARGON2_MEMORY_ALLOCATION_ERROR = (-\d+),/mu.exec(header)[1]);
  const module = await builds["single-threaded"]();
  // Fault: the reference code fails as when the browser refuses the memory, which the small cost
  // of this check cannot make it do.
  module._argon2id_hash_raw = () => code;
  assert.throws(
    () => argon2Engine(module).derive(PASSWORD, new Uint8Array(16), 1024, 1, new Uint8Array(32)),
    { message: "MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory" },
    "the bridge reads argon2.h's memory error as MEMORY_ALLOCATION_FAILED",
  );
}

// An Argon2 build that does not give its known answer is refused before any round: a bridge that
// leaves the key as it was or writes zeros, as a stale view of the WebAssembly's memory would, and
// a build that gives another tag. Nothing secret reaches it, and the self-check names it.
const realArgon2 = argon2Engine(await builds["single-threaded"]());
const noop = () => {};
const unwrittenKey = "Argon2id could not run: the Argon2 engine returned without writing the key";
// Fault: the key left as it was, zeroed or flipped, as by a broken build or a stale memory view.
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
    }));
  expectMessage(
    argon2Refused(detail),
    () => new core.HiddenWalletSession(ZERO_24, 0, 0, noBytes(), faulty),
  );
  assert.deepEqual(rounds, [], `${fault}: refused before round 1`);
}
// A build that goes wrong during the work fails its known answer after the last round: the result
// is dropped, although every round ran and the container was shown as not yet verified.
// Fault: the key of the second 1 MiB known answer, flipped as by a fault during the work.
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
expectMessage(
  argon2Refused("the page's Argon2 build gives another tag"),
  () =>
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
  `Argon2 builds that fail their known answer are refused before round 1 and after the last; `
    + `${residue} non-zero bytes remain after a known answer.`,
);

// The self-test tells where it first left the published path, and how. Argon2 at full size takes
// minutes and 2 GiB, so a test-only engine stands in for it: it answers each published input, the
// password after NFKD and a round's salt as the public vectors record them, with the recorded key,
// and any other input with some key that follows from it, as Argon2id gives one for any input.
// The known answers reach the real build. It gives the published results, with no fault; a key
// changed in one round is a fault in Argon2id at that round; an input that is not published, here
// the password of the built-in suite 3 vector with one letter changed, is a fault before Argon2id
// at the first round; and a result that differs when every input and key was as published, here
// the built-in suite 3 container with one letter changed, is a fault after the last Argon2id call.
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
/**
 * Some key for an input that the published vectors do not hold: any bytes that follow from it, at
 * once, as a stand-in Argon2 engine must answer in the call and the browser's digest cannot.
 */
function someKey(password, salt) {
  const key = new Uint8Array(KEY_BYTES);
  [...password, ...salt].forEach((byte, at) => {
    key[at % key.length] = (key[at % key.length] * 31 + byte) & 0xff;
  });
  return key;
}
// Fault: `spoil` may change a round's key, as a fault in Argon2id would.
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
          ? someKey(password, salt)
          : Buffer.from(recorded, "hex"),
      );
      spoil(rounds, key);
    },
    reserve: noop,
  };
}
// Fault: one letter of a built-in vector in the WebAssembly, damaged as by a download or memory.
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
// Fault: the key of round 5 or 17, changed as a fault in Argon2id would change it.
for (
  const [round, suite3, suite4] of [
    [5, false, true],
    [17, true, false],
  ]
) {
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
// Fault: a letter of the built-in vector's password, damaged as by a download or memory.
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
// Fault: a letter of the built-in vector's container, damaged as by a download or memory.
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
  "The self-test passes with the published round keys and names a fault in Argon2id, before it "
    + "and after it.",
);
