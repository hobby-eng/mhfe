// Part 2b: the self-check of each module, as its class runs it in a worker: exact parts and
// outcomes at both tiers, each part reported as it starts and ends.
// The parts of each module and their names, as the browser tests expect them too.
const {
  repair: REPAIR_PARTS,
  passwords: PASSWORD_PARTS,
  wallet: WALLET_PARTS,
  core: CORE_PARTS,
  labels: LABELS,
} = SELF_CHECK;
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
    timed(
      "passwords",
      (start, end) => bindings.selfCheckPasswords(tier, [], liveRandom, start, end),
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
    timed(
      "core without Argon2",
      (start, end) => bindings.selfCheckCore(tier, [], undefined, start, end),
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
// Fault: the memory above 1 MiB, refused as by a browser that cannot give it.
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
    )
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
for (
  const [tier, check] of [
    ["nightly", (start) => bindings.selfCheckRepair("nightly", [], start, noop)],
    ["Startup", (start) => bindings.selfCheckCore("Startup", [], undefined, start, noop)],
    ["", (start) => bindings.selfCheckArgon2("", [], realArgon2, start, noop)],
  ]
) {
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
// Fault: a card, an address and a search in the WebAssembly, damaged as by a download or memory.
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
const damagedAddress = bindingsOver(damaged(BIP84_ADDRESS));
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
