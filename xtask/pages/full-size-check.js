// The checks of the full-size page of `cargo xtask browser-check-page`. The task puts in front of
// them the package's classes, WORKER_SOURCE, WASM_BASE64, ARGON2_THREADED, ARGON2_SINGLE_THREADED,
// PHRASE, TEST_PASSWORD, BIP84_ADDRESS and FULL_SIZE_CONTAINER, which the native tool and an
// independent OpenSSL script give for that phrase and password.

/** How long a run lasts before it is cancelled, inside round 1, and how soon that must stop it. */
const CANCEL_AFTER_MS = 500;
const CANCEL_WITHIN_MS = 20000;

const output = document.getElementById("log");
const log = (line) => {
  output.textContent += line + "\n";
};
const failures = [];
const expect = (condition, description) => {
  log((condition ? "ok    " : "FAIL  ") + description);
  if (!condition) failures.push(description);
};

async function expectRejection(promise, code, description) {
  try {
    await promise;
    expect(false, description + " (no error)");
  } catch (error) {
    expect(error.code === code, description + " -> " + error.code);
  }
}

async function main() {
  const wasm = Uint8Array.from(atob(WASM_BASE64), (character) => character.charCodeAt(0));
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm,
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
  });
  log("mode: " + client.mode() + ", protocol: " + location.protocol);
  const timer = performance.now();
  const seconds = () => ((performance.now() - timer) / 1000).toFixed(1) + " s";
  const onProgress = ({ stage, round, rounds }) =>
    log("  " + stage + " " + round + "/" + rounds + " at " + seconds());

  // The self-test only on request: it takes minutes.
  if (location.hash.includes("selftest")) {
    const result = await client.selfTest({ onProgress });
    expect(result.suite3.asPublished, "suite 3 " + result.suite3.vector + " encrypts as published");
    expect(
      result.suite4.asPublished,
      "suite 4 " + result.suite4.vector + " recovers as published (" + seconds() + ")",
    );
    expect(result.firstWrongRound === null, "every round key is as published");
    expect(result.fault === null, result.fault === null ? "no fault" : result.fault.message);
    return;
  }

  // The full self-check of every class: seconds, with Argon2 at 64 and 256 MiB.
  if (location.hash.includes("check")) {
    const compiled = await WebAssembly.compile(wasm);
    const parts = { workerSource: WORKER_SOURCE, wasm: compiled };
    for (
      const [name, instance] of [
        ["MhfeClient", client],
        ["MhfeRepair", new MhfeRepair(parts)],
        ["MhfePasswords", new MhfePasswords(parts)],
        ["MhfeWallet", new MhfeWallet(parts)],
      ]
    ) {
      const report = await instance.fullCheck();
      for (const { label, outcome, detail } of report.components) {
        log("  " + label + ": " + outcome + (detail === undefined ? "" : " (" + detail + ")"));
      }
      expect(report.passed, name + " passes its full self-check (" + seconds() + ")");
    }
    return;
  }

  // Refusals that need no Argon2 work. The public test wallet has no BIP39 passphrase.
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "a\uD800",
      passwordRepeat: "a\uD800",
      walletHasPassphrase: false,
    }),
    "INVALID_PASSWORD_TEXT",
    "unpaired surrogate refused",
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: TEST_PASSWORD,
      passwordRepeat: TEST_PASSWORD,
      walletHasPassphrase: false,
      memoryLevel: 1,
    }),
    "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
    "memory level 1 refused",
  );
  await expectRejection(
    client.encrypt({
      phrase: "abandon about",
      password: TEST_PASSWORD,
      passwordRepeat: TEST_PASSWORD,
      walletHasPassphrase: false,
    }),
    "INVALID_PHRASE",
    "invalid phrase refused by the worker",
  );

  // Cancelling inside the first round stops the worker at once.
  const started = performance.now();
  const cancelled = client.encrypt({
    phrase: PHRASE,
    password: TEST_PASSWORD,
    passwordRepeat: TEST_PASSWORD,
    walletHasPassphrase: false,
    onProgress: () => setTimeout(() => client.cancel(), CANCEL_AFTER_MS),
  });
  await expectRejection(cancelled, "CANCELLED", "cancel inside round 1");
  expect(
    performance.now() - started < CANCEL_WITHIN_MS,
    "cancel took under " + CANCEL_WITHIN_MS / 1000 + " s",
  );

  const { container } = await client.encrypt({
    phrase: PHRASE,
    password: TEST_PASSWORD,
    passwordRepeat: TEST_PASSWORD,
    walletHasPassphrase: false,
    onProgress,
  });
  expect(
    container === FULL_SIZE_CONTAINER,
    "full-size encryption gives the native container (" + seconds() + ")",
  );

  if (location.hash.includes("all")) {
    const recovery = await client.decrypt({ container, password: TEST_PASSWORD, onProgress });
    const candidate = recovery.candidates[0];
    expect(
      recovery.kind === "phrase" && candidate.phrase === PHRASE && candidate.words === 12
        && candidate.verified,
      "full-size decryption recovers the verified 12-word phrase (" + seconds() + ")",
    );
    const { matches } = await client.check({
      container,
      password: TEST_PASSWORD,
      reference: { address: BIP84_ADDRESS, coin: "bitcoin" },
      onProgress,
    });
    expect(matches === true, "rehearsal check with the address matches (" + seconds() + ")");
  }
}

main()
  .catch((error) => failures.push("page error: " + (error.code ?? "") + " " + error.message))
  .finally(() => {
    log(failures.length === 0 ? "SUMMARY: PASS" : "SUMMARY: FAIL " + failures.join("; "));
    document.title = failures.length === 0 ? "PASS" : "FAIL";
  });
