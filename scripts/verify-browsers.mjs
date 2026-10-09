// Runs the browser package from dist/ in real browsers, Chromium and Firefox, with Playwright:
//
//   node scripts/verify-browsers.mjs
//
// Build the package first with scripts/build-wasm.sh, install the tools with `npm ci` and the two
// browsers with `npx playwright install chromium firefox`.
//
// scripts/verify-browser-package.mjs checks the same code under Node.js with a stand-in worker.
// This check adds what only a browser does: Blob workers under the Content-Security-Policy of the
// offline wallet tools, the transfer of secrets to them, the threaded Argon2 build in a
// cross-origin isolated page, cancellation and the page's failing callbacks. Each browser opens
// the page twice: as a file (standard mode) and from a loopback server with the isolation
// headers (fast mode), as `mhfe serve` gives them. The page calls every method of the four classes
// with each of its options and compares the results, or the refusals, with known values: public
// vectors, values computed independently, or the results of another method or class.
//
// So that Argon2 takes seconds, a test-only wrapper in the page's copy of the worker runs it with
// 256 KiB and one pass instead of the 2 GiB and twelve passes of suite 3, after checking that
// the core asked for those. The container must then be REDUCED_COST_CONTAINER, which the native
// tests (src/mhfe.rs) and scripts/verify-browser-package.mjs check at the same cost. Only public
// test data is used, and no request may leave the page. The same-length container must be
// REDUCED_COST_SAME_LENGTH_CONTAINER of src/mhfe.rs at that cost. The same wrapper stands for a
// browser that cannot give the memory, for one marker password and one marker container. A run
// takes a few minutes, mostly for the two phrases per page drawn to pass the wallet check, about
// 65,536 BIP39 seeds each.
//
// What the reduced cost cannot show: a PIM above 0 (the wrapper refuses any cost but suite 3's,
// so the page only checks the cost the core asks for) and the self-test's verdict on the published
// vectors, which are computed at full cost (the page checks that it runs both and says "not as
// published"). Nor can a page see whether a worker it stopped has really ended. The known answers
// of the Argon2 builds, at 1, 64 and 256 MiB, pass the wrapper unchanged: every class's startup
// check runs in each page, with its time, under the same policy, the full self-checks too, and a
// WebAssembly whose vector was damaged must close its classes, while an Argon2 build that does
// not start must leave the client open and one of another build must be refused.
import { createECDH, createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath, pathToFileURL } from "node:url";

import { chromium, firefox } from "playwright";

import { bundleClasses } from "./bundle-browser-classes.mjs";
import {
  AMBIGUOUS_12_WORDS,
  FULL_SIZE_CONTAINER,
  PHRASE,
  REDUCED_COST_CONTAINER,
  REDUCED_COST_SAME_LENGTH_CONTAINER,
  SELF_CHECK_PARTS as SELF_CHECK,
} from "./public-test-data.mjs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
/** JSON that is safe inside a script element: "</script" cannot appear in it. */
const inline = (value) => JSON.stringify(value).replaceAll("<", "\\u003c");

// How long one page may take. The page's other checks take under a minute; each of its two
// drawings of a phrase that passes the wallet check takes about 65,536 BIP39 seeds on average,
// half a minute on eight workers, but the number is random: more than N times the average happens
// about once in e^N drawings (more than four times, once in 55). Ten minutes leave room for eight
// times the average of both together, which two drawings exceed about once in 500,000 pages
// (e^-16 x 17), so a page that times out has stopped, not drawn long.
const PAGE_TIMEOUT_MS = 600_000;

// The public test data the page and this script share, beside scripts/public-test-data.mjs.
// Passes the wallet check with the passphrase "TREZOR" (TREZOR_COUNTER in src/wallet_check.rs).
const CHECKED_PHRASE = "abandon ".repeat(21) + "above proof fatigue";
// Passes the wallet check without a passphrase (EMPTY_COUNTER in src/wallet_check.rs).
const EMPTY_CHECKED_PHRASE = "abandon ".repeat(21) + "absorb another spoil";
// The wrong password of the page, one letter off PASSWORD.
const WRONG_PASSWORD = "public test passwore";
// The 256-bit states of PHRASE and of AMBIGUOUS_12_WORDS read as other lengths. A state is the
// phrase's entropy followed by the first bytes of the entropy's SHA-256 (src/packing.rs): for
// PHRASE 16 zero bytes and the first 16 bytes of their SHA-256, for AMBIGUOUS_12_WORDS
// 4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad. These phrases were computed
// from those bytes with the BIP39 English list (SHA-256 of english.txt 2f5eed53...3b24dbda),
// independently of mhfe; the 21 words are the first 28 bytes, the 24 words all 32.
//
// wrongPasswordAs24 is what WRONG_PASSWORD reads from REDUCED_COST_CONTAINER as 24 words. It
// depends on the reduced cost, so it was taken once from this page; the page also encrypts it
// again with WRONG_PASSWORD, which must give REDUCED_COST_CONTAINER, the container of the native
// tests, back. The cipher is a permutation, so only the right 24 words do that.
const READINGS = {
  phraseAs24:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about inner love zone until oven protect tray movie front reopen emerge bachelor",
  ambiguousAs21:
    "essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock",
  ambiguousAs24:
    "essence drama mule dolphin bitter rain abandon abandon able human mule relax forest bleak chest march april confirm pill east sock simple dress sand",
  wrongPasswordAs24:
    "wash humor junk coil author glide void dynamic donor patrol beach outdoor result subject piece mix aim juice raise enjoy pattern name miracle pact",
};
// The password whose encryption check the wrapper below spoils.
const FAULTY_CHECK_PASSWORD = "public test password, faulty check";
// The password and the container for which the wrapper below fails as a browser does that cannot
// give the Argon2 memory: in every round of the password, and when a session of hidden wallets on
// the container reserves its work area. The container is the public vector zero-12.
const MEMORY_FAILURE_PASSWORD = "public test password, memory refused";
const MEMORY_FAILURE_CONTAINER = FULL_SIZE_CONTAINER;

/** The BIP39 seed of a phrase: PBKDF2-HMAC-SHA512, 2,048 iterations, salt "mnemonic" + passphrase. */
function bip39Seed(phrase, passphrase) {
  const BIP39_ITERATIONS = 2048;
  const SEED_BYTES = 64;
  return pbkdf2Sync(
    phrase.normalize("NFKD"),
    `mnemonic${passphrase}`.normalize("NFKD"),
    BIP39_ITERATIONS,
    SEED_BYTES,
    "sha512",
  );
}

/**
 * The BIP32 master key fingerprint of a BIP39 phrase, computed here with Node's crypto from BIP39
 * and BIP32 alone, independently of mhfe: the seed, the master key (HMAC-SHA512 keyed "Bitcoin
 * seed"), its compressed secp256k1 public key, and the first four bytes of RIPEMD-160 of SHA-256
 * of that key.
 */
function masterFingerprint(phrase, passphrase) {
  // The master private key is the left half of the HMAC; the right half is its chain code.
  const masterKey = createHmac("sha512", "Bitcoin seed")
    .update(bip39Seed(phrase, passphrase))
    .digest()
    .subarray(0, 32);
  const curve = createECDH("secp256k1");
  curve.setPrivateKey(masterKey);
  const publicKey = curve.getPublicKey(null, "compressed");
  const keyHash = createHash("ripemd160")
    .update(createHash("sha256").update(publicKey).digest())
    .digest();
  return keyHash.subarray(0, 4).toString("hex");
}

/**
 * Whether a 24-word phrase passes the wallet check MHFE-WALLET-CHECK-SEED-1 with a passphrase,
 * computed here from its definition in src/wallet_check.rs, independently of mhfe: SHA-256 of the
 * ASCII tag, the entropy's 256 bits as a 4-byte big-endian number and the BIP39 seed starts with
 * two zero bytes, 16 bits.
 */
function passesWalletCheck(phrase, passphrase) {
  const ENTROPY_BITS = 256;
  const bits = Buffer.alloc(4);
  bits.writeUInt32BE(ENTROPY_BITS);
  const digest = createHash("sha256")
    .update("MHFE-WALLET-CHECK-SEED-1")
    .update(bits)
    .update(bip39Seed(phrase, passphrase))
    .digest();
  return digest[0] === 0 && digest[1] === 0;
}

// The computations above must first give the published 73c5da0a and the b4e3f5ed of
// src/wallet.rs, both of the BIP39 test phrase, and the two public counters of the wallet check,
// before their other values are trusted.
if (
  masterFingerprint(PHRASE, "") !== "73c5da0a" ||
  masterFingerprint(PHRASE, "TREZOR") !== "b4e3f5ed"
) {
  throw new Error("The independent fingerprint computation does not give the published values.");
}
if (
  !passesWalletCheck(CHECKED_PHRASE, "TREZOR") ||
  passesWalletCheck(CHECKED_PHRASE, "") ||
  !passesWalletCheck(EMPTY_CHECKED_PHRASE, "")
) {
  throw new Error("The independent wallet check does not give the published values.");
}
const FINGERPRINTS = {
  phrase: "73c5da0a",
  phraseWithTrezor: "b4e3f5ed",
  reducedCostContainer: masterFingerprint(REDUCED_COST_CONTAINER, ""),
  sameLengthContainer: masterFingerprint(REDUCED_COST_SAME_LENGTH_CONTAINER, ""),
  fullSizeContainer: masterFingerprint(FULL_SIZE_CONTAINER, ""),
  checkedPhrase: masterFingerprint(CHECKED_PHRASE, ""),
  checkedPhraseWithTrezor: masterFingerprint(CHECKED_PHRASE, "TREZOR"),
  emptyCheckedPhrase: masterFingerprint(EMPTY_CHECKED_PHRASE, ""),
  ambiguous12Words: masterFingerprint(AMBIGUOUS_12_WORDS, ""),
};
for (const [name, phrase] of Object.entries(READINGS)) {
  FINGERPRINTS[name] = masterFingerprint(phrase, "");
}
// Whether each 24-word reading passes the wallet check without a passphrase.
const WALLET_CHECKS = {
  phraseAs24: passesWalletCheck(READINGS.phraseAs24, ""),
  ambiguousAs24: passesWalletCheck(READINGS.ambiguousAs24, ""),
  wrongPasswordAs24: passesWalletCheck(READINGS.wrongPasswordAs24, ""),
};

// The suite 3 cost the core must ask for, and the reduced cost that replaces it here: the cost of
// REDUCED_COST_CONTAINER in src/mhfe.rs. Any other cost is refused with the cost asked for in the
// message, so that the page sees what a PIM asks for. With FAULTY_CHECK_PASSWORD the wrapper
// changes one bit of the key from the 13th call on, the rounds in which an encryption checks its
// new container: it stands for a fault during the long computation, which that check must catch.
// The memory markers fail with the message of the real Argon2 bridge (web/argon2-engine.js), whose
// prefix the core turns into MEMORY_ALLOCATION_FAILED. The wrapper replaces argon2For, which
// receives the request, so that the reserve sees the container; a block keeps its names apart
// from those of the worker and of the Argon2 build in front of it.
const reducedCostWrapper = `
{
  const fullCostArgon2For = argon2For;
  const encoder = new TextEncoder();
  const faultyCheckPassword = encoder.encode(${inline(FAULTY_CHECK_PASSWORD)});
  const memoryFailurePassword = encoder.encode(${inline(MEMORY_FAILURE_PASSWORD)});
  const sameBytes = (bytes, other) =>
    bytes.length === other.length && bytes.every((byte, index) => byte === other[index]);
  const memoryFailure = () =>
    new Error("MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory");
  // The costs of the builds' known answers (src/engine/known_answers.rs), which reach the build.
  const knownAnswerCosts = ["1024/1", "65536/3", "262144/2"];
  argon2For = async (request) => {
    const engine = await fullCostArgon2For(request);
    let calls = 0;
    return {
      derive(password, salt, memoryKib, passes, key) {
        if (knownAnswerCosts.includes(memoryKib + "/" + passes)) {
          return engine.derive(password, salt, memoryKib, passes, key);
        }
        if (memoryKib !== 2097152 || passes !== 12) {
          throw new Error(
            "TEST_COST: the core asked for " + memoryKib + " KiB and " + passes + " passes",
          );
        }
        if (sameBytes(password, memoryFailurePassword)) throw memoryFailure();
        engine.derive(password, salt, 256, 1, key);
        calls += 1;
        if (sameBytes(password, faultyCheckPassword) && calls > 12) key[0] ^= 1;
      },
      reserve(memoryKib) {
        if (memoryKib !== 2097152) throw new Error("TEST_COST: the core did not reserve 2 GiB");
        if (request.container === ${inline(MEMORY_FAILURE_CONTAINER)}) throw memoryFailure();
        return engine.reserve(256);
      },
    };
  };
}
`;

/**
 * The page's checks. This function never runs here: the page gets its source text after the
 * package's classes and the constants of `sources`, and calls it.
 */
function pageScript() {
  const PASSWORD = "public test password";
  const NEW_PASSWORD = "another public test password";
  const THIRD_PASSWORD = "a third public test password";
  // "abandon" 23 times and "art": the 24-word phrase of zero entropy.
  const ZERO_24 = "abandon ".repeat(23) + "art";
  // The public check word vector of the specification (src/check_word.rs), typed in other ways.
  const CHECK_WORD_PASSWORD = "jovial trailing chokehold pavilion cresting ninth";
  const CHECK_WORD_DICE = "35214 62431 15543 44126 21365";
  const CHECK_WORD_MISSING = "jovial trailing ? pavilion cresting ninth";
  const CHECK_WORD_CAPITALS = "JOVIAL Trailing chokehold pavilion cresting ninth";
  // Addresses of PHRASE's wallet (src/wallet.rs): BIP84's published first address, the change
  // address 7 of account 3, the first address with the passphrase "TREZOR" and Ethereum's first.
  const BIP84_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
  const BIP84_PATH = "m/84'/0'/0'/0/0";
  const BIP84_ACCOUNT_3_CHANGE_7 = "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry";
  const BIP84_TREZOR_ADDRESS = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";
  const ETHEREUM_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
  const ETHEREUM_PATH = "m/44'/60'/0'/0/0";
  // The same BIP84 address with its last character changed: its checksum fails.
  const DAMAGED_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv";
  const FINGERPRINT = FINGERPRINTS.phrase;
  const SUITE_3 = "MHFE-BIP39-256-EXPERIMENTAL-3";
  const SUITE_4 = "MHFE-BIP39-LP-EXPERIMENTAL-4";
  const REPAIR_PROFILE = "MHFE-REPAIR-1";
  // The repair words of FULL_SIZE_CONTAINER for each count, from an independent implementation
  // (src/repair.rs).
  const FULL_SIZE_REPAIR_WORDS = {
    2: "labor extra",
    4: "shaft pupil patient jewel",
    6: "credit buzz orbit tired sail coffee",
    8: "appear include vicious move uphold tiger song satoshi",
  };
  // What PIM 1 asks Argon2 for, as the reduced-cost wrapper reports it when it refuses it: the
  // memory of level 0 and 12 x (PIM + 1) passes (src/suite.rs).
  const PIM_1_COST = "2097152 KiB and 24 passes";
  const REPAIR_WORD_CHOICES = [2, 4, 6, 8];
  const KEEP_24 = [{ item: "containerWords", words: 24 }, { item: "password" }];
  const KEEP_SAME_LENGTH = [{ item: "containerWords", words: 12 }, { item: "password" }];
  const PASSPHRASE = { item: "passphrase" };
  const PASSPHRASE_IF_ANY = { item: "passphraseIfAny" };
  // The client's TypeErrors for a walletHasPassphrase that is not a boolean and for a passphrase
  // with the built-in check or the owner (web/client.js), and the library's refusals of a rekey
  // whose passphrase is not stated or stated against its reference (src/rekey.rs), of the
  // built-in check where the length has none or is detected, and of a stated length that the
  // built-in check contradicts (src/error.rs), exactly as the page gets them.
  const WALLET_PASSPHRASE_REQUIRED =
    "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase.";
  const PASSPHRASE_ONLY_WITH_REFERENCE =
    "passphrase belongs only to an address or fingerprint confirmation.";
  const PASSPHRASE_UNSTATED = "Invalid request: say whether the wallet has a BIP39 passphrase";
  const PASSPHRASE_CONTRADICTED =
    "Invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows";
  const REFERENCE_REQUIRED =
    "The built-in check alone does not confirm this recovery: a 24-word original seed phrase, a " +
    "same-length container and a detected length need a receiving address or the master key " +
    "fingerprint of the wallet, or the owner's comparison with the backup, before the phrase is " +
    "encrypted again";
  const lengthDiffers = (found, stated) =>
    `The built-in check finds a ${found}-word original seed phrase, not the ${stated} words ` +
    "stated: confirm it with a receiving address or the master key fingerprint of the wallet";
  const encode = (text) => new TextEncoder().encode(text);

  const results = [];
  const failures = [];
  function expect(condition, description) {
    results.push((condition ? "ok   " : "FAIL ") + description);
    if (!condition) failures.push(description);
  }

  async function expectRejection(promise, code, description, cause) {
    try {
      await promise;
      expect(false, description + " (it resolved)");
    } catch (error) {
      const sameCause = cause === undefined || error.cause === cause;
      expect(error.code === code && sameCause, description + " -> " + error.code);
    }
  }

  /** A heading in the results, one per class or method. */
  function group(title) {
    results.push("-- " + title);
  }

  /** Like expect, but a failure shows the value that was received. */
  function expectEqual(actual, expected, description) {
    const equal = sameValue(actual, expected);
    expect(equal, equal ? description : `${description}: got ${JSON.stringify(actual)}`);
  }

  /**
   * Like expectRejection, for a code that several causes share: the message must also contain
   * `message`, which tells the cause.
   */
  async function expectRefusal(promise, code, message, description) {
    const error = await rejectionOf(promise);
    expect(
      error?.code === code && error.message.includes(message),
      `${description} -> ${error === null ? "it resolved" : `${error.code}: ${error.message}`}`,
    );
  }

  /** Like expectRefusal, for the whole message. */
  async function expectExactRefusal(promise, code, message, description) {
    const error = await rejectionOf(promise);
    expect(
      error?.code === code && error.message === message,
      `${description} -> ${error === null ? "it resolved" : `${error.code}: ${error.message}`}`,
    );
  }

  /**
   * A TypeError of the package, told apart from an accidental one, such as "Cannot read
   * properties of undefined", by `message`, a distinctive part of the message the package throws.
   */
  function isTypeError(error, message) {
    return error instanceof TypeError && error.message.includes(message);
  }

  async function expectTypeError(promise, message, description) {
    const error = await rejectionOf(promise);
    expect(
      isTypeError(error, message),
      `${description} -> ${error === null ? "it resolved" : `${error.name}: ${error.message}`}`,
    );
  }

  /** Like expectTypeError, for the whole message. */
  async function expectExactTypeError(promise, message, description) {
    const error = await rejectionOf(promise);
    expect(
      error instanceof TypeError && error.message === message,
      `${description} -> ${error === null ? "it resolved" : `${error.name}: ${error.message}`}`,
    );
  }

  function expectThrownTypeError(action, message, description) {
    try {
      action();
      expect(false, description + " (nothing was thrown)");
    } catch (error) {
      expect(isTypeError(error, message), `${description} -> ${error.name}: ${error.message}`);
    }
  }

  /** "resolved", "rejected", or "pending" when the promise has not settled after `ms`. */
  async function outcomeWithin(promise, ms) {
    let timer;
    const pending = new Promise((resolve) => {
      timer = setTimeout(() => resolve("pending"), ms);
    });
    const settled = promise.then(
      () => "resolved",
      () => "rejected",
    );
    const outcome = await Promise.race([settled, pending]);
    clearTimeout(timer);
    return outcome;
  }

  /** The error a promise rejects with, or null when it resolves. */
  async function rejectionOf(promise) {
    try {
      await promise;
      return null;
    } catch (error) {
      return error;
    }
  }

  /** Whether two JSON-like values are equal, objects whatever the order of their keys. */
  function sameValue(a, b) {
    if (a === b) return true;
    if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    const keys = Object.keys(a);
    return (
      keys.length === Object.keys(b).length &&
      keys.every((key) => Object.hasOwn(b, key) && sameValue(a[key], b[key]))
    );
  }

  /** The named fields of an object, to compare them without the others. */
  function fieldsOf(object, names) {
    return Object.fromEntries(names.map((name) => [name, object?.[name]]));
  }

  /** A progress callback and the "stage round/rounds" lines it has received, in order. */
  function progressLog() {
    const lines = [];
    return {
      lines,
      onProgress: ({ stage, round, rounds }) => lines.push(`${stage} ${round}/${rounds}`),
    };
  }

  /** The progress lines of rounds `first` to `last` of `rounds` in `stage`. */
  function roundLines(stage, first, last, rounds) {
    return Array.from(
      { length: last - first + 1 },
      (_, index) => `${stage} ${first + index}/${rounds}`,
    );
  }

  async function main() {
    // The core takes the package's WebAssembly as bytes; the other classes share one compiled
    // module, as a page that uses several classes does.
    const client = new MhfeClient({
      workerSource: WORKER_SOURCE,
      wasm: bytes(WASM_BASE64),
      argon2Threaded: ARGON2_THREADED,
      argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    });
    const compiled = await WebAssembly.compile(bytes(WASM_BASE64));
    const repair = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: compiled });
    const passwords = new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled });
    const wallet = new MhfeWallet({ workerSource: WORKER_SOURCE, wasm: compiled });
    // Containers the encryption checks make, for the checks of the other methods.
    const made = {};

    await checkStartupChecks(client, repair, passwords, wallet);
    await checkConstruction(client, compiled);
    await checkReading(client);
    await checkEncrypt(client, repair, made);
    await checkDecrypt(client, wallet, made);
    await checkRehearsal(client, made);
    await checkCancelAndCallbacks(client);
    await checkMemoryFailures(client);
    await checkRekey(client, repair, wallet, made);
    await checkHiddenWallets(client, wallet, made);
    await checkSelfTest(client);
    await checkFullChecks(client, repair, passwords, wallet);
    await checkFailingSelfCheck(compiled);
    await checkArgon2Start();
    await checkRepair(repair);
    await checkPasswords(passwords);
    await checkWallet(wallet);
    await checkRuntime(client, passwords, wallet, compiled);
    return client.mode();
  }

  async function checkConstruction(client, compiled) {
    group("MhfeClient: construction and fixed values");
    const parts = {
      workerSource: WORKER_SOURCE,
      argon2Threaded: ARGON2_THREADED,
      argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    };
    expectThrownTypeError(
      () => new MhfeClient(),
      "workerSource must be the text of the file.",
      "a client without its parts is refused",
    );
    expectThrownTypeError(
      () => new MhfeClient({ ...parts, workerSource: "", wasm: compiled }),
      "workerSource must be the text of the file.",
      "an empty workerSource is refused",
    );
    expectThrownTypeError(
      () => new MhfeClient({ ...parts, argon2Threaded: undefined, wasm: compiled }),
      "argon2Threaded must be the text of the file.",
      "a missing threaded Argon2 build is refused",
    );
    expectThrownTypeError(
      () => new MhfeClient({ ...parts, argon2SingleThreaded: 42, wasm: compiled }),
      "argon2SingleThreaded must be the text of the file.",
      "a single-threaded Argon2 build that is not text is refused",
    );
    expectThrownTypeError(
      () => new MhfeClient({ ...parts, wasm: "runtime/mhfe.wasm" }),
      "wasm must be a Uint8Array or a WebAssembly.Module.",
      "a wasm that is neither bytes nor a compiled module is refused",
    );
    expect(client.maxSupportedMemLevel() === 0, "maxSupportedMemLevel is 0, 2 GiB");
    const parameters = await client.parameters();
    expect(parameters.version === VERSION, "the core reports the package version");
    expectEqual(
      parameters,
      {
        version: VERSION,
        suiteId: SUITE_3,
        sameLengthSuiteId: SUITE_4,
        rounds: 12,
        maxPim: 1023,
        maxMemoryLevel: 21,
        highestBrowserMemoryLevel: 0,
        wordCounts: [12, 15, 18, 21, 24],
        builtInCheckWordCounts: [12, 15, 18, 21],
        repairWordCounts: [2, 4, 6, 8],
        recommendedRepairWords: 4,
        repairCapacities: [
          { count: 2, unreadable: 2, wrong: 1 },
          { count: 4, unreadable: 4, wrong: 2 },
          { count: 6, unreadable: 6, wrong: 3 },
          { count: 8, unreadable: 8, wrong: 4 },
        ],
        hiddenWalletRefusals: [
          "PASSWORD_ALREADY_USED",
          "HIDDEN_WALLET_PASSES_CHECK",
          "PASSWORDS_DIFFER",
          "PASSWORD_REPAIR_NOT_OFFERED",
          "EMPTY_PASSWORD",
          "PASSWORD_TOO_LONG",
          "INVALID_PASSWORD_UTF8",
          "CONTROL_CHARACTER_IN_PASSWORD",
          "UNASSIGNED_CHARACTER",
        ],
        decoyScanGap: 20,
        argon2Parts: ["argon2", "argon2-sizes"],
      },
      "parameters gives every fixed value of the core",
    );
    const fromModule = new MhfeClient({ ...parts, wasm: compiled });
    expect(fromModule.maxSupportedMemLevel() === 0, "a client takes a compiled WebAssembly.Module");
    const recovery = await fromModule.decrypt({
      container: REDUCED_COST_CONTAINER,
      password: PASSWORD,
    });
    expect(
      recovery.candidates[0].phrase === PHRASE,
      "a client given the compiled module runs a long operation",
    );
  }

  async function checkReading(client) {
    group("MhfeClient.readPhrase and readContainer");
    const read = await client.readPhrase(PHRASE.toUpperCase());
    expect(
      read.phrase === PHRASE && read.words === 12 && read.otherLengths.length === 0,
      "readPhrase writes every word out",
    );
    const shortForms = PHRASE.split(" ")
      .map((word) => word.slice(0, 4))
      .join("  ");
    expectEqual(
      await client.readPhrase(shortForms),
      {
        phrase: PHRASE,
        words: 12,
        otherLengths: [],
        containers: [
          { sameLength: false, words: 24, wrongWordPassesOneIn: 256, otherLengths: [] },
          { sameLength: true, words: 12, wrongWordPassesOneIn: 16, otherLengths: [] },
        ],
      },
      "readPhrase reads four-letter forms and lists the 24-word and the same-length container",
    );
    expectEqual(
      (await client.readPhrase(AMBIGUOUS_12_WORDS)).otherLengths,
      [21],
      "readPhrase names the other length that detection would also accept",
    );
    const long = await client.readPhrase(ZERO_24);
    expect(
      long.containers.length === 1 &&
        long.containers[0].sameLength === false &&
        long.containers[0].words === 24,
      "a 24-word phrase has only the 24-word container",
    );
    await expectRejection(
      client.readPhrase("abandon about"),
      "INVALID_PHRASE",
      "a phrase of two words is refused",
    );
    await expectRejection(
      client.readPhrase("abandon ".repeat(11) + "abandon"),
      "INVALID_PHRASE",
      "a phrase whose checksum fails is refused",
    );

    const containerShortForms = REDUCED_COST_CONTAINER.toUpperCase()
      .split(" ")
      .map((word) => word.slice(0, 4))
      .join(" ");
    expectEqual(
      await client.readContainer(containerShortForms),
      {
        container: REDUCED_COST_CONTAINER,
        words: 24,
        suiteId: SUITE_3,
        phraseLengths: [12, 15, 18, 21, 24],
        builtInCheckLengths: [12, 15, 18, 21],
        // A detected length needs the wallet or its owner: a 24-word original may pass a short
        // check by chance (AUD-017-FUN001).
        confirmationFor: {
          0: "walletOrOwner",
          12: "builtInCheck",
          15: "builtInCheck",
          18: "builtInCheck",
          21: "builtInCheck",
          24: "walletOrOwner",
        },
        hiddenWallets: true,
        offersWalletCheck: true,
        containerFingerprint: FINGERPRINTS.reducedCostContainer,
      },
      "readContainer gives every fact of a 24-word container typed in capitals and short forms",
    );
    expectEqual(
      await client.readContainer(REDUCED_COST_SAME_LENGTH_CONTAINER),
      {
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        words: 12,
        suiteId: SUITE_4,
        phraseLengths: [12],
        builtInCheckLengths: [],
        confirmationFor: { 0: "walletOrOwner", 12: "walletOrOwner" },
        hiddenWallets: false,
        offersWalletCheck: false,
        containerFingerprint: FINGERPRINTS.sameLengthContainer,
      },
      "readContainer gives every fact of a same-length container",
    );
    await expectRejection(
      client.readContainer("abandon about"),
      "INVALID_CONTAINER",
      "a container of two words is refused",
    );

    // The search for missing words without the repair words: the candidates, and the decoy
    // wallet, the container itself, found by its fingerprint without a password or Argon2.
    const missingLast = FULL_SIZE_CONTAINER.split(" ")
      .map((word, index) => (index === 23 ? "?" : word))
      .join(" ");
    expectEqual(
      await client.searchCandidates({ container: missingLast }),
      { missing: [24], candidates: 8, offersWalletSearch: true, offersOwnChecks: true },
      "searchCandidates counts the 8 candidates of a missing last word",
    );
    const progress = [];
    const found = await client.searchDecoy({
      container: missingLast,
      reference: { fingerprint: FINGERPRINTS.fullSizeContainer },
      onProgress: (value) => progress.push(value),
    });
    expectEqual(
      fieldsOf(found, ["found", "container", "words", "containerFingerprint"]),
      {
        found: true,
        container: FULL_SIZE_CONTAINER,
        words: [{ position: 24, word: "peace" }],
        containerFingerprint: FINGERPRINTS.fullSizeContainer,
      },
      "searchDecoy finds the missing word by the container's own fingerprint",
    );
    expect(
      progress.at(-1)?.stage === "search" && progress.at(-1)?.candidates === 8,
      "searchDecoy tells how far it has come",
    );
    const missed = await client.searchDecoy({
      container: missingLast,
      reference: { fingerprint: "00000000" },
    });
    expectEqual(
      fieldsOf(missed, ["found", "container"]),
      { found: false, container: null },
      "searchDecoy finds nothing with another fingerprint",
    );
    await expectRejection(
      client.searchWallet({
        container: missingLast.replace(/^\S+/, "?"),
        password: PASSWORD,
        reference: { builtInCheck: true },
      }),
      "TOO_MANY_MISSING_WORDS",
      "searchWallet refuses two missing words before any round",
    );
  }

  async function checkEncrypt(client, repair, made) {
    group("MhfeClient.encrypt");
    const sealPhrase = (options) =>
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        ...options,
      });
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: "a\tb",
        passwordRepeat: "a\tb",
        walletHasPassphrase: false,
      }),
      "CONTROL_CHARACTER_IN_PASSWORD",
      "a password with a TAB is refused",
    );

    const log = progressLog();
    const shown = [];
    const sealed = await sealPhrase({
      repairWordCount: 4,
      onProgress: log.onProgress,
      onUnverified: (result) => {
        log.lines.push("unverified");
        shown.push(result);
      },
    });
    expectEqual(
      log.lines,
      [...roundLines("encrypt", 1, 12, 24), "unverified", ...roundLines("check", 13, 24, 24)],
      "encrypt runs 12 rounds, shows the container unverified, then checks it in 12 more",
    );
    expectEqual(
      shown,
      [
        {
          container: REDUCED_COST_CONTAINER,
          containerFingerprint: FINGERPRINTS.reducedCostContainer,
        },
      ],
      "onUnverified receives the native container and its fingerprint",
    );
    const cards = {};
    for (const count of REPAIR_WORD_CHOICES) {
      cards[count] = (await repair.repairWords({ container: REDUCED_COST_CONTAINER, count })).words;
    }
    expectEqual(
      sealed,
      {
        container: REDUCED_COST_CONTAINER,
        suiteId: SUITE_3,
        containerFingerprint: FINGERPRINTS.reducedCostContainer,
        builtInCheck: true,
        otherLengths: [],
        repairWords: cards[4],
        repairProfile: REPAIR_PROFILE,
        keep: [...KEEP_24, { item: "repairWords" }],
      },
      "encrypt resolves to the native container with every field and the repair module's card",
    );

    const passwordBytes = encode(PASSWORD);
    const repeatBytes = encode(PASSWORD);
    const asTyped = await client.encrypt({
      phrase: PHRASE,
      password: passwordBytes,
      passwordRepeat: repeatBytes,
      passwordRepair: "asTyped",
      repairWordCount: 2,
      walletHasPassphrase: false,
    });
    expect(
      asTyped.container === REDUCED_COST_CONTAINER &&
        asTyped.repairWords === cards[2] &&
        asTyped.repairProfile === REPAIR_PROFILE,
      "a password as bytes, kept as typed, gives the same container, with two repair words",
    );
    const decoder = new TextDecoder();
    expect(
      decoder.decode(passwordBytes) === PASSWORD && decoder.decode(repeatBytes) === PASSWORD,
      "the page's password bytes are copied, neither emptied nor wiped",
    );
    const withPassphrase = await sealPhrase({ walletHasPassphrase: true, repairWordCount: 6 });
    expectEqual(
      withPassphrase,
      {
        ...sealed,
        repairWords: cards[6],
        keep: [...KEEP_24, { item: "passphrase" }, { item: "repairWords" }],
      },
      "walletHasPassphrase adds the passphrase to what to keep; six repair words and their profile",
    );
    // Without callbacks, as for output to a file: the result comes only after the check.
    const quiet = await sealPhrase({ repairWordCount: 8 });
    expectEqual(
      quiet,
      { ...sealed, repairWords: cards[8] },
      "encrypt without callbacks resolves to the checked container, eight repair words and profile",
    );
    expectEqual(
      await client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: repeatBytes,
        walletHasPassphrase: false,
      }),
      { ...sealed, repairWords: null, repairProfile: null, keep: KEEP_24 },
      "a password as text and its repetition as the same bytes are the same password",
    );
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: passwordBytes,
        passwordRepeat: WRONG_PASSWORD,
        walletHasPassphrase: false,
      }),
      "PASSWORDS_DIFFER",
      "a password as bytes and a repetition as other text differ",
    );

    const checkWord = await client.encrypt({
      phrase: PHRASE,
      password: CHECK_WORD_PASSWORD,
      passwordRepeat: CHECK_WORD_PASSWORD,
      walletHasPassphrase: false,
    });
    made.checkWord = checkWord.container;
    const corrected = await client.encrypt({
      phrase: PHRASE,
      password: CHECK_WORD_CAPITALS,
      passwordRepeat: CHECK_WORD_CAPITALS,
      passwordRepair: "corrected",
      walletHasPassphrase: false,
    });
    expect(
      corrected.container === made.checkWord,
      'passwordRepair "corrected" encrypts with the written form of the password',
    );
    const restored = await client.encrypt({
      phrase: PHRASE,
      password: CHECK_WORD_MISSING,
      passwordRepeat: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
      walletHasPassphrase: false,
    });
    expect(
      restored.container === made.checkWord,
      "passwordRepair { repair: 3 } encrypts with the restored third word",
    );
    await expectRejection(
      sealPhrase({ passwordRepair: "corrected" }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      '"corrected" is refused for a password the review does not correct',
    );

    const same = await sealPhrase({ sameLength: true });
    expectEqual(
      same,
      {
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        suiteId: SUITE_4,
        containerFingerprint: FINGERPRINTS.sameLengthContainer,
        builtInCheck: false,
        otherLengths: [],
        repairWords: null,
        repairProfile: null,
        keep: [{ item: "containerWords", words: 12 }, { item: "password" }],
      },
      "encrypt with sameLength gives the native 12-word container with every field",
    );
    const ambiguous = await client.encrypt({
      phrase: AMBIGUOUS_12_WORDS,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    });
    made.ambiguous = ambiguous.container;
    expectEqual(
      fieldsOf(ambiguous, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
      {
        suiteId: SUITE_3,
        builtInCheck: true,
        otherLengths: [21],
        keep: [...KEEP_24, { item: "wordCount", words: 12 }],
      },
      "a phrase that detection could also read as 21 words adds its word count to what to keep",
    );
    const checked = await client.encrypt({
      phrase: CHECKED_PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      walletHasPassphrase: false,
    });
    made.checked = checked.container;
    expectEqual(
      fieldsOf(checked, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
      { suiteId: SUITE_3, builtInCheck: false, otherLengths: [], keep: KEEP_24 },
      "a 24-word phrase gets a 24-word container without a built-in check",
    );
    made.emptyChecked = (
      await client.encrypt({
        phrase: EMPTY_CHECKED_PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
      })
    ).container;

    await expectRejection(
      sealPhrase({ passwordRepeat: WRONG_PASSWORD }),
      "PASSWORDS_DIFFER",
      "a repetition that differs is refused",
    );
    await expectRejection(
      client.encrypt({ phrase: PHRASE, password: PASSWORD, walletHasPassphrase: false }),
      "PASSWORDS_DIFFER",
      "a password without its repetition is refused",
    );
    await expectRejection(
      client.encrypt({ phrase: PHRASE, password: encode(PASSWORD), walletHasPassphrase: false }),
      "PASSWORDS_DIFFER",
      "a password as bytes without its repetition is refused the same way",
    );
    // The password's own rules come before the comparison, as in the command-line tool, where a
    // script's first line is refused before its second is read.
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: "a\tb",
        passwordRepeat: "a\tc",
        walletHasPassphrase: false,
      }),
      "CONTROL_CHARACTER_IN_PASSWORD",
      "a password that breaks a rule is refused for it, before its repetition is compared",
    );
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: "",
        passwordRepeat: "x",
        walletHasPassphrase: false,
      }),
      "EMPTY_PASSWORD",
      "an empty password is refused before its repetition is compared",
    );
    // Without an answer, left out or null, what to keep names any passphrase of the wallet in its
    // place: a page need not ask.
    for (const [description, value] of [
      ["left out", undefined],
      ["null", null],
    ]) {
      expectEqual(
        fieldsOf(
          await client.encrypt({
            phrase: PHRASE,
            password: PASSWORD,
            passwordRepeat: PASSWORD,
            repairWordCount: 2,
            ...(value === undefined ? {} : { walletHasPassphrase: value }),
          }),
          ["container", "keep"],
        ),
        {
          container: REDUCED_COST_CONTAINER,
          keep: [...KEEP_24, PASSPHRASE_IF_ANY, { item: "repairWords" }],
        },
        `encrypt with walletHasPassphrase ${description} names any passphrase of the wallet`,
      );
    }
    for (const value of ["no", 0]) {
      await expectExactTypeError(
        sealPhrase({ walletHasPassphrase: value }),
        WALLET_PASSPHRASE_REQUIRED,
        `a walletHasPassphrase of ${JSON.stringify(value)}, not a boolean, is refused`,
      );
    }
    const refusalLog = progressLog();
    await expectRejection(
      client.encrypt({
        phrase: ZERO_24,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        sameLength: true,
        walletHasPassphrase: false,
        onProgress: refusalLog.onProgress,
      }),
      "SAME_LENGTH_NEEDS_SHORT_PHRASE",
      "a same-length container of a 24-word phrase is refused",
    );
    await expectRejection(
      client.encrypt({
        phrase: "abandon about",
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        onProgress: refusalLog.onProgress,
      }),
      "INVALID_PHRASE",
      "an invalid phrase is refused",
    );
    expect(refusalLog.lines.length === 0, "both refusals came before any Argon2 round");
    await expectRejection(
      sealPhrase({ memoryLevel: 1 }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "memory level 1 (4 GiB) is refused in a browser",
    );
    await expectRejection(
      sealPhrase({ memoryLevel: 22 }),
      "INVALID_MEMORY_LEVEL",
      "memory level 22 is refused",
    );
    await expectRejection(sealPhrase({ pim: 1024 }), "INVALID_PIM", "PIM 1024 is refused");
    await expectRejection(
      sealPhrase({ repairWordCount: 3 }),
      "INVALID_REPAIR_WORDS",
      "three repair words are refused",
    );
    const pimError = await rejectionOf(sealPhrase({ pim: 1 }));
    expect(
      pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
      "PIM 1 asks Argon2 for 24 passes, which the reduced-cost wrapper refuses",
    );

    const faultyLog = progressLog();
    const faultyShown = [];
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: FAULTY_CHECK_PASSWORD,
        passwordRepeat: FAULTY_CHECK_PASSWORD,
        repairWordCount: 4,
        walletHasPassphrase: false,
        onProgress: faultyLog.onProgress,
        onUnverified: ({ container }) => faultyShown.push(container),
      }),
      "VERIFICATION_FAILED",
      "a fault in the rounds of the check rejects with VERIFICATION_FAILED",
    );
    expect(
      faultyShown.length === 1 && faultyLog.lines.at(-1) === "check 24/24",
      "the unverified container was shown, and the check ran its rounds before it failed",
    );
    const cancelShown = [];
    await expectRejection(
      sealPhrase({
        onUnverified: ({ container }) => cancelShown.push(container),
        onProgress: ({ stage }) => {
          if (stage === "check") client.cancel();
        },
      }),
      "CANCELLED",
      "cancel() in the check stops an encryption",
    );
    expect(
      cancelShown[0] === REDUCED_COST_CONTAINER,
      "the container cancelled in its check had been shown unverified",
    );
  }

  async function checkDecrypt(client, wallet, made) {
    group("MhfeClient.decrypt");
    const container = REDUCED_COST_CONTAINER;
    const verified = {
      words: 12,
      verified: true,
      status: "verified",
      phrase: PHRASE,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINT,
      walletCheck: null,
      statedWords: null,
      otherLengths: [],
    };
    const log = progressLog();
    expectEqual(
      await client.decrypt({ container, password: PASSWORD, onProgress: log.onProgress }),
      { kind: "phrase", candidates: [verified] },
      "decrypt recovers the verified 12-word phrase with every field",
    );
    expectEqual(log.lines, roundLines("recover", 1, 12, 12), "a recovery reports 12 rounds");
    expectEqual(
      await client.decrypt({ container, password: encode(PASSWORD), words: 12 }),
      { kind: "phrase", candidates: [verified] },
      "the chosen length 12 with the password as bytes gives the same",
    );
    /** A 24-word reading of a state, with the values computed independently in the script. */
    const readAs24 = (name, status, otherLengths = []) => ({
      words: 24,
      verified: false,
      status,
      phrase: READINGS[name],
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS[name],
      walletCheck: WALLET_CHECKS[name],
      statedWords: null,
      otherLengths,
    });
    // 24 words stated beside a 12-word reading whose check passes: both readings, the checked one
    // first, naming the length stated, as the length rules of recovery say (AUD-015-FUN001).
    const as24 = await client.decrypt({ container, password: PASSWORD, words: 24 });
    expectEqual(
      as24,
      {
        kind: "ambiguous",
        candidates: [
          { ...verified, statedWords: 24 },
          readAs24("phraseAs24", "readAs24Chosen", [12]),
        ],
      },
      "the chosen length 24 gives the checked 12 words first, then the whole state: the entropy " +
        "and its SHA-256, with every field",
    );
    const walletFingerprints = [];
    for (const { phrase } of as24.candidates) {
      walletFingerprints.push(await wallet.fingerprint({ phrase }));
    }
    expectEqual(
      as24.candidates.map((candidate) => candidate.fingerprintWithoutPassphrase),
      walletFingerprints,
      "each candidate's fingerprint is the wallet module's",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, memoryLevel: 1 }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a recovery at memory level 1 is refused in a browser",
    );
    // A stated short length whose check fails while another's passes: the check takes precedence,
    // and the reading names the length stated (AUD-015-FUN001).
    expectEqual(
      await client.decrypt({ container, password: PASSWORD, words: 15 }),
      { kind: "phrase", candidates: [{ ...verified, statedWords: 15 }] },
      "a chosen length whose check fails gives the 12 words whose check passes, naming the 15 " +
        "stated, with every field",
    );
    // The wrong password's state passes no short check (it reads as 24 words below).
    await expectRejection(
      client.decrypt({ container, password: WRONG_PASSWORD, words: 15 }),
      "VERIFIER_MISMATCH",
      "a chosen length whose check fails, where no other passes, is refused",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, words: 13 }),
      "INVALID_WORD_COUNT",
      "a word count of 13 is refused",
    );
    const wrong = await client.decrypt({ container, password: WRONG_PASSWORD });
    expectEqual(
      wrong,
      { kind: "phrase", candidates: [readAs24("wrongPasswordAs24", "readAs24")] },
      "a wrong password reads as 24 unverified words (status readAs24), with every field",
    );
    expect(
      (
        await client.encrypt({
          phrase: wrong.candidates[0].phrase,
          password: WRONG_PASSWORD,
          passwordRepeat: WRONG_PASSWORD,
          walletHasPassphrase: false,
        })
      ).container === container,
      "those 24 words, encrypted again with the wrong password, give the container back",
    );

    const sameLength = {
      ...verified,
      verified: false,
      status: "noBuiltInCheck",
      suiteId: SUITE_4,
    };
    expectEqual(
      await client.decrypt({ container: REDUCED_COST_SAME_LENGTH_CONTAINER, password: PASSWORD }),
      { kind: "phrase", candidates: [sameLength] },
      "a same-length container recovers the phrase, not verified, with every field",
    );
    expectEqual(
      await client.decrypt({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        words: 12,
      }),
      { kind: "phrase", candidates: [sameLength] },
      "a same-length container takes its own length",
    );
    await expectRejection(
      client.decrypt({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        words: 15,
      }),
      "LENGTH_CHOICE_NOT_APPLICABLE",
      "a same-length container refuses another length",
    );

    const ambiguousOriginal = (statedWords = null) => ({
      words: 12,
      verified: true,
      status: "verified",
      phrase: AMBIGUOUS_12_WORDS,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS.ambiguous12Words,
      walletCheck: null,
      statedWords,
      otherLengths: [21],
    });
    const ambiguousAs21 = (statedWords = null) => ({
      words: 21,
      verified: true,
      status: "verified",
      phrase: READINGS.ambiguousAs21,
      suiteId: SUITE_3,
      fingerprintWithoutPassphrase: FINGERPRINTS.ambiguousAs21,
      walletCheck: null,
      statedWords,
      otherLengths: [12],
    });
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD }),
      {
        kind: "ambiguous",
        candidates: [
          ambiguousOriginal(),
          ambiguousAs21(),
          readAs24("ambiguousAs24", "readAs24", [12, 21]),
        ],
      },
      "an ambiguous container lists the 12 and 21 verified words and the 24-word reading in full",
    );
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD, words: 12 }),
      { kind: "phrase", candidates: [ambiguousOriginal()] },
      "a length stated among those that pass resolves the ambiguity",
    );
    // 24 words stated beside lengths that pass: every reading, the checked ones first, as the
    // length rules of recovery say (AUD-015-FUN001).
    expectEqual(
      await client.decrypt({ container: made.ambiguous, password: PASSWORD, words: 24 }),
      {
        kind: "ambiguous",
        candidates: [
          ambiguousOriginal(24),
          ambiguousAs21(24),
          readAs24("ambiguousAs24", "readAs24Chosen", [12, 21]),
        ],
      },
      "24 stated words give the checked readings first and the 24-word reading in full",
    );

    expectEqual(
      await client.decrypt({ container: made.checked, password: PASSWORD }),
      {
        kind: "phrase",
        candidates: [
          {
            words: 24,
            verified: false,
            status: "readAs24",
            phrase: CHECKED_PHRASE,
            suiteId: SUITE_3,
            fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
            walletCheck: false,
            statedWords: null,
            otherLengths: [],
          },
        ],
      },
      "a 24-word phrase that passes the wallet check only with its passphrase does not pass without",
    );
    expectEqual(
      (await client.decrypt({ container: made.checked, password: PASSWORD, passphrase: "TREZOR" }))
        .candidates[0].walletCheck,
      true,
      "with its passphrase, the same 24-word reading passes the 16-bit check",
    );
    expectEqual(
      await client.decrypt({ container: made.emptyChecked, password: PASSWORD }),
      {
        kind: "phrase",
        candidates: [
          {
            words: 24,
            verified: false,
            status: "readAs24",
            phrase: EMPTY_CHECKED_PHRASE,
            suiteId: SUITE_3,
            fingerprintWithoutPassphrase: FINGERPRINTS.emptyCheckedPhrase,
            walletCheck: true,
            statedWords: null,
            otherLengths: [],
          },
        ],
      },
      "a 24-word phrase that passes the wallet check without a passphrase is reported so",
    );

    const restored = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
    });
    expect(
      restored.candidates[0].phrase === PHRASE && restored.candidates[0].verified,
      "passwordRepair { repair: 3 } opens the container of the check-word password",
    );
    const corrected = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_CAPITALS,
      passwordRepair: "corrected",
    });
    expect(
      corrected.candidates[0].phrase === PHRASE && corrected.candidates[0].verified,
      'passwordRepair "corrected" opens it with the written form',
    );
    const capitals = await client.decrypt({
      container: made.checkWord,
      password: CHECK_WORD_CAPITALS,
    });
    expect(
      capitals.candidates.every((candidate) => candidate.phrase !== PHRASE),
      "kept as typed, the password with capitals is another password",
    );
    await expectRejection(
      client.decrypt({
        container: made.checkWord,
        password: CHECK_WORD_MISSING,
        passwordRepair: { repair: 2 },
      }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      "a repair the review did not offer is refused",
    );
    await expectRejection(
      client.decrypt({ container, password: PASSWORD, passwordRepair: "corrected" }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      '"corrected" is refused for a password the review does not correct',
    );
    const pimError = await rejectionOf(client.decrypt({ container, password: PASSWORD, pim: 1 }));
    expect(
      pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
      "a recovery with PIM 1 asks Argon2 for 24 passes",
    );
  }

  async function checkRehearsal(client, made) {
    group("MhfeClient.check");
    const fullCheck = (reference, options = {}) =>
      client.check({
        container: REDUCED_COST_CONTAINER,
        password: PASSWORD,
        reference,
        ...options,
      });
    const check = async (reference, options = {}) =>
      fieldsOf(await fullCheck(reference, options), ["matches", "path"]);
    // The original seed phrase's own checks come with a match: the built-in check of the 12-word
    // phrase, and the phrase + passphrase check, which a phrase drawn without it fails.
    expectEqual(
      (await fullCheck({ fingerprint: FINGERPRINT })).evidence,
      { builtInCheck: 12, walletCheck: null },
      "a check lists the built-in check of a 12-word phrase, no wallet check without a passphrase",
    );
    const matched = (path = null) => ({ matches: true, path });
    const notMatched = { matches: false, path: null };
    const log = progressLog();
    expectEqual(
      await check({ fingerprint: FINGERPRINT }, { onProgress: log.onProgress }),
      matched(),
      "check matches the master key fingerprint",
    );
    expectEqual(
      log.lines,
      [...roundLines("recover", 1, 12, 12), "compare 12/12"],
      "a check reports 12 rounds, then compare once",
    );
    expectEqual(
      await check({ fingerprint: "00000000" }),
      notMatched,
      "another fingerprint does not match",
    );
    expectEqual(
      await check({ fingerprint: FINGERPRINT }, { password: encode(PASSWORD) }),
      matched(),
      "a check takes the password as bytes",
    );
    expectEqual(
      await check({ address: BIP84_ADDRESS, coin: "bitcoin" }),
      matched(BIP84_PATH),
      "a Bitcoin address is found at BIP84's first path",
    );
    expectEqual(
      await check({ address: BIP84_ACCOUNT_3_CHANGE_7, coin: "bitcoin" }),
      matched("m/84'/0'/3'/1/7"),
      "the standard search finds change address 7 of account 3",
    );
    expectEqual(
      await check({ address: ETHEREUM_ADDRESS, coin: "ethereum" }),
      matched(ETHEREUM_PATH),
      "an Ethereum address is found on Ethereum's path",
    );
    expectEqual(
      await check({ address: BIP84_ADDRESS, coin: "bitcoin", path: BIP84_PATH }),
      matched(BIP84_PATH),
      "an address at its own path matches",
    );
    expectEqual(
      await check({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/0'/0'/0/1" }),
      notMatched,
      "an address at another path does not match",
    );
    expectEqual(
      await check({ address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" }, { passphrase: "TREZOR" }),
      matched(BIP84_PATH),
      "with the passphrase, the passphrase wallet's address matches",
    );
    expectEqual(
      await check({ fingerprint: FINGERPRINTS.phraseWithTrezor }, { passphrase: encode("TREZOR") }),
      matched(),
      "with the passphrase as bytes, the passphrase wallet's fingerprint matches",
    );
    expectEqual(
      await check({ fingerprint: FINGERPRINT }, { passphrase: "TREZOR" }),
      notMatched,
      "the fingerprint without the passphrase does not match a wallet with one",
    );
    expectEqual(await check({ words: 12 }), matched(), "the built-in check of 12 words matches");
    expectEqual(await check({ words: 0 }), matched(), "the length detected matches as 12 words");
    // The length rules of recovery: a short length whose check passes takes precedence over the
    // stated one, so 15 stated words match, and the evidence names the 12 found (AUD-015-FUN001).
    expectEqual(
      await fullCheck({ words: 15 }),
      { matches: true, path: null, evidence: { builtInCheck: 12, walletCheck: null } },
      "the built-in check of 15 stated words matches at the 12 found, which the evidence names",
    );
    expectEqual(
      await fullCheck({ words: 15 }, { password: WRONG_PASSWORD }),
      { matches: false, path: null, evidence: { builtInCheck: null, walletCheck: null } },
      "where no short check passes, as with the wrong password, the built-in check of 15 words " +
        "does not match",
    );
    await expectRejection(
      check({ words: 24 }),
      "INVALID_WORD_COUNT",
      "24 words have no built-in check",
    );
    expectEqual(
      fieldsOf(
        await client.check({
          container: made.checkWord,
          password: CHECK_WORD_MISSING,
          passwordRepair: { repair: 3 },
          reference: { fingerprint: FINGERPRINT },
        }),
        ["matches", "path"],
      ),
      matched(),
      "passwordRepair { repair: 3 } restores the password of a check",
    );
    expectEqual(
      fieldsOf(
        await client.check({
          container: REDUCED_COST_SAME_LENGTH_CONTAINER,
          password: PASSWORD,
          reference: { address: BIP84_ADDRESS, coin: "bitcoin" },
        }),
        ["matches", "path"],
      ),
      matched(BIP84_PATH),
      "a same-length container is checked against an address",
    );

    const onChecked = async (reference, options) =>
      fieldsOf(
        await client.check({ container: made.checked, password: PASSWORD, reference, ...options }),
        ["matches", "path"],
      );
    expectEqual(
      await onChecked({ walletCheck: true }, { passphrase: "TREZOR" }),
      matched(),
      "the wallet check with its passphrase passes",
    );
    expectEqual(
      await onChecked({ walletCheck: true }, { passphrase: "trezor" }),
      notMatched,
      "the wallet check with another passphrase does not",
    );
    expectEqual(
      await onChecked(
        { fingerprint: FINGERPRINTS.checkedPhraseWithTrezor },
        { passphrase: "TREZOR" },
      ),
      matched(),
      "a 24-word phrase's passphrase wallet matches its fingerprint",
    );
    // The length detected: the passphrase finds the 24-word phrase drawn with its check; without
    // it the page is asked for the length and its fingerprint is compared on the same recovery.
    expectEqual(
      await onChecked({ words: 0 }, { passphrase: "TREZOR" }),
      matched(),
      "the length detected finds a 24-word phrase by the phrase + passphrase check",
    );
    let lengthAsked = 0;
    const askedLog = progressLog();
    expectEqual(
      await onChecked(
        { words: 0 },
        {
          onProgress: askedLog.onProgress,
          onNoLength: () => {
            lengthAsked += 1;
            return { fingerprint: FINGERPRINTS.checkedPhraseWithTrezor, passphrase: "TREZOR" };
          },
        },
      ),
      matched(),
      "with no length detected, the fingerprint the page gives matches",
    );
    expect(
      lengthAsked === 1 &&
        askedLog.lines.filter((line) => line.startsWith("recover")).length === 12,
      "the page is asked once, and the recovery runs once",
    );
    expectEqual(
      await onChecked({ words: 0 }, { onNoLength: () => null }),
      notMatched,
      "without an answer the result stays",
    );
    const refusalLog = progressLog();
    const onProgress = refusalLog.onProgress;
    await expectRejection(
      onChecked({ walletCheck: true }, { onProgress }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check without a passphrase is refused",
    );
    await expectRejection(
      client.check({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        reference: { walletCheck: true },
        passphrase: "TREZOR",
        onProgress,
      }),
      "NO_WALLET_CHECK",
      "a same-length container has no wallet check",
    );
    // The library's order, the same as through the command line: no wallet check before the
    // empty passphrase.
    await expectRejection(
      client.check({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        reference: { walletCheck: true },
        onProgress,
      }),
      "NO_WALLET_CHECK",
      "a same-length container has no wallet check, also without a passphrase",
    );
    await expectRejection(
      client.check({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        password: PASSWORD,
        reference: { words: 12 },
        onProgress,
      }),
      "NO_BUILT_IN_CHECK",
      "a same-length container has no built-in check",
    );
    await expectRejection(
      check({ address: BIP84_ADDRESS, coin: "doge" }, { onProgress }),
      "INVALID_COIN",
      "an unknown coin is refused",
    );
    await expectRejection(
      check({ address: DAMAGED_ADDRESS, coin: "bitcoin" }, { onProgress }),
      "INVALID_ADDRESS",
      "an address whose checksum fails is refused",
    );
    await expectRejection(
      check({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/x" }, { onProgress }),
      "INVALID_DERIVATION_PATH",
      "a malformed path is refused",
    );
    await expectRejection(
      check({ fingerprint: "73c5da0" }, { onProgress }),
      "INVALID_FINGERPRINT",
      "a fingerprint of seven digits is refused",
    );
    await expectRejection(
      check({ fingerprint: FINGERPRINT }, { passwordRepair: "corrected", onProgress }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      '"corrected" is refused for a password the review does not correct',
    );
    await expectRejection(
      check({ fingerprint: FINGERPRINT }, { memoryLevel: 1, onProgress }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a check at memory level 1 is refused in a browser",
    );
    expect(refusalLog.lines.length === 0, "each of these refusals came before any Argon2 round");

    const oneKind = "reference must be exactly one of";
    await expectTypeError(
      check({ address: BIP84_ADDRESS }),
      "reference.coin must name the coin of the address",
      "an address without its coin is refused: no coin is the default",
    );
    await expectTypeError(check(undefined), oneKind, "a check without a reference is refused");
    await expectTypeError(
      check({ fingerprint: FINGERPRINT, address: BIP84_ADDRESS }),
      oneKind,
      "a reference of two kinds is refused",
    );
    await expectTypeError(
      check({ fingerprint: FINGERPRINT, coin: "bitcoin" }),
      "reference.coin belongs only to an address reference.",
      "a coin without an address is refused",
    );
    await expectTypeError(
      check({ words: 12, path: BIP84_PATH }),
      "reference.path belongs only to an address reference.",
      "a path without an address is refused",
    );
    await expectTypeError(
      check({ walletCheck: false }),
      "reference.walletCheck must be true.",
      "walletCheck must be true",
    );
    await expectTypeError(
      check({ address: 42 }),
      "reference.address must be a string.",
      "an address that is not text is refused",
    );
  }

  async function checkCancelAndCallbacks(client) {
    group("MhfeClient.cancel and the page's callbacks");
    const container = REDUCED_COST_CONTAINER;
    const cancelledAtOnce = client.decrypt({ container, password: PASSWORD });
    client.cancel();
    await expectRejection(cancelledAtOnce, "CANCELLED", "cancel before the first round");
    const cancelledLater = client.decrypt({
      container,
      password: PASSWORD,
      onProgress: ({ round }) => {
        if (round === 2) client.cancel();
      },
    });
    await expectRejection(cancelledLater, "CANCELLED", "cancel in the second round");
    expect(
      (await rejectionOf(cancelledLater)) instanceof MhfeCancelledError,
      "a cancelled operation rejects with MhfeCancelledError",
    );
    expect(
      (await client.readContainer(container)).container === container,
      "a new operation runs after a cancel",
    );

    const running = client.decrypt({ container, password: PASSWORD });
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
      }),
      "BUSY",
      "a second long operation is refused while one runs",
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE,
      "reading words does not wait for the long operation",
    );
    expect((await running).candidates[0].phrase === PHRASE, "the first operation still ends");

    const pageError = new Error("synthetic page error");
    await expectRejection(
      client.decrypt({
        container,
        password: PASSWORD,
        onProgress: () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onProgress stops the operation",
      pageError,
    );
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        onUnverified: () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onUnverified stops the operation",
      pageError,
    );
    await expectRejection(
      client.decrypt({
        container,
        password: PASSWORD,
        onProgress: async () => {
          throw pageError;
        },
      }),
      "CALLBACK_FAILED",
      "an async onProgress that rejects stops the operation",
      pageError,
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE,
      "a new operation runs after a callback failed",
    );
    await expectTypeError(
      client.decrypt({ container, password: PASSWORD, onProgress: "show" }),
      "onProgress must be a function.",
      "an onProgress that is not a function is refused",
    );
    await expectTypeError(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
        onUnverified: "show",
      }),
      "onUnverified must be a function.",
      "an onUnverified that is not a function is refused",
    );
  }

  async function checkMemoryFailures(client) {
    group("MhfeClient: memory the browser cannot give");
    // The core reports the 2 GiB of memory level 0 that it asked for, not the reduced cost.
    const message = "The computer could not reserve 2 GiB of memory for Argon2";
    const failed = (error) =>
      error?.code === "MEMORY_ALLOCATION_FAILED" && error.message === message;
    const log = progressLog();
    const recovery = await rejectionOf(
      client.decrypt({
        container: REDUCED_COST_CONTAINER,
        password: MEMORY_FAILURE_PASSWORD,
        onProgress: log.onProgress,
      }),
    );
    expect(
      failed(recovery) && sameValue(log.lines, ["recover 1/12"]),
      `a recovery fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${recovery?.code}`,
    );
    const encryptionLog = progressLog();
    const encryption = await rejectionOf(
      client.encrypt({
        phrase: PHRASE,
        password: MEMORY_FAILURE_PASSWORD,
        passwordRepeat: MEMORY_FAILURE_PASSWORD,
        walletHasPassphrase: false,
        onProgress: encryptionLog.onProgress,
      }),
    );
    expect(
      failed(encryption) && sameValue(encryptionLog.lines, ["encrypt 1/24"]),
      `an encryption fails with MEMORY_ALLOCATION_FAILED in round 1 -> ${encryption?.code}`,
    );

    const sessionStart = await rejectionOf(
      client.openHiddenWallets({ container: MEMORY_FAILURE_CONTAINER, mainPassphrase: "" }),
    );
    expect(
      failed(sessionStart),
      `a session of hidden wallets fails at its start, when it reserves its work area -> ${sessionStart?.code}`,
    );
    const session = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const openLog = progressLog();
    const opening = await rejectionOf(
      session.open({
        password: MEMORY_FAILURE_PASSWORD,
        passwordRepeat: MEMORY_FAILURE_PASSWORD,
        onProgress: openLog.onProgress,
      }),
    );
    expect(
      failed(opening) && sameValue(openLog.lines, ["recover 1/12"]),
      `the session after it reserved its area fails in a wallet's round 1 -> ${opening?.code}`,
    );
    await expectRejection(
      session.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "SESSION_CLOSED",
      "a memory failure is no refusal: it ends the session",
    );
    expect(
      (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
        .candidates[0].verified,
      "the slot is free after each memory failure",
    );
  }

  async function checkRekey(client, repair, wallet, made) {
    group("MhfeClient.rekey");
    const base = {
      container: REDUCED_COST_CONTAINER,
      words: 12,
      password: PASSWORD,
      newPassword: NEW_PASSWORD,
      newPasswordRepeat: NEW_PASSWORD,
      confirmation: { builtInCheck: true },
      walletHasPassphrase: false,
    };
    // A rekey must give what encrypt gives for the same phrase with the new password.
    const sealWithNew = (phrase, options = {}) =>
      client.encrypt({
        phrase,
        password: NEW_PASSWORD,
        passwordRepeat: NEW_PASSWORD,
        walletHasPassphrase: false,
        ...options,
      });
    /**
     * What a rekey resolves to: what encrypt gives for the confirmed phrase, with `walletCheck`,
     * the 16-bit source check of a recovered 24-word reading with the reference's passphrase or
     * none, null for every other length.
     */
    const asRekeyResult = (sealed, walletCheck = null) => ({ ...sealed, walletCheck });
    const sealedWithNew = await sealWithNew(PHRASE);
    const log = progressLog();
    const shown = [];
    const rekeyed = await client.rekey({
      ...base,
      onProgress: log.onProgress,
      onUnverified: (result) => {
        log.lines.push("unverified");
        shown.push(result);
      },
    });
    expectEqual(
      log.lines,
      [
        ...roundLines("recover", 1, 12, 36),
        ...roundLines("encrypt", 13, 24, 36),
        "unverified",
        ...roundLines("check", 25, 36, 36),
      ],
      "a rekey reports 36 rounds: recover, encrypt, the unverified container, check",
    );
    expectEqual(
      shown,
      [
        {
          container: sealedWithNew.container,
          containerFingerprint: sealedWithNew.containerFingerprint,
        },
      ],
      "onUnverified receives the new container and its fingerprint",
    );
    expectEqual(
      rekeyed,
      asRekeyResult(sealedWithNew),
      "a rekey resolves to what encrypt gives with the new password, every field, and no wallet " +
        "check for 12 words",
    );
    expect(
      rekeyed.containerFingerprint === (await wallet.fingerprint({ phrase: rekeyed.container })),
      "the new container's fingerprint is the wallet module's",
    );
    expectEqual(
      fieldsOf(rekeyed, [
        "suiteId",
        "builtInCheck",
        "otherLengths",
        "repairWords",
        "repairProfile",
        "keep",
      ]),
      {
        suiteId: SUITE_3,
        builtInCheck: true,
        otherLengths: [],
        repairWords: null,
        repairProfile: null,
        keep: KEEP_24,
      },
      "a rekey resolves as encrypt does, with every field",
    );
    const afterRekey = await client.decrypt({
      container: rekeyed.container,
      password: NEW_PASSWORD,
    });
    expect(
      afterRekey.candidates[0].phrase === PHRASE && afterRekey.candidates[0].verified,
      "a rekey seals the phrase with the new password",
    );
    expect(
      (await client.rekey({ ...base, newPasswordRepeat: encode(NEW_PASSWORD) })).container ===
        sealedWithNew.container,
      "a new password as text and its repetition as the same bytes are the same password",
    );
    // The length detected: a 24-word original may pass a short check by chance, so the built-in
    // check alone confirms no detected length (REFERENCE_REQUIRED before any round, below). The
    // fingerprint, an address or the owner does, and a reference is compared with every reading
    // (AUD-017-FUN001).
    expectEqual(
      await client.rekey({ ...base, words: 0, confirmation: { fingerprint: FINGERPRINT } }),
      asRekeyResult(sealedWithNew),
      "a rekey with the length detected, confirmed by the fingerprint, seals the 12-word phrase: " +
        "what encrypt gives, every field",
    );
    let detectedOwnerSaw = null;
    const byDetectedOwner = await client.rekey({
      ...base,
      words: 0,
      confirmation: {
        owner: (check) => {
          detectedOwnerSaw = check;
          return true;
        },
      },
    });
    expectEqual(
      detectedOwnerSaw,
      { phrase: PHRASE, words: 12, fingerprintWithoutPassphrase: FINGERPRINT },
      "with the length detected the owner is shown the 12 words found, and no length stated",
    );
    expect(
      byDetectedOwner.container === sealedWithNew.container,
      "the owner's yes confirms the length detected",
    );
    expectEqual(
      await client.rekey({
        ...base,
        container: made.ambiguous,
        words: 0,
        confirmation: { fingerprint: FINGERPRINTS.ambiguous12Words },
      }),
      asRekeyResult(await sealWithNew(AMBIGUOUS_12_WORDS)),
      "a detection that finds two lengths is told apart by the fingerprint, compared with each " +
        "reading: what encrypt gives the 12 words, every field",
    );
    await expectRejection(
      client.rekey({ ...base, container: made.ambiguous, words: 12 }),
      "AMBIGUOUS_LENGTH",
      "a length stated among two that pass does not let the built-in check alone confirm a rekey",
    );
    await expectRejection(
      client.rekey({
        ...base,
        newPassword: encode(NEW_PASSWORD),
        newPasswordRepeat: "another public test passwore",
      }),
      "PASSWORDS_DIFFER",
      "a new password as bytes and a repetition as other text differ",
    );

    const toCheckWord = await client.rekey({
      ...base,
      newPassword: CHECK_WORD_MISSING,
      newPasswordRepeat: CHECK_WORD_MISSING,
      newPasswordRepair: { repair: 3 },
      repairWordCount: 4,
    });
    const card = await repair.repairWords({ container: toCheckWord.container, count: 4 });
    expect(
      toCheckWord.container === made.checkWord,
      "newPasswordRepair restores the new password: the container its encryption gives",
    );
    expectEqual(
      fieldsOf(toCheckWord, ["repairWords", "repairProfile", "keep"]),
      {
        repairWords: card.words,
        repairProfile: REPAIR_PROFILE,
        keep: [...KEEP_24, { item: "repairWords" }],
      },
      "a rekey with repairWordCount 4 gives the repair module's card",
    );
    const back = await client.rekey({
      ...base,
      container: made.checkWord,
      password: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
      newPassword: PASSWORD,
      newPasswordRepeat: PASSWORD,
    });
    expect(
      back.container === REDUCED_COST_CONTAINER,
      "passwordRepair restores the old password: rekeyed back, the native container again",
    );
    // The built-in check shows nothing of a BIP39 passphrase, so the page states it; a wallet that
    // has one keeps it after the password, before the repair words.
    const withPassphrase = await client.rekey({
      ...base,
      walletHasPassphrase: true,
      repairWordCount: 2,
    });
    expectEqual(
      withPassphrase.keep,
      [...KEEP_24, PASSPHRASE, { item: "repairWords" }],
      "a rekey stated to have a passphrase keeps it after the password, before the repair words",
    );
    expectEqual(
      withPassphrase,
      asRekeyResult(await sealWithNew(PHRASE, { walletHasPassphrase: true, repairWordCount: 2 })),
      "it is what encrypt gives with the same answer and repair words, every field",
    );

    let ownerSaw = null;
    const ownerBase = {
      ...base,
      container: made.checked,
      words: 24,
    };
    const ownerSealed = await client.rekey({
      ...ownerBase,
      confirmation: {
        owner: async (check) => {
          ownerSaw = check;
          return true;
        },
      },
    });
    expectEqual(
      ownerSaw,
      {
        phrase: CHECKED_PHRASE,
        words: 24,
        fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
      },
      "the owner is shown the recovered phrase and its fingerprint",
    );
    expectEqual(
      fieldsOf(ownerSealed, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
      { suiteId: SUITE_3, builtInCheck: false, otherLengths: [], keep: KEEP_24 },
      "the owner's yes, from a promise, seals the 24-word phrase",
    );
    // CHECKED_PHRASE fails the 16-bit wallet check without its passphrase "TREZOR", as the script
    // checks before the page runs.
    expectEqual(
      ownerSealed,
      asRekeyResult(await sealWithNew(CHECKED_PHRASE), false),
      "the container the owner confirmed is what encrypt gives with the new password, with the " +
        "24-word reading's wallet check, every field",
    );
    const ownerRecovery = await client.decrypt({
      container: ownerSealed.container,
      password: NEW_PASSWORD,
    });
    expect(
      ownerRecovery.candidates[0].phrase === CHECKED_PHRASE,
      "the container the owner confirmed opens with the new password",
    );
    const ownerWithPassphrase = await client.rekey({
      ...ownerBase,
      walletHasPassphrase: true,
      confirmation: { owner: () => true },
    });
    expectEqual(
      fieldsOf(ownerWithPassphrase, ["container", "keep"]),
      { container: ownerSealed.container, keep: [...KEEP_24, PASSPHRASE] },
      "the owner's rekey stated to have a passphrase keeps it; the container is the same",
    );
    // A stated short length that the check contradicts: the owner may confirm the reading the
    // check found, and is shown the length stated beside it, which the page names first.
    const ownerNo = [];
    await expectRejection(
      client.rekey({
        ...base,
        words: 15,
        confirmation: {
          owner: (check) => {
            ownerNo.push(check);
            return false;
          },
        },
      }),
      "NOT_CONFIRMED_BY_OWNER",
      "the owner's no stops a rekey",
    );
    expectEqual(
      ownerNo,
      [{ phrase: PHRASE, words: 12, statedWords: 15, fingerprintWithoutPassphrase: FINGERPRINT }],
      "the owner of 15 stated words saw the 12-word reading the check found, with the 15 stated",
    );
    // 24 words stated beside a 12-word reading whose check passes: the owner cannot tell the two
    // readings apart, so the library refuses once the recovery has found them, before the owner
    // is asked, even an owner with a yes ready; an address or the fingerprint confirms one
    // (AUD-015-FUN001, AUD-016-BLD002).
    const ownerOf24 = [];
    const ownerOf24Log = progressLog();
    await expectExactRefusal(
      client.rekey({
        ...base,
        words: 24,
        onProgress: ownerOf24Log.onProgress,
        confirmation: {
          owner: (check) => {
            ownerOf24.push(check);
            return true;
          },
        },
      }),
      "LENGTH_DIFFERS",
      lengthDiffers(12, 24),
      "24 words stated beside a 12-word reading whose check passes cannot reach the owner",
    );
    expectEqual(ownerOf24, [], "the owner was not asked");
    expectEqual(
      ownerOf24Log.lines,
      roundLines("recover", 1, 12, 36),
      "it is refused after the recovery's rounds, before anything is sealed",
    );
    expectEqual(
      await client.rekey({ ...base, words: 24, confirmation: { fingerprint: FINGERPRINT } }),
      asRekeyResult(sealedWithNew),
      "the fingerprint confirms the 12-word reading beside 24 stated words: what encrypt gives, " +
        "every field",
    );
    await expectRejection(
      client.rekey({ ...ownerBase, confirmation: { owner: () => "yes" } }),
      "NOT_CONFIRMED_BY_OWNER",
      "anything but true from the owner stops a rekey",
    );
    const ownerError = new Error("synthetic owner error");
    await expectRejection(
      client.rekey({
        ...ownerBase,
        confirmation: {
          owner: () => {
            throw ownerError;
          },
        },
      }),
      "CALLBACK_FAILED",
      "an owner callback that throws stops a rekey",
      ownerError,
    );
    // An MhfeError of another call, here the BUSY of a recovery started while the rekey holds the
    // slot, must not pass for the rekey's own error.
    let busy = null;
    const ownerBusy = await rejectionOf(
      client.rekey({
        ...ownerBase,
        confirmation: {
          owner: async () => {
            busy = await rejectionOf(
              client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }),
            );
            throw busy;
          },
        },
      }),
    );
    expect(
      busy?.code === "BUSY" && ownerBusy?.code === "CALLBACK_FAILED" && ownerBusy.cause === busy,
      `an MhfeError thrown by the owner ends the rekey with CALLBACK_FAILED, it as the cause -> ${ownerBusy?.code}`,
    );
    let ownerAsked;
    let answerOwner;
    const asked = new Promise((resolve) => {
      ownerAsked = resolve;
    });
    const awaitingOwner = client.rekey({
      ...ownerBase,
      confirmation: {
        owner: () => {
          ownerAsked();
          return new Promise((resolve) => {
            answerOwner = resolve;
          });
        },
      },
    });
    await asked;
    client.cancel();
    expect(
      (await rejectionOf(awaitingOwner)) instanceof MhfeCancelledError,
      "client.cancel() while a rekey awaits the owner's answer stops it",
    );
    answerOwner(true);
    expect(
      (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
        .candidates[0].verified,
      "the owner's late yes goes nowhere, and the slot is free",
    );
    const unverifiedError = new Error("synthetic page error");
    const unverifiedLog = progressLog();
    await expectRejection(
      client.rekey({
        ...base,
        onProgress: unverifiedLog.onProgress,
        onUnverified: () => {
          throw unverifiedError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onUnverified stops a rekey",
      unverifiedError,
    );
    expect(
      unverifiedLog.lines.at(-1) === "encrypt 24/36",
      "it stops where the new container is shown, before its check",
    );

    // A same-length container has no built-in check: the wallet confirms its phrase. A reference
    // with an empty passphrase matches the phrase's wallet without one and proves nothing about
    // funds under a passphrase, so these rekeys keep base's answer, false, unless they say other.
    const sameBase = {
      ...base,
      container: REDUCED_COST_SAME_LENGTH_CONTAINER,
      words: undefined,
    };
    const sameSealed = await sealWithNew(PHRASE, { sameLength: true });
    const sameSealedWithPassphrase = await sealWithNew(PHRASE, {
      sameLength: true,
      walletHasPassphrase: true,
    });
    const sameRekey = await client.rekey({
      ...sameBase,
      confirmation: { fingerprint: FINGERPRINT },
    });
    expectEqual(
      fieldsOf(sameRekey, ["suiteId", "builtInCheck", "otherLengths", "keep"]),
      {
        suiteId: SUITE_4,
        builtInCheck: false,
        otherLengths: [],
        keep: KEEP_SAME_LENGTH,
      },
      "a same-length rekey confirmed by the fingerprint, stated without a passphrase, seals a " +
        "same-length container and keeps no passphrase",
    );
    expectEqual(
      sameRekey,
      asRekeyResult(sameSealed),
      "it is what encrypt with sameLength gives with the new password, every field, and no " +
        "wallet check",
    );
    const sameRecovery = await client.decrypt({
      container: sameRekey.container,
      password: NEW_PASSWORD,
    });
    expect(
      sameRecovery.candidates[0].phrase === PHRASE &&
        sameRecovery.candidates[0].status === "noBuiltInCheck",
      "the rekeyed same-length container opens with the new password",
    );
    const sameContainer = (result) => result.container === sameSealed.container;
    expect(
      sameContainer(
        await client.rekey({ ...sameBase, words: 12, confirmation: { fingerprint: FINGERPRINT } }),
      ),
      "a same-length container takes its own length, 12, as the word count",
    );
    const addressLog = progressLog();
    const byAddress = await client.rekey({
      ...sameBase,
      confirmation: { address: BIP84_ADDRESS, coin: "bitcoin" },
      onProgress: addressLog.onProgress,
    });
    expect(
      sameContainer(byAddress) && sameValue(byAddress.keep, KEEP_SAME_LENGTH),
      "a rekey confirmed by a Bitcoin address without a passphrase, stated without one, gives " +
        "the same container and keeps no passphrase",
    );
    expectEqual(
      addressLog.lines,
      [
        ...roundLines("recover", 1, 12, 36),
        "compare 12/36",
        ...roundLines("encrypt", 13, 24, 36),
        ...roundLines("check", 25, 36, 36),
      ],
      "a rekey confirmed by the wallet compares once after the recovery",
    );
    const byEthereum = await client.rekey({
      ...sameBase,
      confirmation: { address: ETHEREUM_ADDRESS, coin: "ethereum", path: ETHEREUM_PATH },
    });
    expect(
      sameContainer(byEthereum),
      "a rekey confirmed by an Ethereum address at its path gives the same container",
    );
    // A wallet stated to have a passphrase is compared with it: a reference without it would
    // match the phrase's wallet without one and say nothing about the funds under the passphrase
    // (the specification's re-encryption rules), so it is refused before any round.
    for (const [confirmation, description] of [
      [{ fingerprint: FINGERPRINT }, "a fingerprint"],
      [{ address: BIP84_ADDRESS, coin: "bitcoin" }, "an address"],
    ]) {
      for (const passphrase of [undefined, ""]) {
        await expectRejection(
          client.rekey({ ...sameBase, confirmation, passphrase, walletHasPassphrase: true }),
          "INVALID_REQUEST",
          `${description} with ${passphrase === undefined ? "no" : "an empty"} passphrase, ` +
            "stated to be of a wallet with one, is refused",
        );
      }
    }
    // Only a reference compared with a non-empty passphrase shows that the wallet has one: the
    // answer may be left out.
    const byPassphrase = await client.rekey({
      ...sameBase,
      confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
      passphrase: "TREZOR",
      walletHasPassphrase: undefined,
    });
    expect(
      sameContainer(byPassphrase),
      "a rekey confirmed by the passphrase wallet's fingerprint, with the passphrase, as well",
    );
    // The reference's passphrase shows that the wallet has one, stated or not.
    expectEqual(
      byPassphrase.keep,
      [...KEEP_SAME_LENGTH, PASSPHRASE],
      "the fingerprint's passphrase, unstated, puts the passphrase in what to keep",
    );
    expectEqual(
      await client.rekey({
        ...sameBase,
        confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
        passphrase: "TREZOR",
        walletHasPassphrase: true,
      }),
      asRekeyResult(sameSealedWithPassphrase),
      "the fingerprint's passphrase, stated as well, gives what encrypt gives with it, every field",
    );
    const byTrezorAddress = await client.rekey({
      ...sameBase,
      confirmation: { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
      passphrase: "TREZOR",
      walletHasPassphrase: undefined,
    });
    expect(
      sameContainer(byTrezorAddress),
      "a rekey confirmed by the passphrase wallet's address, with the passphrase, as well",
    );
    expectEqual(
      byTrezorAddress.keep,
      [...KEEP_SAME_LENGTH, PASSPHRASE],
      "the address's passphrase, unstated, puts the passphrase in what to keep",
    );
    expectEqual(
      fieldsOf(
        await client.rekey({
          ...sameBase,
          confirmation: { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
          passphrase: "TREZOR",
          walletHasPassphrase: true,
        }),
        ["container", "keep"],
      ),
      { container: byTrezorAddress.container, keep: [...KEEP_SAME_LENGTH, PASSPHRASE] },
      "the address's passphrase, stated as well, keeps it",
    );
    const fromBytes = await client.rekey({
      ...sameBase,
      password: encode(PASSWORD),
      newPassword: encode(NEW_PASSWORD),
      newPasswordRepeat: encode(NEW_PASSWORD),
      confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
      passphrase: encode("TREZOR"),
      walletHasPassphrase: undefined,
    });
    expect(
      sameContainer(fromBytes) && sameValue(fromBytes.keep, [...KEEP_SAME_LENGTH, PASSPHRASE]),
      "a rekey takes the passwords, the repetition and the passphrase as bytes; the passphrase " +
        "as bytes shows the wallet's too",
    );
    let sameOwnerSaw = null;
    const bySameOwner = await client.rekey({
      ...sameBase,
      walletHasPassphrase: false,
      confirmation: {
        owner: (check) => {
          sameOwnerSaw = check;
          return true;
        },
      },
    });
    expectEqual(
      sameOwnerSaw,
      { phrase: PHRASE, words: 12, fingerprintWithoutPassphrase: FINGERPRINT },
      "the owner of a same-length container is shown its 12-word phrase",
    );
    expect(sameContainer(bySameOwner), "the owner's yes seals the same container");
    const mismatchLog = progressLog();
    await expectRejection(
      client.rekey({
        ...sameBase,
        confirmation: { fingerprint: FINGERPRINTS.phraseWithTrezor },
        onProgress: mismatchLog.onProgress,
      }),
      "REFERENCE_MISMATCH",
      "a fingerprint of another wallet, stated without a passphrase, stops the rekey",
    );
    expect(
      mismatchLog.lines.at(-1) === "compare 12/36",
      "it stops after the comparison, before anything is sealed",
    );

    // A late refusal: the built-in check finds 12 words, not the 15 stated. It takes precedence,
    // but only the wallet confirms the phrase then, so the rekey stops once the recovery's rounds
    // have found the length, before anything is sealed (AUD-015-FUN001).
    const lengthLog = progressLog();
    await expectExactRefusal(
      client.rekey({ ...base, words: 15, onProgress: lengthLog.onProgress }),
      "LENGTH_DIFFERS",
      lengthDiffers(12, 15),
      "a stated length that the built-in check contradicts needs the wallet's confirmation",
    );
    expectEqual(
      lengthLog.lines,
      roundLines("recover", 1, 12, 36),
      "it is refused after the recovery's rounds, before anything is sealed",
    );
    expectEqual(
      await client.rekey({ ...base, words: 15, confirmation: { fingerprint: FINGERPRINT } }),
      asRekeyResult(sealedWithNew),
      "the fingerprint confirms the 12-word reading the check found: what encrypt gives, every " +
        "field",
    );

    // Early refusals, before any Argon2 round.
    const refusalLog = progressLog();
    await expectRejection(
      client.rekey({
        ...base,
        newPassword: PASSWORD,
        newPasswordRepeat: PASSWORD,
        onProgress: refusalLog.onProgress,
      }),
      "NEW_PASSWORD_SAME_AS_OLD",
      "the old password and settings are refused as the new ones",
    );
    await expectExactRefusal(
      client.rekey({ ...base, words: 24, onProgress: refusalLog.onProgress }),
      "REFERENCE_REQUIRED",
      REFERENCE_REQUIRED,
      "a 24-word phrase has no built-in check to confirm it",
    );
    await expectRejection(
      client.rekey({
        ...sameBase,
        words: 15,
        confirmation: { fingerprint: FINGERPRINT },
        onProgress: refusalLog.onProgress,
      }),
      "LENGTH_CHOICE_NOT_APPLICABLE",
      "a same-length container refuses another word count",
    );
    await expectRejection(
      client.rekey({ ...base, memoryLevel: 1, onProgress: refusalLog.onProgress }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "an old memory level 1 is refused in a browser",
    );
    expect(refusalLog.lines.length === 0, "these refusals came before any Argon2 round");

    /** A refusal with `code` and exactly `message`, which must come before any Argon2 round. */
    const expectEarlyRefusal = async (options, code, message, description) => {
      const rounds = progressLog();
      await expectExactRefusal(
        client.rekey({ ...options, onProgress: rounds.onProgress }),
        code,
        message,
        description,
      );
      expect(rounds.lines.length === 0, `${description}: before any Argon2 round`);
    };
    /** A refusal of the passphrase's answer. */
    const expectPassphraseRefusal = (options, message, description) =>
      expectEarlyRefusal(options, "INVALID_REQUEST", message, description);
    // A length without a built-in check refuses that check first, before the answer is judged:
    // without the answer, it is still REFERENCE_REQUIRED. So does the length detected on a 24-word
    // container, where a 24-word original may pass a short check by chance (AUD-017-FUN001).
    for (const [options, description] of [
      [{ ...base, words: 24 }, "a 24-word phrase"],
      [{ ...sameBase, confirmation: { builtInCheck: true } }, "a same-length container"],
      [{ ...base, words: 0 }, "the length detected"],
    ]) {
      for (const walletHasPassphrase of [undefined, false, true]) {
        await expectEarlyRefusal(
          { ...options, walletHasPassphrase },
          "REFERENCE_REQUIRED",
          REFERENCE_REQUIRED,
          `${description} refuses the built-in check with the answer ${walletHasPassphrase}`,
        );
      }
    }
    await expectPassphraseRefusal(
      { ...base, walletHasPassphrase: undefined },
      PASSPHRASE_UNSTATED,
      "the built-in check shows nothing of a passphrase: a rekey without the answer is refused",
    );
    let ownerAskedUnstated = false;
    await expectPassphraseRefusal(
      {
        ...ownerBase,
        walletHasPassphrase: undefined,
        confirmation: {
          owner: () => {
            ownerAskedUnstated = true;
            return true;
          },
        },
      },
      PASSPHRASE_UNSTATED,
      "nor does the owner's comparison: an owner's rekey without the answer is refused",
    );
    expect(!ownerAskedUnstated, "the owner was not asked: the refusal came before the recovery");
    // A reference with an empty passphrase matches the phrase's wallet without one, as it does
    // here, and proves nothing about funds under a passphrase: without the answer it is refused.
    for (const [confirmation, description] of [
      [{ fingerprint: FINGERPRINT }, "a fingerprint"],
      [{ address: BIP84_ADDRESS, coin: "bitcoin" }, "an address"],
    ]) {
      for (const passphrase of [undefined, "", encode("")]) {
        await expectPassphraseRefusal(
          { ...sameBase, confirmation, passphrase, walletHasPassphrase: undefined },
          PASSPHRASE_UNSTATED,
          `${description} with ${passphrase === undefined ? "no" : "an empty"} passphrase` +
            `${passphrase instanceof Uint8Array ? " as bytes" : ""} shows nothing: a rekey ` +
            "without the answer is refused",
        );
      }
    }
    for (const [confirmation, passphrase, description] of [
      [
        { fingerprint: FINGERPRINTS.phraseWithTrezor },
        "TREZOR",
        "a fingerprint with a passphrase, stated to be of a wallet without one, is refused",
      ],
      [
        { address: BIP84_TREZOR_ADDRESS, coin: "bitcoin" },
        encode("TREZOR"),
        "an address with a passphrase as bytes, stated to be of a wallet without one, is refused",
      ],
    ]) {
      await expectPassphraseRefusal(
        { ...sameBase, confirmation, passphrase, walletHasPassphrase: false },
        PASSPHRASE_CONTRADICTED,
        description,
      );
    }
    // A passphrase belongs only to an address or a fingerprint: with the built-in check or the
    // owner, the client refuses it, and the owner is not asked.
    let ownerAskedWithPassphrase = false;
    for (const [options, description] of [
      [base, "the built-in check"],
      [
        {
          ...ownerBase,
          confirmation: {
            owner: () => {
              ownerAskedWithPassphrase = true;
              return true;
            },
          },
        },
        "the owner",
      ],
    ]) {
      for (const passphrase of ["TREZOR", encode("TREZOR")]) {
        await expectExactTypeError(
          client.rekey({ ...options, passphrase, walletHasPassphrase: true }),
          PASSPHRASE_ONLY_WITH_REFERENCE,
          `a passphrase${typeof passphrase === "string" ? "" : " as bytes"} with ${description} ` +
            "is refused",
        );
      }
    }
    expect(!ownerAskedWithPassphrase, "the owner was not asked with a passphrase given");
    // The answer may be left out of a rekey, but one given is a boolean: null is not.
    for (const walletHasPassphrase of ["no", 1, 0, {}, null]) {
      await expectExactTypeError(
        client.rekey({ ...base, walletHasPassphrase }),
        WALLET_PASSPHRASE_REQUIRED,
        `a walletHasPassphrase of ${JSON.stringify(walletHasPassphrase)}, not a boolean, is ` +
          "refused in a rekey too",
      );
    }
    await expectRejection(
      client.rekey({ ...base, newPasswordRepeat: "another public test passwore" }),
      "PASSWORDS_DIFFER",
      "a new password whose repetition differs is refused",
    );
    await expectRejection(
      client.rekey({ ...base, newMemoryLevel: 1 }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a new memory level 1 is refused in a browser",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { walletCheck: true } }),
      "not by the wallet check",
      "the wallet check never confirms a rekey",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { words: 12 } }),
      "not by a word count",
      "a word count does not confirm a rekey",
    );
    const builtInCheckAlone = "confirmation must be exactly one kind; builtInCheck must be true.";
    await expectTypeError(
      client.rekey({ ...base, confirmation: { owner: () => true, builtInCheck: true } }),
      builtInCheckAlone,
      "an owner callback together with another kind is refused",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { builtInCheck: true, fingerprint: FINGERPRINT } }),
      builtInCheckAlone,
      "the built-in check together with a fingerprint is refused",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { owner: () => true, fingerprint: FINGERPRINT } }),
      "confirmation must be exactly one kind; owner must be a function.",
      "an owner callback together with a fingerprint is refused",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: undefined }),
      "confirmation must be one of { builtInCheck: true }, { address, coin, path? }, " +
        "{ fingerprint } or { owner }.",
      "a rekey without a confirmation is refused, naming what a rekey takes",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { coin: "bitcoin" } }),
      "confirmation must be one of { builtInCheck: true }",
      "a confirmation of no kind is refused, naming what a rekey takes",
    );
    await expectTypeError(
      client.rekey({ ...base, confirmation: { builtInCheck: false } }),
      builtInCheckAlone,
      "builtInCheck must be true",
    );
    await expectTypeError(
      client.rekey({ ...sameBase, confirmation: { fingerprint: FINGERPRINT, path: BIP84_PATH } }),
      "reference.path belongs only to an address reference.",
      "a path without an address is refused in a confirmation",
    );

    // The new settings are judged as the seal uses them: the old password with PIM 1 is a new
    // container, and the seal, not the recovery, asks Argon2 for PIM 1's cost.
    const newPimLog = progressLog();
    const newPimError = await rejectionOf(
      client.rekey({
        ...base,
        newPassword: PASSWORD,
        newPasswordRepeat: PASSWORD,
        newPim: 1,
        onProgress: newPimLog.onProgress,
      }),
    );
    expect(
      newPimError?.code === "ARGON2_FAILED" &&
        newPimError.message.includes(PIM_1_COST) &&
        newPimLog.lines.at(-1) === "encrypt 13/36",
      "newPim 1 with the old password is accepted, and the seal asks for 24 passes",
    );
    const oldPimLog = progressLog();
    const oldPimError = await rejectionOf(
      client.rekey({ ...base, pim: 1, onProgress: oldPimLog.onProgress }),
    );
    expect(
      oldPimError?.code === "ARGON2_FAILED" &&
        oldPimError.message.includes(PIM_1_COST) &&
        sameValue(oldPimLog.lines, ["recover 1/36"]),
      "the old PIM 1 makes the recovery ask for 24 passes",
    );
  }

  async function checkHiddenWallets(client, wallet, made) {
    group("MhfeClient.openHiddenWallets");
    const wallets = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    await expectRejection(
      client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }),
      "BUSY",
      "an open session holds the long-operation slot",
    );
    expect(
      (await client.readContainer(REDUCED_COST_CONTAINER)).hiddenWallets,
      "reading words runs while a session is open",
    );
    const log = progressLog();
    const opening = wallets.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
      onProgress: log.onProgress,
    });
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "BUSY",
      "a second wallet does not open while one opens",
    );
    const hidden = await opening;
    await expectTypeError(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD, onProgress: 1 }),
      "onProgress must be a function.",
      "an onProgress that is not a function is refused",
    );
    expectEqual(log.lines, roundLines("recover", 1, 12, 12), "opening one reports 12 rounds");
    expect(
      hidden.fingerprintWithoutPassphrase === (await wallet.fingerprint({ phrase: hidden.phrase })),
      "a hidden wallet's fingerprint is the wallet module's",
    );
    await expectRejection(
      wallets.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "PASSWORD_ALREADY_USED",
      "a password opens one hidden wallet only",
    );
    await expectRejection(
      wallets.open({ password: PASSWORD, passwordRepeat: PASSWORD }),
      "HIDDEN_WALLET_PASSES_CHECK",
      "the main password's reading passes the built-in check, so it is no hidden wallet",
    );
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "PASSWORDS_DIFFER",
      "a repetition that differs is refused",
    );
    await expectRejection(
      wallets.open({ password: THIRD_PASSWORD, passwordRepeat: encode(NEW_PASSWORD) }),
      "PASSWORDS_DIFFER",
      "a repetition as bytes of another password is refused",
    );
    await expectRejection(
      wallets.open({
        password: CHECK_WORD_MISSING,
        passwordRepeat: CHECK_WORD_MISSING,
        passwordRepair: { repair: 2 },
      }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      "a repair the review did not offer is refused",
    );
    // Nothing is sent for a repair position that is not a word number, so the session stays open.
    const repairPosition = "a word number from 1.";
    for (const position of [-1, 0, 2 ** 32]) {
      await expectTypeError(
        wallets.open({
          password: CHECK_WORD_MISSING,
          passwordRepeat: CHECK_WORD_MISSING,
          passwordRepair: { repair: position },
        }),
        repairPosition,
        `passwordRepair { repair: ${position} } is refused`,
      );
    }
    const restored = await wallets.open({
      password: CHECK_WORD_MISSING,
      passwordRepeat: CHECK_WORD_MISSING,
      passwordRepair: { repair: 3 },
    });
    await expectRejection(
      wallets.open({ password: CHECK_WORD_PASSWORD, passwordRepeat: CHECK_WORD_PASSWORD }),
      "PASSWORD_ALREADY_USED",
      "passwordRepair { repair: 3 } opened the wallet of the restored password",
    );
    // Every password the core refuses before any work leaves the session open: the wallet of
    // THIRD_PASSWORD opens below.
    for (const [password, code] of [
      ["public\ttest password", "CONTROL_CHARACTER_IN_PASSWORD"],
      [new Uint8Array([0x70, 0xff]), "INVALID_PASSWORD_UTF8"],
      ["public \u0378 test password", "UNASSIGNED_CHARACTER"],
      ["a".repeat(1025), "PASSWORD_TOO_LONG"],
    ]) {
      await expectRejection(
        wallets.open({ password, passwordRepeat: password }),
        code,
        `a password refused with ${code} leaves the session open`,
      );
    }
    await expectRejection(
      wallets.open({ password: encode(THIRD_PASSWORD) }),
      "PASSWORDS_DIFFER",
      "a password without its repetition leaves the session open",
    );
    const second = await wallets.open({
      password: encode(THIRD_PASSWORD),
      passwordRepeat: encode(THIRD_PASSWORD),
    });
    await wallets.close();
    await expectRejection(
      wallets.open({ password: "x", passwordRepeat: "x" }),
      "SESSION_CLOSED",
      "a closed session refuses to open a wallet",
    );
    expect(
      (await outcomeWithin(wallets.close(), 5000)) === "resolved",
      "closing a closed session resolves at once",
    );
    const closedTwice = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const firstClose = closedTwice.close();
    const secondClose = closedTwice.close();
    expect(firstClose === secondClose, "a second close() returns the first one's promise");
    await secondClose;
    const afterClose = await client.decrypt({
      container: REDUCED_COST_CONTAINER,
      password: PASSWORD,
    });
    expect(
      afterClose.candidates[0].phrase === PHRASE,
      "once the second close() resolves, the session has freed the long-operation slot",
    );

    // A hidden wallet is the container read as 24 words with its password.
    const readAs24 = async (password) => {
      const [reading] = (
        await client.decrypt({ container: REDUCED_COST_CONTAINER, password, words: 24 })
      ).candidates;
      return {
        phrase: reading.phrase,
        words: 24,
        fingerprintWithoutPassphrase: reading.fingerprintWithoutPassphrase,
      };
    };
    const newPasswordWallet = await readAs24(NEW_PASSWORD);
    const checkWordWallet = await readAs24(CHECK_WORD_PASSWORD);
    const thirdWallet = await readAs24(THIRD_PASSWORD);
    expectEqual(
      hidden,
      newPasswordWallet,
      "after close the slot is free; a hidden wallet is the container read as 24 words",
    );
    expectEqual(
      restored,
      checkWordWallet,
      "the restored password's wallet is the container read with the full password",
    );
    expectEqual(
      second,
      thirdWallet,
      "the session stayed open after the refusals; a password as bytes opens its own wallet",
    );

    const again = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    expectEqual(
      await again.open({
        password: CHECK_WORD_CAPITALS,
        passwordRepeat: CHECK_WORD_CAPITALS,
        passwordRepair: "corrected",
      }),
      checkWordWallet,
      'passwordRepair "corrected" opens the wallet of the written form',
    );
    expectEqual(
      await again.open({ password: THIRD_PASSWORD, passwordRepeat: encode(THIRD_PASSWORD) }),
      thirdWallet,
      "a password as text and its repetition as the same bytes are the same password",
    );
    expectEqual(
      await again.open({ password: encode(NEW_PASSWORD), passwordRepeat: NEW_PASSWORD }),
      newPasswordWallet,
      "and so are a password as bytes and its repetition as the same text",
    );
    expect(
      (await outcomeWithin(again.close(), 5000)) === "resolved",
      "close() while the session waits resolves once the worker has ended",
    );

    // A failing onProgress of an open ends the whole session.
    const failing = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    const progressError = new Error("synthetic page error");
    await expectRejection(
      failing.open({
        password: NEW_PASSWORD,
        passwordRepeat: NEW_PASSWORD,
        onProgress: () => {
          throw progressError;
        },
      }),
      "CALLBACK_FAILED",
      "a throwing onProgress stops the open",
      progressError,
    );
    await expectRejection(
      failing.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "a failing onProgress ends the whole session",
    );

    // The main wallet's passphrase counts: a reading that passes the wallet check with it is
    // refused, and without it the same password opens that reading.
    const withPassphrase = await client.openHiddenWallets({
      container: made.checked,
      mainPassphrase: "TREZOR",
    });
    await expectRejection(
      withPassphrase.open({ password: PASSWORD, passwordRepeat: PASSWORD }),
      "HIDDEN_WALLET_PASSES_CHECK",
      "a reading that passes the wallet check with the main passphrase is refused",
    );
    const interrupted = withPassphrase.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
    });
    client.cancel();
    await expectRejection(interrupted, "CANCELLED", "client.cancel() during an open stops it");
    await expectRejection(
      withPassphrase.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "client.cancel() ends the session",
    );
    const withoutPassphrase = await client.openHiddenWallets({
      container: made.checked,
      mainPassphrase: new Uint8Array(0),
    });
    expectEqual(
      await withoutPassphrase.open({
        password: encode(PASSWORD),
        passwordRepeat: encode(PASSWORD),
      }),
      {
        phrase: CHECKED_PHRASE,
        words: 24,
        fingerprintWithoutPassphrase: FINGERPRINTS.checkedPhrase,
      },
      "with an empty main passphrase as bytes, the same password opens that reading",
    );
    const closedDuringOpen = withoutPassphrase.open({
      password: NEW_PASSWORD,
      passwordRepeat: NEW_PASSWORD,
    });
    expect(
      (await outcomeWithin(withoutPassphrase.close(), 5000)) === "resolved",
      "close() during an open resolves once the session has ended",
    );
    expect(
      (await rejectionOf(closedDuringOpen)) instanceof MhfeCancelledError,
      "close() during an open stops it with MhfeCancelledError",
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE &&
        (await client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }))
          .candidates[0].verified,
      "after close() during an open the slot is free",
    );

    const waiting = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      mainPassphrase: "",
    });
    client.cancel();
    await expectRejection(
      waiting.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
      "SESSION_CLOSED",
      "client.cancel() while the session waits ends it",
    );
    const atPim1 = await client.openHiddenWallets({
      container: REDUCED_COST_CONTAINER,
      pim: 1,
      mainPassphrase: "",
    });
    const pimError = await rejectionOf(
      atPim1.open({ password: NEW_PASSWORD, passwordRepeat: NEW_PASSWORD }),
    );
    expect(
      pimError?.code === "ARGON2_FAILED" && pimError.message.includes(PIM_1_COST),
      "a session at PIM 1 asks Argon2 for 24 passes",
    );
    await expectRejection(
      atPim1.open({ password: THIRD_PASSWORD, passwordRepeat: THIRD_PASSWORD }),
      "SESSION_CLOSED",
      "a failure that is no refusal ends the session",
    );
    await expectRejection(
      client.openHiddenWallets({
        container: REDUCED_COST_CONTAINER,
        memoryLevel: 1,
        mainPassphrase: "",
      }),
      "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
      "a session at memory level 1 is refused in a browser",
    );
    await expectRejection(
      client.openHiddenWallets({
        container: REDUCED_COST_SAME_LENGTH_CONTAINER,
        mainPassphrase: "",
      }),
      "NO_HIDDEN_WALLETS",
      "hidden wallets open on a 24-word container only",
    );
    await expectTypeError(
      client.openHiddenWallets({ container: REDUCED_COST_CONTAINER }),
      "mainPassphrase is required",
      "the main passphrase is required",
    );
  }

  async function checkSelfTest(client) {
    group("MhfeClient.selfTest");
    const log = progressLog();
    const result = await client.selfTest({ onProgress: log.onProgress });
    expectEqual(
      log.lines,
      [...roundLines("encrypt", 1, 12, 24), ...roundLines("recover", 13, 24, 24)],
      "the self-test encrypts the suite 3 vector, then recovers the suite 4 vector",
    );
    // The vectors are published at full cost, so at the reduced cost neither can match, and the
    // key of the first round already differs from the published one, for the published input:
    // the fault the self-test names is in Argon2id.
    expectEqual(
      result,
      {
        passed: false,
        suite3: { vector: "zero-12", asPublished: false },
        suite4: { vector: "same-length-zero-12", asPublished: false },
        firstWrongRound: 1,
        fault: {
          kind: "argon2-key",
          round: 1,
          message:
            "first wrong round 1 of 24: Argon2id returned another key for the published input, " +
            "so the fault is in Argon2id",
        },
      },
      "at the reduced cost the self-test names both vectors, the first wrong round and its fault",
    );
  }

  /** The parts of a report as "id outcome" lines, with the detail of any part that did not pass. */
  function partLines(report) {
    return report.components.map(
      ({ id, outcome, detail }) => `${id} ${outcome}${detail === undefined ? "" : `: ${detail}`}`,
    );
  }

  /** The lines of parts that all passed. */
  function passedLines(ids) {
    return ids.map((id) => `${id} passed`);
  }

  /** Whether every part has the label the library gives it. */
  function labelled(report) {
    return report.components.every(
      ({ id, label }) => SELF_CHECK.labels[id] === undefined || SELF_CHECK.labels[id] === label,
    );
  }

  async function checkStartupChecks(client, repair, passwords, wallet) {
    group("Startup checks, before the first operation");
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    // The wallet, repair and passwords classes share one compiled WebAssembly: a part one of them
    // passed is not run again by the next. The client has its own, so it runs every part.
    const checks = [
      ["MhfeWallet", () => wallet.startupCheck(), [...pageParts, ...SELF_CHECK.wallet]],
      [
        "MhfeRepair",
        () => repair.startupCheck(),
        ["browser-features", "package-parts", ...SELF_CHECK.repair],
      ],
      ["MhfePasswords", () => passwords.startupCheck(), [...pageParts, ...SELF_CHECK.passwords]],
      [
        "MhfeClient without Argon2",
        () => client.startupCheck({ argon2: false }),
        [...pageParts, ...SELF_CHECK.core],
      ],
      ["MhfeClient with Argon2", () => client.startupCheck(), [...pageParts, ...SELF_CHECK.core]],
    ];
    for (const [name, check, ids] of checks) {
      const started = performance.now();
      const report = await check();
      const time = Math.round(performance.now() - started);
      const expected = passedLines(ids).map((line) =>
        name === "MhfeClient without Argon2" && line === "argon2 passed"
          ? "argon2 notRun: this check leaves Argon2 out"
          : line,
      );
      expectEqual(partLines(report), expected, `${name}: every part as expected`);
      expect(
        report.passed &&
          report.tier === "startup" &&
          report.version === VERSION &&
          report.buildId === PACKAGE_BUILD_ID &&
          labelled(report),
        `${name}: passed, at the startup tier, of this version and build`,
      );
      expect(time < 2000, `${name}: the startup check took ${time} ms, under 2 s`);
    }
    expect(
      (await wallet.startupCheck()) === (await wallet.startupCheck()),
      "a startup check is made once per page",
    );
  }

  async function checkFullChecks(client, repair, passwords, wallet) {
    group("Full self-checks");
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    for (const [name, check, ids] of [
      [
        "MhfeRepair",
        () => repair.fullCheck(),
        ["browser-features", "package-parts", ...SELF_CHECK.repair],
      ],
      ["MhfePasswords", () => passwords.fullCheck(), [...pageParts, ...SELF_CHECK.passwords]],
      ["MhfeWallet", () => wallet.fullCheck(), [...pageParts, ...SELF_CHECK.wallet]],
    ]) {
      const started = performance.now();
      const report = await check();
      const time = Math.round(performance.now() - started);
      expectEqual(
        partLines(report),
        passedLines(ids),
        `${name}: every part passes at the full tier`,
      );
      expect(report.passed && report.tier === "full" && labelled(report), `${name}: passed`);
      expect(true, `${name}: the full self-check took ${time} ms`);
    }
    // The core's, with Argon2 at 64 and 256 MiB: the single-threaded build, then on an isolated
    // page the threaded one, never both at once.
    const fast = client.mode() === "fast";
    const events = [];
    const started = performance.now();
    const report = await client.fullCheck({
      onProgress: ({ id, running, outcome }) =>
        events.push({ id, running, outcome, at: performance.now() }),
    });
    const time = Math.round(performance.now() - started);
    expectEqual(
      partLines(report),
      [
        ...passedLines([...pageParts, ...SELF_CHECK.core]),
        "argon2-sizes-single-threaded passed",
        fast
          ? "argon2-sizes-threaded passed"
          : "argon2-sizes-threaded notRun: the page is not cross-origin isolated",
        "published-vectors notRun: they take minutes and 2 GiB: selfTest() runs them",
        "memory-locking notAvailable: a web page cannot keep its memory out of swap",
        "core-dumps notAvailable: the browser keeps its own crash reports, which a page cannot turn off",
        "isolation notAvailable: a web page cannot sandbox itself or prove that it is offline",
        "hidden-input notAvailable: a web page has no terminal whose echo it could read back",
      ],
      `MhfeClient: every part at the full tier, Argon2's sizes of ${fast ? "both builds" : "the single-threaded build"}`,
    );
    expect(report.passed && labelled(report), `MhfeClient: the full self-check took ${time} ms`);
    const ran = [...SELF_CHECK.core, "argon2-sizes-single-threaded"];
    if (fast) ran.push("argon2-sizes-threaded");
    expectEqual(
      events.map(({ id, running, outcome }) => (running ? `start ${id}` : `end ${id} ${outcome}`)),
      ran.flatMap((id) => [`start ${id}`, `end ${id} passed`]),
      "MhfeClient: each part is reported as it starts and ends, one after the other",
    );
    if (fast) {
      const single = events.find(
        ({ id, running }) => id === "argon2-sizes-single-threaded" && !running,
      );
      const threaded = events.find(({ id, running }) => id === "argon2-sizes-threaded" && running);
      expect(
        single.at <= threaded.at,
        "the threaded build starts only after the single-threaded build has ended",
      );
    }
  }

  async function checkFailingSelfCheck(compiled) {
    group("A self-check that fails");
    // The package's WebAssembly with one letter of a published repair card changed, as a damaged
    // download or memory would: the repair words and the cipher's rounds, which hold the card of
    // their first vector, fail, named by their place only, and their classes stay closed.
    const damaged = bytes(WASM_BASE64);
    const card = new TextEncoder().encode("shaft pupil patient jewel");
    let at = -1;
    for (let index = 0; index + card.length <= damaged.length; index += 1) {
      if (card.every((byte, offset) => damaged[index + offset] === byte)) {
        at = index;
        break;
      }
    }
    damaged[at + card.length - 1] ^= 1;
    const repair = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: damaged });
    const report = await repair.startupCheck();
    expectEqual(
      partLines(report),
      [
        "browser-features passed",
        "package-parts passed",
        "bip39-words passed",
        "repair-words failed: card 1 of 1 gives other words",
      ],
      "a damaged card fails the repair words at startup",
    );
    const refusal = await rejectionOf(
      repair.repairWords({ container: FULL_SIZE_CONTAINER, count: 4 }),
    );
    expect(
      refusal?.code === "SELF_CHECK_FAILED" &&
        refusal.message ===
          "The self-test failed: Repair words (MHFE-REPAIR-1): card 1 of 1 gives other words. " +
            "Do not use this program on this computer" &&
        refusal.report === report,
      `the repair module stays closed -> ${refusal?.code}: ${refusal?.message}`,
    );
    const client = new MhfeClient({
      workerSource: WORKER_SOURCE,
      wasm: damaged,
      argon2Threaded: ARGON2_THREADED,
      argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    });
    const encryption = await rejectionOf(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
      }),
    );
    expect(
      encryption?.code === "SELF_CHECK_FAILED" &&
        encryption.message ===
          "The self-test failed: Cipher rounds: vector 5 of 10 gives other repair words. " +
            "Do not use this program on this computer" &&
        encryption.report.components.find(({ id }) => id === "repair-words")?.outcome === "failed",
      `the client encrypts nothing -> ${encryption?.code}: ${encryption?.message}`,
    );
    // A worker of another build than the WebAssembly refuses it before it runs.
    const otherWorker = WORKER_SOURCE.replace(
      `WORKER_BUILD_ID = "${PACKAGE_BUILD_ID}"`,
      'WORKER_BUILD_ID = "0123456789abcdef"',
    );
    await expectExactRefusal(
      new MhfeRepair({ workerSource: otherWorker, wasm: compiled }).parameters(),
      "PACKAGE_MISMATCH",
      `The file runtime/mhfe.wasm is of build ${PACKAGE_BUILD_ID} and runtime/worker.js of ` +
        "build 0123456789abcdef: take every file of the package from one build.",
      "a worker of another build refuses the WebAssembly",
    );
  }

  async function checkArgon2Start() {
    group("An Argon2 build that does not start, or of another build");
    // A build that does not start gave no wrong answer, as when the browser refuses its memory:
    // Argon2 is not available, the client stays open, the report is not kept, and an operation
    // gets its own error. On an isolated page, a threaded build that does not start makes the
    // check fall back to the single-threaded build, with a warning. The stand-in builds are the
    // package's own, whose start is replaced by one that fails.
    const fast = globalThis.crossOriginIsolated === true;
    const cause = fast
      ? "the stand-in threaded build does not start"
      : "the stand-in build does not start";
    const failingStart = (name) =>
      `\n${name} = () => Promise.reject(new Error(${JSON.stringify(cause)}));\n`;
    const client = new MhfeClient({
      workerSource: WORKER_SOURCE,
      wasm: bytes(WASM_BASE64),
      argon2Threaded: fast ? ARGON2_THREADED + failingStart("createArgon2Mt") : ARGON2_THREADED,
      argon2SingleThreaded: fast
        ? ARGON2_SINGLE_THREADED
        : ARGON2_SINGLE_THREADED + failingStart("createArgon2St"),
    });
    const notStarted = `the ${fast ? "threaded" : "single-threaded"} Argon2 build did not start: ${cause}`;
    const argon2Line = fast
      ? `argon2 warning: ${notStarted}; the check ran the single-threaded build of the standard mode instead`
      : `argon2 notAvailable: Argon2id could not run: ${notStarted}`;
    const pageParts = ["browser-features", "package-parts", "page-encoding"];
    const startupLines = [...pageParts, ...SELF_CHECK.core].map((id) =>
      id === "argon2" ? argon2Line : `${id} passed`,
    );
    const first = await client.startupCheck();
    expectEqual(
      partLines(first),
      startupLines,
      `startupCheck(): Argon2 says why (${fast ? "fast" : "standard"} mode)`,
    );
    expect(
      first.passed && labelled(first),
      "the report passes: a build that does not start is no wrong answer",
    );
    const again = await client.startupCheck();
    expect(
      again !== first && sameValue(again, first),
      "the report is not kept: the next call checks again",
    );
    await expectExactRefusal(
      client.encrypt({
        phrase: PHRASE,
        password: PASSWORD,
        passwordRepeat: PASSWORD,
        walletHasPassphrase: false,
      }),
      "INTERNAL_ERROR",
      cause.charAt(0).toUpperCase() + cause.slice(1),
      "the client stays open, and an encryption gets its own error",
    );
    const full = await client.fullCheck();
    expectEqual(
      partLines(full).filter((line) => line.startsWith("argon2")),
      [
        argon2Line,
        fast
          ? "argon2-sizes-single-threaded passed"
          : `argon2-sizes-single-threaded notAvailable: Argon2id could not run: ${notStarted}`,
        fast
          ? `argon2-sizes-threaded notAvailable: Argon2id could not run: ${notStarted}`
          : "argon2-sizes-threaded notRun: the page is not cross-origin isolated",
      ],
      "fullCheck(): every Argon2 part says why",
    );
    expect(full.passed, "the full report passes too");
    // An Argon2 build of another build than the worker is refused before it runs, by a check and
    // by the self-test, which waits for no check.
    const file = fast ? "core/argon2-mt.js" : "core/argon2-st.js";
    const constant = fast ? "ARGON2_THREADED_BUILD_ID" : "ARGON2_SINGLE_THREADED_BUILD_ID";
    const otherBuild = (source) =>
      source.replace(`${constant} = "${PACKAGE_BUILD_ID}";`, `${constant} = "0123456789abcdef";`);
    const mixed = new MhfeClient({
      workerSource: WORKER_SOURCE,
      wasm: bytes(WASM_BASE64),
      argon2Threaded: fast ? otherBuild(ARGON2_THREADED) : ARGON2_THREADED,
      argon2SingleThreaded: fast ? ARGON2_SINGLE_THREADED : otherBuild(ARGON2_SINGLE_THREADED),
    });
    // The path keeps its spelling: the message starts with a word (AUD-010).
    const mismatch =
      `The file ${file} is of build 0123456789abcdef and runtime/worker.js of build ` +
      `${PACKAGE_BUILD_ID}: take every file of the package from one build.`;
    await expectExactRefusal(
      mixed.startupCheck(),
      "PACKAGE_MISMATCH",
      mismatch,
      `${file} of another build: startupCheck()`,
    );
    await expectExactRefusal(
      mixed.selfTest(),
      "PACKAGE_MISMATCH",
      mismatch,
      `${file} of another build: selfTest()`,
    );
  }

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
    for (const [typed, reading, wordCount, unreadable, description] of [
      [FULL_SIZE_CONTAINER, "container", 24, [], "a valid container phrase"],
      [containerWith({ 3: "?", 17: "?" }), "marked", 24, [3, 17], "words marked with ?"],
      [containerWith({ 3: "?", 9: "towr" }), "marked", 24, [3, 9], "a ? and a word not listed"],
      [containerWith({ 9: "towr" }), "notAContainer", 24, [], "a word not listed alone"],
      [FULL_SIZE_CONTAINER.split(" ").slice(1).join(" "), "wrongLength", 23, [], "23 words"],
    ]) {
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

  async function checkPasswords(passwords) {
    group("MhfePasswords");
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

    const review = (fields) => ({
      profile: "MHFE-PASSWORD-CHECK-1",
      correction: null,
      correctionText: null,
      offersCorrection: false,
      repairsFirst: false,
      repairs: [],
      ...fields,
    });
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
      { bits: 77.55, weak: false },
      "the strength is of the password after its repair: six list words",
    );
    expectEqual(
      await passwords.strength({ password: CHECK_WORD_CAPITALS, passwordRepair: "corrected" }),
      { bits: 77.55, weak: false },
      "the strength is of the corrected password",
    );
    await expectRejection(
      passwords.strength({ password: CHECK_WORD_MISSING, passwordRepair: { repair: 2 } }),
      "PASSWORD_REPAIR_NOT_OFFERED",
      "a repair the review did not offer is refused",
    );

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
    await expectRefusal(
      passwords.make({ kind: "characters", dice: "11111" }),
      "INVALID_REQUEST",
      "a character password cannot come from dice",
      "characters cannot come from dice",
    );
    await expectExactTypeError(
      passwords.make({ kind: "checkWord", count: 7 }),
      'count belongs only to the kinds "words" and "characters": "checkWord" always gives five ' +
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
      "INVALID_DICE_ROLLS",
      "dice for one word of two are refused",
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

  async function checkWallet(wallet) {
    group("MhfeWallet");
    expectThrownTypeError(
      () => new MhfeWallet({ workerSource: WORKER_SOURCE }),
      "wasm must be a Uint8Array or a WebAssembly.Module.",
      "a wallet module without the WebAssembly is refused",
    );
    const coin = (id, name, addressForms) => ({ id, name, addressForms });
    expectEqual(
      await wallet.parameters(),
      {
        version: VERSION,
        coins: [
          coin("bitcoin", "Bitcoin", "1…, 3…, bc1q… or bc1p…"),
          coin("bitcoin-cash", "Bitcoin Cash", "bitcoincash:q… or 1…"),
          coin("cosmos", "Cosmos", "cosmos1…"),
          coin("dash", "Dash", "X… or dash1k…"),
          coin("dogecoin", "Dogecoin", "D…"),
          coin("ethereum", "Ethereum and EVM networks", "0x…"),
          coin("ethereum-classic", "Ethereum Classic", "0x…"),
          coin("injective", "Injective", "inj1…"),
          coin("litecoin", "Litecoin", "L…, M…, 3… or ltc1q…"),
          coin("tron", "Tron", "T…"),
          coin("xrp", "XRP", "r…"),
          coin("zcash", "Zcash", "t1…"),
        ],
        walletCheckBits: 16,
        drawReportInterval: 1024,
        maxChosenWords: 1,
        maxNeverUseWords: 1,
        recommendedRandomBits: 240,
      },
      "parameters gives the version, the twelve coins of an address check with their names and " +
        "address forms, 16 bits of wallet check, a report every 1,024 draws, and the limits of " +
        "the wishes: 1 chosen word, 1 word never to use, 240 random bits recommended",
    );

    expect(
      (await wallet.fingerprint({ phrase: PHRASE })) === FINGERPRINT,
      "the wallet module gives the master key fingerprint",
    );
    expect(
      (await wallet.fingerprint({ phrase: PHRASE, passphrase: "TREZOR" })) ===
        FINGERPRINTS.phraseWithTrezor &&
        (await wallet.fingerprint({ phrase: PHRASE, passphrase: encode("TREZOR") })) ===
          FINGERPRINTS.phraseWithTrezor,
      "the fingerprint with a passphrase, as text or bytes",
    );
    await expectRejection(
      wallet.fingerprint({ phrase: "abandon about" }),
      "INVALID_PHRASE",
      "an invalid phrase has no fingerprint",
    );

    expect(
      await wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: "TREZOR" }),
      "the wallet module confirms the published wallet check",
    );
    expect(
      (await wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: encode("trezor") })) ===
        false &&
        (await wallet.walletCheck({ phrase: EMPTY_CHECKED_PHRASE, passphrase: "TREZOR" })) ===
          false,
      "the wallet check fails with another passphrase and for another phrase",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: CHECKED_PHRASE, passphrase: "" }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check with an empty passphrase is refused",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: CHECKED_PHRASE }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check without a passphrase is refused",
    );
    await expectRejection(
      wallet.walletCheck({ phrase: PHRASE, passphrase: "TREZOR" }),
      "INVALID_WORD_COUNT",
      "the wallet check of a 12-word phrase is refused",
    );

    // The default search: ten accounts, two chains and the first hundred addresses of each.
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin" }),
      {
        type: "native SegWit (BIP84)",
        search: "m/84'/0'/0'-9'/0-1/0-99",
        addresses: 2000,
        onlyPath: false,
      },
      "describeAddress states Bitcoin's standard search: 2,000 addresses",
    );
    // The decoy search of two missing words: the first account, as far as the gap.
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", scanGap: 20 }),
      {
        type: "native SegWit (BIP84)",
        search: "m/84'/0'/0'-0'/0-1/0-19",
        addresses: 40,
        onlyPath: false,
      },
      "describeAddress with a scan gap states the first account's first 20 of each chain",
    );
    expectEqual(
      await wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", path: BIP84_PATH }),
      { type: "native SegWit (BIP84)", search: BIP84_PATH, addresses: 1, onlyPath: true },
      "describeAddress with a path searches that path only",
    );
    expectEqual(
      await wallet.describeAddress({ address: ETHEREUM_ADDRESS, coin: "ethereum" }),
      { type: null, search: "m/44'/60'/0'-9'/0-1/0-99", addresses: 2000, onlyPath: false },
      "an Ethereum address has no type of its own",
    );
    await expectTypeError(
      wallet.describeAddress({ address: BIP84_ADDRESS }),
      "coin must name the coin of the address",
      "describeAddress without a coin is refused: no coin is the default",
    );
    await expectRejection(
      wallet.describeAddress({ address: BIP84_ADDRESS, coin: "doge" }),
      "INVALID_COIN",
      "an unknown coin is refused",
    );
    await expectRejection(
      wallet.describeAddress({ address: DAMAGED_ADDRESS, coin: "bitcoin" }),
      "INVALID_ADDRESS",
      "an address whose checksum fails is refused",
    );
    await expectRejection(
      wallet.describeAddress({ address: BIP84_ADDRESS, coin: "bitcoin", path: "m/84'/x" }),
      "INVALID_DERIVATION_PATH",
      "a malformed path is refused",
    );

    const drawn = await wallet.drawPhrase();
    expect(
      drawn.words === 24 && drawn.phrase.split(" ").length === 24,
      "the wallet module draws a phrase from the browser's randomness",
    );
    expect(
      drawn.walletCheck === false &&
        drawn.workers === 1 &&
        drawn.fingerprintWithPassphrase === (await wallet.fingerprint({ phrase: drawn.phrase })),
      "a phrase without a passphrase gets no wallet check, from one worker, with its fingerprint",
    );
    // A chosen word: its cost as the library rates it, and a phrase that meets it.
    const oneFixed = await wallet.describeDraw({
      chosen: [{ word: "happy", position: 1 }],
      walletCheck: true,
    });
    expect(
      oneFixed.randomBits === 229 &&
        oneFixed.randomness === "notRecommended" &&
        oneFixed.recognisable === true &&
        oneFixed.fixedPosition === true,
      "a word at a fixed position with the wallet check keeps 229 bits: allowed, not " +
        "recommended, and recognisable",
    );
    const hint = await wallet.wordHints({ typed: "abandon ZO" });
    expect(
      hint.hint === "words" && hint.words.join(" ") === "zone zoo",
      "the hint below BIP39 words lists the words that begin with the last two letters",
    );
    await expectRejection(
      wallet.describeDraw({
        chosen: [
          { word: "happy", position: 1 },
          { word: "zoo", position: 5 },
        ],
      }),
      "INVALID_WORD_WISH",
      "a second chosen word is refused",
    );
    const wished = await wallet.drawPhrase({
      chosen: [{ word: "zoo", position: 24 }],
      neverUse: ["abandon"],
    });
    const wishedWords = wished.phrase.split(" ");
    expect(
      wishedWords[23] === "zoo" && !wishedWords.includes("abandon"),
      "a drawn phrase has the chosen word at its position and no word never to use",
    );
    await expectRejection(
      wallet.drawPhrase({ chosen: [{ word: "notaword", position: 1 }] }),
      "INVALID_WORD_WISH",
      "a chosen word that is not a BIP39 word is refused",
    );
    const withPassphrase = await wallet.drawPhrase({
      passphrase: "TREZOR",
      passphraseRepeat: encode("TREZOR"),
      walletCheck: false,
    });
    expect(
      withPassphrase.walletCheck === false &&
        withPassphrase.workers === 1 &&
        withPassphrase.fingerprintWithPassphrase ===
          (await wallet.fingerprint({ phrase: withPassphrase.phrase, passphrase: "TREZOR" })),
      "a phrase with a passphrase and no check has the fingerprint with that passphrase",
    );
    await expectTypeError(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "TREZOR" }),
      "walletCheck must be true or false when a passphrase is given.",
      "with a passphrase, walletCheck must be chosen",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "trezor", walletCheck: true }),
      "PASSPHRASES_DIFFER",
      "a passphrase whose repetition differs is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", walletCheck: false }),
      "PASSPHRASES_DIFFER",
      "a passphrase without its repetition is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ walletCheck: true }),
      "WALLET_CHECK_NEEDS_PASSPHRASE",
      "the wallet check without a passphrase is refused",
    );
    await expectTypeError(
      wallet.drawPhrase({
        passphrase: "TREZOR",
        passphraseRepeat: "TREZOR",
        walletCheck: true,
        workers: 0,
      }),
      "workers must be a whole number from 1 to 256.",
      "no workers are refused",
    );
    // Counts the workers a drawing really starts, through the page's Worker constructor.
    const countingWorkers = async (draw) => {
      const RealWorker = globalThis.Worker;
      let workersStarted = 0;
      globalThis.Worker = class extends RealWorker {
        constructor(...options) {
          super(...options);
          workersStarted += 1;
        }
      };
      try {
        return { result: await draw(), workersStarted };
      } finally {
        globalThis.Worker = RealWorker;
      }
    };
    const { result: unchecked, workersStarted: uncheckedWorkers } = await countingWorkers(() =>
      wallet.drawPhrase({ workers: 3 }),
    );
    expect(
      unchecked.walletCheck === false && unchecked.workers === 1 && uncheckedWorkers === 1,
      "a phrase without the wallet check is drawn by one worker, whatever workers says",
    );

    const checkedDraw = {
      passphrase: "TREZOR",
      passphraseRepeat: "TREZOR",
      walletCheck: true,
    };
    // Every worker of a checked draw failing at once, here from a random source of zeros, must
    // not take the page down: Firefox crashed the page when a worker was terminated while it
    // loaded the WebAssembly (reported by wallet-tools, 2026-10-08).
    const zeros = new MhfeWallet({
      workerSource:
        'Object.defineProperty(crypto, "getRandomValues", { value: (b) => b.fill(0) });\n' +
        WORKER_SOURCE,
      wasm: await WebAssembly.compile(bytes(WASM_BASE64)),
    });
    await expectRejection(
      zeros.drawPhrase({ ...checkedDraw, workers: 8 }),
      "RANDOM_FAILED",
      "eight workers that all fail at once end the drawing with RANDOM_FAILED, the page alive",
    );
    const running = wallet.drawPhrase({ ...checkedDraw, workers: 2 });
    await expectRejection(wallet.drawPhrase(), "BUSY", "a second drawing waits for none: BUSY");
    wallet.cancel();
    await expectRejection(running, "CANCELLED", "cancel() stops a drawing");
    expect(
      (await rejectionOf(running)) instanceof MhfeCancelledError,
      "a cancelled drawing rejects with MhfeCancelledError",
    );

    /** Whether a drawn phrase passes the wallet check with "TREZOR" and has that fingerprint. */
    const passesWithTrezor = async (drawnPhrase) =>
      drawnPhrase.words === 24 &&
      drawnPhrase.walletCheck === true &&
      (await wallet.walletCheck({ phrase: drawnPhrase.phrase, passphrase: "TREZOR" })) &&
      drawnPhrase.fingerprintWithPassphrase ===
        (await wallet.fingerprint({ phrase: drawnPhrase.phrase, passphrase: "TREZOR" }));
    // The two checked drawings of the page, about 65,536 BIP39 seeds each: one on the default
    // workers, one on a count given.
    const reports = [];
    const checked = await wallet.drawPhrase({
      ...checkedDraw,
      onProgress: (progress) => reports.push(progress),
    });
    const defaultWorkers = Math.min(navigator.hardwareConcurrency || 1, 8);
    expect(
      checked.workers === defaultWorkers && (await passesWithTrezor(checked)),
      `a checked phrase passes the wallet check, drawn on the default ${defaultWorkers} workers`,
    );
    // Whether a report comes at all is chance here: the phrase may be found before 1,024 draws.
    // The drawing stopped after three reports below checks that they come.
    expect(
      reports.every(
        (report, index) => report.stage === "draw" && report.draws === (index + 1) * 1024,
      ),
      `each of the ${reports.length} reports of the drawing adds the 1,024 draws of one worker`,
    );
    const givenWorkers = defaultWorkers > 1 ? defaultWorkers - 1 : 2;
    const { result: onGiven, workersStarted: givenStarted } = await countingWorkers(() =>
      wallet.drawPhrase({ ...checkedDraw, workers: givenWorkers }),
    );
    expect(
      onGiven.workers === givenWorkers &&
        givenStarted === givenWorkers &&
        (await passesWithTrezor(onGiven)),
      `a checked phrase drawn on ${givenWorkers} workers, as asked, passes the wallet check`,
    );

    // Each worker reports every 1,024 of its draws, so the total grows by 1,024 a report. A phrase
    // found before the third report (about one drawing in 21) ends the drawing first, so it is
    // tried again.
    let stoppedReports = [];
    let stopped = null;
    for (let attempt = 0; attempt < 5 && !(stopped instanceof MhfeCancelledError); attempt += 1) {
      const seen = [];
      stopped = await rejectionOf(
        wallet.drawPhrase({
          ...checkedDraw,
          workers: 2,
          onProgress: (progress) => {
            seen.push(progress);
            if (seen.length === 3) wallet.cancel();
          },
        }),
      );
      stoppedReports = seen;
    }
    expectEqual(
      stoppedReports,
      [
        { stage: "draw", draws: 1024 },
        { stage: "draw", draws: 2048 },
        { stage: "draw", draws: 3072 },
      ],
      "a drawing reports the draws of all workers, 1,024 more each time, until it is cancelled",
    );

    // The first report comes after 1,024 draws of a worker; a phrase found before it (about one
    // drawing in 32 on two workers) ends without one, so the drawing is tried again.
    const pageError = new Error("synthetic page error");
    let failure = null;
    let firstReport = null;
    for (let attempt = 0; attempt < 5 && failure === null; attempt += 1) {
      failure = await rejectionOf(
        wallet.drawPhrase({
          ...checkedDraw,
          workers: 2,
          onProgress: (progress) => {
            firstReport ??= progress;
            return Promise.reject(pageError);
          },
        }),
      );
    }
    expect(
      failure?.code === "CALLBACK_FAILED" &&
        failure.cause === pageError &&
        sameValue(firstReport, { stage: "draw", draws: 1024 }),
      "an onProgress whose promise rejects stops the drawing at the first report",
    );
    const after = await wallet.drawPhrase({
      passphrase: encode("TREZOR"),
      passphraseRepeat: "TREZOR",
      walletCheck: false,
    });
    expect(
      after.words === 24 &&
        after.workers === 1 &&
        after.fingerprintWithPassphrase ===
          (await wallet.fingerprint({ phrase: after.phrase, passphrase: "TREZOR" })),
      "a new drawing runs after one stopped; a passphrase as bytes is read",
    );
  }

  async function checkRuntime(client, passwords, wallet, compiled) {
    group("Runtime");
    await expectRejection(
      new MhfeRepair({
        workerSource: WORKER_SOURCE,
        wasm: new Uint8Array([0, 97, 115, 109]),
      }).parameters(),
      "WORKER_FAILED",
      "WebAssembly that does not compile rejects with WORKER_FAILED",
    );
    await expectRejection(
      new MhfeRepair({ workerSource: "this is not JavaScript (", wasm: compiled }).parameters(),
      "WORKER_FAILED",
      "a worker whose script does not parse rejects with WORKER_FAILED",
    );
    await expectRejection(
      new MhfePasswords({
        workerSource: 'throw new Error("stopped");',
        wasm: compiled,
      }).parameters(),
      "WORKER_FAILED",
      "a worker whose script throws rejects with WORKER_FAILED",
    );
    await expectRejection(
      client.encrypt({
        phrase: PHRASE,
        password: "a\uD800",
        passwordRepeat: "a\uD800",
        walletHasPassphrase: false,
      }),
      "INVALID_PASSWORD_TEXT",
      "a password with an unpaired surrogate is refused",
    );
    await expectRejection(
      new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled }).review({
        password: "\uDC00 test",
      }),
      "INVALID_PASSWORD_TEXT",
      "the passwords module refuses an unpaired surrogate too",
    );
    expect(
      (await client.readPhrase(PHRASE)).phrase === PHRASE,
      "the client works after workers that failed",
    );

    // The client's own byte copies of secrets, seen through the page's TextEncoder, must be wiped
    // when an operation cannot start: here the browser refuses the worker's Blob URL.
    const copies = [];
    const RealTextEncoder = globalThis.TextEncoder;
    globalThis.TextEncoder = class extends RealTextEncoder {
      encode(text) {
        const encoded = super.encode(text);
        if (text === PASSWORD || text === "TREZOR") copies.push(encoded);
        return encoded;
      }
    };
    const realCreateObjectURL = URL.createObjectURL;
    const wiped = () => copies.every((copy) => copy.every((byte) => byte === 0));
    try {
      URL.createObjectURL = () => {
        throw new Error("refused by the page");
      };
      const refusedCheck = () =>
        client.check({
          container: REDUCED_COST_CONTAINER,
          password: PASSWORD,
          reference: { fingerprint: FINGERPRINT },
          passphrase: "TREZOR",
        });
      await expectRejection(
        refusedCheck(),
        "WORKER_FAILED",
        "a Blob URL the browser refuses rejects with WORKER_FAILED",
      );
      await expectRejection(
        refusedCheck(),
        "WORKER_FAILED",
        "the refused operation freed its slot: the next is not BUSY",
      );
      URL.createObjectURL = realCreateObjectURL;
      expect(
        copies.length === 4 && wiped(),
        "the copies of the password and the passphrase were wiped",
      );
      copies.length = 0;
      await expectTypeError(
        passwords.review({ password: PASSWORD, passwordRepeat: 5 }),
        "repeated password must be a string or a Uint8Array.",
        "a repetition that is not text is refused",
      );
      await expectRejection(
        wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "\uD800", walletCheck: true }),
        "INVALID_PASSWORD_TEXT",
        "a passphrase repetition with an unpaired surrogate is refused",
      );
      // A repetition of the wrong type is refused before anything is copied (AUD-016-API003);
      // the unpaired surrogate is refused after the passphrase was copied, and that copy is wiped.
      expect(
        copies.length === 1 && wiped(),
        "the first entry's copy is wiped when its repetition is refused",
      );
    } finally {
      URL.createObjectURL = realCreateObjectURL;
      globalThis.TextEncoder = RealTextEncoder;
    }
  }

  function bytes(base64) {
    return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
  }

  main()
    .then((mode) => {
      window.mhfeCheck = { mode, results, failures };
    })
    .catch((error) => {
      failures.push("page error: " + (error.code ?? "") + " " + error.message);
      window.mhfeCheck = { mode: null, results, failures };
    });
}

const { version, buildId } = JSON.parse(read("dist/modules.json").toString());
const sources = `
const VERSION = ${inline(version)};
const PACKAGE_BUILD_ID = ${inline(buildId)};
const SELF_CHECK = ${inline(SELF_CHECK)};
const WORKER_SOURCE = ${inline(read("dist/runtime/worker.js").toString() + reducedCostWrapper)};
const WASM_BASE64 = ${inline(read("dist/runtime/mhfe.wasm").toString("base64"))};
const ARGON2_THREADED = ${inline(read("dist/core/argon2-mt.js").toString())};
const ARGON2_SINGLE_THREADED = ${inline(read("dist/core/argon2-st.js").toString())};
const PHRASE = ${inline(PHRASE)};
const REDUCED_COST_CONTAINER = ${inline(REDUCED_COST_CONTAINER)};
const REDUCED_COST_SAME_LENGTH_CONTAINER = ${inline(REDUCED_COST_SAME_LENGTH_CONTAINER)};
const FULL_SIZE_CONTAINER = ${inline(FULL_SIZE_CONTAINER)};
const CHECKED_PHRASE = ${inline(CHECKED_PHRASE)};
const EMPTY_CHECKED_PHRASE = ${inline(EMPTY_CHECKED_PHRASE)};
const AMBIGUOUS_12_WORDS = ${inline(AMBIGUOUS_12_WORDS)};
const WRONG_PASSWORD = ${inline(WRONG_PASSWORD)};
const READINGS = ${inline(READINGS)};
const FAULTY_CHECK_PASSWORD = ${inline(FAULTY_CHECK_PASSWORD)};
const MEMORY_FAILURE_PASSWORD = ${inline(MEMORY_FAILURE_PASSWORD)};
const MEMORY_FAILURE_CONTAINER = ${inline(MEMORY_FAILURE_CONTAINER)};
const FINGERPRINTS = ${inline(FINGERPRINTS)};
const WALLET_CHECKS = ${inline(WALLET_CHECKS)};
`;
const checks = `(${pageScript.toString()})();\n`;
const classes = bundleClasses(root, [
  "core/client.js",
  "repair/repair.js",
  "passwords/passwords.js",
  "wallet/wallet.js",
]);
const script = classes + sources + checks;

// The policy of scripts/build-browser-check.mjs and the offline wallet tools: nothing but this
// one script, WebAssembly and Blob workers.
const scriptHash = createHash("sha256").update(script, "utf8").digest("base64");
const policy = [
  "default-src 'none'",
  `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
  "connect-src 'none'",
  "worker-src blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");
const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${policy}" />
    <title>MHFE browser check</title>
  </head>
  <body>
    <script type="module">${script}</script>
  </body>
</html>
`;
const pagePath = fileURLToPath(new URL("target/browser-check/reduced-cost.html", root));
mkdirSync(new URL("target/browser-check/", root), { recursive: true });
writeFileSync(pagePath, page);

// The headers that make the page cross-origin isolated, so that the threaded Argon2 build runs.
const server = createServer((request, response) => {
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
  });
  response.end(page);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

const addresses = {
  standard: pathToFileURL(pagePath).href,
  fast: `http://127.0.0.1:${server.address().port}/`,
};
let failed = false;
try {
  for (const browserType of [chromium, firefox]) {
    const browser = await browserType.launch();
    try {
      for (const [mode, address] of Object.entries(addresses)) {
        failed = !(await checkPage(browser, browserType.name(), mode, address)) || failed;
      }
    } finally {
      await browser.close();
    }
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}
if (failed) {
  console.error("The browser check failed.");
  process.exit(1);
}
console.log("The browser package passes its checks in Chromium and Firefox, in both modes.");

/** Opens the page in a new tab and reports its results; true when everything passed. */
async function checkPage(browser, browserName, mode, address) {
  const page = await browser.newPage();
  const strayRequests = [];
  const pageErrors = [];
  // The page itself and its Blob workers are the only things it may load.
  page.on("request", (request) => {
    const url = request.url();
    if (url !== address && !url.startsWith("blob:")) strayRequests.push(url);
  });
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  try {
    await page.goto(address);
    const finished = page.waitForFunction(() => window.mhfeCheck !== undefined, null, {
      timeout: PAGE_TIMEOUT_MS,
    });
    finished.catch(() => {});
    // An error that stops the page's script, such as a SyntaxError, would otherwise wait out the
    // timeout; every uncaught error fails the check anyway.
    const stopped = new Promise((resolve) => page.once("pageerror", resolve));
    await Promise.race([finished, stopped]);
    const {
      mode: clientMode,
      results,
      failures,
    } = (await page.evaluate(() => window.mhfeCheck)) ?? {
      mode: null,
      results: [],
      failures: ["the page's script stopped"],
    };
    if (clientMode !== mode) failures.push(`the client ran in ${clientMode} mode, not ${mode}`);
    for (const url of strayRequests) failures.push(`a request left the page: ${url}`);
    for (const error of pageErrors) failures.push(`uncaught page error: ${error}`);
    console.log(`${browserName} ${browser.version()}, ${mode} mode:`);
    for (const line of results) console.log(`  ${line}`);
    for (const failure of failures) console.log(`  FAIL ${failure}`);
    return failures.length === 0;
  } finally {
    await page.close();
  }
}
