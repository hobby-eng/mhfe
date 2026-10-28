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

