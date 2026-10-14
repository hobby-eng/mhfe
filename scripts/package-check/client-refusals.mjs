// Part 4 of the checks of the browser package, continued: the refusals of the core client. Every
// error rejects the promise, the checks of the arguments included, and a refusal of the library
// that the client gives early is given in the library's words; a passphrase where it does not
// belong is refused before any message reaches a worker.
import assert from "node:assert/strict";

import { PHRASE } from "../public-test-data.mjs";
import { StandInWorker, started } from "./stand-in-worker.mjs";
import {
  NOT_BOOLEAN_ANSWERS,
  REKEY_PASSPHRASE_ONLY_WITH_REFERENCE,
  SEARCH_PASSPHRASE_ONLY_WITH_REFERENCE,
  WALLET_PASSPHRASE_REQUIRED,
  encode,
} from "./test-values.mjs";

/**
 * The client's encrypt of PHRASE with the password repeated and no BIP39 passphrase, and its rekey
 * of the stand-in's container, with what its checks of the confirmation need: `options` adds to
 * them or replaces them.
 */
export function clientCalls(client) {
  const encrypt = (options) =>
    client.encrypt({
      phrase: PHRASE,
      passwordRepeat: options.password,
      walletHasPassphrase: false,
      ...options,
    });
  const rekeyWith = (options) =>
    client.rekey({
      container: "c",
      password: "p",
      newPassword: "n",
      newPasswordRepeat: "n",
      ...options,
    });
  return { encrypt, rekeyWith };
}

/** The TypeError of a walletHasPassphrase that is not a boolean, with its exact message. */
const walletPassphraseRequired = { name: "TypeError", message: WALLET_PASSPHRASE_REQUIRED };
/** The TypeError of a passphrase with the built-in check or the owner, with its exact message. */
const searchPassphraseOnlyWithReference = {
  name: "TypeError",
  message: SEARCH_PASSPHRASE_ONLY_WITH_REFERENCE,
};
const rekeyPassphraseOnlyWithReference = {
  name: "TypeError",
  message: REKEY_PASSPHRASE_ONLY_WITH_REFERENCE,
};

/** Every error rejects the promise, the checks of the arguments included: none is thrown. */
export async function checkClientRefusals(client, libraryMessages) {
  const { encrypt, rekeyWith } = clientCalls(client);
  const refusals = [
    ...encryptRefusals(client, encrypt, libraryMessages),
    ...rekeyAndCallRefusals(client, encrypt, rekeyWith, libraryMessages),
    ...passwordTypeRefusals(encrypt, rekeyWith),
  ];
  for (const [call, expected] of refusals) {
    let result;
    assert.doesNotThrow(() => {
      result = call();
    }, "a refusal is a rejected promise, not an exception");
    assert.ok(result instanceof Promise);
    await assert.rejects(result, expected);
  }
}

/** The refusals of encrypt's options, and of a word count that is not a number. */
function encryptRefusals(client, encrypt, libraryMessages) {
  return [
    // encrypt may be given no answer, but one given is a boolean.
    ...[...NOT_BOOLEAN_ANSWERS, "yes"].map((walletHasPassphrase) => [
      () => encrypt({ password: "p", walletHasPassphrase }),
      walletPassphraseRequired,
    ]),
    [() => encrypt({ password: "p", sameLength: "yes" }), TypeError],
    [() => encrypt({ password: "p", repairWordCount: 3 }), { code: "INVALID_REPAIR_WORDS" }],
    [() => encrypt({ password: "p", passwordRepair: { repair: "3" } }), TypeError],
    [() => encrypt({ password: "a\uD800" }), { code: "INVALID_PASSWORD_TEXT" }],
    [
      () => encrypt({ password: "p", memoryLevel: 1 }),
      {
        code: "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
        message: libraryMessages.MEMORY_LEVEL_NOT_SUPPORTED_HERE,
      },
    ],
    [
      () => encrypt({ password: "p", pim: 1024 }),
      { code: "INVALID_PIM", message: libraryMessages.INVALID_PIM },
    ],
    [
      () => encrypt({ password: "p", memoryLevel: 22 }),
      { code: "INVALID_MEMORY_LEVEL", message: libraryMessages.INVALID_MEMORY_LEVEL },
    ],
    [
      () => encrypt({ password: "p", repairWordCount: 3 }),
      { code: "INVALID_REPAIR_WORDS", message: libraryMessages.INVALID_REPAIR_WORDS },
    ],
    // A value that is not a number, such as text pasted into the wrong field, is never repeated.
    [
      () => encrypt({ password: "p", pim: "abandon ability able" }),
      {
        code: "INVALID_PIM",
        message: "The PIM must be a whole number from 0 to 1023, not a number",
      },
    ],
    [
      () => encrypt({ password: "p", repairWordCount: "abandon" }),
      {
        code: "INVALID_REPAIR_WORDS",
        message:
          "The repair words cannot be used: a card has 2, 4, 6 or 8 repair words, not a number",
      },
    ],
    [
      () => client.decrypt({ container: "c", password: "p", words: "abandon" }),
      {
        code: "INVALID_WORD_COUNT",
        message: "The original seed phrase must have 12, 15, 18, 21 or 24 words, not a number",
      },
    ],
  ];
}

/** The refusals of a rekey's settings and answers, and of calls without what they need. */
function rekeyAndCallRefusals(client, encrypt, rekeyWith, libraryMessages) {
  return [
    // A rekey names its new settings, and the old ones as the container's.
    [
      () =>
        rekeyWith({
          confirmation: { builtInCheck: true },
          walletHasPassphrase: false,
          newPim: 1024,
        }),
      { code: "INVALID_PIM", message: libraryMessages.NEW_PIM },
    ],
    [
      () =>
        rekeyWith({
          confirmation: { builtInCheck: true },
          walletHasPassphrase: false,
          newMemoryLevel: 22,
        }),
      { code: "INVALID_MEMORY_LEVEL", message: libraryMessages.NEW_MEMORY_LEVEL },
    ],
    [
      () =>
        rekeyWith({ confirmation: { builtInCheck: true }, walletHasPassphrase: false, pim: 1024 }),
      { code: "INVALID_PIM", message: libraryMessages.INVALID_PIM },
    ],
    [() => encrypt({ password: "p", onUnverified: "show" }), TypeError],
    [() => client.encrypt(), TypeError],
    [
      () => client.decrypt({ container: "c", password: "p", words: 13 }),
      { code: "INVALID_WORD_COUNT", message: libraryMessages.INVALID_WORD_COUNT },
    ],
    [
      () => client.check({ container: "c", password: "p", reference: { words: 24 } }),
      { code: "INVALID_WORD_COUNT", message: libraryMessages.NO_BUILT_IN_CHECK_AT_24 },
    ],
    [
      () =>
        client.rekey({
          container: "c",
          password: "p",
          newPassword: "n",
          newPasswordRepeat: "n",
          confirmation: { words: 12 },
        }),
      TypeError,
    ],
    // A rekey's answer may be left out, but when given it is a boolean: null is not.
    ...["yes", ...NOT_BOOLEAN_ANSWERS, null].map((walletHasPassphrase) => [
      () => rekeyWith({ confirmation: { builtInCheck: true }, walletHasPassphrase }),
      walletPassphraseRequired,
    ]),
    [
      () =>
        rekeyWith({
          confirmation: { builtInCheck: true },
          walletHasPassphrase: false,
          onConfirmAgain: "again",
        }),
      TypeError,
    ],
    // A passphrase, as text or bytes, belongs only to an address or a fingerprint.
    ...[{ builtInCheck: true }, { owner: () => true }].flatMap((confirmation) =>
      ["TREZOR", encode("TREZOR")].map((passphrase) => [
        () => rekeyWith({ confirmation, passphrase, walletHasPassphrase: true }),
        rekeyPassphraseOnlyWithReference,
      ]),
    ),
    [() => client.openHiddenWallets({ container: "c" }), TypeError],
    [() => client.readPhrase(42), TypeError],
    [() => client.readContainer(), TypeError],
  ];
}

/**
 * A password of another type than a string or a Uint8Array is a TypeError, also when it is given
 * twice: the two entries do not differ, they are not passwords (AUD-010). The types are checked
 * before the entries are compared. A repetition left out still differs.
 */
function passwordTypeRefusals(encrypt, rekeyWith) {
  return [
    ...[new Uint16Array([112]), new ArrayBuffer(1), new Uint8ClampedArray([112]), 5, null].flatMap(
      (value) => [
        [
          () => encrypt({ password: value, passwordRepeat: value }),
          { name: "TypeError", message: "password must be a string or a Uint8Array." },
        ],
        [
          () => encrypt({ password: value, passwordRepeat: undefined }),
          { name: "TypeError", message: "password must be a string or a Uint8Array." },
        ],
        [
          () => encrypt({ password: "p", passwordRepeat: value }),
          { name: "TypeError", message: "repeated password must be a string or a Uint8Array." },
        ],
        [
          () =>
            rekeyWith({
              confirmation: { builtInCheck: true },
              walletHasPassphrase: false,
              newPassword: value,
              newPasswordRepeat: value,
            }),
          { name: "TypeError", message: "new password must be a string or a Uint8Array." },
        ],
        [
          () =>
            rekeyWith({
              confirmation: { builtInCheck: true },
              walletHasPassphrase: false,
              newPasswordRepeat: value,
            }),
          {
            name: "TypeError",
            message: "repeated new password must be a string or a Uint8Array.",
          },
        ],
      ],
    ),
    [
      () => encrypt({ password: undefined, passwordRepeat: "p" }),
      { name: "TypeError", message: "password must be a string or a Uint8Array." },
    ],
  ];
}

/**
 * A passphrase inside the reference instead of beside it, or a misspelled key, is refused before
 * any message reaches a worker, rather than dropped (AUD-023-API001); so is a passphrase with
 * searchWallet()'s built-in check. The documented shapes still send it.
 */
export async function checkMisplacedPassphrases(client) {
  const { rekeyWith } = clientCalls(client);
  let worker;
  const startedBeforeMisplaced = StandInWorker.started.length;
  const misplaced = [];
  for (const { inside, name } of [
    { inside: { fingerprint: "00000000", passphrase: "TREZOR" }, name: "passphrase" },
    { inside: { address: "a", coin: "btc", passphrase: "TREZOR" }, name: "passphrase" },
    { inside: { fingerprint: "00000000", passPhrase: "TREZOR" }, name: "passPhrase" },
  ]) {
    const message = (object) =>
      name === "passphrase"
        ? `passphrase is given beside the ${object}, not inside it.`
        : `${object}.${name} is not a key of a ${object}.`;
    const reference = { name: "TypeError", message: message("reference") };
    misplaced.push(
      [() => client.check({ container: "c", password: "p", reference: inside }), reference],
      [() => client.searchDecoy({ container: "c ?", reference: inside }), reference],
      [
        () => client.searchWallet({ container: "c ?", password: "p", reference: inside }),
        reference,
      ],
      [
        () => rekeyWith({ confirmation: inside, walletHasPassphrase: true }),
        { name: "TypeError", message: message("confirmation") },
      ],
    );
  }
  misplaced.push([
    () =>
      client.searchWallet({
        container: "c ?",
        password: "p",
        reference: { builtInCheck: true },
        passphrase: "TREZOR",
      }),
    searchPassphraseOnlyWithReference,
  ]);
  for (const [call, expected] of misplaced) await assert.rejects(call(), expected);
  assert.equal(StandInWorker.started.length, startedBeforeMisplaced, "no worker was started");
  // The built-in check with an empty passphrase still searches.
  const ownCheckSearch = client.searchWallet({
    container: "c ?",
    password: "p",
    reference: { builtInCheck: true },
    passphrase: "",
  });
  worker = await started();
  assert.equal(worker.messages[0].referenceKind, "builtInCheck");
  worker.reply({ type: "result", result: { found: [] } });
  assert.deepEqual(await ownCheckSearch, { found: [] });
  // The wallet check is no answer to onNoLength: it tells neither the length nor the wallet.
  const noLengthWalletCheck = client.check({
    container: "c",
    password: "p",
    reference: { words: 0 },
    onNoLength: () => ({ walletCheck: true, passphrase: "TREZOR" }),
  });
  worker = await started();
  worker.reply({ type: "ask", question: "noLength", value: { builtInCheck: null } });
  await assert.rejects(
    noLengthWalletCheck,
    (error) =>
      error.code === "CALLBACK_FAILED" &&
      error.cause instanceof TypeError &&
      error.cause.message ===
        "onNoLength gives a length, an address or a fingerprint, not the wallet check.",
  );
}
