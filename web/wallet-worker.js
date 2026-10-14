// @ts-check
// The wallet module's operations in the package's worker, with its self-check, whose full tier
// tries the worker's crypto.getRandomValues too.
"use strict";

/** The field types of this module's DTO; Rust keeps numeric and mnemonic rules. */
const WALLET_FIELDS = /** @type {const} */ ({
  tier: "text",
  skip: "texts",
  phrase: "bytes",
  passphrase: "bytes",
  passphraseRepeat: "bytes",
  address: "text",
  coin: "text",
  path: "text",
  scanGap: "optionalNumber",
  typed: "bytes",
  chosenWords: "bytes",
  places: "numbers",
  neverUse: "text",
  walletCheck: "boolean",
});

/** @typedef {CheckedFields<typeof WALLET_FIELDS>} WalletRequest */

/**
 * The wallet module's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<unknown>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const WALLET_OPERATIONS = operationsWithFields(WALLET_FIELDS, {
  parameters: () => JSON.parse(mhfe.walletParameters()),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckWallet(request.tier, request.skip, host.random, onStart, onResult),
    ),
  walletCheck: (request) => mhfe.walletCheck(request.phrase, request.passphrase),
  fingerprint: (request) => mhfe.walletFingerprint(request.phrase, request.passphrase),
  describeAddress: (request) =>
    JSON.parse(
      mhfe.describeAddress(request.address, request.coin, request.path, request.scanGap ?? 0),
    ),
  wordHints: (request) => JSON.parse(mhfe.wordHints("bip39", request.typed)),
  describeDraw: (request) =>
    JSON.parse(
      mhfe.describeDraw(
        request.chosenWords,
        Float64Array.from(request.places),
        request.neverUse,
        request.walletCheck,
      ),
    ),
  drawPhrase: (request, host) =>
    JSON.parse(
      mhfe.drawPhrase(
        request.passphrase,
        request.passphraseRepeat,
        request.chosenWords,
        Float64Array.from(request.places),
        request.neverUse,
        request.walletCheck,
        host.random,
        (draws) => host.post("draws", draws),
      ),
    ),
});
