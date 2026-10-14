// @ts-check
// The wallet module's operations in the package's worker, with its self-check, whose full tier
// tries the worker's crypto.getRandomValues too.
"use strict";

/**
 * A request of the wallet module's operations as web/wallet.js sends it; each operation reads its
 * own fields. The secrets arrive as bytes, which the worker wipes after the operation.
 * @typedef {SelfCheckRequest & { phrase: Uint8Array, passphrase: Uint8Array,
 *   passphraseRepeat: Uint8Array, address: string, coin: string, path: string,
 *   scanGap: number | undefined, typed: Uint8Array, chosenWords: Uint8Array, places: number[],
 *   neverUse: string, walletCheck: boolean }} WalletRequest
 */

/**
 * The wallet module's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<WalletRequest>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const WALLET_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.walletParameters()),
  packageVersion: () => mhfe.packageVersion(),
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
        Uint32Array.from(request.places),
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
        Uint32Array.from(request.places),
        request.neverUse,
        request.walletCheck,
        host.random,
        (draws) => host.post("draws", draws),
      ),
    ),
};
