// The wallet module's operations in the package's worker, with its self-check.
"use strict";

const WALLET_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.walletParameters()),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckWallet(request.tier, request.skip, onStart, onResult),
    ),
  walletCheck: (request) => mhfe.walletCheck(request.phrase, request.passphrase),
  fingerprint: (request) => mhfe.walletFingerprint(request.phrase, request.passphrase),
  describeAddress: (request) =>
    JSON.parse(
      mhfe.describeAddress(request.address, request.coin, request.path, request.scanGap ?? 0),
    ),
  wordHints: (request) => JSON.parse(mhfe.wordHints("bip39", request.typed)),
};
