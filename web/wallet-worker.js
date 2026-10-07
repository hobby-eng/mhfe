// The wallet module's operations in the package's worker, with its self-check, whose full tier
// tries the worker's crypto.getRandomValues too.
"use strict";

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
    JSON.parse(mhfe.describeAddress(request.address, request.coin, request.path)),
  drawPhrase: (request, host) =>
    JSON.parse(
      mhfe.drawPhrase(request.passphrase, request.walletCheck, host.random, (draws) =>
        host.post("draws", draws),
      ),
    ),
};
