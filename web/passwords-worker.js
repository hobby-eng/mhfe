// The passwords module's operations in the package's worker, with its self-check, whose full tier
// tries the worker's crypto.getRandomValues too.
"use strict";

const PASSWORD_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.passwordParameters()),
  packageVersion: () => mhfe.packageVersion(),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckPasswords(request.tier, request.skip, host.random, onStart, onResult),
    ),
  review: (request) =>
    JSON.parse(mhfe.reviewPassword(request.password, request.passwordRepeat, request.repeated)),
  strength: (request) =>
    JSON.parse(mhfe.passwordStrength(request.password, request.choice, request.position)),
  make: (request, host) =>
    JSON.parse(mhfe.makePassword(request.kind, request.count, request.rolls, host.random)),
  wordHints: (request) => JSON.parse(mhfe.wordHints("eff", request.typed)),
};
