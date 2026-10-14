// @ts-check
// The passwords module's operations in the package's worker, with its self-check, whose full tier
// tries the worker's crypto.getRandomValues too.
"use strict";

/** The field types of this module's DTO; Rust keeps numeric and mnemonic rules. */
const PASSWORDS_FIELDS = /** @type {const} */ ({
  tier: "text",
  skip: "texts",
  password: "bytes",
  passwordRepeat: "bytes",
  repeated: "boolean",
  choice: "text",
  position: "number",
  kind: "text",
  count: "optionalNumber",
  rolls: "bytes",
  typed: "bytes",
});

/** @typedef {CheckedFields<typeof PASSWORDS_FIELDS>} PasswordsRequest */

/**
 * The passwords module's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<unknown>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const PASSWORD_OPERATIONS = operationsWithFields(PASSWORDS_FIELDS, {
  parameters: () => JSON.parse(mhfe.passwordParameters()),
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
});
