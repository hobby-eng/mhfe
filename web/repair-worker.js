// @ts-check
// The repair module's operations in the package's worker, with its self-check.
"use strict";

/** The field types of this module's DTO; Rust keeps numeric and mnemonic rules. */
const REPAIR_FIELDS = /** @type {const} */ ({
  tier: "text",
  skip: "texts",
  container: "text",
  count: "number",
  card: "text",
});

/** @typedef {CheckedFields<typeof REPAIR_FIELDS>} RepairRequest */

/**
 * The repair module's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<unknown>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const REPAIR_OPERATIONS = operationsWithFields(REPAIR_FIELDS, {
  parameters: () => JSON.parse(mhfe.repairParameters()),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckRepair(request.tier, request.skip, onStart, onResult),
    ),
  repairWords: (request) => JSON.parse(mhfe.repairWords(request.container, request.count)),
  repairContainer: (request) => JSON.parse(mhfe.repairContainer(request.container, request.card)),
  inspectContainer: (request) => JSON.parse(mhfe.inspectContainer(request.container)),
});
