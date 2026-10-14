// @ts-check
// The repair module's operations in the package's worker, with its self-check.
"use strict";

/**
 * A request of the repair module's operations as web/repair.js sends it; each operation reads its
 * own fields.
 * @typedef {SelfCheckRequest & { container: string, count: number, card: string }} RepairRequest
 */

/**
 * The repair module's operations by name, which web/worker-start.js serves.
 * @type {Record<string, Operation<RepairRequest>>}
 */
// oxlint-disable-next-line no-unused-vars -- web/worker-start.js serves it in runtime/worker.js
const REPAIR_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.repairParameters()),
  packageVersion: () => mhfe.packageVersion(),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckRepair(request.tier, request.skip, onStart, onResult),
    ),
  repairWords: (request) => JSON.parse(mhfe.repairWords(request.container, request.count)),
  repairContainer: (request) => JSON.parse(mhfe.repairContainer(request.container, request.card)),
  inspectContainer: (request) => JSON.parse(mhfe.inspectContainer(request.container)),
};
