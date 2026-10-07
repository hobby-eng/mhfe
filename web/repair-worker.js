// The repair module's operations in the package's worker, with its self-check.
"use strict";

const REPAIR_OPERATIONS = {
  parameters: () => JSON.parse(mhfe.repairParameters()),
  packageVersion: () => mhfe.packageVersion(),
  selfCheck: (request, host) =>
    host.selfCheck(request.tier, (onStart, onResult) =>
      mhfe.selfCheckRepair(request.tier, request.skip, onStart, onResult),
    ),
  repairWords: (request) => JSON.parse(mhfe.repairWords(request.container, request.count)),
  repairPlate: (request) => JSON.parse(mhfe.repairPlate(request.plate, request.card)),
};
