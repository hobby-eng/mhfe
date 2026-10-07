// The end of the package's worker: it serves the operations of every module, by module and name.
"use strict";

serveOperations(mhfe, {
  core: CORE_OPERATIONS,
  repair: REPAIR_OPERATIONS,
  passwords: PASSWORD_OPERATIONS,
  wallet: WALLET_OPERATIONS,
});
