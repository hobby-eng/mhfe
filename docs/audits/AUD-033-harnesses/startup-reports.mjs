// Actual classes and raw inspection with finite worker-boundary envelope faults.
import { checkCheckpointGates } from "../../../scripts/package-check/checkpoint-gates.mjs";
import { loadClasses } from "../../../scripts/package-check/page-classes.mjs";
import { checkStartupReportBoundaries } from "../../../scripts/package-check/startup-report-boundaries.mjs";
import { installStandInWorker } from "../../../scripts/package-check/stand-in-worker.mjs";
const classes = await loadClasses();
installStandInWorker();
await checkCheckpointGates(classes.runtime);
await checkStartupReportBoundaries(classes);
console.log("Startup completeness, immutable-cache, failure-latch and dispatch controls passed.");
