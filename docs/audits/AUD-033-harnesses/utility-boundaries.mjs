// Public regression controls over the currently built package; no drawing or full-cost Argon2.
import { checkInputText } from "../../../scripts/package-check/input-text.mjs";
import { loadClasses } from "../../../scripts/package-check/page-classes.mjs";
import { checkUtilityInputBoundaries, checkUtilityClassBoundaries } from "../../../scripts/package-check/utility-input-boundaries.mjs";
import { installStandInWorker } from "../../../scripts/package-check/stand-in-worker.mjs";
const classes = await loadClasses();
installStandInWorker();
await checkInputText(classes.runtime, 8192);
checkUtilityInputBoundaries();
await checkUtilityClassBoundaries(classes);
console.log("Utility raw, byte-copy, framed-entry and class cancellation controls passed.");
