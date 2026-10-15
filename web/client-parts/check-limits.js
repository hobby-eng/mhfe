// @ts-check
import {
  MAX_PIM,
  MAX_MEMORY_LEVEL,
  HIGHEST_BROWSER_MEMORY_LEVEL,
  WORD_COUNTS,
  BUILT_IN_CHECK_WORD_COUNTS,
  REPAIR_WORD_COUNTS,
  DECOY_SCAN_GAP,
} from "./values.js";
import { isRecord, packageMismatch } from "../../runtime/runtime.js";

/**
 * The core's fixed values must be the limits this file checks before any secret is copied
 * (scripts/verify-browser-package.mjs compares them too); otherwise the files come from different
 * builds.
 * @param {unknown} parameters
 */
export function requireSameLimits(parameters) {
  const same =
    isRecord(parameters) &&
    isNumberArray(parameters.wordCounts) &&
    isNumberArray(parameters.builtInCheckWordCounts) &&
    isNumberArray(parameters.repairWordCounts) &&
    parameters.maxPim === MAX_PIM &&
    parameters.maxMemoryLevel === MAX_MEMORY_LEVEL &&
    parameters.highestBrowserMemoryLevel === HIGHEST_BROWSER_MEMORY_LEVEL &&
    parameters.wordCounts.join() === WORD_COUNTS.join() &&
    parameters.builtInCheckWordCounts.join() === BUILT_IN_CHECK_WORD_COUNTS.join() &&
    [0, ...parameters.repairWordCounts].join() === REPAIR_WORD_COUNTS.join() &&
    parameters.decoyScanGap === DECOY_SCAN_GAP;
  if (!same) {
    throw packageMismatch("The files core/client.js and runtime/mhfe.wasm have different limits");
  }
}

/**
 * Numeric-array shape of the core's limits before comparisons use its array methods.
 * @param {unknown} value
 * @returns {value is number[]}
 */
export function isNumberArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "number");
}
