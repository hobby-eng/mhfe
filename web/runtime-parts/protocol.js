// @ts-check
// Validated worker envelopes, payloads and self-check reports.
import { isRecord } from "./values.js";
import { isErrorCode, packageMismatch } from "./errors.js";
/** @import { HandlerResult, WorkerHandler, ArrivedHandler, WorkerReply, SetReport } from "../types/runtime-shared.d.ts" */
/** @import { MhfeComponentResult, MhfeErrorCode } from "../runtime.d.ts" */

// Deliberate copies of library protocol facts: the page must validate a worker's messages before
// invoking any handler, without calling the worker it is checking. The package's checkClientLimits
// compares these named sets with suiteParameters(), whose values come from the Rust owners.
const ROUND_PROGRESS_STAGES = ["recover", "encrypt", "check", "compare"];
const ROUND_PROGRESS_TOTALS = [12, 24, 36];
const OPENED_WORD_COUNT = 24;

/**
 * A worker error validated before its code enters MhfeError.
 * @param {unknown} value
 * @returns {{ code: MhfeErrorCode, message: string }}
 */
export function readWorkerError(value) {
  if (!isRecord(value) || !isErrorCode(value.code) || typeof value.message !== "string") {
    throw packageMismatch("The worker returned a malformed error");
  }
  return { code: value.code, message: value.message };
}

/**
 * Validates a channel's payload before a heterogeneous typed handler receives it. A handler's
 * declared parameter belongs to its registered channel; the cast stays inside this adapter,
 * after the channel reader has checked the received fields.
 * @param {WorkerHandler} handler
 * @param {string} channel
 * @param {unknown} value
 * @returns {() => HandlerResult}
 */
export function checkedPageHandler(handler, channel, value) {
  const checked = readWorkerValue(channel, value);
  return () => /** @type {ArrivedHandler} */ (handler)(checked);
}

/**
 * A worker channel's DTO. Values are returned only after the properties used by page handlers
 * are checked; malformed protocol data is PACKAGE_MISMATCH, independent of callback failures.
 * @param {string} channel
 * @param {unknown} value
 * @returns {unknown}
 */
function readWorkerValue(channel, value) {
  const numeric = (/** @type {unknown} */ item) =>
    typeof item === "number" && Number.isFinite(item);
  const numbers = (/** @type {unknown} */ items) => Array.isArray(items) && items.every(numeric);
  const mismatch = () => {
    throw packageMismatch(`The worker sent a malformed ${channel} value`);
  };
  if (channel === "ready") {
    if (value !== null) mismatch();
    return value;
  }
  if (channel === "draws") {
    if (!numeric(value)) mismatch();
    return value;
  }
  if (channel === "component") return readComponent(value);
  if (channel === "refused") return readWorkerError(value);
  if (!isRecord(value) || Array.isArray(value)) return mismatch();
  switch (channel) {
    case "componentStart":
      if (typeof value.id !== "string" || typeof value.label !== "string") mismatch();
      break;
    case "progress":
      if (typeof value.stage !== "string") return mismatch();
      if (value.stage === "search") {
        if (
          !numeric(value.candidate) ||
          !numeric(value.candidates) ||
          (value.round !== undefined && !numeric(value.round)) ||
          (value.rounds !== undefined && !numeric(value.rounds))
        )
          mismatch();
      } else if (
        !ROUND_PROGRESS_STAGES.includes(value.stage) ||
        typeof value.round !== "number" ||
        !Number.isSafeInteger(value.round) ||
        typeof value.rounds !== "number" ||
        !ROUND_PROGRESS_TOTALS.includes(value.rounds) ||
        value.round < 1 ||
        value.round > value.rounds
      )
        mismatch();
      break;
    case "unverified":
      if (typeof value.container !== "string" || typeof value.containerFingerprint !== "string")
        mismatch();
      break;
    case "ownerCheck":
      if (
        typeof value.phrase !== "string" ||
        !numeric(value.words) ||
        (value.statedWords !== undefined && !numeric(value.statedWords)) ||
        typeof value.fingerprintWithoutPassphrase !== "string" ||
        typeof value.rehearsalNeedsPassphrase !== "boolean"
      )
        mismatch();
      break;
    case "confirmAgain":
      readWorkerError(value);
      if (!numbers(value.ownerLengths)) mismatch();
      break;
    case "opened":
      if (
        typeof value.phrase !== "string" ||
        value.words !== OPENED_WORD_COUNT ||
        typeof value.fingerprintWithoutPassphrase !== "string"
      )
        mismatch();
      break;
    case "noLength":
      if (
        !(value.builtInCheck === null || numeric(value.builtInCheck)) ||
        !numbers(value.matchingLengths) ||
        !(value.walletCheck === null || typeof value.walletCheck === "boolean") ||
        !Array.isArray(value.passed)
      )
        return mismatch();
      for (const passed of value.passed) {
        if (
          !isRecord(passed) ||
          !(
            passed.check === "walletCheck" ||
            (passed.check === "builtInCheck" && numeric(passed.words)) ||
            (passed.check === "builtInChecks" && numbers(passed.lengths))
          )
        )
          mismatch();
      }
      break;
    default:
      return mismatch();
  }
  return value;
}

/**
 * A library component's outcome tag. Deliberate copy of MhfeComponentResult's declaration:
 * runtime messages need the type-only enum's values before they can be used.
 * @param {unknown} value
 * @returns {value is MhfeComponentResult["outcome"]}
 */
function isComponentOutcome(value) {
  return (
    value === "passed" ||
    value === "warning" ||
    value === "notAvailable" ||
    value === "notRun" ||
    value === "failed"
  );
}

/**
 * A self-check component at the page-worker trust boundary, without trusting a producer's cast.
 * @param {unknown} value
 * @returns {MhfeComponentResult}
 */
function readComponent(value) {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.label !== "string" ||
    !isComponentOutcome(value.outcome) ||
    (value.detail !== undefined && typeof value.detail !== "string")
  ) {
    throw packageMismatch("The worker returned a malformed self-check component");
  }
  const component = { id: value.id, label: value.label, outcome: value.outcome };
  return value.detail === undefined ? component : { ...component, detail: value.detail };
}

/**
 * Text-array shape at a protocol trust boundary, including every element.
 * @param {unknown} value
 * @returns {value is string[]}
 */
function isTextArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

/**
 * A self-check set received from a worker; partial or null results are package mismatches.
 * @param {unknown} value
 * @returns {SetReport}
 */
export function readSetReport(value) {
  if (
    !isRecord(value) ||
    !(typeof value.version === "string" || value.version === null) ||
    !Array.isArray(value.components) ||
    (value.ids !== undefined && !isTextArray(value.ids))
  ) {
    throw packageMismatch("The worker returned a malformed self-check report");
  }
  const report = { version: value.version, components: value.components.map(readComponent) };
  const componentIds = report.components.map(({ id }) => id);
  if (
    componentIds.some((id) => id.length === 0) ||
    new Set(componentIds).size !== componentIds.length
  ) {
    throw packageMismatch("The worker returned repeated or empty self-check component identities");
  }
  if (value.ids === undefined) {
    // A trap cannot supply its final order, but an explicit failed part closes the class.
    if (!report.components.some(({ outcome }) => outcome === "failed") || value.passed === true) {
      throw packageMismatch("The worker omitted the self-check identities");
    }
    return report;
  }
  const ids = value.ids;
  if (
    typeof value.version !== "string" ||
    (value.tier !== "startup" && value.tier !== "full") ||
    typeof value.passed !== "boolean" ||
    ids.length === 0 ||
    ids.some((id) => id.length === 0) ||
    new Set(ids).size !== ids.length ||
    componentIds.some((id) => !ids.includes(id))
  ) {
    throw packageMismatch("The worker returned inconsistent self-check identities or tier");
  }
  return { ...report, ids, tier: value.tier, passed: value.passed };
}

/**
 * The news a worker posts besides its result, error and questions, which go to the page's
 * handlers of the same name: web/worker-runtime.js (progress and the self-check's parts),
 * web/core-worker.js (unverified) and web/wallet-worker.js (draws). scripts/verify-browser-package.mjs
 * keeps this list equal to the types the worker scripts post.
 */
export const WORKER_NEWS = ["progress", "componentStart", "component", "draws", "unverified"];

/**
 * A message or question of a worker that this page does not know or cannot read, as from a worker
 * of another build. Only text is shown as it is: String() of an object a worker sent may throw, as
 * one whose own toString is not a function.
 * @param {unknown} name
 */
export function unknownMessage(name) {
  const shown = typeof name === "string" || name === null ? String(name) : typeof name;
  return packageMismatch(`The worker sent a message this page does not know (${shown})`);
}

/**
 * Whether `reply` is a message as the package's worker posts it (web/worker-runtime.js), so that
 * reading it cannot throw: an object with a type, a ready's build as text, and an error's code and
 * message as text. A result and the value of news or of a question go to the page as they are, and
 * a question is checked when it is answered.
 * @param {unknown} reply
 * @returns {reply is WorkerReply}
 */
export function isReadableReply(reply) {
  if (!isRecord(reply) || typeof reply.type !== "string") return false;
  if (reply.type === "ready") return typeof reply.buildId === "string";
  if (reply.type !== "error") return true;
  const { error } = reply;
  return isRecord(error) && isErrorCode(error.code) && typeof error.message === "string";
}
