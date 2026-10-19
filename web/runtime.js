// @ts-check
// The runtime the module classes of the mhfe browser package share: errors, the WebAssembly
// compiled once, the worker of one operation, the byte copies of secrets, and the self-check that
// a class runs before its first operation. Every module class (core/client.js, repair/repair.js,
// passwords/passwords.js, wallet/wallet.js) imports it from "../runtime/runtime.js" and uses it by
// composition.
//
// A page supplies every part as text or bytes, because a page under a strict
// Content-Security-Policy may not fetch anything. Each operation runs in a new Web Worker made from
// a Blob of the package's worker script, runtime/worker.js, so the page never blocks, cancel()
// ends an operation at once, and the worker's memory, secrets included, is freed when the worker
// is terminated, which waits until a worker still loading the WebAssembly has loaded it. Every module
// runs in the same WebAssembly, runtime/mhfe.wasm; a request names its module and operation.
//
// The types of the JSDoc comments come from the declaration file beside this file, runtime.d.ts,
// and from the typedefs below for what the declaration leaves out (TS-13).

/**
 * @import { CompiledModule as DeclaredCompiledModule, MhfeError as DeclaredError,
 *   MhfeModuleClass as DeclaredModuleClass,
 *   InputTextBoundary as DeclaredInputTextBoundary } from "./runtime.d.ts"
 */

/** @import { NoKeys } from "./types/api-presence.d.ts" */
/** @typedef {NoKeys<Exclude<keyof DeclaredCompiledModule, keyof CompiledModule>>} MissingCompiledKeys */
/** @typedef {NoKeys<Exclude<keyof CompiledModule, keyof DeclaredCompiledModule>>} ExtraCompiledKeys */
/** @typedef {NoKeys<Exclude<keyof DeclaredError, keyof MhfeError>>} MissingErrorKeys */
/** @typedef {NoKeys<Exclude<keyof MhfeError, keyof DeclaredError>>} ExtraErrorKeys */
/** @typedef {NoKeys<Exclude<keyof DeclaredModuleClass<unknown>, keyof MhfeModuleClass>>} MissingModuleKeys */
/** @typedef {NoKeys<Exclude<keyof MhfeModuleClass, keyof DeclaredModuleClass<unknown>>>} ExtraModuleKeys */
/** @typedef {NoKeys<Exclude<keyof typeof DeclaredCompiledModule, keyof typeof CompiledModule>>} MissingCompiledStatics */
/** @typedef {NoKeys<Exclude<keyof typeof CompiledModule, keyof typeof DeclaredCompiledModule>>} ExtraCompiledStatics */
/** @typedef {NoKeys<Exclude<keyof typeof DeclaredError, keyof typeof MhfeError>>} MissingErrorStatics */
/** @typedef {NoKeys<Exclude<keyof typeof MhfeError, keyof typeof DeclaredError>>} ExtraErrorStatics */
/** @typedef {NoKeys<Exclude<keyof typeof DeclaredModuleClass, keyof typeof MhfeModuleClass>>} MissingModuleStatics */
/** @typedef {NoKeys<Exclude<keyof typeof MhfeModuleClass, keyof typeof DeclaredModuleClass>>} ExtraModuleStatics */
/** @typedef {NoKeys<Exclude<keyof DeclaredInputTextBoundary, keyof InputTextBoundary>>} MissingTextBoundaryKeys */
/** @typedef {NoKeys<Exclude<keyof InputTextBoundary, keyof DeclaredInputTextBoundary>>} ExtraTextBoundaryKeys */

// Source parts are joined by scripts/browser-source.mjs into the unchanged shipped path.
/** @import { CompiledModule } from "./runtime-parts/compiled.js" */
/** @import { MhfeError } from "./runtime-parts/errors.js" */
/** @import { MhfeModuleClass } from "./runtime-parts/modules.js" */
/** @import { InputTextBoundary } from "./runtime-parts/input-text.js" */

/** Shared errors exports. */
export {
  BUILD_ID,
  MhfeError,
  MhfeCancelledError,
  packageMismatch,
} from "./runtime-parts/errors.js";

/** Shared values exports. */
export { isRecord, sentence, countsText } from "./runtime-parts/values.js";

/** Library-parameter-driven raw text admission before owned copies. */
export { InputTextBoundary, requireInputText } from "./runtime-parts/input-text.js";

/** Shared protocol exports. */
export { readSetReport } from "./runtime-parts/protocol.js";

/** Shared jobs exports. */
export { WorkerJob, OperationSlot } from "./runtime-parts/jobs.js";

/** Shared secrets exports. */
export {
  SecretBytes,
  SecretRequest,
  requireSecret,
  secretOrEmpty,
  encodeSecret,
} from "./runtime-parts/secrets.js";

/** Shared arguments exports. */
export {
  HIGHEST_WORD_POSITION,
  describeChoice,
  requireText,
  requireKnownKeys,
  refuseUnknownOptions,
  requireBoolean,
  requireCallback,
} from "./runtime-parts/arguments.js";

/** Shared callbacks exports. */
export { askPage } from "./runtime-parts/callbacks.js";

/** Shared compiled exports. */
export { CompiledModule } from "./runtime-parts/compiled.js";

/** Shared checks exports. */
export { PackageCheck } from "./runtime-parts/checks.js";

/** Shared modules exports. */
export { ModuleWorker, MhfeModuleClass, wordHintsOf } from "./runtime-parts/modules.js";
