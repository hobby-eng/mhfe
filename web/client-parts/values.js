// @ts-check
// Deliberate copies of library limits for refusal before any secret is copied.
// The package checks compare these with suiteParameters(), including the Argon2 part names.
/** @import { MhfeComponentResult } from "../../runtime/runtime.js" */

/** Four Argon2 lanes in parallel; needs a cross-origin isolated page, such as `mhfe serve` gives. */
export const FAST_MODE = "fast";

/** One lane after another; works everywhere, including a page opened as a file. */
export const STANDARD_MODE = "standard";

/** The reference Argon2 code allows 2 GiB when pointers are 32 bits wide, as in WebAssembly: memory level 0 only. */
export const HIGHEST_BROWSER_MEMORY_LEVEL = 0;

export const MAX_PIM = 1023;

export const MAX_MEMORY_LEVEL = 21;

export const WORD_COUNTS = [12, 15, 18, 21, 24];

export const BUILT_IN_CHECK_WORD_COUNTS = [12, 15, 18, 21];

export const REPAIR_WORD_COUNTS = [0, 2, 4, 6, 8];

export const DECOY_SCAN_GAP = 20;

export const REFERENCE_KINDS = ["address", "fingerprint", "words", "walletCheck"];

/** The forms of a reference in each operation's refusal (AUD-024-API004). */
export const ADDRESS_REFERENCE_FORMS = "{ address, coin, path? } or { fingerprint }";

export const CHECK_REFERENCE_FORMS =
  "{ address, coin, path? }, { fingerprint }, { words } or { walletCheck: true }";

export const WALLET_SEARCH_FORMS =
  "{ address, coin, path? }, { fingerprint }, { walletCheck: true } or { builtInCheck: true }";

export const NO_LENGTH_FORMS =
  "{ words: 12 | 15 | 18 | 21 }, { address, coin, path? } or { fingerprint }";

/** Every key a reference may have: its kind, and the coin and path of an address. */
export const REFERENCE_KEYS = [...REFERENCE_KINDS, "coin", "path"];

/** The options of a hidden-wallet session's open(). */
export const OPEN_KEYS = ["password", "passwordRepeat", "passwordRepair", "onProgress"];

/** The name of this module's operations in the package's worker. */
export const CORE_MODULE = "core";

/** The build of this file, which scripts/stamp-build-id.mjs writes; see BUILD_ID in the runtime. */
export const CLIENT_BUILD_ID = "development";

export const ARGON2_PART = "argon2";

export const ARGON2_SIZES_PART = "argon2-sizes";

/** How the full self-check names the check at 64 and 256 MiB of each of the two Argon2 builds. */
export const ARGON2_SIZES_OF_BUILD = {
  singleThreaded: {
    id: "argon2-sizes-single-threaded",
    label: "Argon2id at 64 and 256 MiB, single-threaded build",
  },
  threaded: { id: "argon2-sizes-threaded", label: "Argon2id at 64 and 256 MiB, threaded build" },
};

/**
 * What the full self-check lists without running: the published vectors, which take minutes and
 * 2 GiB and run in selfTest() only. The parts of the command-line tool's self-test that a browser
 * cannot check come from the WebAssembly, with the reason (selfCheckProcess).
 * @type {MhfeComponentResult[]}
 */
export const NOT_RUN_IN_FULL_CHECK = [
  {
    id: "published-vectors",
    label: "Published vectors",
    outcome: "notRun",
    detail: "they take minutes and 2 GiB: selfTest() runs them",
  },
];
