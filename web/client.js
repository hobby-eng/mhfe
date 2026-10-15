// @ts-check
// The core module of the mhfe browser package: encryption, recovery, the rehearsal check, rekey,
// hidden wallets and the self-test, with Argon2. Every operation runs in a new Web Worker, so a
// long Argon2 computation never blocks the page, cancel() can end it at once, and the worker's
// memory is freed when the worker is terminated, as soon as it has loaded the WebAssembly.
//
// The page supplies the parts of the module as text and bytes, because a page under a strict
// Content-Security-Policy may not fetch anything:
//
//   const client = new MhfeClient({
//     workerSource,          // text of runtime/worker.js
//     wasm,                  // runtime/mhfe.wasm as a Uint8Array or a WebAssembly.Module
//     argon2Threaded,        // text of core/argon2-mt.js
//     argon2SingleThreaded,  // text of core/argon2-st.js
//   });
//
// A page that uses other module classes too compiles runtime/mhfe.wasm once, with
// WebAssembly.compile, and passes the WebAssembly.Module to each.
//
// Every operation returns a promise and reports every error by rejecting it, the checks of its
// arguments included; none throws when it is called. A callback of the page that throws, or whose
// promise rejects, stops the operation and rejects it with CALLBACK_FAILED. mode(),
// maxSupportedMemLevel() and cancel() are synchronous. Only the constructor throws, for missing
// package parts. One long operation runs at a time (BUSY otherwise); reading words and the
// parameters never wait. The first operation waits for the class's startup check
// (startupCheck()); parameters(), selfTest(), startupCheck() and fullCheck() do not.

import { refuseUnknownOptions } from "../runtime/runtime.js";

export { MhfeCancelledError, MhfeError } from "../runtime/runtime.js";

/**
 * @import { MhfeClient as DeclaredClient, MhfeSources } from "./client.d.ts"
 */

/** @import { OptionsOf } from "./types/client-shared.d.ts" */
/** @import { NoKeys } from "./types/api-presence.d.ts" */
/** @typedef {NoKeys<Exclude<keyof DeclaredClient, keyof MhfeClient>>} DeclaredButMissing */
/** @typedef {NoKeys<Exclude<keyof MhfeClient, keyof DeclaredClient>>} PresentButUndeclared */
/** @typedef {NoKeys<Exclude<keyof typeof DeclaredClient, keyof typeof MhfeClient>>} MissingStatics */
/** @typedef {NoKeys<Exclude<keyof typeof MhfeClient, keyof typeof DeclaredClient>>} ExtraStatics */

import { CoreReads } from "./client-parts/reads.js";
import { CoreEncryption } from "./client-parts/encryption.js";
import { CoreRehearsal } from "./client-parts/rehearsal.js";
import { CoreSearch } from "./client-parts/search.js";
import { CoreRekey } from "./client-parts/rekey.js";
import { CoreHiddenWallets } from "./client-parts/hidden.js";
import { CoreChecks } from "./client-parts/checks.js";
import { CoreRuntime } from "./client-parts/operation-runtime.js";

/** The public Argon2 mode names. */
export { FAST_MODE, STANDARD_MODE } from "./client-parts/values.js";

/** Thin core installer: operation groups share one worker slot and startup gate. */
export class MhfeClient {
  /** @type {CoreReads} */
  #reads;
  /** @type {CoreEncryption} */
  #encryption;
  /** @type {CoreRehearsal} */
  #rehearsal;
  /** @type {CoreSearch} */
  #search;
  /** @type {CoreRekey} */
  #rekey;
  /** @type {CoreHiddenWallets} */
  #hidden;
  /** @type {CoreChecks} */
  #checks;
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {Partial<MhfeSources>} [sources] */
  constructor(sources = {}) {
    this.#runtime = new CoreRuntime(sources, () => this.#checks.ready());
    this.#reads = new CoreReads(this.#runtime);
    this.#encryption = new CoreEncryption(this.#runtime);
    this.#rehearsal = new CoreRehearsal(this.#runtime);
    this.#search = new CoreSearch(this.#runtime);
    this.#rekey = new CoreRekey(this.#runtime);
    this.#hidden = new CoreHiddenWallets(this.#runtime);
    this.#checks = new CoreChecks(this.#runtime);
  }
  /** Delegates to the shared operation-runtime owner. */
  mode() {
    return this.#runtime.mode();
  }
  /** @param {OptionsOf<"startupCheck">} [options] */
  async startupCheck(options) {
    return this.#checks.startupCheck(options);
  }
  /** @param {OptionsOf<"fullCheck">} [options] */
  async fullCheck(options) {
    return this.#checks.fullCheck(options);
  }
  /** Delegates to the shared operation-runtime owner. */
  maxSupportedMemLevel() {
    return this.#runtime.maxSupportedMemLevel();
  }
  /** Delegates to the shared reads owner. */
  async parameters() {
    return this.#reads.parameters();
  }
  /** @param {unknown} phrase */
  async readPhrase(phrase) {
    return this.#reads.readPhrase(phrase);
  }
  /** @param {unknown} container */
  async readContainer(container) {
    return this.#reads.readContainer(container);
  }
  /** @param {OptionsOf<"encrypt">} [options] */
  async encrypt(options) {
    return this.#encryption.encrypt(options);
  }
  /** @param {OptionsOf<"decrypt">} [options] */
  async decrypt(options) {
    return this.#encryption.decrypt(options);
  }
  /** @param {OptionsOf<"check">} [options] */
  async check(options) {
    return this.#rehearsal.check(options);
  }
  /** @param {OptionsOf<"keepOldContainer">} [options] */
  async keepOldContainer(options) {
    return this.#reads.keepOldContainer(options);
  }
  /** @param {OptionsOf<"searchCandidates">} [options] */
  async searchCandidates(options) {
    return this.#reads.searchCandidates(options);
  }
  /** @param {OptionsOf<"searchDecoy">} [options] */
  async searchDecoy(options) {
    return this.#search.searchDecoy(options);
  }
  /** @param {OptionsOf<"searchWallet">} [options] */
  async searchWallet(options) {
    return this.#search.searchWallet(options);
  }
  /** @param {OptionsOf<"rekey">} [options] */
  async rekey(options) {
    return this.#rekey.rekey(options);
  }
  /** @param {OptionsOf<"openHiddenWallets">} [options] */
  async openHiddenWallets(options) {
    return this.#hidden.openHiddenWallets(options);
  }
  /** @param {OptionsOf<"selfTest">} [options] */
  async selfTest(options) {
    return this.#checks.selfTest(options);
  }
  /** Delegates to the shared operation-runtime owner. */
  cancel() {
    return this.#runtime.cancel();
  }
}

refuseUnknownOptions(MhfeClient.prototype, {
  startupCheck: ["argon2"],
  fullCheck: ["onProgress"],
  encrypt: [
    "phrase",
    "password",
    "passwordRepeat",
    "passwordRepair",
    "pim",
    "memoryLevel",
    "sameLength",
    "repairWordCount",
    "walletHasPassphrase",
    "onProgress",
    "onUnverified",
  ],
  decrypt: [
    "container",
    "password",
    "passwordRepair",
    "pim",
    "memoryLevel",
    "words",
    "passphrase",
    "onProgress",
  ],
  check: [
    "container",
    "password",
    "passwordRepair",
    "pim",
    "memoryLevel",
    "reference",
    "passphrase",
    "onProgress",
    "onNoLength",
  ],
  keepOldContainer: ["pim", "memoryLevel"],
  searchCandidates: ["container"],
  searchDecoy: ["container", "reference", "passphrase", "scanGap", "onProgress"],
  searchWallet: [
    "container",
    "password",
    "passwordRepair",
    "pim",
    "memoryLevel",
    "reference",
    "passphrase",
    "onProgress",
  ],
  rekey: [
    "container",
    "words",
    "password",
    "passwordRepair",
    "pim",
    "memoryLevel",
    "newPassword",
    "newPasswordRepeat",
    "newPasswordRepair",
    "newPim",
    "newMemoryLevel",
    "repairWordCount",
    "confirmation",
    "passphrase",
    "walletHasPassphrase",
    "onProgress",
    "onUnverified",
    "onConfirmAgain",
  ],
  openHiddenWallets: ["container", "pim", "memoryLevel", "mainPassphrase"],
  selfTest: ["onProgress"],
});
