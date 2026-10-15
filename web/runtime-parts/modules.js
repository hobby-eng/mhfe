// @ts-check
// Common operations of browser modules without Argon2.
import { encodeSecret } from "./secrets.js";
import { CompiledModule } from "./compiled.js";
import { PackageCheck } from "./checks.js";
import { requireCallback, refuseUnknownOptions } from "./arguments.js";
import { WorkerJob } from "./jobs.js";
/** @import { WorkerRequest, WorkerHandlers, SelfCheckListener, PackageCheckOptions } from "../types/runtime-shared.d.ts" */
/** @import { MhfeSelfCheckTier } from "../runtime.d.ts" */

/**
 * The hint for `typed`, a line of words typed so far, from the word list of the class that `module`
 * serves: what MhfeWallet.wordHints() and MhfePasswords.wordHints() give. The line may be part of a
 * seed phrase or a password, so it reaches the worker as bytes that the worker wipes.
 * @param {ModuleWorker} module
 * @param {unknown} typed
 */
export async function wordHintsOf(module, typed) {
  await module.ready();
  return module.run({ operation: "wordHints", typed: encodeSecret(typed, "typed") });
}

/**
 * What the module classes without Argon2 (repair, passwords, wallet) hold in common, used by
 * composition: the worker's text, the compiled WebAssembly and the class's self-check, with which
 * each runs its set of known answers and its operations, each in a worker of its own. The core's
 * MhfeClient has its own, with its slot and Argon2 builds.
 */
export class ModuleWorker {
  /** @type {string} */
  #module;
  /** @type {string} */
  #workerSource;
  /** @type {CompiledModule} */
  #wasm;
  /** @type {PackageCheck} */
  #check;

  /**
   * `module` names the module's operations in the worker; `workerSource` is the text of
   * runtime/worker.js and `wasm` runtime/mhfe.wasm, as the page passed them; the rest goes to the
   * class's PackageCheck.
   * @param {{ module: string, workerSource: unknown, wasm: unknown }
   *   & Omit<PackageCheckOptions, "wasm" | "identityOf">} options
   */
  constructor({ module, workerSource, wasm, classFile, classBuildId, needs, secrets }) {
    if (typeof workerSource !== "string" || workerSource.length === 0) {
      throw new TypeError("workerSource must be the text of runtime/worker.js.");
    }
    this.#module = module;
    this.#workerSource = workerSource;
    this.#wasm = new CompiledModule(wasm, "wasm");
    this.#check = new PackageCheck({
      wasm: this.#wasm,
      classFile,
      classBuildId,
      needs,
      secrets,
    });
  }

  /** The class's startup check, made once; see a class's startupCheck(). */
  startupCheck() {
    return this.#check.startup("startup", (skip, handlers) =>
      this.#selfCheck("startup", skip, handlers),
    );
  }

  /**
   * The class's full self-check, run anew; see a class's fullCheck().
   * @param {SelfCheckListener | undefined} onProgress
   */
  fullCheck(onProgress) {
    requireCallback(onProgress, "onProgress");
    return this.#check.full(
      [{ run: (skip, handlers) => this.#selfCheck("full", skip, handlers) }],
      onProgress,
    );
  }

  /** Resolves once the startup check has passed; rejects with SELF_CHECK_FAILED otherwise. */
  ready() {
    return this.#check.require(() => this.startupCheck());
  }

  /**
   * Runs an operation of the module in a worker of its own, its secret buffers transferred.
   * @param {WorkerRequest} message
   */
  run(message) {
    return this.start(message).done;
  }

  /**
   * Starts an operation in a worker of its own, whose messages go to `handlers`, and gives the
   * job, which can be stopped, with the promise of its result.
   * @param {WorkerRequest} message
   * @param {WorkerHandlers} [handlers]
   */
  start(message, handlers = {}) {
    const job = new WorkerJob([this.#workerSource], handlers);
    const request = { module: this.#module, ...message };
    return { job, done: job.run(request, this.#wasm) };
  }

  /**
   * Runs the module's set of known answers at `tier` in a worker of its own.
   * @param {MhfeSelfCheckTier} tier
   * @param {string[]} skip
   * @param {WorkerHandlers} handlers
   */
  #selfCheck(tier, skip, handlers) {
    return new WorkerJob([this.#workerSource], handlers).run(
      { module: this.#module, operation: "selfCheck", tier, skip },
      this.#wasm,
    );
  }
}

/**
 * What the module classes MhfeRepair, MhfePasswords and MhfeWallet have in common: their
 * self-checks and their fixed values, through the ModuleWorker each runs its operations with. A
 * class extends it with its own operations and keeps the same ModuleWorker in a private field of
 * its own.
 */
export class MhfeModuleClass {
  /** @type {ModuleWorker} */
  #module;

  /** @param {ModuleWorker} module */
  constructor(module) {
    this.#module = module;
  }

  /**
   * The quick self-check of the class, which every other method but parameters(), fullCheck() and
   * cancel() awaits before its first call: known answers of each part the class computes, each
   * with a case it must refuse, and what the page itself must do. Resolves to `{ passed, tier,
   * version, buildId, components: [{ id, label, outcome, detail? }] }`, made once per page: parts
   * that another class of the page passed with the same WebAssembly are not run again. When a part
   * has failed, every method of the class rejects with SELF_CHECK_FAILED from then on, the report
   * attached; a page keeps its controls closed and shows the report.
   */
  async startupCheck() {
    return this.#module.startupCheck();
  }

  /**
   * The full self-check, run anew each time: every part with its slower cases.
   * `onProgress({ id, label, running, outcome?, detail? })` hears of each part as it starts and
   * ends. Resolves to a report as startupCheck() does; a failed part closes the class as there.
   * @param {{ onProgress?: SelfCheckListener }} [options]
   */
  async fullCheck({ onProgress } = {}) {
    return this.#module.fullCheck(onProgress);
  }

  /** The module's fixed values; see the class's declaration file. */
  async parameters() {
    return this.#module.run({ operation: "parameters" });
  }
}

refuseUnknownOptions(MhfeModuleClass.prototype, { fullCheck: ["onProgress"] });
