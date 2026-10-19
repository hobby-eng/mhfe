// @ts-check
/** @import { MhfeSelfCheckTier, WorkerHandlers } from "../../runtime/runtime.js" */
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import {
  CLIENT_BUILD_ID,
  ARGON2_PART,
  ARGON2_SIZES_PART,
  FAST_MODE,
  ARGON2_CHECKS_OF_BUILD,
  NOT_RUN_IN_FULL_CHECK,
  CORE_MODULE,
} from "./values.js";
import { requireSameLimits } from "./check-limits.js";
import {
  PackageCheck,
  requireBoolean,
  requireCallback,
  WorkerJob,
  readSetReport,
  isRecord,
} from "../../runtime/runtime.js";
/** @import { CheckStep } from "../../runtime/runtime.js" */
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreChecks owns this operation group behind the client's shared worker boundary. */
export class CoreChecks {
  /** @type {CoreRuntime} */
  #runtime;
  /** @type {PackageCheck} */
  #check;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
    this.#check = new PackageCheck({
      wasm: runtime.wasm,
      classFile: "core/client.js",
      classBuildId: CLIENT_BUILD_ID,
      needs: ["threads"],
      secrets: true,
      // Argon2's known answer holds for the build that gave it, which another client may not use.
      identityOf: (id) => (id === ARGON2_PART ? runtime.argon2Source() : undefined),
    });
  }
  /**
   * The quick self-check of the core: known answers of every part encryption, recovery, the
   * rehearsal check, rekey and hidden wallets compute, each with a case it must refuse, and what
   * the page itself must do. With `argon2` (the default) it also runs Argon2's known answer at
   * 1 MiB through this mode's Argon2 build, which it loads; `argon2: false` leaves Argon2 out (not
   * run), for a quick check at a page's start, since every operation runs that known answer itself
   * before its first round and after its last. Resolves to `{ passed, tier, version, buildId,
   * components: [{ id, label, outcome, detail? }] }`, made once per page for each choice: parts
   * that another class of the page passed with the same WebAssembly are not run again. Every
   * operation but parameters() and selfTest() awaits it before its first call (without Argon2 when
   * none ran yet). When a part has failed, every such operation rejects with SELF_CHECK_FAILED from
   * then on, the report attached; a page keeps its controls closed and shows the report.
   *
   * An Argon2 build that does not start gave no wrong answer: Argon2 is then not available, with
   * the cause, the class stays open and the next call checks again, and an operation gets its own
   * error. When only the threaded build of the fast mode does not start, the check runs the
   * single-threaded build of the standard mode instead, and Argon2 passes with a warning that says
   * so.
   * @param {OptionsOf<"startupCheck">} [options]
   */
  async startupCheck({ argon2 = true } = {}) {
    requireBoolean(argon2, "argon2");
    return this.#check.startup(argon2 ? "argon2" : "withoutArgon2", (skip, handlers) =>
      this.#coreCheck("startup", skip, argon2, handlers),
    );
  }
  /**
   * The full self-check, run anew each time, in seconds: every part with its slower cases, and
   * Argon2 at 64 and 256 MiB with each build in turn, never two at once: the single-threaded build,
   * then on a cross-origin isolated page the threaded one (not run otherwise). It lists the
   * published vectors as not run (selfTest() runs them) and the parts a browser cannot check as not
   * available, with the reason. `onProgress({ id, label, running, outcome?, detail? })` hears of
   * each part as it starts and ends. Resolves to a report as startupCheck() does; a failed part
   * closes the client as there. A browser that cannot give 256 MiB, and an Argon2 build that does
   * not start, make those parts not available rather than failed, as startupCheck() describes.
   * @param {OptionsOf<"fullCheck">} [options]
   */
  async fullCheck({ onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    /** @type {(build: typeof ARGON2_CHECKS_OF_BUILD.singleThreaded, threaded: boolean) => CheckStep} */
    const sizesOf = (build, threaded) => ({
      run: (_, handlers) => this.#argon2Check(threaded, handlers),
      rename: (component) =>
        component.id === ARGON2_SIZES_PART
          ? { ...component, ...build.sizes }
          : component.id === ARGON2_PART
            ? { ...component, ...build.knownAnswer }
            : component,
    });
    /** @type {CheckStep} */
    const threaded =
      this.#runtime.mode() === FAST_MODE
        ? sizesOf(ARGON2_CHECKS_OF_BUILD.threaded, true)
        : {
            components: Object.values(ARGON2_CHECKS_OF_BUILD.threaded).map((part) => ({
              ...part,
              outcome: "notRun",
              detail: "the page is not cross-origin isolated",
            })),
          };
    return this.#check.full(
      [
        { run: (skip, handlers) => this.#coreCheck("full", skip, true, handlers) },
        sizesOf(ARGON2_CHECKS_OF_BUILD.singleThreaded, false),
        threaded,
        { components: NOT_RUN_IN_FULL_CHECK },
        { run: (skip, handlers) => this.#processCheck(skip, handlers) },
      ],
      onProgress,
    );
  }
  /**
   * The self-test with the two published vectors at their full cost: an encryption of suite 3
   * ("encrypt", rounds 1 to 12 of 24) and a recovery of suite 4 ("recover", 13 to 24). It takes
   * minutes and 2 GiB, so a page starts it only when the person asks; it does not wait for the
   * startup check. Resolves to `{ passed, suite3: { vector, asPublished }, suite4: { vector,
   * asPublished }, firstWrongRound, fault }`. `fault`, null when the test passed, tells where it
   * first left the published path, as `{ kind, round, message }`: "argon2-input" when Argon2id
   * was given an input the published vector does not have, so the fault lies before Argon2id;
   * "argon2-key" when the published input gave another key, so the fault lies in Argon2id; and
   * "after-argon2", round null, when every input and key was as published. `message` is the
   * sentence to show. `firstWrongRound` is that round, 1 to 12 the encryption and 13 to 24 the
   * recovery, or null.
   * @param {OptionsOf<"selfTest">} [options]
   */
  async selfTest({ onProgress } = {}) {
    return this.#runtime.long({ operation: "selfTest" }, { onProgress, noPassword: true }, false);
  }
  /** Resolves once the startup check has passed; see startupCheck(). */
  ready() {
    return this.#check.require(() => this.startupCheck({ argon2: false }));
  }
  /**
   * The core's set of known answers at `tier` in a worker of its own, through this mode's Argon2
   * build when `argon2`. In fast mode the single-threaded build follows the threaded one, so that
   * the check falls back to it, and says so, when the threaded build does not start
   * (web/core-worker.js); an operation still uses the threaded build and gets its own error. The
   * core's limits must be this file's, which it checks before any secret is copied: a difference
   * means parts of different builds (PACKAGE_MISMATCH).
   * @param {MhfeSelfCheckTier} tier
   * @param {string[]} skip
   * @param {boolean} argon2
   * @param {WorkerHandlers} handlers
   */
  async #coreCheck(tier, skip, argon2, handlers) {
    const scripts = [this.#runtime.workerSource];
    if (argon2 && this.#runtime.mode() === FAST_MODE) {
      scripts.unshift(this.#runtime.argon2Source(true), this.#runtime.argon2Source(false));
    } else if (argon2) {
      scripts.unshift(this.#runtime.argon2Source(false));
    }
    // The worker of this build gives the core's report with its fixed values (web/core-worker.js).
    const result = await new WorkerJob(scripts, handlers).run(
      {
        module: CORE_MODULE,
        operation: "selfCheck",
        tier,
        skip,
        argon2,
        argon2Script: this.#runtime.argon2Script(argon2 && this.#runtime.mode() === FAST_MODE),
      },
      this.#runtime.wasm,
    );
    const report = readSetReport(result);
    requireSameLimits(isRecord(result) ? result.parameters : undefined);
    return report;
  }
  /**
   * The process parts of the command-line tool's self-test, in a worker of its own, as the
   * library reports them in a browser: the memory lock and the parts a page cannot check.
   * @param {string[]} skip
   * @param {WorkerHandlers} handlers
   */
  #processCheck(skip, handlers) {
    return new WorkerJob([this.#runtime.workerSource], handlers).run(
      { module: CORE_MODULE, operation: "selfCheckProcess", tier: "full", skip },
      this.#runtime.wasm,
    );
  }
  /**
   * One Argon2 build alone at 1, 64 and 256 MiB, in a worker of its own. Its complete declared
   * full tier runs, including the inexpensive known answer, without any implicit skipped result.
   * @param {boolean} threaded
   * @param {WorkerHandlers} handlers
   */
  #argon2Check(threaded, handlers) {
    const source = threaded ? this.#runtime.argon2Source(true) : this.#runtime.argon2Source(false);
    return new WorkerJob([source, this.#runtime.workerSource], handlers).run(
      {
        module: CORE_MODULE,
        operation: "selfCheckArgon2",
        tier: "full",
        skip: [],
        argon2Script: this.#runtime.argon2Script(threaded),
      },
      this.#runtime.wasm,
    );
  }
}
