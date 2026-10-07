// The repair module of the mhfe browser package: the repair words of a container and the repair of
// a damaged plate (MHFE-REPAIR-1). No Argon2 and no secret. A page supplies the module's files as
// text and bytes:
//
//   const repair = new MhfeRepair({
//     workerSource,   // text of runtime/worker.js
//     wasm,           // runtime/mhfe.wasm as a Uint8Array or a WebAssembly.Module
//   });
//
// A page that uses several module classes compiles runtime/mhfe.wasm once, with
// WebAssembly.compile, and passes the WebAssembly.Module to each.
//
// Every method returns a promise and reports every error by rejecting it; none throws when it is
// called. Each call runs in a worker of its own, so calls never wait for each other. The first call
// waits for the class's startup check (startupCheck()).

import {
  CompiledModule,
  PackageCheck,
  WorkerJob,
  requireCallback,
  requireText,
} from "../runtime/runtime.js";

export { MhfeError } from "../runtime/runtime.js";

/** The name of this module's operations in the package's worker. */
const REPAIR_MODULE = "repair";
/** The build of this file, which scripts/stamp-build-id.mjs writes; see BUILD_ID in the runtime. */
const REPAIR_BUILD_ID = "development";

export class MhfeRepair {
  #workerSource;
  #wasm;
  #check;

  constructor({ workerSource, wasm } = {}) {
    if (typeof workerSource !== "string" || workerSource.length === 0) {
      throw new TypeError("workerSource must be the text of runtime/worker.js.");
    }
    this.#workerSource = workerSource;
    this.#wasm = new CompiledModule(wasm, "wasm");
    this.#check = new PackageCheck({
      wasm: this.#wasm,
      classFile: "repair/repair.js",
      classBuildId: REPAIR_BUILD_ID,
      secrets: false,
    });
  }

  /**
   * The quick self-check of this class, which every other method awaits before its first call:
   * known answers of each part the class computes, each with a case it must refuse, and what the
   * page itself must do. Resolves to `{ passed, tier, version, buildId, components: [{ id, label,
   * outcome, detail? }] }`, made once per page: parts that another class of the page passed with
   * the same WebAssembly are not run again. When a part has failed, every method of the class
   * rejects with SELF_CHECK_FAILED from then on, the report attached; a page keeps its controls
   * closed and shows the report.
   */
  async startupCheck() {
    return this.#check.startup("startup", (skip, handlers) =>
      this.#selfCheck("startup", skip, handlers),
    );
  }

  /**
   * The full self-check, run anew each time: every part with its slower cases.
   * `onProgress({ id, label, running, outcome?, detail? })` hears of each part as it starts and
   * ends. Resolves to a report as startupCheck() does; a failed part closes the class as there.
   */
  async fullCheck({ onProgress } = {}) {
    requireCallback(onProgress, "onProgress");
    return this.#check.full(
      [{ run: (skip, handlers) => this.#selfCheck("full", skip, handlers) }],
      onProgress,
    );
  }

  /**
   * The module's fixed values: `{ version, profile, repairWordCounts, recommendedRepairWords,
   * repairCapacities: [{ count, unreadable, wrong }] }`.
   */
  async parameters() {
    return this.#run({ operation: "parameters" });
  }

  /**
   * The repair words of a container, which a person writes on a card kept apart from the plate.
   * Resolves to `{ profile, words, repairsUnreadable, repairsWrong }`. Make them only from a
   * container whose recovery was rehearsed; a container that does not open its wallet gets a card
   * that repairs the wrong words faithfully.
   */
  async repairWords({ container, count } = {}) {
    requireText(container, "container");
    if (!Number.isSafeInteger(count)) throw new TypeError("count must be 2, 4, 6 or 8.");
    await this.#ready();
    return this.#run({ operation: "repairWords", container, count });
  }

  /**
   * Repairs a container from its plate and card words as read, "?" for a word that cannot be
   * read. Resolves to `{ container, containerFingerprint, unchanged, plateWords, cardWords,
   * changes: [{ onCard, position, read, word }] }`; a page shows every change. A repair does not
   * show that the card belongs to the plate: only a rehearsal against the wallet does.
   */
  async repairPlate({ plate, card } = {}) {
    requireText(plate, "plate");
    requireText(card, "card");
    await this.#ready();
    return this.#run({ operation: "repairPlate", plate, card });
  }

  /** Runs the module's set of known answers at `tier` in a worker of its own. */
  #selfCheck(tier, skip, handlers) {
    return new WorkerJob([this.#workerSource], handlers).run(
      { module: REPAIR_MODULE, operation: "selfCheck", tier, skip },
      [],
      this.#wasm,
    );
  }

  /** Resolves once the startup check has passed; see startupCheck(). */
  #ready() {
    return this.#check.require(() => this.startupCheck());
  }

  #run(message) {
    return new WorkerJob([this.#workerSource]).run(
      { module: REPAIR_MODULE, ...message },
      [],
      this.#wasm,
    );
  }
}
