// @ts-check
// Self-check gating, sharing and page-owned known answers.
import { askPage } from "./callbacks.js";
import { readSetReport } from "./protocol.js";
import { BUILD_ID, packageMismatch, MhfeError } from "./errors.js";
import { messageOf, isRecord, sentence } from "./values.js";
import { encodeSecret } from "./secrets.js";
/** @import { SetReport, RunSet, CheckStep, SelfCheckListener, PackageCheckOptions } from "../types/runtime-shared.d.ts" */
/** @import { CompiledModule as DeclaredCompiledModule, MhfeComponentResult, MhfeSelfCheckReport, MhfeSelfCheckTier } from "../runtime.d.ts" */

// The self-check of a class: known answers of every part the class computes, compared before its
// first operation and again in the page's full self-test. The WebAssembly brings the checks of its
// parts (src/self_check.rs, `selfCheck*` in src/wasm_api/); the page adds what only the page can
// check, before any worker runs.

/**
 * What a part of a startup check gives when it could not run here ("notAvailable") or ran with a
 * limit ("warning"); at startup only an Argon2 build that did not start gives them
 * (web/core-worker.js), which the browser may well start at the next call.
 */
const TRANSIENT_OUTCOMES = ["notAvailable", "warning"];

/** The page's own parts, by identifier and the name a person reads. */
const PAGE_PARTS = {
  features: { id: "browser-features", label: "Browser features" },
  package: { id: "package-parts", label: "Package parts" },
  encoding: { id: "page-encoding", label: "Text encoding of the page" },
};

/**
 * The text whose UTF-8 bytes the page must give the worker: the password of the public vector
 * unicode-password (its inputs.password_utf8_hex), with a composed letter, a ligature, a
 * full-width letter, the Angstrom sign, a circled digit, a character outside the Basic
 * Multilingual Plane and a Cyrillic letter.
 */
const ENCODING_PROBE = "Caf\u00e9 \ufb01 \uff30\u212b\u2460 \u{1f510} \u0439";
const ENCODING_PROBE_UTF8 = "436166c3a920efac8120efbcb0e284abe291a020f09f949020d0b9";
/** A lone surrogate, which the page must refuse (validation-cases.json javascript_passwords). */
const LONE_SURROGATE = "a\uD800";

/**
 * The parts each page passed, per WebAssembly the page gave the classes: a part another class has
 * passed with the same WebAssembly is not run again at startup. Kept by the WebAssembly object, so
 * that it goes away with it.
 * @type {WeakMap<Uint8Array | WebAssembly.Module, Map<string, Map<unknown, MhfeComponentResult>>>}
 */
const passedOnPage = new WeakMap();

/**
 * The self-check of one class on its page. `startup()` runs once, before the first operation:
 * the page's own parts, then the class's parts in a worker, leaving out those another class of the
 * page has passed. `require()` is what every operation awaits: it rejects with SELF_CHECK_FAILED,
 * the report attached, once any part has failed, and then for good. A worker that did not start
 * (WORKER_FAILED) or parts of different builds (PACKAGE_MISMATCH) give no report: the check is
 * tried again at the next call. So is a report with a part that could not run here or ran with a
 * limit, such as an Argon2 build that did not start, which the browser may give at the next call.
 * `full()` runs every part, the slower cases included, anew.
 */
export class PackageCheck {
  /** @type {DeclaredCompiledModule} */
  #wasm;
  /** @type {string} */
  #classFile;
  /** @type {string} */
  #classBuildId;
  /** @type {("random" | "threads")[]} */
  #needs;
  /** @type {boolean} */
  #secrets;
  /** @type {(id: string) => unknown} */
  #identityOf;
  /** @type {Map<string, Promise<MhfeSelfCheckReport>>} */
  #startups = new Map();
  /** @type {MhfeSelfCheckReport | null} */
  #failed = null;

  /**
   * `wasm` is the class's CompiledModule; `classFile` and `classBuildId` name the class file and
   * its stamped build. `needs` lists what the class needs beyond workers and WebAssembly:
   * "random" (crypto.getRandomValues) and "threads" (SharedArrayBuffer on an isolated page).
   * `secrets` says whether the class encodes secrets. `identityOf(id)` tells apart parts whose
   * outcome depends on more than the WebAssembly, such as Argon2's on the build that ran it.
   * @param {PackageCheckOptions} options
   */
  constructor({
    wasm,
    classFile,
    classBuildId,
    needs = [],
    secrets,
    identityOf = () => undefined,
  }) {
    this.#wasm = wasm;
    this.#classFile = classFile;
    this.#classBuildId = classBuildId;
    this.#needs = needs;
    this.#secrets = secrets;
    this.#identityOf = identityOf;
  }

  /**
   * The startup report of `variant`, made once: `runSet(skip, handlers)` runs the class's set in
   * a worker without the parts `skip` and resolves to its report.
   * @param {string} variant
   * @param {RunSet} runSet
   */
  startup(variant, runSet) {
    let report = this.#startups.get(variant);
    if (report === undefined) {
      report = this.#check("startup", [{ run: runSet, skipPassed: true }]);
      this.#startups.set(variant, report);
      // No report, such as when the worker did not start, or one that depends on what the browser
      // gave this time: the next call tries again. A failed part stays in #failed regardless.
      const forget = () => {
        if (this.#startups.get(variant) === report) this.#startups.delete(variant);
      };
      report.then((made) => {
        if (made.components.some(({ outcome }) => TRANSIENT_OUTCOMES.includes(outcome))) forget();
      }, forget);
    }
    return report;
  }

  /**
   * Resolves once a startup report of this class has passed, running `startDefault()` when none
   * runs yet; rejects with SELF_CHECK_FAILED once a part has failed.
   * @param {() => Promise<MhfeSelfCheckReport>} startDefault
   * @returns {Promise<void>}
   */
  async require(startDefault) {
    if (this.#failed !== null) throw selfCheckFailed(this.#failed);
    const [running] = this.#startups.values();
    const report = await (running ?? startDefault());
    if (!report.passed) throw selfCheckFailed(report);
    // A full check that failed while this one ran closes the class too (AUD-014-SEC001): what
    // follows the await runs before any other message of a worker, so nothing slips through.
    if (this.#failed !== null) throw selfCheckFailed(this.#failed);
  }

  /**
   * Every part at the full tier, run anew. `steps` are run one after the other, never two at once:
   * `{ run(skip, handlers), rename? }` runs a set in a worker, `rename(component)` naming its parts
   * in this report, such as those of one Argon2 build; `{ components }` lists parts that are not
   * run here, with the reason. `onProgress` hears of each part as it starts and ends.
   * @param {CheckStep[]} steps
   * @param {SelfCheckListener | undefined} onProgress
   */
  full(steps, onProgress) {
    return this.#check("full", steps, onProgress);
  }

  /**
   * The report at `tier`: the page's own parts, then `steps`; see startup() and full().
   * @param {MhfeSelfCheckTier} tier
   * @param {CheckStep[]} steps
   * @param {SelfCheckListener} [onProgress]
   * @returns {Promise<MhfeSelfCheckReport>}
   */
  async #check(tier, steps, onProgress) {
    const start = async (/** @type {{ id: string, label: string }} */ part) => {
      if (onProgress)
        await askPage(onProgress, { id: part.id, label: part.label, running: true }, "onProgress");
    };
    const end = async (/** @type {MhfeComponentResult} */ part) => {
      if (onProgress) await askPage(onProgress, { ...part, running: false }, "onProgress");
    };
    await start(PAGE_PARTS.features);
    let features = this.#features();
    /** @type {string | null} */
    let version = null;
    if (features.outcome === "passed") {
      const compiled = await this.#compiles();
      if (compiled !== null) features = compiled;
    }
    const components = [features];
    await end(features);
    await start(PAGE_PARTS.package);
    const packageParts = this.#packageParts();
    components.push(packageParts);
    await end(packageParts);
    if (this.#secrets) {
      await start(PAGE_PARTS.encoding);
      const encoded = encodingPart();
      components.push(encoded);
      await end(encoded);
    }
    if (components.every((component) => component.outcome !== "failed")) {
      for (const step of steps) {
        if (step.components !== undefined) {
          for (const part of step.components) {
            await start(part);
            components.push(part);
            await end(part);
          }
          continue;
        }
        const rename = step.rename ?? ((component) => component);
        const ran = readSetReport(
          await step.run(step.skipPassed ? this.#passedIds() : [], {
            componentStart: (/** @type {{ id: string, label: string }} */ part) =>
              onProgress?.({ ...rename(part), running: true }),
            component: (/** @type {MhfeComponentResult} */ part) =>
              onProgress?.({ ...rename(part), running: false }),
          }),
        );
        version ??= ran.version;
        components.push(...this.#placed(ran, step.skipPassed).map(rename));
      }
    }
    const report = {
      passed: components.every((component) => component.outcome !== "failed"),
      tier,
      version,
      buildId: BUILD_ID,
      components,
    };
    if (!report.passed) this.#failed ??= report;
    return report;
  }

  /**
   * What the class needs of the browser, probed without running anything.
   * @returns {MhfeComponentResult}
   */
  #features() {
    const missing = [];
    if (
      typeof WebAssembly !== "object" ||
      typeof WebAssembly.Module?.customSections !== "function"
    ) {
      missing.push("WebAssembly");
    }
    for (const [name, present] of /** @type {const} */ ([
      ["Worker", typeof Worker === "function"],
      ["Blob", typeof Blob === "function"],
      [
        "URL.createObjectURL",
        typeof URL === "function" && typeof URL.createObjectURL === "function",
      ],
      ["TextEncoder", typeof TextEncoder === "function"],
    ])) {
      if (!present) missing.push(name);
    }
    if (
      this.#needs.includes("random") &&
      typeof globalThis.crypto?.getRandomValues !== "function"
    ) {
      missing.push("crypto.getRandomValues");
    }
    // The threaded Argon2 build runs only on an isolated page, which must then share memory.
    const threads = this.#needs.includes("threads") && globalThis.crossOriginIsolated === true;
    if (threads && (typeof SharedArrayBuffer !== "function" || typeof Atomics !== "object")) {
      missing.push("SharedArrayBuffer and Atomics");
    }
    return missing.length === 0
      ? { ...PAGE_PARTS.features, outcome: "passed" }
      : {
          ...PAGE_PARTS.features,
          outcome: "failed",
          detail: `the browser lacks ${missing.join(", ")}`,
        };
  }

  /**
   * Whether the WebAssembly compiles here; null when it does. A page whose
   * Content-Security-Policy lacks 'wasm-unsafe-eval' cannot compile it.
   * @returns {Promise<MhfeComponentResult | null>}
   */
  async #compiles() {
    try {
      await this.#wasm.get();
      return null;
    } catch (error) {
      return {
        ...PAGE_PARTS.features,
        outcome: "failed",
        detail:
          "the WebAssembly does not compile here, as when the page's Content-Security-Policy " +
          `lacks 'wasm-unsafe-eval': ${messageOf(error)}`,
      };
    }
  }

  /**
   * The class file and this runtime must come from one build; the worker compares its build with
   * the WebAssembly's and with this runtime's when it starts (WorkerJob).
   * @returns {MhfeComponentResult}
   */
  #packageParts() {
    if (this.#classBuildId !== BUILD_ID) {
      throw packageMismatch(
        `The file ${this.#classFile} is of build ${this.#classBuildId} and runtime/runtime.js of ` +
          `build ${BUILD_ID}`,
      );
    }
    return { ...PAGE_PARTS.package, outcome: "passed" };
  }

  /** The parts another class of the page has passed with this WebAssembly. */
  #passedIds() {
    const passed = this.#passed();
    return [...passed.keys()].filter((id) => passed.get(id)?.has(this.#identityOf(id)));
  }

  /**
   * The parts passed with this WebAssembly on the page: for each identifier, the outcome for each
   * identity of the part (see the constructor), undefined for most.
   */
  #passed() {
    let passed = passedOnPage.get(this.#wasm.source);
    if (passed === undefined) {
      passed = new Map();
      passedOnPage.set(this.#wasm.source, passed);
    }
    return passed;
  }

  /**
   * The parts of a worker's report in the set's order, those left out because another class
   * passed them included as that class found them. At startup the parts that passed are kept for
   * the other classes. A report of a WebAssembly that stopped has no order: its parts as they are.
   * @param {SetReport} ran
   * @param {boolean | undefined} skipPassed
   */
  #placed(ran, skipPassed) {
    if (!skipPassed) return ran.components;
    const passed = this.#passed();
    for (const component of ran.components) {
      if (component.outcome !== "passed") continue;
      let identities = passed.get(component.id);
      if (identities === undefined) {
        identities = new Map();
        passed.set(component.id, identities);
      }
      identities.set(this.#identityOf(component.id), component);
    }
    if (ran.ids === undefined) return ran.components;
    return ran.ids
      .map(
        (id) =>
          ran.components.find((component) => component.id === id) ??
          passed.get(id)?.get(this.#identityOf(id)),
      )
      .filter((component) => component !== undefined);
  }
}

/**
 * The page's encoding of secrets, compared with a published vector, and its refusal.
 * @returns {MhfeComponentResult}
 */
function encodingPart() {
  let failure = null;
  try {
    const owned = encodeSecret(ENCODING_PROBE, "probe");
    let hex;
    try {
      hex = Array.from(owned.bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    } finally {
      owned.wipe();
    }
    if (hex !== ENCODING_PROBE_UTF8) failure = "the page encodes text into other UTF-8 bytes";
  } catch {
    failure = "the page cannot encode text";
  }
  if (failure === null) {
    try {
      encodeSecret(LONE_SURROGATE, "probe");
      failure = "a lone surrogate is accepted instead of refused";
    } catch (error) {
      if (!isRecord(error) || error.code !== "INVALID_PASSWORD_TEXT") {
        failure = "a lone surrogate is refused with another error";
      }
    }
  }
  return failure === null
    ? { ...PAGE_PARTS.encoding, outcome: "passed" }
    : { ...PAGE_PARTS.encoding, outcome: "failed", detail: failure };
}

/**
 * The error of every operation of a class whose self-check found a part that failed. Its text is
 * a deliberate copy of `self_check::failure_message`, which a report of page parts cannot call; the
 * package checks compare both word for word.
 * @param {MhfeSelfCheckReport} report
 */
function selfCheckFailed(report) {
  // A report that did not pass has a part that failed.
  const failed = report.components.find((component) => component.outcome === "failed");
  // A detail that ends a sentence of its own keeps one period, as in the library (AUD-015-UI005).
  const detail = String(failed?.detail).replace(/\.+$/u, "");
  return new MhfeError(
    "SELF_CHECK_FAILED",
    sentence(
      `the self-test failed: ${failed?.label}: ${detail}. ` +
        "Do not use this program on this computer",
    ),
    { report },
  );
}
