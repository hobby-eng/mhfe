// The runtime the module classes of the mhfe browser package share: errors, the WebAssembly
// compiled once, the worker of one operation, the byte copies of secrets, and the self-check that
// a class runs before its first operation. Every module class (core/client.js, repair/repair.js,
// passwords/passwords.js, wallet/wallet.js) imports it from "../runtime/runtime.js" and uses it by
// composition.
//
// A page supplies every part as text or bytes, because a page under a strict
// Content-Security-Policy may not fetch anything. Each operation runs in a new Web Worker made from
// a Blob of the package's worker script, runtime/worker.js, so the page never blocks, cancel()
// stops at once, and the worker's memory, secrets included, is freed when it ends. Every module
// runs in the same WebAssembly, runtime/mhfe.wasm; a request names its module and operation.

/**
 * The build of the package these files come from, which scripts/stamp-build-id.mjs derives from
 * every file a page loads before it stamps any: runtime/mhfe.wasm, this file, runtime/worker.js,
 * each class file and both Argon2 builds. It writes it into each of these, the WebAssembly's
 * custom section "mhfe-build" included; the classes and the worker compare them, so that parts of
 * different builds, even ones that differ in a script alone, are never used together.
 * "development" before the build stamps it.
 */
export const BUILD_ID = "development";

export class MhfeError extends Error {
  /**
   * `options.cause` keeps the original error, as for CALLBACK_FAILED; `options.report` the
   * self-check report of SELF_CHECK_FAILED.
   */
  constructor(code, message, options) {
    super(message, options);
    this.name = "MhfeError";
    this.code = code;
    if (options?.report !== undefined) this.report = options.report;
  }
}

export class MhfeCancelledError extends MhfeError {
  constructor() {
    super("CANCELLED", "The operation was cancelled.");
    this.name = "MhfeCancelledError";
  }
}

/** The package's WebAssembly, compiled the first time a worker needs it and then shared. */
export class CompiledModule {
  #wasm;
  #compiled = null;

  constructor(wasm, name) {
    // A browser without WebAssembly gets this far, so that the class's self-check can say what
    // is missing instead of the constructor failing with a ReferenceError.
    if (!(wasm instanceof Uint8Array) && !isCompiledModule(wasm)) {
      throw new TypeError(`${name} must be a Uint8Array or a WebAssembly.Module.`);
    }
    this.#wasm = wasm;
  }

  /**
   * The bytes or the module the page passed: the classes made with the same one share their
   * self-check results on the page.
   */
  get source() {
    return this.#wasm;
  }

  /** The compiled WebAssembly, which a worker receives as it is: no worker compiles it again. */
  get() {
    this.#compiled ??= isCompiledModule(this.#wasm)
      ? Promise.resolve(this.#wasm)
      : WebAssembly.compile(this.#wasm);
    return this.#compiled;
  }
}

function isCompiledModule(value) {
  return typeof WebAssembly === "object" && value instanceof WebAssembly.Module;
}

/**
 * How long a worker may take to start and load the WebAssembly, until it says it is ready. A
 * minute is ample even on a slow phone; without a limit, a browser that silently refuses to run a
 * worker would leave the operation waiting for ever. The operation itself has no time limit.
 */
const WORKER_START_TIMEOUT_MS = 60_000;

/**
 * One operation in one worker. `scripts` are joined into the worker's Blob; `handlers` receive the
 * worker's messages by type. A handler of the page that fails ends the operation: the worker
 * stops, which frees its secrets, and the promise rejects with CALLBACK_FAILED and the page's error
 * as the cause. An `ask` handler answers the worker; its promise is awaited.
 */
export class WorkerJob {
  #scripts;
  #handlers;
  #worker = null;
  #url = null;
  #ended = false;
  #settle = null;
  #onEnd;
  #startTimer = null;

  constructor(scripts, handlers = {}, onEnd = () => {}) {
    this.#scripts = scripts;
    this.#handlers = handlers;
    this.#onEnd = onEnd;
  }

  /**
   * Starts the worker with `message`, which names its module and operation; its `compiled` field
   * is filled from `wasm`, a CompiledModule, once that is compiled. Until the worker owns them,
   * the secrets of `message` belong to this job: every failure on the way wipes them.
   */
  run(message, transfer, wasm) {
    return new Promise((resolve, reject) => {
      this.#settle = { resolve, reject };
      const start = async () => {
        let compiled;
        try {
          compiled = await wasm.get();
        } catch (error) {
          this.stop(
            new MhfeError("WORKER_FAILED", `The WebAssembly did not compile: ${error.message}`),
          );
          return;
        }
        // cancel() during the compilation ends the job before any worker exists.
        if (this.#ended) return;
        // A browser may refuse the Blob, its URL or the worker; each ends the job the same way.
        try {
          this.#url = URL.createObjectURL(
            new Blob([this.#scripts.join("\n;\n")], { type: "text/javascript" }),
          );
          this.#worker = new Worker(this.#url, { name: "mhfe" });
        } catch (error) {
          this.stop(
            new MhfeError(
              "WORKER_FAILED",
              `The browser refused to start the worker: ${error.message}`,
            ),
          );
          return;
        }
        this.#worker.onmessage = (event) => this.#receive(event.data);
        this.#worker.onerror = (event) => {
          event.preventDefault();
          this.stop(
            new MhfeError("WORKER_FAILED", event.message || "The worker stopped unexpectedly."),
          );
        };
        this.#startTimer = setTimeout(() => {
          this.stop(new MhfeError("WORKER_FAILED", "The worker did not start within a minute."));
        }, WORKER_START_TIMEOUT_MS);
        this.send({ ...message, compiled }, transfer);
      };
      start()
        .catch((error) => {
          this.stop(new MhfeError("WORKER_FAILED", `The worker did not start: ${error.message}`));
        })
        .finally(() => {
          if (this.#ended) wipeSecrets(message);
        });
    });
  }

  /** Sends a later step to the worker, such as a session's next request. */
  send(message, transfer = []) {
    if (this.#ended || this.#worker === null) {
      wipeSecrets(message);
      return;
    }
    try {
      this.#worker.postMessage(message, transfer);
    } catch (error) {
      wipeSecrets(message);
      this.stop(new MhfeError("WORKER_FAILED", `The request could not be sent: ${error.message}`));
    }
  }

  /** Ends the job once: the worker stops; `error` rejects its promise, null resolves nothing. */
  stop(error) {
    if (this.#ended) return;
    this.#ended = true;
    clearTimeout(this.#startTimer);
    this.#worker?.terminate();
    if (this.#url !== null) URL.revokeObjectURL(this.#url);
    this.#onEnd(this);
    if (error !== null) this.#settle?.reject(error);
  }

  get ended() {
    return this.#ended;
  }

  #receive(reply) {
    // Messages that were already on their way when the job ended are ignored.
    if (this.#ended) return;
    if (reply.type === "ready") {
      this.#started(reply.buildId);
    } else if (reply.type === "result") {
      this.stop(null);
      this.#settle.resolve(reply.result);
    } else if (reply.type === "error") {
      this.stop(new MhfeError(reply.error.code, sentence(reply.error.message)));
    } else if (reply.type === "ask") {
      this.#answer(reply.question, reply.value);
    } else {
      this.callPage(this.#handlers[reply.type], reply.value, reply.type);
    }
  }

  /**
   * The worker has loaded the WebAssembly, which matched the worker's own build. Its build must be
   * this runtime's too; a difference stops the job before the request is served.
   */
  #started(buildId) {
    clearTimeout(this.#startTimer);
    this.#startTimer = null;
    if (buildId !== BUILD_ID) {
      this.stop(
        new MhfeError(
          "PACKAGE_MISMATCH",
          `The file runtime/worker.js is of build ${buildId} and runtime/runtime.js of build ` +
            `${BUILD_ID}: take every file of the package from one build.`,
        ),
      );
    }
  }

  /** Calls a page callback whose result is not awaited; a throw or a rejection stops the job. */
  callPage(callback, value, name) {
    try {
      const returned = callback?.(value);
      if (typeof returned?.then === "function") {
        returned.then(undefined, (cause) => {
          // Once the job has ended there is nothing left to stop: the page's rejection stays
          // unhandled, as it would be without this client, instead of being swallowed.
          if (this.#ended) throw cause;
          this.stop(callbackFailed(name, cause));
        });
      }
    } catch (cause) {
      this.stop(callbackFailed(name, cause));
    }
  }

  /** Asks the page and sends its answer back to the worker. */
  async #answer(question, value) {
    const handler = this.#handlers[question];
    try {
      const answer = await handler(value);
      this.send({ type: "answer", value: answer?.message ?? answer }, answer?.transfer ?? []);
    } catch (cause) {
      // A handler that wraps the page's callback may name the failure itself; anything else,
      // an MhfeError of another call included, becomes CALLBACK_FAILED with it as the cause.
      const named = cause instanceof MhfeError && cause.code === "CALLBACK_FAILED";
      this.stop(named ? cause : callbackFailed(question, cause));
    }
  }
}

/**
 * The one long operation a class runs at a time: a second one is refused with BUSY, and cancel()
 * stops the running one, including a session that waits for the page.
 */
export class OperationSlot {
  #running = null;

  requireIdle() {
    if (this.#running !== null) {
      throw new MhfeError("BUSY", "Another operation is still running.");
    }
  }

  /** A job that holds the slot until it ends. */
  job(scripts, handlers) {
    this.requireIdle();
    const job = new WorkerJob(scripts, handlers, (ended) => {
      if (this.#running === ended) this.#running = null;
    });
    this.#running = job;
    return job;
  }

  /**
   * Holds the slot while `ready`, the class's startup check, settles, then returns what `begin`
   * returns: `begin` starts the operation's job in the slot at once, with nothing in between. A
   * cancel() in the meantime rejects with MhfeCancelledError, and a rejected `ready` rejects with
   * its error; both free the slot.
   */
  async after(ready, begin) {
    this.requireIdle();
    let cancel;
    let stopped = null;
    const cancelled = new Promise((_, reject) => {
      cancel = reject;
    });
    const waiting = {
      stop: (error) => {
        stopped = error;
        cancel(error);
      },
    };
    this.#running = waiting;
    try {
      await Promise.race([ready, cancelled]);
      // A cancel() after the check settled, before this went on, stops the operation too.
      if (stopped !== null) throw stopped;
    } finally {
      if (this.#running === waiting) this.#running = null;
    }
    return begin();
  }

  cancel() {
    this.#running?.stop(new MhfeCancelledError());
  }
}

/**
 * The highest word position the Rust core reads (a 32-bit number); a position above the
 * password's words is refused there with PASSWORD_REPAIR_NOT_OFFERED.
 */
const HIGHEST_WORD_POSITION = 0xffff_ffff;

/** The fields of a request that hold secrets; this client's own byte copies of them. */
const SECRET_FIELDS = [
  "phrase",
  "password",
  "passwordRepeat",
  "passphrase",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
];

/**
 * Overwrites this client's byte copies of the secrets in a request or in a session's answer
 * (`value`); they are its own arrays. A copy already transferred to the worker is empty, and
 * filling a transferred array would throw, so it is left alone.
 */
export function wipeSecrets(message) {
  for (const holder of [message, message?.value]) {
    for (const field of SECRET_FIELDS) {
      const bytes = holder?.[field];
      if (typeof bytes?.fill === "function" && bytes.byteLength > 0) bytes.fill(0);
    }
  }
}

/** The transfer list of a request's secrets, so that no copy stays in the page. */
export function secretBuffers(message) {
  return SECRET_FIELDS.map((field) => message[field]?.buffer).filter(Boolean);
}

/** A secret is given as text or as its UTF-8 bytes; anything else is a TypeError. */
export function requireSecret(value, name) {
  if (typeof value !== "string" && !(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a string or a Uint8Array.`);
  }
}

/**
 * UTF-8 bytes of a phrase, password, passphrase or dice digits, in a plain Uint8Array of their
 * own, which the transfer to the worker empties and a refusal wipes. A JavaScript string may hold
 * a lone surrogate, which TextEncoder would silently turn into U+FFFD, so such a string is refused
 * instead. Bytes are copied into a new array rather than with their own slice(): a subclass such
 * as Node's Buffer, or the Buffer that bundlers add to a page, slices into a view of the caller's
 * memory, which the transfer would empty and a refusal would wipe.
 */
export function encodeSecret(value, name, emptyAllowed) {
  requireSecret(value, name);
  let bytes;
  if (typeof value === "string") {
    if (!isWellFormed(value)) {
      throw new MhfeError(
        "INVALID_PASSWORD_TEXT",
        `The ${name} contains an unpaired surrogate, which is not valid text.`,
      );
    }
    bytes = new TextEncoder().encode(value);
  } else {
    bytes = new Uint8Array(value);
  }
  if (!emptyAllowed && bytes.length === 0) {
    throw new MhfeError("EMPTY_PASSWORD", `The ${name} is empty.`);
  }
  return bytes;
}

function isWellFormed(text) {
  if (typeof text.isWellFormed === "function") return text.isWellFormed();
  // With the u flag a valid pair is one code point, so only a lone surrogate matches.
  return !/[\uD800-\uDFFF]/u.test(text);
}

/**
 * A review choice of the password check word: undefined or "asTyped" keeps the password as typed,
 * "corrected" takes its written form, `{ repair: position }` the repair at that word.
 */
export function describeChoice(choice, name) {
  if (choice === undefined || choice === "asTyped") return ["", 0];
  if (choice === "corrected") return ["corrected", 0];
  if (
    choice !== null &&
    typeof choice === "object" &&
    Number.isSafeInteger(choice.repair) &&
    choice.repair >= 1 &&
    choice.repair <= HIGHEST_WORD_POSITION
  ) {
    return ["repair", choice.repair];
  }
  throw new TypeError(
    `${name} must be "asTyped", "corrected" or { repair: position }, a word number from 1.`,
  );
}

export function requireText(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string.`);
}

export function requireBoolean(value, name) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be a boolean.`);
}

export function requireCallback(value, name) {
  if (value !== undefined && typeof value !== "function") {
    throw new TypeError(`${name} must be a function.`);
  }
}

/**
 * A page shows an error message as it is, so it starts with a capital letter, as the messages of
 * the command-line tool do. The Rust core's messages start in lower case to fit inside a sentence.
 */
export function sentence(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function callbackFailed(name, cause) {
  return new MhfeError("CALLBACK_FAILED", `The page's ${name} callback failed.`, { cause });
}

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
  #wasm;
  #classFile;
  #classBuildId;
  #needs;
  #secrets;
  #identityOf;
  #startups = new Map();
  #failed = null;

  /**
   * `wasm` is the class's CompiledModule; `classFile` and `classBuildId` name the class file and
   * its stamped build. `needs` lists what the class needs beyond workers and WebAssembly:
   * "random" (crypto.getRandomValues) and "threads" (SharedArrayBuffer on an isolated page).
   * `secrets` says whether the class encodes secrets. `identityOf(id)` tells apart parts whose
   * outcome depends on more than the WebAssembly, such as Argon2's on the build that ran it.
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
   */
  async require(startDefault) {
    if (this.#failed !== null) throw selfCheckFailed(this.#failed);
    const [running] = this.#startups.values();
    const report = await (running ?? startDefault());
    if (!report.passed) throw selfCheckFailed(report);
  }

  /**
   * Every part at the full tier, run anew. `steps` are run one after the other, never two at once:
   * `{ run(skip, handlers), rename? }` runs a set in a worker, `rename(component)` naming its parts
   * in this report, such as those of one Argon2 build; `{ components }` lists parts that are not
   * run here, with the reason. `onProgress` hears of each part as it starts and ends.
   */
  full(steps, onProgress) {
    return this.#check("full", steps, onProgress);
  }

  async #check(tier, steps, onProgress) {
    const components = [this.#features(), this.#packageParts()];
    if (this.#secrets) components.push(encodingPart());
    let version = null;
    if (components[0].outcome === "passed") {
      const compiled = await this.#compiles();
      if (compiled !== null) components[0] = compiled;
    }
    if (components.every((component) => component.outcome !== "failed")) {
      for (const step of steps) {
        if (step.components !== undefined) {
          components.push(...step.components);
          continue;
        }
        const rename = step.rename ?? ((component) => component);
        const ran = await step.run(step.skipPassed ? this.#passedIds() : [], {
          componentStart: (part) => onProgress?.({ ...rename(part), running: true }),
          component: (part) => onProgress?.({ ...rename(part), running: false }),
        });
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

  /** What the class needs of the browser, probed without running anything. */
  #features() {
    const missing = [];
    if (
      typeof WebAssembly !== "object" ||
      typeof WebAssembly.Module?.customSections !== "function"
    ) {
      missing.push("WebAssembly");
    }
    for (const [name, present] of [
      ["Worker", typeof Worker === "function"],
      ["Blob", typeof Blob === "function"],
      [
        "URL.createObjectURL",
        typeof URL === "function" && typeof URL.createObjectURL === "function",
      ],
      ["TextEncoder", typeof TextEncoder === "function"],
    ]) {
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
          `lacks 'wasm-unsafe-eval': ${error.message}`,
      };
    }
  }

  /**
   * The class file and this runtime must come from one build; the worker compares its build with
   * the WebAssembly's and with this runtime's when it starts (WorkerJob).
   */
  #packageParts() {
    if (this.#classBuildId !== BUILD_ID) {
      throw new MhfeError(
        "PACKAGE_MISMATCH",
        `The file ${this.#classFile} is of build ${this.#classBuildId} and runtime/runtime.js of ` +
          `build ${BUILD_ID}: take every file of the package from one build.`,
      );
    }
    return { ...PAGE_PARTS.package, outcome: "passed" };
  }

  /** The parts another class of the page has passed with this WebAssembly. */
  #passedIds() {
    const passed = this.#passed();
    return [...passed.keys()].filter((id) => passed.get(id).has(this.#identityOf(id)));
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
   */
  #placed(ran, skipPassed) {
    if (!skipPassed) return ran.components;
    const passed = this.#passed();
    for (const component of ran.components) {
      if (component.outcome !== "passed") continue;
      if (!passed.has(component.id)) passed.set(component.id, new Map());
      passed.get(component.id).set(this.#identityOf(component.id), component);
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

/** The page's encoding of secrets, compared with a published vector, and its refusal. */
function encodingPart() {
  let failure = null;
  try {
    const bytes = encodeSecret(ENCODING_PROBE, "probe", false);
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (hex !== ENCODING_PROBE_UTF8) failure = "the page encodes text into other UTF-8 bytes";
  } catch {
    failure = "the page cannot encode text";
  }
  if (failure === null) {
    try {
      encodeSecret(LONE_SURROGATE, "probe", false);
      failure = "a lone surrogate is accepted instead of refused";
    } catch (error) {
      if (error?.code !== "INVALID_PASSWORD_TEXT") {
        failure = "a lone surrogate is refused with another error";
      }
    }
  }
  return failure === null
    ? { ...PAGE_PARTS.encoding, outcome: "passed" }
    : { ...PAGE_PARTS.encoding, outcome: "failed", detail: failure };
}

/** The error of every operation of a class whose self-check found a part that failed. */
function selfCheckFailed(report) {
  const failed = report.components.find((component) => component.outcome === "failed");
  return new MhfeError(
    "SELF_CHECK_FAILED",
    sentence(
      `the self-test failed: ${failed.label}: ${failed.detail}. ` +
        "Do not use this program on this computer",
    ),
    { report },
  );
}
