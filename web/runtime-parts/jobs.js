// @ts-check
// One worker job and the exclusive long-operation slot.
import { SecretRequest } from "./secrets.js";
import { MhfeError, packageMismatch, BUILD_ID, MhfeCancelledError } from "./errors.js";
import { messageOf, isRecord, sentence } from "./values.js";
import {
  isReadableReply,
  unknownMessage,
  readWorkerError,
  WORKER_NEWS,
  checkedPageHandler,
} from "./protocol.js";
import { callbackFailed } from "./callbacks.js";
/** @import { WorkerRequest, WorkerHandler, WorkerHandlers } from "../types/runtime-shared.d.ts" */
/** @import { CompiledModule as DeclaredCompiledModule } from "../runtime.d.ts" */

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
  /** @type {string[]} */
  #scripts;
  /** @type {WorkerHandlers} */
  #handlers;
  /** @type {Worker | null} */
  #worker = null;
  /** @type {string | null} */
  #url = null;
  #ended = false;
  /** The request's buffers while compilation or worker startup is pending.
   * @type {SecretRequest | null} */
  #request = null;
  /** @type {{ resolve: (result: unknown) => void, reject: (error: Error) => void } | null} */
  #settle = null;
  /** @type {(job: WorkerJob) => void} */
  #onEnd;
  /** @type {number | undefined} */
  #startTimer = undefined;
  /** Whether the worker has loaded the WebAssembly: it has sent its first message. */
  #loaded = false;
  /**
   * Whether the worker has said, in its "ready", that it is of this build. Before that only
   * "ready" and "error" are read: no handler of the page runs, and no result is taken, from a
   * worker of another build (AUD-024-API006).
   */
  #buildChecked = false;

  /**
   * @param {string[]} scripts
   * @param {WorkerHandlers} [handlers]
   * @param {(job: WorkerJob) => void} [onEnd]
   */
  constructor(scripts, handlers = {}, onEnd = () => {}) {
    this.#scripts = scripts;
    this.#handlers = handlers;
    this.#onEnd = onEnd;
  }

  /**
   * Starts the worker with `message`, which names its module and operation; its `compiled` field
   * is filled from `wasm`, a CompiledModule, once that is compiled. Until the worker owns them,
   * the secrets of `message` belong to this job: every failure on the way wipes them. Resolves to
   * the worker's result as it arrived.
   * @param {WorkerRequest} message
   * @param {DeclaredCompiledModule} wasm
   * @returns {Promise<unknown>}
   */
  run(message, wasm) {
    const owned = new SecretRequest(message);
    this.#request = owned;
    return new Promise((resolve, reject) => {
      this.#settle = { resolve, reject };
      const start = async () => {
        let compiled;
        try {
          compiled = await wasm.get();
        } catch (error) {
          this.stop(
            new MhfeError("WORKER_FAILED", `The WebAssembly did not compile: ${messageOf(error)}`),
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
              `The browser refused to start the worker: ${messageOf(error)}`,
            ),
          );
          return;
        }
        this.#worker.onmessage = (event) => this.#receive(event.data);
        this.#worker.onerror = (event) => {
          event.preventDefault();
          // A failed worker loads nothing more and may stop at once.
          this.#loaded = true;
          if (this.#ended) this.#terminate();
          this.stop(
            new MhfeError("WORKER_FAILED", event.message || "The worker stopped unexpectedly."),
          );
        };
        this.#startTimer = setTimeout(() => {
          this.stop(new MhfeError("WORKER_FAILED", "The worker did not start within a minute."));
          // A minute without loading: it is not waited for any longer.
          this.#terminate();
        }, WORKER_START_TIMEOUT_MS);
        this.send({ ...message, compiled });
      };
      start()
        .catch((error) => {
          this.stop(
            new MhfeError("WORKER_FAILED", `The worker did not start: ${messageOf(error)}`),
          );
        })
        .finally(() => {
          owned.wipe();
        });
    });
  }

  /**
   * Sends a later step to the worker, such as a session's next request.
   * @param {WorkerRequest} message
   */
  send(message) {
    const owned = new SecretRequest(message);
    if (this.#ended || this.#worker === null) {
      owned.wipe();
      return;
    }
    try {
      this.#worker.postMessage(owned.message, owned.transfer);
    } catch (error) {
      owned.wipe();
      this.stop(
        new MhfeError("WORKER_FAILED", `The request could not be sent: ${messageOf(error)}`),
      );
    } finally {
      owned.wipe();
    }
  }

  /**
   * Ends the job once: `error` rejects its promise, null resolves nothing, and the worker stops.
   * A worker that is still loading the WebAssembly stops once it has loaded it, or when it fails,
   * or at the start's time limit: Firefox crashes the whole page when a worker is terminated while
   * it loads the WebAssembly, as when every worker of a draw fails within milliseconds. Its
   * request is answered by nobody: its messages are ignored from now on. `error` is an
   * MhfeError, or the TypeError of a class that refused an answer of the page.
   * @param {Error | null} error
   */
  stop(error) {
    if (this.#ended) return;
    this.#ended = true;
    this.#request?.wipe();
    this.#request = null;
    clearTimeout(this.#startTimer);
    if (this.#loaded || this.#worker === null) {
      this.#terminate();
    } else {
      this.#startTimer = setTimeout(() => this.#terminate(), WORKER_START_TIMEOUT_MS);
    }
    this.#onEnd(this);
    if (error !== null) this.#settle?.reject(error);
  }

  #terminate() {
    clearTimeout(this.#startTimer);
    this.#startTimer = undefined;
    this.#worker?.terminate();
    this.#worker = null;
    if (this.#url !== null) URL.revokeObjectURL(this.#url);
    this.#url = null;
  }

  get ended() {
    return this.#ended;
  }

  /** @param {unknown} reply */
  #receive(reply) {
    // A worker's first message, whatever it is, comes after it has loaded the WebAssembly.
    this.#loaded = true;
    // Messages that were already on their way when the job ended are ignored; a worker that was
    // left to finish loading stops now.
    if (this.#ended) {
      this.#terminate();
      return;
    }
    // A reply that this page cannot read ends the job as a fault of the package, as an unknown
    // type does: reading it as it is would throw inside the worker's event handler and leave the
    // job running, its slot taken and its worker alive (AUD-016-API002).
    if (!isReadableReply(reply)) {
      this.stop(unknownMessage(isRecord(reply) ? (reply.type ?? reply) : reply));
      return;
    }
    if (reply.type === "ready") {
      // isReadableReply checked that a ready's build is text.
      this.#started(/** @type {string} */ (reply.buildId));
    } else if (!this.#buildChecked && reply.type !== "error") {
      this.stop(
        packageMismatch(`The worker sent ${JSON.stringify(reply.type)} before it said its build`),
      );
    } else if (reply.type === "result") {
      this.stop(null);
      this.#settle?.resolve(reply.result);
    } else if (reply.type === "error") {
      const error = readWorkerError(reply.error);
      this.stop(new MhfeError(error.code, sentence(error.message)));
    } else if (reply.type === "ask") {
      void this.#answer(reply.question, reply.value);
    } else if (WORKER_NEWS.includes(reply.type)) {
      // News the page did not ask for has no handler and is dropped.
      this.callPage(this.#ownHandler(reply.type), reply.value, reply.type);
    } else {
      this.stop(unknownMessage(reply.type));
    }
  }

  /**
   * The page's handler named `name`: an own property of the handlers only, so that a message named
   * after an Object.prototype member such as "constructor" or "toString" reaches no page code
   * (AUD-015-SEC007).
   * @param {string} name
   */
  #ownHandler(name) {
    return Object.hasOwn(this.#handlers, name) ? this.#handlers[name] : undefined;
  }

  /**
   * The worker has loaded the WebAssembly, which matched the worker's own build. Its build must be
   * this runtime's too; a difference stops the job. The worker has the request already and starts
   * it at once, so the stop terminates it while it runs, and its result is never used.
   * @param {string} buildId
   */
  #started(buildId) {
    clearTimeout(this.#startTimer);
    this.#startTimer = undefined;
    if (buildId !== BUILD_ID) {
      this.stop(
        packageMismatch(
          `The file runtime/worker.js is of build ${buildId} and runtime/runtime.js of build ` +
            BUILD_ID,
        ),
      );
      return;
    }
    this.#buildChecked = true;
  }

  /**
   * Calls a page callback whose result is not awaited; a throw or a rejection stops the job.
   * @param {WorkerHandler | undefined} callback
   * @param {unknown} value
   * @param {string} name
   */
  callPage(callback, value, name) {
    if (callback === undefined) return;
    let invoke;
    try {
      invoke = checkedPageHandler(callback, name, value);
    } catch (mismatch) {
      this.stop(
        mismatch instanceof Error
          ? mismatch
          : packageMismatch("The worker value could not be read"),
      );
      return;
    }
    try {
      const returned = invoke();
      if (typeof returned?.then === "function") {
        returned.then(undefined, (cause) => this.#pageFailed(name, cause));
      }
    } catch (cause) {
      this.#pageFailed(name, cause);
    }
  }

  /**
   * Ends the job when the page's callback for the message `name` failed with `cause`. Once the
   * job has ended there is nothing left to stop: the page's error is thrown again, a rejection
   * left unhandled, as it would be without this client, instead of being swallowed
   * (AUD-024-API008).
   * @param {string} name
   * @param {unknown} cause
   */
  #pageFailed(name, cause) {
    if (this.#ended) throw cause;
    this.stop(callbackFailed(name, cause));
  }

  /**
   * Asks the page and sends its answer back to the worker.
   * @param {unknown} question
   * @param {unknown} value
   */
  async #answer(question, value) {
    // A question must be answered: one the page has no handler for is a fault of the package.
    const handler = typeof question === "string" ? this.#ownHandler(question) : undefined;
    if (typeof question !== "string" || typeof handler !== "function") {
      this.stop(unknownMessage(question));
      return;
    }
    try {
      const answer = await checkedPageHandler(handler, question, value)();
      this.send({ type: "answer", value: answer?.message ?? answer });
    } catch (cause) {
      // The class's handler calls the page through askPage, which names what the page's own
      // function throws CALLBACK_FAILED; anything else is the class's refusal of the answer, a
      // TypeError or an MhfeError, which ends the job as it is (AUD-024-API007). After the end,
      // nothing is swallowed (#pageFailed).
      if (this.#ended) throw cause;
      this.stop(cause instanceof Error ? cause : callbackFailed(question, cause));
    }
  }
}

/**
 * The one long operation a class runs at a time: a second one is refused with BUSY, and cancel()
 * stops the running one, including a session that waits for the page.
 */
export class OperationSlot {
  /**
   * What holds the slot, which cancel() stops with MhfeCancelledError.
   * @type {{ stop(error: MhfeError): void } | null}
   */
  #running = null;

  /** Refuses a second long operation with BUSY. */
  requireIdle() {
    if (this.#running !== null) {
      throw new MhfeError("BUSY", "Another operation is still running.");
    }
  }

  /**
   * A job that holds the slot until it ends.
   * @param {string[]} scripts
   * @param {WorkerHandlers} handlers
   */
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
   * @template Ready, Begun
   * @param {Promise<Ready>} ready
   * @param {(value: Ready) => Begun | PromiseLike<Begun>} begin
   * @returns {Promise<Begun>}
   */
  async after(ready, begin) {
    this.requireIdle();
    /** @type {(error: MhfeError) => void} */
    let cancel;
    /** @type {MhfeError | null} */
    let stopped = null;
    /** @type {Promise<never>} */
    const cancelled = new Promise((_, reject) => {
      cancel = reject;
    });
    const waiting = {
      stop: (/** @type {MhfeError} */ error) => {
        stopped = error;
        cancel(error);
      },
    };
    this.#running = waiting;
    let value;
    try {
      value = await Promise.race([ready, cancelled]);
      // A cancel() after the check settled, before this went on, stops the operation too.
      if (stopped !== null) throw stopped;
    } finally {
      if (this.#running === waiting) this.#running = null;
    }
    return begin(value);
  }

  /**
   * Holds the slot for work the class runs itself, such as a phrase drawn on several workers at
   * once: cancel() calls `stop(error)`. Returns the function that frees the slot when it ends.
   * @param {(error: MhfeError) => void} stop
   * @returns {() => void}
   */
  hold(stop) {
    this.requireIdle();
    const running = { stop };
    this.#running = running;
    return () => {
      if (this.#running === running) this.#running = null;
    };
  }

  /** Stops what holds the slot, if anything does. */
  cancel() {
    this.#running?.stop(new MhfeCancelledError());
  }
}
