// @ts-check
/** @import { WorkerJob } from "../../runtime/runtime.js" */
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import { OPEN_KEYS } from "./values.js";
import { requireRepetition } from "./input.js";
import {
  requireText,
  MhfeError,
  sentence,
  requireKnownKeys,
  requireCallback,
  describeChoice,
  encodeSecret,
  SecretRequest,
  MhfeCancelledError,
} from "../../runtime/runtime.js";
/** @import { WorkerRefusal, PendingOpen, HiddenWalletsHandle, SessionStart } from "../types/client-shared.d.ts" */
/** @import { MhfeProgress } from "../client.d.ts" */
/** @import { WorkerAnswer, WorkerRequest } from "../../runtime/runtime.js" */
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreHiddenWallets owns this operation group behind the client's shared worker boundary. */
export class CoreHiddenWallets {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * Opens a session of hidden wallets on a 24-word container, with the main wallet's BIP39
   * passphrase (`mainPassphrase`, required, empty for a wallet without one). Resolves, once the
   * Argon2 work area is reserved, to a handle:
   *
   * - `open({ password, passwordRepeat, passwordRepair, onProgress })` opens the wallet of a new
   *   password, twelve rounds, and resolves to `{ phrase, words, fingerprintWithoutPassphrase }`.
   *   A password used already (PASSWORD_ALREADY_USED), one whose wallet would pass a check
   *   (HIDDEN_WALLET_PASSES_CHECK) and a password refused before any work reject it, and the
   *   session stays open.
   * - `close()` ends the session: the Rust code overwrites every password and the passphrase in
   *   it, and the worker ends. During an `open` it stops the worker at once instead, which frees
   *   its memory without overwriting it. Resolves once the session has ended.
   *
   * The session holds the long-operation slot until it is closed or cancelled. Nothing is created
   * or stored: the container and each password give the same wallet every time. The page shows no
   * list or count of the wallets opened.
   * @param {OptionsOf<"openHiddenWallets">} [options]
   */
  async openHiddenWallets({ container, pim = 0, memoryLevel = 0, mainPassphrase } = {}) {
    requireText(container, "container");
    if (mainPassphrase === undefined) {
      throw new TypeError("mainPassphrase is required; an empty one means a wallet without one.");
    }
    /** @type {PendingOpen | null} */ let pendingOpen = null;
    /** @type {((request: WorkerAnswer) => void) | null} */ let nextRequest = null;
    /** @type {Promise<void> | null} */ let closing = null;
    /** @type {HiddenWalletsHandle | null} */ let handle = null;
    /** @type {SessionStart} */ let ready;
    // The worker waits for the page's next request (`nextRequest` is set) between wallets.
    /** @type {() => Promise<WorkerAnswer>} */ const waitForPage = () =>
      new Promise((resolve) => {
        nextRequest = resolve;
      });
    const sendRequest = (/** @type {WorkerAnswer} */ request) => {
      const send = nextRequest;
      nextRequest = null;
      if (send === null) throw new TypeError("The worker does not wait for a request.");
      send(request);
    };
    const answerOpen = (/** @type {(open: PendingOpen | null) => void} */ settle) => {
      const open = pendingOpen;
      pendingOpen = null;
      settle(open);
      return waitForPage();
    };
    const handlers = {
      ready: () => {
        ready.resolve(handle);
        return waitForPage();
      },
      opened: (/** @type {unknown} */ wallet) => answerOpen((open) => open?.resolve(wallet)),
      refused: (/** @type {WorkerRefusal} */ error) =>
        answerOpen((open) => open?.reject(new MhfeError(error.code, sentence(error.message)))),
      progress: (/** @type {MhfeProgress} */ value) => pendingOpen?.onProgress?.(value),
    };
    /** @type {WorkerJob} */ let job;
    handle = {
      open: async (options = {}) => {
        requireKnownKeys(options, OPEN_KEYS, "open");
        const { password, passwordRepeat, passwordRepair, onProgress } = options;
        if (job.ended || closing !== null) {
          throw new MhfeError("SESSION_CLOSED", "The session is closed.");
        }
        if (pendingOpen !== null) throw new MhfeError("BUSY", "A wallet is being opened.");
        requireCallback(onProgress, "onProgress");
        const repeat = requireRepetition(password, passwordRepeat, "password");
        const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
        // Built one secret at a time, so that a refused repetition wipes the password's copy too
        // (AUD-011-SEC001).
        /** @type {WorkerRequest} */ const message = { choice, position };
        let handed = false;
        try {
          message.password = encodeSecret(password, "password");
          message.passwordRepeat = encodeSecret(repeat, "repeated password");
          return new Promise((/** @type {(wallet: unknown) => void} */ resolve, reject) => {
            pendingOpen = { resolve, reject, onProgress };
            sendRequest({ message });
            handed = true;
          });
        } finally {
          if (!handed) new SecretRequest(message).wipe();
        }
      },
      // Every call returns the same promise, which settles once the session has ended.
      close: () => {
        closing ??= closeSession();
        return closing;
      },
    };
    const closeSession = async () => {
      if (nextRequest !== null) {
        // The worker waits: it frees the session, which overwrites its secrets, and ends.
        sendRequest({ message: { close: true } });
      } else if (!job.ended) {
        // An open is running: its worker stops at once.
        const open = pendingOpen;
        pendingOpen = null;
        job.stop(new MhfeCancelledError());
        open?.reject(new MhfeCancelledError());
      }
      await done.then(
        () => undefined,
        () => undefined,
      );
    };
    const started = new Promise((/** @type {SessionStart["resolve"]} */ resolve, reject) => {
      ready = { resolve, reject };
    });
    /** @type {Promise<unknown>} */ let done;
    ({ job, done } = await this.#runtime.begin(
      { operation: "hiddenWallets", container },
      { pim, memoryLevel, mainPassphrase, handlers, noPassword: true },
    ));
    done.then(undefined, (error) => {
      ready.reject(error);
      pendingOpen?.reject(error);
      pendingOpen = null;
    });
    return started;
  }
}
