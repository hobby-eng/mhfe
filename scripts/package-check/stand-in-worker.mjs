// Part 4 of the checks of the browser package, continued: the stand-in worker that the page-side
// classes start in place of a browser's Worker. It records what each class posts and replies as
// a check tells it; a self-check it answers by itself, with the package's WebAssembly in this
// process. The real worker runs in a browser test (scripts/verify-browsers.mjs).
import { resolveObjectURL } from "node:buffer";

import { nextTurn } from "./expect.mjs";
import { BUILD_ID, bindings, parameters, realArgon2 } from "./package.mjs";

/** The operations of the self-checks, which a stand-in worker answers by itself. */
const SELF_CHECK_OPERATIONS = ["selfCheck", "selfCheckArgon2", "selfCheckProcess"];
/** Counts the events of the stand-in workers, so that their order can be compared. */
let workerEvents = 0;

/** A browser's Worker as a class starts it: it records what the page posts and replies as told. */
export class StandInWorker {
  static last = null;
  static started = [];
  /** The workers of the classes' self-checks, in the order they were asked. */
  static checks = [];
  /** How a self-check is answered: by default as the package's worker would; see below. */
  static serveCheck = null;
  /**
   * Whether a worker says it has loaded the WebAssembly as soon as it has its first request, as
   * the package's worker does; a test of a worker still loading turns it off.
   */
  static loads = true;
  constructor(url) {
    this.script = resolveObjectURL(url);
    this.terminated = false;
    // Whether it has said it is ready, which started() waits for.
    this.ready = false;
    this.messages = [];
    /**
     * The transfer list of each message as the page gave it: each buffer with its size before the
     * transfer, which empties it.
     */
    this.transfers = [];
    this.createdAt = workerEvents += 1;
    StandInWorker.last = this;
    StandInWorker.started.push(this);
    this.received = new Promise((resolve) => {
      this.firstMessage = resolve;
    });
  }
  postMessage(message, transfer = []) {
    this.transfers.push(transfer.map((buffer) => ({ buffer, byteLength: buffer.byteLength })));
    // structuredClone with a transfer list empties the sender's buffers, as a real worker does.
    this.messages.push(structuredClone(message, { transfer }));
    this.firstMessage();
    if (this.messages.length === 1 && SELF_CHECK_OPERATIONS.includes(message.operation)) {
      this.selfCheck = true;
      StandInWorker.checks.push(this);
      setTimeout(() => this.#serveCheck(), 0);
    } else if (this.messages.length === 1 && StandInWorker.loads) {
      setTimeout(() => {
        if (!this.terminated) this.reply({ type: "ready", buildId: BUILD_ID });
        this.ready = true;
      }, 0);
    }
  }
  async #serveCheck() {
    // The package's worker says its build before anything else (AUD-024-API006); a check that
    // tests another build says so again with that one.
    this.reply({ type: "ready", buildId: BUILD_ID });
    this.ready = true;
    try {
      const result = await StandInWorker.serveCheck(this.messages[0], this);
      if (!this.terminated && result !== undefined) this.reply({ type: "result", result });
    } catch (error) {
      if (!this.terminated) this.reply({ type: "error", error: describeWorkerError(error) });
    }
  }
  reply(data) {
    this.onmessage({ data });
  }
  terminate() {
    this.terminated = true;
    this.terminatedAt ??= workerEvents += 1;
  }
}

/** An error as the worker posts it: "CODE: message" from the WebAssembly. */
function describeWorkerError(error) {
  const [, code, message] = /^([A-Z_]+): (.*)$/su.exec(error.message);
  return { code, message };
}

/**
 * Answers a self-check as the package's worker does, with the package's WebAssembly in this
 * process: ready with this build, each part as it starts and ends, then the report; Argon2 by the
 * single-threaded build, whichever build the class placed in front.
 */
export function servedByTheWebAssembly(message, worker) {
  worker.reply({ type: "ready", buildId: BUILD_ID });
  const onStart = (id, label) => worker.reply({ type: "componentStart", value: { id, label } });
  const onResult = (json) => worker.reply({ type: "component", value: JSON.parse(json) });
  const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
  const { tier, skip } = message;
  const argon2 = message.argon2 === false ? undefined : realArgon2;
  const run = {
    "repair.selfCheck": () => bindings.selfCheckRepair(tier, skip, onStart, onResult),
    "passwords.selfCheck": () => bindings.selfCheckPasswords(tier, skip, random, onStart, onResult),
    "wallet.selfCheck": () => bindings.selfCheckWallet(tier, skip, random, onStart, onResult),
    "core.selfCheck": () => bindings.selfCheckCore(tier, skip, argon2, onStart, onResult),
    "core.selfCheckArgon2": () => bindings.selfCheckArgon2(tier, skip, argon2, onStart, onResult),
    "core.selfCheckProcess": () => bindings.selfCheckProcess(tier, skip, onStart, onResult),
  }[`${message.module}.${message.operation}`];
  const report = JSON.parse(run());
  return message.module === "core" && message.operation === "selfCheck"
    ? { ...report, parameters }
    : report;
}

/** Puts the stand-in in place of the browser's Worker, answering self-checks as the package's. */
export function installStandInWorker() {
  globalThis.Worker = StandInWorker;
  StandInWorker.serveCheck = servedByTheWebAssembly;
}

/**
 * The worker of the call just made, once its request has been sent to it: the latest running one
 * that is not a self-check's, and whose request `matches` accepts when several run.
 */
export async function started(matches = () => true) {
  for (let tries = 0; tries < 50; tries += 1) {
    const worker = StandInWorker.started.findLast(
      (each) => !each.selfCheck && each.messages.length > 0 && matches(each.messages[0]),
    );
    // A worker that loads says it is ready before any other message, as the package's does.
    const loaded = worker?.ready === true || !StandInWorker.loads;
    if (worker !== undefined && !worker.terminated && loaded) return worker;
    await nextTurn();
  }
  throw new Error("no worker received its request");
}

/** A Worker that the browser refuses to start. */
export class RefusedWorker {
  constructor() {
    throw new Error("refused by the stand-in");
  }
}

/** The TextEncoder of Node.js, which some checks replace for a while to see the classes' copies. */
export const RealTextEncoder = globalThis.TextEncoder;

/** A TextEncoder that keeps the arrays it gives for `texts` in `copies`, to see them wiped. */
export function encoderKeeping(texts, copies) {
  return class extends RealTextEncoder {
    encode(text) {
      const bytes = super.encode(text);
      if (texts.includes(text)) copies.push(bytes);
      return bytes;
    }
  };
}
