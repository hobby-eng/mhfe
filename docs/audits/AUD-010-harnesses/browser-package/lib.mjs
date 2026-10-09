// Shared helpers of the AUD-010 browser-package probes: a recorder of checks that ends the process
// with a non-zero exit code when one fails, the package's ES modules loaded from data URLs (the
// repository has no "type": "module", so Node would read dist/*.js as CommonJS), and a stand-in
// Worker that records what the page sends and answers as a test asks. Synthetic values only.
import { readFileSync } from "node:fs";

/** Records checks; `finish()` prints a summary and sets a non-zero exit code on any failure. */
export class Checks {
  #failed = 0;
  #passed = 0;

  constructor(title) {
    console.log(`# ${title}`);
  }

  ok(condition, label, detail = "") {
    if (condition) {
      this.#passed += 1;
      console.log(`ok   ${label}`);
    } else {
      this.#failed += 1;
      console.log(`FAIL ${label}${detail === "" ? "" : ` -- ${detail}`}`);
    }
    return condition;
  }

  /** Records an observation that is not a pass/fail check. */
  note(text) {
    console.log(`note ${text}`);
  }

  async rejects(promiseOrFunction, expected, label) {
    let outcome;
    try {
      const value =
        typeof promiseOrFunction === "function" ? promiseOrFunction() : promiseOrFunction;
      if (!(value instanceof Promise)) {
        return this.ok(false, label, "the call returned without a promise");
      }
      await value;
      outcome = { resolved: true };
    } catch (error) {
      outcome = { error };
    }
    if (outcome.resolved) return this.ok(false, label, "it resolved");
    const { error } = outcome;
    const matches =
      typeof expected === "function"
        ? error instanceof expected
        : error?.code === expected || error?.constructor?.name === expected;
    return this.ok(
      matches,
      `${label} -> ${error?.code ?? error?.constructor?.name}`,
      `got ${error?.constructor?.name} ${error?.code ?? ""}: ${error?.message}`,
    );
  }

  /** Whether calling `call` throws synchronously instead of returning a promise. */
  throwsSynchronously(call) {
    try {
      const value = call();
      value?.catch?.(() => {});
      return false;
    } catch {
      return true;
    }
  }

  finish() {
    console.log(`# ${this.#passed} passed, ${this.#failed} failed`);
    if (this.#failed > 0) process.exitCode = 1;
  }
}

export const dataUrl = (text) =>
  `data:text/javascript;base64,${Buffer.from(text).toString("base64")}`;

/**
 * The runtime and the four class modules of `folder` ("web" or "dist"), loaded as a page loads
 * them: each class imports the one shared runtime module.
 */
export async function loadPackage(folder) {
  const path = (name) => (folder === "web" ? `web/${name.split("/").at(-1)}` : `dist/${name}`);
  const runtimeUrl = dataUrl(readFileSync(path("runtime/runtime.js"), "utf8"));
  const loadClass = (name) =>
    import(
      dataUrl(
        readFileSync(path(name), "utf8").replaceAll(
          '"../runtime/runtime.js"',
          JSON.stringify(runtimeUrl),
        ),
      )
    );
  return {
    runtime: await import(runtimeUrl),
    core: await loadClass("core/client.js"),
    repair: await loadClass("repair/repair.js"),
    passwords: await loadClass("passwords/passwords.js"),
    wallet: await loadClass("wallet/wallet.js"),
  };
}

/** The secret fields of a request (web/runtime.js SECRET_FIELDS). */
export const SECRET_FIELDS = [
  "password",
  "passwordRepeat",
  "passphrase",
  "newPassword",
  "newPasswordRepeat",
  "mainPassphrase",
  "rolls",
];

/** The core's limits, which MhfeClient compares with the worker's parameters. */
export const CORE_PARAMETERS = {
  version: "0.5.0",
  maxPim: 1023,
  maxMemoryLevel: 21,
  highestBrowserMemoryLevel: 0,
  wordCounts: [12, 15, 18, 21, 24],
  repairWordCounts: [2, 4, 6, 8],
};

/**
 * A stand-in for the browser's Worker. Each instance records the messages it gets (a copy of the
 * secret bytes, taken before the transfer empties the page's arrays, as a real worker would own
 * them) and the transfer lists. `StandInWorker.respond(worker, message)` decides the replies;
 * by default a self-check is answered with a passing report of build `buildId` and anything else
 * with nothing, so that a test drives it by hand with `reply()`.
 */
export class StandInWorker {
  static instances = [];
  static buildId = "development";
  static respond = StandInWorker.defaultRespond;
  /** Throws from the constructor when set, as a browser that refuses the worker would. */
  static refuse = null;

  constructor(url, options) {
    if (StandInWorker.refuse !== null) throw StandInWorker.refuse;
    this.url = url;
    this.options = options;
    this.messages = [];
    this.transfers = [];
    this.terminated = false;
    this.onmessage = null;
    this.onerror = null;
    StandInWorker.instances.push(this);
  }

  postMessage(message, transfer = []) {
    const received = { ...message };
    for (const field of SECRET_FIELDS) {
      if (message?.[field] instanceof Uint8Array) received[field] = message[field].slice();
    }
    if (message?.value !== null && typeof message?.value === "object") {
      received.value = { ...message.value };
      for (const field of SECRET_FIELDS) {
        if (message.value[field] instanceof Uint8Array) {
          received.value[field] = message.value[field].slice();
        }
      }
    }
    this.transfers.push(transfer);
    // A real postMessage detaches every transferred buffer in the sender.
    for (const buffer of transfer) structuredClone(buffer, { transfer: [buffer] });
    this.messages.push(received);
    setTimeout(() => StandInWorker.respond(this, received), 0);
  }

  reply(data) {
    if (!this.terminated) this.onmessage?.({ data });
  }

  terminate() {
    this.terminated = true;
  }

  get isSelfCheck() {
    return ["selfCheck", "selfCheckArgon2"].includes(this.messages[0]?.operation);
  }

  static defaultRespond(worker, message) {
    if (worker.messages.length !== 1) return;
    if (!["selfCheck", "selfCheckArgon2"].includes(message.operation)) return;
    worker.reply({ type: "ready", buildId: StandInWorker.buildId });
    const report = { version: "0.5.0", tier: message.tier, passed: true, ids: [], components: [] };
    const result =
      message.module === "core" && message.operation === "selfCheck"
        ? { ...report, parameters: CORE_PARAMETERS }
        : report;
    worker.reply({ type: "result", result });
  }

  static reset() {
    StandInWorker.instances = [];
    StandInWorker.buildId = "development";
    StandInWorker.respond = StandInWorker.defaultRespond;
    StandInWorker.refuse = null;
  }

  /** The latest worker that is not a self-check's, once it has its request. */
  static async operation(matches = () => true) {
    for (let tries = 0; tries < 200; tries += 1) {
      const worker = StandInWorker.instances.findLast(
        (each) => !each.isSelfCheck && each.messages.length > 0 && matches(each.messages[0]),
      );
      if (worker !== undefined) return worker;
      await tick();
    }
    throw new Error("no worker received its request");
  }
}

export const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** An empty WebAssembly module: compiles, and has no build section (an unstamped "development"). */
export const emptyWasm = () => new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);

/** Package parts for the classes; the stand-in worker never runs the sources. */
export const standInSources = () => ({
  workerSource: "stand-in worker source",
  wasm: emptyWasm(),
  argon2Threaded: "stand-in threaded source",
  argon2SingleThreaded: "stand-in single-threaded source",
});

/**
 * dist/runtime/worker.js run in this process with the package's real WebAssembly, `self` a
 * stand-in that collects what the worker posts. Returns `send(message)`, resolving to the posted
 * messages for it. `globals` are names placed in front of the worker, such as an Argon2 build.
 */
export function inProcessWorker(globals = {}) {
  const script = readFileSync("dist/runtime/worker.js", "utf8");
  const posted = [];
  const workerSelf = {
    postMessage: (message) => posted.push(recordOf(message)),
    crypto: globalThis.crypto,
    crossOriginIsolated: false,
  };
  new Function("self", ...Object.keys(globals), script)(workerSelf, ...Object.values(globals));
  return {
    self: workerSelf,
    async send(message) {
      posted.length = 0;
      await workerSelf.onmessage({ data: message });
      return [...posted];
    },
  };
}

/**
 * A copy of what a worker posts, as a browser's structured clone would deliver it; a compiled
 * WebAssembly.Module, which a browser clones but Node may not, is recorded by a marker, and a
 * function, which no browser clones, makes the record say so.
 */
function recordOf(value) {
  if (value instanceof WebAssembly.Module) return "[WebAssembly.Module]";
  if (typeof value === "function") throw new DOMException("a function", "DataCloneError");
  if (ArrayBuffer.isView(value)) return value.slice();
  if (Array.isArray(value)) return value.map(recordOf);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, each]) => [key, recordOf(each)]));
  }
  return value;
}

/** The package's real WebAssembly, compiled once. */
export function packageModule() {
  return new WebAssembly.Module(readFileSync("dist/runtime/mhfe.wasm"));
}

/** The build stamped into dist/. */
export function distBuildId() {
  return JSON.parse(readFileSync("dist/modules.json", "utf8")).buildId;
}
