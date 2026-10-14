// AUD-024 api-contracts harness (commit b6fca69): checks the contracts of the browser package's
// classes and WebAssembly bindings that the api-contracts review found broken. Each check states
// the expected behaviour from its source and prints PASS or FAIL; the script exits 1 when any
// check fails, 0 otherwise. At b6fca69 every check fails. It runs the built package (dist/) in
// Node.js: the real worker script in this process for the self-checks and for the modules without
// Argon2, and a scripted stand-in worker for the core's long operations, so that no Argon2 round
// runs. Run from the repository root:
//
//   node docs/audits/AUD-024-harnesses/api-contracts/check-contracts.mjs
import { readFileSync } from "node:fs";

import {
  BUILD_ID,
  InProcessWorker,
  ROOT,
  coreSources,
  dist,
  outcome,
  sources,
  summarize,
  wasmBytes,
  workerSource,
} from "./harness.mjs";

/** How the stand-in answers a long operation of the core: set per check. */
let script = null;
/** What the stand-in received: the request, then each answer. */
const received = [];
const LONG = new Set(["encrypt", "decrypt", "check", "searchWallet", "rekey", "hiddenWallets"]);
class ProbeWorker {
  constructor(url) {
    this.url = url;
    this.real = null;
    this.scripted = false;
    this.onmessage = null;
    this.onerror = null;
    this.terminated = false;
  }
  reply(value) {
    setTimeout(() => !this.terminated && this.onmessage?.({ data: value }), 0);
  }
  postMessage(message, transfer = []) {
    if (!this.scripted && this.real === null && !LONG.has(message.operation)) {
      this.real = new InProcessWorker(this.url);
      this.real.onmessage = (event) => this.onmessage?.(event);
    }
    if (this.real !== null) {
      this.real.postMessage(message, transfer);
      return;
    }
    const data = summarize(structuredClone(message, { transfer }));
    received.push(data);
    const first = !this.scripted;
    this.scripted = true;
    if (first) this.reply({ type: "ready", buildId: BUILD_ID });
    script(data, first, (value) => this.reply(value));
  }
  terminate() {
    this.terminated = true;
    this.real?.terminate();
  }
}
globalThis.Worker = ProbeWorker;
const endWith = (reply) =>
  reply({ type: "error", error: { code: "INVALID_REQUEST", message: "stand-in end" } });

const { MhfeClient } = await import(dist("core/client.js"));
const { MhfeRepair } = await import(dist("repair/repair.js"));
const { MhfePasswords } = await import(dist("passwords/passwords.js"));
const { MhfeWallet } = await import(dist("wallet/wallet.js"));
const client = new MhfeClient(coreSources());
await client.startupCheck({ argon2: false });
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MARKED = `${"abandon ".repeat(23)}?`;
const ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

let failures = 0;
function report(name, passed, detail) {
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${name}: ${detail}`);
}

// 1. web/client.d.ts:376 and docs/BROWSER-PACKAGE.md:290-296: the owner's yes is true or
// { passphrase }; anything else stops the rekey (NOT_CONFIRMED_BY_OWNER).
{
  received.length = 0;
  script = (data, first, reply) => {
    if (first) {
      reply({
        type: "ask",
        question: "ownerCheck",
        value: {
          phrase: PHRASE,
          words: 12,
          fingerprintWithoutPassphrase: "73c5da0a",
          rehearsalNeedsPassphrase: true,
        },
      });
    } else {
      endWith(reply);
    }
  };
  await outcome(
    client.rekey({
      container: PHRASE,
      password: "old",
      newPassword: "new",
      newPasswordRepeat: "new",
      confirmation: { owner: () => ({ confirmed: false, passphrase: "a passphrase" }) },
      walletHasPassphrase: true,
    }),
  );
  const answer = received.find((data) => data.type === "answer")?.value;
  report(
    "owner-answer-extra-keys",
    answer?.confirmed !== true,
    `owner answered { confirmed: false, passphrase }; the page sent ${JSON.stringify(answer)}`,
  );
}

// 2. CHECK-API-001 (extra fields: reject rather than guess) and web/client.js:1294-1297 (any other
// key "is refused rather than dropped"): a misspelled setting does not fall back to its default.
{
  received.length = 0;
  script = (data, first, reply) => endWith(reply);
  const result = await outcome(
    client.encrypt({ phrase: PHRASE, password: "p", passwordRepeat: "p", PIM: 7 }),
  );
  const request = received[0];
  report(
    "misspelled-option",
    request === undefined,
    request === undefined
      ? JSON.stringify(result)
      : `encrypt({ PIM: 7 }) reached the worker with pim ${request.pim}`,
  );
}

// 3. web/runtime.d.ts:156 (a sentence a page can show as it is) and docs/API.md:1044-1046: a whole
// number out of range is refused with a sentence that is true and names the parameter.
{
  const passwords = new MhfePasswords(sources());
  const wallet = new MhfeWallet(sources());
  const count = (await outcome(passwords.make({ count: 2 ** 32 }))).rejected?.message ?? "";
  const gap = (await outcome(wallet.describeAddress({ address: ADDRESS, coin: "bitcoin", scanGap: 2 ** 32 })))
    .rejected?.message ?? "";
  const path = (await outcome(wallet.describeAddress({ address: ADDRESS, coin: "bitcoin", scanGap: 2 ** 31 + 1 })))
    .rejected?.code;
  const passed =
    !/must be a whole number, not 4294967296/u.test(count) &&
    !gap.startsWith("ScanGap") &&
    path !== "INVALID_DERIVATION_PATH";
  report(
    "out-of-range-numbers",
    passed,
    `make count 2**32: "${count}"; describeAddress scanGap 2**32: "${gap}"; scanGap 2**31+1: ${path}`,
  );
}

// 4. docs/API.md:993-995 (CALLBACK_FAILED: a callback of the page threw or rejected) and
// docs/BROWSER-PACKAGE.md:214-216 (an onNoLength answer of detection again is a TypeError).
{
  const repair = new MhfeRepair(sources());
  const named = (await outcome(
    repair.fullCheck({
      onProgress: () => {
        throw new Error("page failure");
      },
    }),
  )).rejected?.message ?? "";
  received.length = 0;
  script = (data, first, reply) => {
    if (first) {
      reply({
        type: "ask",
        question: "noLength",
        value: { builtInCheck: null, matchingLengths: [], passed: [], walletCheck: false },
      });
    } else {
      endWith(reply);
    }
  };
  const refusal = (await outcome(
    client.check({
      container: PHRASE,
      password: "p",
      reference: { words: 0 },
      onNoLength: () => ({ words: 0 }),
    }),
  )).rejected;
  report(
    "callback-failure-attribution",
    /onProgress/u.test(named) && refusal?.name === "TypeError",
    `fullCheck onProgress threw: "${named}"; onNoLength answered { words: 0 }: ${refusal?.name} ${refusal?.code ?? ""} "${refusal?.message}"`,
  );
}

// 5. The refusal of a malformed reference names the forms the method takes (searchDecoy: an
// address or a fingerprint; searchWallet: also { walletCheck: true } and { builtInCheck: true }).
{
  const decoy = (await outcome(client.searchDecoy({ container: MARKED, reference: {} }))).rejected
    ?.message ?? "";
  const ofWallet = (await outcome(client.searchWallet({ container: MARKED, password: "p", reference: {} })))
    .rejected?.message ?? "";
  report(
    "reference-refusal-names-the-forms",
    !/\{ words \}|walletCheck/u.test(decoy) && /builtInCheck/u.test(ofWallet),
    `searchDecoy: "${decoy}"; searchWallet: "${ofWallet}"`,
  );
}

// 6. docs/BROWSER-PACKAGE.md:455-461 and web/wallet.js:353-356: at most one word never to use, and
// a chosen word that cannot be used is INVALID_WORD_WISH.
{
  const wallet = new MhfeWallet(sources());
  const two = await outcome(wallet.describeDraw({ neverUse: ["", "abandon"] }));
  const empty = (await outcome(wallet.describeDraw({ chosen: [{ word: "", position: 3 }] }))).rejected;
  report(
    "word-wishes",
    two.rejected !== undefined && empty?.code === "INVALID_WORD_WISH",
    `neverUse ["", "abandon"]: ${JSON.stringify(two).slice(0, 80)}; chosen word "": ${empty?.code} "${empty?.message}"`,
  );
}

// 7. docs/API.md:947-948: onProgress receives every part as it starts and as it ends.
{
  const repair = new MhfeRepair(sources());
  const heard = new Set();
  const full = await repair.fullCheck({ onProgress: ({ id }) => heard.add(id) });
  const unheard = full.components.filter(({ id }) => !heard.has(id)).map(({ id }) => id);
  report("full-check-progress", unheard.length === 0, `parts never reported: ${JSON.stringify(unheard)}`);
}

// 8. docs/API.md:1044-1046: the bindings refuse numbers that are not whole numbers in range "so
// that no value wraps around"; core/rekey.rs:332 keeps a boolean answer strict for the same reason.
{
  const workerSelf = { postMessage: () => {}, crypto: globalThis.crypto, crossOriginIsolated: false };
  // oxlint-disable-next-line typescript/no-implied-eval -- the package's own worker script
  const mhfe = new Function("self", `${workerSource}\nreturn mhfe;`)(workerSelf);
  mhfe.initSync({ module: new WebAssembly.Module(wasmBytes) });
  const zoo = new TextEncoder().encode("zoo");
  let wrapped;
  try {
    wrapped = JSON.parse(mhfe.describeDraw(zoo, [2 ** 32], "", false)).fixedPosition;
  } catch {
    wrapped = "refused";
  }
  let stringCheck;
  try {
    const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };
    const pass = new TextEncoder().encode("a passphrase");
    stringCheck = JSON.parse(
      mhfe.drawPhrase(pass, pass.slice(), new Uint8Array(), new Uint32Array(), "", "true", random, () => {}),
    ).walletCheck;
  } catch {
    stringCheck = "refused";
  }
  report(
    "binding-argument-coercion",
    wrapped === "refused" && stringCheck === "refused",
    `describeDraw place 2**32: ${wrapped === "refused" ? "refused" : `taken, fixedPosition ${wrapped}`}; drawPhrase wallet_check "true": ${stringCheck === "refused" ? "refused" : `taken, walletCheck ${stringCheck}`}`,
  );
}

// 9. web/runtime.d.ts:156: the INVALID_COIN message is a sentence a page can show as it is.
{
  const wallet = new MhfeWallet(sources());
  const coin = (await outcome(wallet.describeAddress({ address: ADDRESS, coin: "monero" }))).rejected
    ?.message ?? "";
  report("coin-refusal-sentence", !/^Unknown coin the coins are/u.test(coin), `"${coin}"`);
}

// 10. DOC-06: docs/API.md quotes makePassword's refusal of a count with "checkWord" as the binding
// gives it.
{
  const api = readFileSync(`${ROOT}/docs/API.md`, "utf8").replace(/\s+/gu, " ");
  const quoted = /\("(checkWord takes no count[^"]*)"\)/u.exec(api)?.[1] ?? null;
  const passwords = new MhfePasswords(sources());
  const actual = (await outcome(passwords.make({ kind: "checkWord", count: 5 }))).rejected?.message;
  report(
    "api-md-quotes-the-refusal",
    quoted === null || actual?.toLowerCase().startsWith(quoted.toLowerCase()),
    `API.md quotes "${quoted}"; the refusal is "${actual}"`,
  );
}

// 11. CORE-10: the error codes after which a session of hidden wallets stays open come from
// MhfeError::code(), not typed again.
{
  const hidden = readFileSync(`${ROOT}/src/hidden.rs`, "utf8");
  const list = /KEEPS_SESSION_OPEN: \[&'static str; \d+\] = \[([^\]]*)\]/u.exec(hidden)?.[1] ?? "";
  const literals = list.match(/"[A-Z0-9_]+"/gu) ?? [];
  report(
    "session-refusal-codes-from-the-library",
    literals.length === 0,
    `src/hidden.rs KEEPS_SESSION_OPEN types ${literals.length} codes as string literals`,
  );
}

console.log(failures === 0 ? "every check passed" : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
