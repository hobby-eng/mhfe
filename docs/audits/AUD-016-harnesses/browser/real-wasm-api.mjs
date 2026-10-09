// AUD-016: exercise the freshly built browser classes, production worker, and real WASM at
// bounded cost. A VM implements the Worker transport in Node; this is not real-browser evidence.
// No Argon2 source is loaded or called. Inputs are public BIP39 fixtures and synthetic values.
import assert from "node:assert/strict";
import { resolveObjectURL } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = new URL("../../../../", import.meta.url);
const bytes = (path) => readFileSync(new URL(path, root));
const read = (path) => bytes(path).toString();
const dataUrl = (text) => `data:text/javascript;base64,${Buffer.from(text).toString("base64")}`;
const runtimeUrl = dataUrl(read("dist/runtime/runtime.js"));
const runtime = await import(runtimeUrl);
const load = async (path) =>
  import(dataUrl(read(path).replaceAll('"../runtime/runtime.js"', `"${runtimeUrl}"`)));
const { MhfeWallet } = await load("dist/wallet/wallet.js");
const { MhfePasswords } = await load("dist/passwords/passwords.js");
const { MhfeRepair } = await load("dist/repair/repair.js");
const workerSource = read("dist/runtime/worker.js");
const wasm = await WebAssembly.compile(bytes("dist/runtime/mhfe.wasm"));
const parts = { workerSource, wasm };
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CONTAINER =
  "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
const MAX_U32 = 0xffff_ffff;
let failures = 0;
let assertions = 0;
const check = (label, passed, detail) => {
  failures += Number(!passed);
  assertions += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}: ${JSON.stringify(detail)}`);
};
async function resultOf(action) {
  try {
    return { resolved: await action() };
  } catch (error) {
    return { rejected: { name: error.name, code: error.code, message: error.message } };
  }
}

class VmWorker {
  static all = [];
  constructor(url) {
    this.terminated = false;
    VmWorker.all.push(this);
    const sandbox = {
      WebAssembly,
      TextDecoder,
      TextEncoder,
      console,
      setTimeout,
      clearTimeout,
      self: {
        crypto: globalThis.crypto,
        crossOriginIsolated: false,
        postMessage: (message) => {
          const copied = structuredClone(message);
          setTimeout(() => {
            if (!this.terminated) this.onmessage?.({ data: copied });
          }, 0);
        },
      },
    };
    this.sandbox = sandbox;
    this.loaded = resolveObjectURL(url)
      .text()
      .then((source) => {
        if (!this.terminated) vm.runInNewContext(source, sandbox, { filename: "worker.js" });
      });
  }
  postMessage(message, transfer = []) {
    const copied = structuredClone(message, { transfer });
    this.loaded.then(async () => {
      if (this.terminated) return;
      try {
        await this.sandbox.self.onmessage({ data: copied });
      } catch (error) {
        if (!this.terminated) this.onerror?.({ message: error.message, preventDefault() {} });
      }
    });
  }
  terminate() {
    this.terminated = true;
    this.sandbox = null;
  }
}
globalThis.Worker = VmWorker;
console.log(`BUILD ${runtime.BUILD_ID}`);
for (const path of ["dist/runtime/mhfe.wasm", "dist/runtime/worker.js"])
  console.log(`ARTIFACT ${path} ${createHash("sha256").update(bytes(path)).digest("hex")}`);

const passwords = new MhfePasswords(parts);
const wallet = new MhfeWallet(parts);
const repair = new MhfeRepair(parts);
for (const [name, module] of [
  ["passwords", passwords],
  ["wallet", wallet],
  ["repair", repair],
]) {
  const report = await module.startupCheck();
  check(`${name} real-WASM startup`, report.passed === true, {
    passed: report.passed,
    components: report.components.length,
    version: report.version,
  });
}

for (const [label, action] of [
  [
    "password review with null repetition",
    () => passwords.review({ password: "", passwordRepeat: null }),
  ],
  [
    "wallet check with null passphrase",
    () => wallet.walletCheck({ phrase: PHRASE, passphrase: null }),
  ],
  [
    "draw with null repetition",
    () => wallet.drawPhrase({ passphrase: "public", passphraseRepeat: null, walletCheck: false }),
  ],
]) {
  const result = await resultOf(action);
  check(`explicit null ${label} is a TypeError`, result.rejected?.name === "TypeError", result);
}

const fingerprint = await wallet.fingerprint({ phrase: PHRASE });
check("published BIP39/BIP32 fingerprint", fingerprint === "73c5da0a", { fingerprint });
const card = await repair.repairWords({ container: CONTAINER, count: 4 });
// The independently computed value in src/repair.rs and verify-browser-package.mjs.
check("public suite-3 repair-card result", card.words === "shaft pupil patient jewel", {
  words: card.words,
  profile: card.profile,
});
const dicePassword = await passwords.make({ kind: "words", count: 1, dice: "11111" });
check("published EFF dice 11111", dicePassword.password === "abacus", {
  password: dicePassword.password,
  checkWord: dicePassword.checkWord,
});

for (const count of [MAX_U32 + 1, MAX_U32 + 3, -1, 0, 33]) {
  const result = await resultOf(() => passwords.make({ kind: "words", count }));
  check(
    `password count ${count} is refused without wrapping`,
    result.rejected?.code === "INVALID_PASSWORD_SIZE",
    result,
  );
}
for (const count of [MAX_U32 + 1, MAX_U32 + 3, -1, 3]) {
  const result = await resultOf(() => repair.repairWords({ container: CONTAINER, count }));
  check(
    `repair count ${count} is refused without wrapping`,
    result.rejected?.code === "INVALID_REPAIR_WORDS",
    result,
  );
}
for (const scanGap of [MAX_U32 + 1, MAX_U32 + 21]) {
  const result = await resultOf(() =>
    wallet.describeAddress({
      address: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
      coin: "bitcoin",
      scanGap,
    }),
  );
  check(
    `address scan gap ${scanGap} is refused without wrapping`,
    result.rejected?.code === "INVALID_REQUEST",
    result,
  );
}
const position = await resultOf(() =>
  wallet.describeDraw({ chosen: [{ word: "abandon", position: MAX_U32 + 2 }] }),
);
check(
  "chosen-word position cannot wrap into a valid index",
  position.rejected?.name === "TypeError",
  position,
);

// The browser class must preserve caller bytes even when the WASM binding refuses bad UTF-8.
const input = new Uint8Array([0xff, 0xfe, 0xfd]);
const before = new Uint8Array(input);
const invalidUtf8 = await resultOf(() => passwords.review({ password: input }));
check(
  "invalid UTF-8 is refused and caller bytes stay owned",
  invalidUtf8.rejected?.code === "INVALID_PASSWORD_UTF8" &&
    input.every((byte, index) => byte === before[index]),
  invalidUtf8,
);
assert.ok(
  VmWorker.all.every((worker) => worker.terminated),
  "every operation worker terminated",
);
console.log(`Checks complete: ${assertions - failures} passed, ${failures} failed assertions.`);
process.exitCode = failures === 0 ? 0 : 1;
