// AUD-010 secrets-security probe (CHECK-SEC-001, CHECK-SEC-005): which secret copies stay in the
// WebAssembly's linear memory after a binding of the browser package returns.
//
// Loads the package's wasm-bindgen glue (target/wasm-bindgen/mhfe.js) over the built
// runtime/mhfe.wasm in Node.js, a fresh instance for every case, calls one binding with public,
// synthetic secrets and counts each secret's bytes in the linear memory before and after the call.
// Operations with Argon2 use the package's single-threaded Argon2 build at a reduced cost for the
// rounds (256 KiB, one pass) and at full cost for its known answers, as
// scripts/verify-browser-package.mjs does. Nothing is written to disk.
//
// Claims checked (docs/API.md "Secrets are UTF-8 bytes, which the bindings wipe; a result that
// holds a secret is written into a buffer of its final size, wiped once it has become a JavaScript
// string", and "Every buffer and binding this crate owns that holds a password, phrase, ... is
// wiped when dropped"):
//   W1 a password or passphrase passed as bytes leaves no copy behind;
//   W2 a secret result (phrase, password) leaves no copy behind once returned;
//   W3 a phrase passed as text (wasm-bindgen &str) leaves no copy behind.
// Informational, not a pass condition: copies inside dependencies, here the HMAC-SHA512 key block
// of the BIP39 seed (phrase XOR 0x36), which docs/API.md places outside the crate's control.
//
// Prints one line per case and exits 1 when any W1 to W3 case leaves a copy.
//
//   node docs/audits/AUD-010-harnesses/secrets-security/wasm-residue.mjs
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const root = new URL("../../../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const encode = (text) => new TextEncoder().encode(text);

const glue = read("target/wasm-bindgen/mhfe.js").toString();
const module = new WebAssembly.Module(read("dist/runtime/mhfe.wasm"));
vm.runInThisContext(read("web/argon2-engine.js").toString(), { filename: "argon2-engine.js" });
const argon2Engine = vm.runInThisContext("argon2Engine");
const createArgon2St = require(new URL("dist/core/argon2-st.js", root).pathname);

/** Public synthetic secrets, unique enough not to occur in the module by chance. */
const PASSWORD = "public sentinel password 6c1e";
const NEW_PASSWORD = "public sentinel new password 3d77";
const HIDDEN_PASSWORD = "public sentinel hidden password 51aa";
const PASSPHRASE = "public sentinel passphrase 9b42";
/** The public BIP39 vector of entropy 7f…7f, 12 words, and as a person might type it. */
const PHRASE_12 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PHRASE_12_TYPED = PHRASE_12.toUpperCase().split(" ").join("  ");
/** The public phrase of scripts/verify-browser-package.mjs and its container at the reduced cost. */
const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ABANDON_TYPED = ABANDON.toUpperCase().split(" ").join("  ");
const ABANDON_PASSWORD = "public test password";
const REDUCED_CONTAINER =
  "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet";
const KNOWN_ANSWER_COSTS = ["1024/1", "65536/3", "262144/2"];
const REDUCED_MEMORY_KIB = 256;
const REDUCED_PASSES = 1;

function fresh() {
  const bindings = new Function(`${glue}\nreturn mhfe;`)();
  const { memory } = bindings.initSync({ module });
  return { bindings, memory };
}

const xor36 = (text) => Buffer.from(encode(text).map((byte) => byte ^ 0x36));

const random = { fill: (bytes) => globalThis.crypto.getRandomValues(bytes) };

async function reducedArgon2() {
  const engine = argon2Engine(await createArgon2St());
  return {
    derive(password, salt, memoryKib, passes, key) {
      if (KNOWN_ANSWER_COSTS.includes(`${memoryKib}/${passes}`)) {
        engine.derive(password, salt, memoryKib, passes, key);
      } else {
        engine.derive(password, salt, REDUCED_MEMORY_KIB, REDUCED_PASSES, key);
      }
    },
    reserve() {},
  };
}

const results = [];
/**
 * Runs `call(bindings)` on a fresh instance and compares the copies of each needle before and
 * after: `needles` maps a label to [claim, bytes or text], claim "W1".."W3" (must leave none) or
 * "info".
 */
async function measure(name, needles, call) {
  const { bindings, memory } = fresh();
  let outcome;
  // Copies of the fixed needles already in a fresh instance, such as a public vector's text in the
  // module's data, are not left by the call.
  const before = Object.fromEntries(
    Object.entries(needles).map(([label, [, needle]]) => [
      label,
      typeof needle === "function" ? null : positions(memory, needle),
    ]),
  );
  try {
    outcome = await call(bindings);
  } catch (error) {
    outcome = `threw ${String(error.message ?? error).split(":")[0]}`;
  }
  for (const [label, [claim, needle]] of Object.entries(needles)) {
    if (typeof needle === "function" && typeof outcome === "string" && outcome.startsWith("threw")) {
      results.push({ name, label, claim, left: 0, failed: true });
      console.log(`FAIL ${claim} ${name}: ${label}: the call ${outcome}`);
      continue;
    }
    const text = typeof needle === "function" ? needle(outcome) : needle;
    // A result's text is known only now; a fresh, untouched instance tells where it lies already.
    const already = before[label] ?? positions(fresh().memory, text);
    const left = positions(memory, text).filter((at) => !already.includes(at));
    // A copy that follows "mnemonic" is the first block of BIP39's PBKDF2 salt inside the bip39
    // crate's hash engine: a dependency's working buffer, outside the crate's own claim.
    const inDependency = left.filter((at) => precededBy(memory, at, "mnemonic"));
    const own = left.length - inDependency.length;
    const failed = claim !== "info" && own > 0;
    results.push({ name, label, claim, left: own, failed });
    console.log(
      `${failed ? "FAIL" : claim === "info" ? "info" : "pass"} ${claim} ${name}: ${label}: ` +
        `${own} cop${own === 1 ? "y" : "ies"} left` +
        (inDependency.length > 0
          ? `, ${inDependency.length} more in bip39's PBKDF2 salt block (dependency)`
          : ""),
    );
  }
}

function positions(memory, needle) {
  const bytes = Buffer.from(memory.buffer);
  const pattern = Buffer.from(needle);
  const found = [];
  for (let at = bytes.indexOf(pattern); at !== -1; at = bytes.indexOf(pattern, at + 1)) found.push(at);
  return found;
}

function precededBy(memory, at, prefix) {
  const bytes = Buffer.from(memory.buffer);
  return at >= prefix.length && bytes.subarray(at - prefix.length, at).toString("latin1") === prefix;
}

// W1: passwords and passphrases as bytes.
await measure("checkPassword, accepted", { password: ["W1", PASSWORD] }, (m) =>
  m.checkPassword(encode(PASSWORD)),
);
await measure("checkPassword, refused (control character)", { password: ["W1", "public sentinel"] }, (m) =>
  m.checkPassword(encode("public sentinel\u0007")),
);
await measure("reviewPassword, repetition differs", { password: ["W1", PASSWORD] }, (m) =>
  m.reviewPassword(encode(PASSWORD), encode(`${PASSWORD}x`), true),
);
await measure("passwordStrength", { password: ["W1", PASSWORD] }, (m) =>
  m.passwordStrength(encode(PASSWORD), "", 0),
);
await measure(
  "walletFingerprint, phrase as text",
  {
    passphrase: ["W1", PASSPHRASE],
    "phrase as typed": ["W3", PHRASE_12_TYPED],
    "phrase written out": ["W3", PHRASE_12],
    "phrase XOR 0x36 (HMAC key block in bip39)": ["info", xor36(PHRASE_12)],
  },
  (m) => m.walletFingerprint(PHRASE_12_TYPED, encode(PASSPHRASE)),
);
await measure("walletCheck, 24-word phrase", { passphrase: ["W1", PASSPHRASE] }, (m) =>
  m.walletCheck(REDUCED_CONTAINER, encode(PASSPHRASE)),
);

// W2: secret results.
await measure(
  "describePhrase",
  { "phrase as typed": ["W3", PHRASE_12_TYPED], "phrase written out (result)": ["W2", PHRASE_12] },
  (m) => m.describePhrase(PHRASE_12_TYPED),
);
await measure(
  "makePassword characters",
  { "returned password": ["W2", (made) => JSON.parse(made).password] },
  (m) => String(m.makePassword("characters", 24, new Uint8Array(), random)),
);
await measure(
  "makePassword checkWord from dice",
  { "returned password": ["W2", (made) => JSON.parse(made).password] },
  (m) =>
    String(m.makePassword("checkWord", undefined, encode("35214 62431 15543 44126 21365"), random)),
);
await measure(
  "drawPhrase without check",
  {
    passphrase: ["W1", PASSPHRASE],
    "returned phrase": ["W2", (drawn) => JSON.parse(drawn).phrase],
  },
  (m) => String(m.drawPhrase(encode(PASSPHRASE), false, random, () => {})),
);

// Argon2 operations at a reduced round cost.
await measure(
  "encrypt",
  {
    password: ["W1", ABANDON_PASSWORD],
    "phrase as typed": ["W3", ABANDON_TYPED],
    "phrase written out": ["W3", ABANDON],
  },
  async (m) => {
    const argon2 = await reducedArgon2();
    const made = JSON.parse(
      m.encrypt(ABANDON_TYPED, encode(ABANDON_PASSWORD), encode(ABANDON_PASSWORD), "", 0, 0, 0,
        false, 0, false, argon2, () => {}, () => {}),
    );
    if (made.container !== REDUCED_CONTAINER) throw new Error("PROBE: another container");
    return made;
  },
);
await measure(
  "decrypt",
  { password: ["W1", ABANDON_PASSWORD], "recovered phrase (result)": ["W2", ABANDON] },
  async (m) => {
    const argon2 = await reducedArgon2();
    const recovered = JSON.parse(
      String(m.decrypt(REDUCED_CONTAINER, encode(ABANDON_PASSWORD), "", 0, 0, 0, 0, argon2, () => {})),
    );
    if (recovered.candidates[0].phrase !== ABANDON) throw new Error("PROBE: another phrase");
    return recovered;
  },
);
await measure(
  "hidden wallet session, after free()",
  {
    "main passphrase": ["W1", PASSPHRASE],
    "hidden password": ["W1", HIDDEN_PASSWORD],
    "opened wallet (result)": ["W2", (wallet) => wallet.phrase],
  },
  async (m) => {
    const argon2 = await reducedArgon2();
    const session = new m.HiddenWalletSession(REDUCED_CONTAINER, 0, 0, encode(PASSPHRASE), argon2);
    const wallet = JSON.parse(
      String(session.open(encode(HIDDEN_PASSWORD), encode(HIDDEN_PASSWORD), "", 0, () => {})),
    );
    session.free();
    return wallet;
  },
);
await measure(
  "rekey session with owner confirmation, after free()",
  {
    "old password": ["W1", ABANDON_PASSWORD],
    "new password": ["W1", NEW_PASSWORD],
    "recovered phrase": ["W2", ABANDON],
  },
  async (m) => {
    const argon2 = await reducedArgon2();
    const session = new m.RekeySession(REDUCED_CONTAINER, 12, encode(ABANDON_PASSWORD), "", 0, 0,
      0, true, argon2);
    session.setNew(encode(NEW_PASSWORD), encode(NEW_PASSWORD), "", 0, 0, 0, 0);
    const recovered = JSON.parse(
      String(session.recover("builtInCheck", "", "", "", new Uint8Array(), false, () => {})),
    );
    const sealed = JSON.parse(session.seal(() => {}, () => {}));
    session.free();
    return { recovered, sealed };
  },
);

const failed = results.filter((result) => result.failed);
const claims = [...new Set(failed.map((result) => result.claim))].sort();
console.log(
  `${results.length} measurements; ${failed.length} with a copy left${
    claims.length > 0 ? ` (claims ${claims.join(", ")})` : ""
  }.`,
);
process.exit(failed.length > 0 ? 1 : 0);
