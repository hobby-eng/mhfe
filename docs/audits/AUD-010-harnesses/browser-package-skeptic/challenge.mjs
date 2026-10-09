// AUD-010 skeptic probe: an independent reproduction of the browser-package reviewer's findings,
// written without that reviewer's helpers. Each check states the behaviour the documentation
// promises, so a failing check reproduces a finding. Synthetic secrets only; no Argon2, no worker
// thread. Exits non-zero when a check fails.
//
//   node docs/audits/AUD-010-harnesses/browser-package-skeptic/challenge.mjs
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = new URL("../../../../", import.meta.url);
let failed = 0;
let passed = 0;
function check(condition, label, detail = "") {
  if (condition) passed += 1;
  else failed += 1;
  console.log(
    `${condition ? "ok  " : "FAIL"} ${label}${condition || !detail ? "" : ` -- ${detail}`}`,
  );
}
const note = (text) => console.log(`note ${text}`);
const source = (path) => readFileSync(new URL(path, root), "utf8");
// web/runtime.js has no imports; the repository has no "type": "module", so load it as a data URL.
const runtime = await import(
  `data:text/javascript;base64,${Buffer.from(source("web/runtime.js")).toString("base64")}`
);
const synthetic = () => new TextEncoder().encode("synthetic-test");

// 1. The worker's operation lookup (web/worker-runtime.js serveOperations).
{
  console.log("# 1 worker operation lookup");
  const posts = [];
  const context = vm.createContext({
    self: { postMessage: (message) => posts.push(message), crypto: globalThis.crypto },
    WebAssembly,
    TextDecoder,
  });
  vm.runInContext(source("web/worker-runtime.js"), context);
  const bindings = { initSync() {}, packageVersion: () => "probe" };
  context.serveOperations(bindings, {
    core: { ping: () => "pong" },
    repair: { ping: () => "pong" },
  });
  // The smallest valid module: no build section, which an unstamped worker ("development") accepts.
  const compiled = new WebAssembly.Module(new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
  const send = async (fields) => {
    posts.length = 0;
    await context.self.onmessage({ data: { compiled, ...fields } });
    return posts.filter(({ type }) => type === "result" || type === "error").at(-1);
  };
  const served = await send({ module: "core", operation: "ping" });
  check(served?.result === "pong", "a listed operation is served");
  const unknown = await send({ module: "core", operation: "nothing" });
  check(unknown?.error?.code === "INVALID_REQUEST", "an unknown operation is refused");
  for (const [module, operation] of [
    ["core", "constructor"],
    ["repair", "toString"],
    ["__proto__", "constructor"],
    ["constructor", "keys"],
    ["constructor", "assign"],
  ]) {
    const password = synthetic();
    const answer = await send({ module, operation, password });
    const echoed = answer?.result?.password instanceof Uint8Array;
    check(
      answer?.type === "error" && answer.error.code === "INVALID_REQUEST",
      `the inherited name ${module}.${operation} is refused with INVALID_REQUEST`,
      `answer ${answer?.type}${echoed ? ", echoing the request with its password field" : ""}`,
    );
  }
  // Function as an operation: its body would be String(host), so it cannot compile.
  const viaFunction = await send({ module: "constructor", operation: "constructor" });
  note(
    `constructor.constructor (Function) answers ${viaFunction?.type} ${viaFunction?.error?.code}`,
  );
  // The Worker object is a private field of WorkerJob: only page code that replaces Worker reaches it.
  note(`WorkerJob keeps its worker private: ${/#worker\b/u.test(source("web/runtime.js"))}`);
}

// 2. encodeSecret with a Uint8Array subclass whose slice() returns a view.
{
  console.log("# 2 encodeSecret copies");
  class ViewSlicing extends Uint8Array {
    // As the 'buffer' npm polyfill and Node's Buffer do: slice() shares the caller's memory.
    slice(start, end) {
      return this.subarray(start, end);
    }
  }
  const plain = synthetic();
  check(
    runtime.encodeSecret(plain, "password", false).buffer !== plain.buffer,
    "a plain Uint8Array is copied",
  );
  for (const [label, make] of [
    ["Node's Buffer", () => Buffer.from("synthetic-test")],
    ["a view-slicing subclass", () => new ViewSlicing(synthetic())],
  ]) {
    const caller = make();
    const copy = runtime.encodeSecret(caller, "password", false);
    check(copy.buffer !== caller.buffer, `${label} is copied into a buffer of its own`);
    const request = { password: copy };
    const transfer = runtime.secretBuffers(request);
    note(`${label}: the transfer list holds an ArrayBuffer of ${transfer[0].byteLength} bytes`);
    let transferred = "transferred";
    try {
      structuredClone(request, { transfer });
    } catch (error) {
      // Node marks its Buffer pool as not transferable; WorkerJob.send then wipes the request.
      transferred = `${error.name}: ${error.message}`;
      runtime.wipeSecrets(request);
    }
    note(`${label}: the transfer gives ${transferred}`);
    // A detached array has length 0, and some() on it throws, so test the length first.
    const kept = caller.length === 14 && caller.some((byte) => byte !== 0);
    check(
      kept,
      `${label}: the caller's array keeps its length and bytes after the send`,
      caller.length === 14 ? "its bytes are all zero" : `its length is ${caller.length}`,
    );
    const refused = make();
    runtime.wipeSecrets({ password: runtime.encodeSecret(refused, "password", false) });
    check(
      refused.some((byte) => byte !== 0),
      `${label}: a refusal does not zero the caller's bytes`,
    );
    const twice = make();
    const pair = {
      password: runtime.encodeSecret(twice, "password", false),
      passwordRepeat: runtime.encodeSecret(twice, "repeated password", false),
    };
    let sent = "sent";
    try {
      structuredClone(pair, { transfer: runtime.secretBuffers(pair) });
    } catch (error) {
      sent = `${error.name}: ${error.message}`;
    }
    check(sent === "sent", `${label} given as password and repetition can be transferred`, sent);
  }
}

// 3. requireSamePassword (web/client.js) with values that are neither strings nor Uint8Arrays.
{
  console.log("# 3 requireSamePassword types");
  const client = source("web/client.js");
  const body = client.slice(
    client.indexOf("function requireSamePassword("),
    client.indexOf("/** The PIM and memory level"),
  );
  const requireSamePassword = new Function(
    "encodeSecret",
    "MhfeError",
    `${body}; return requireSamePassword;`,
  )(runtime.encodeSecret, runtime.MhfeError);
  for (const [label, first, second] of [
    ["Uint16Array twice", new Uint16Array([1]), new Uint16Array([1])],
    ["ArrayBuffer twice", new ArrayBuffer(2), new ArrayBuffer(2)],
    ["the number 5 twice", 5, 5],
    ["a missing password and a string repetition", undefined, "synthetic-test"],
  ]) {
    let outcome = "accepted";
    try {
      requireSamePassword(first, second);
    } catch (error) {
      outcome =
        error instanceof TypeError ? "TypeError" : `${error.constructor.name} ${error.code}`;
    }
    check(outcome === "TypeError", `encrypt's password check: ${label} is a TypeError`, outcome);
  }
}

// 4. makePassword "checkWord" and count (src/wasm_api/passwords.rs).
{
  console.log("# 4 checkWord count");
  const rust = source("src/wasm_api/passwords.rs");
  const ignores = /"checkWord" => Ok\(PasswordRecipe::check_word\(\)\)/u.test(rust);
  check(
    !ignores,
    'make_password refuses a count given with "checkWord"',
    'the "checkWord" arm never reads count',
  );
  note(
    `the binding's own comment says count is ignored for "checkWord": ${rust.includes('(ignored for "checkWord")')}`,
  );
  const passwords = source("web/passwords.js");
  note(
    `MhfePasswords.make checks count only as a whole number: ${/count !== undefined && !Number.isSafeInteger\(count\)/u.test(passwords)}`,
  );
}

// 5. PACKAGE_MISMATCH text from the worker, as WorkerJob shows it.
{
  console.log("# 5 PACKAGE_MISMATCH spelling");
  const workerText = "runtime/mhfe.wasm is of build development and runtime/worker.js of build x";
  const shown = runtime.sentence(workerText);
  check(
    shown.startsWith("runtime/"),
    "the worker's PACKAGE_MISMATCH keeps the path runtime/",
    shown,
  );
  check(
    runtime.sentence("core/argon2-st.js is of build y").startsWith("core/"),
    "the core worker's PACKAGE_MISMATCH keeps the path core/",
  );
}

console.log(`# ${passed} passed, ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
