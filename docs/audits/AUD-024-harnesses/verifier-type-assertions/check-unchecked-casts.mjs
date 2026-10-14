// AUD-024 verifier harness (review only): what the unproven type assertions of the browser package
// let through at b6fca69. It loads the package's classes as scripts/verify-browser-package.mjs
// does (dist/ of the same commit, with its stand-in Worker), and drives:
//
//   1. control: a rekey confirmed by the owner, whose worker asks "ownerCheck" (exit 2 if this
//      does not behave as the package check expects: the probe no longer fits the package);
//   2. a rekey confirmed by a fingerprint, and 3. by the built-in check, whose worker asks
//      "ownerCheck": the handler of web/client.js:767-769 casts `owner` (PageOwner | undefined) to
//      PageOwner and calls it. A question the page has no answer for is a fault of the package,
//      PACKAGE_MISMATCH (web/runtime.js:438-442); expected that here too;
//   4. a core self-check report without `parameters` (web/client.js:1086 casts the worker's result
//      to SetReport & { parameters }), and 5. a module's self-check result that is null
//      (web/runtime.js:1150 casts it to SetReport): expected an MhfeError, as every rejection of a
//      class is documented to be one, ideally PACKAGE_MISMATCH as for a core of other limits.
//
// No real worker, no Argon2 rounds, no secrets beyond the package check's own test strings.
// Exit 0 when every case gets the expected outcome, 1 when one does not, 2 when the control fails.
import { checkClientLimits, loadClasses, sources } from "../../../../scripts/package-check/page-classes.mjs";
import {
  StandInWorker,
  installStandInWorker,
  servedByTheWebAssembly,
  started,
} from "../../../../scripts/package-check/stand-in-worker.mjs";

const nextTurn = () => new Promise((resolve) => setTimeout(resolve, 0));
const shownToOwner = {
  phrase: "p", words: 12, fingerprintWithoutPassphrase: "00000000",
  rehearsalNeedsPassphrase: false,
};

const classes = await loadClasses();
checkClientLimits();
installStandInWorker();
const { MhfeClient, MhfeRepair, MhfeError } = classes;
const client = new MhfeClient(sources);

/** How a promise settled, as one line. */
async function outcome(promise) {
  try {
    return { line: `resolved ${JSON.stringify(await promise)}`, error: null };
  } catch (error) {
    const cause = error?.cause === undefined ? "" : `; cause ${error.cause?.name}: ${error.cause?.message}`;
    return {
      line: `rejected ${error?.name} ${error?.code ?? "(no code)"}: ${error?.message}${cause}`,
      error,
    };
  }
}

/** A rekey with `confirmation` whose stand-in worker asks "ownerCheck" and then gives a result. */
async function rekeyAskedOwner(confirmation, walletHasPassphrase) {
  const ownerCalls = [];
  const rekeying = client.rekey({
    container: "c",
    words: 15,
    password: "old",
    newPassword: "new",
    newPasswordRepeat: "new",
    confirmation:
      confirmation === "owner"
        ? { owner: (check) => ownerCalls.push(check) > 0 }
        : confirmation,
    walletHasPassphrase,
  });
  // Settled from the start, so that an early rejection is not an unhandled one.
  const settling = outcome(rekeying);
  const worker = await started();
  const kind = worker.messages[0].confirmKind;
  worker.reply({ type: "ask", question: "ownerCheck", value: shownToOwner });
  await nextTurn();
  await nextTurn();
  const answered = worker.messages.length > 1 ? JSON.stringify(worker.messages[1].type) : "nothing";
  if (!worker.terminated) worker.reply({ type: "result", result: { container: "n" } });
  const settled = await settling;
  return { kind, ownerCalls: ownerCalls.length, answered, terminated: worker.terminated, ...settled };
}

let failed = 0;
const report = (label, ok, line) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}: ${line}`);
  if (!ok) failed += 1;
};

// 1. Control.
const control = await rekeyAskedOwner("owner", true);
console.log(
  `control: confirmKind ${control.kind}; owner called ${control.ownerCalls} time(s); ` +
    `worker sent ${control.answered}; ${control.line}`,
);
if (control.kind !== "owner" || control.ownerCalls !== 1 || control.error !== null) {
  console.log("the control does not behave as the package check expects");
  process.exit(2);
}

// 2 and 3. A confirmation without an owner, whose worker asks the owner anyway.
for (const [label, confirmation] of [
  ["fingerprint confirmation, worker asks ownerCheck", { fingerprint: "00000000" }],
  ["built-in-check confirmation, worker asks ownerCheck", { builtInCheck: true }],
]) {
  const asked = await rekeyAskedOwner(confirmation, false);
  report(
    label,
    asked.error instanceof MhfeError && asked.error.code === "PACKAGE_MISMATCH",
    `confirmKind ${asked.kind}; worker sent ${asked.answered}; worker terminated ${asked.terminated}; ${asked.line}`,
  );
}

// 4. A core self-check report without `parameters`.
StandInWorker.serveCheck = (message, worker) => {
  const { parameters: _dropped, ...report } = servedByTheWebAssembly(message, worker);
  return report;
};
{
  const settled = await outcome(new MhfeClient({ ...sources, wasm: new Uint8Array(sources.wasm) }).startupCheck());
  report(
    "core self-check report without parameters",
    settled.error instanceof MhfeError,
    settled.line,
  );
}

// 5. A module's self-check result that is null.
StandInWorker.serveCheck = (message, worker) => {
  servedByTheWebAssembly(message, worker);
  return null;
};
{
  const settled = await outcome(
    new MhfeRepair({ workerSource: "repair worker", wasm: new Uint8Array(sources.wasm) }).startupCheck(),
  );
  report("module self-check result null", settled.error instanceof MhfeError, settled.line);
}
StandInWorker.serveCheck = servedByTheWebAssembly;

console.log(failed === 0 ? "every case as expected" : `${failed} case(s) not as expected`);
// The threaded Argon2 build that package.mjs loads may keep the process alive.
process.exit(failed === 0 ? 0 : 1);
