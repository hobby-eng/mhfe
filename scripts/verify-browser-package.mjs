// Checks the browser package in dist/ with Node.js. Build it first with scripts/build-wasm.sh.
//
//   node scripts/verify-browser-package.mjs          fast checks, a few seconds
//   node scripts/verify-browser-package.mjs --full   also one full-size encryption (2 GiB)
//
// Part 1 runs the core module of the package's WebAssembly and the real Argon2 bridge with both
// Emscripten builds. To stay fast it lowers the Argon2 cost in a test wrapper, which lets only the
// known answers of the Argon2 build through unchanged (1 MiB with one pass, before and after every
// operation, and 64 MiB with three passes and 256 MiB with two in the full self-check); the result
// must equal the container that the native engine gives at the same cost (REDUCED_COST_CONTAINER
// in src/mhfe.rs).
// It also gives the core Argon2 builds that fail their known answer, and the self-test the
// published round keys in place of Argon2 at full size, to check the fault it names. Part 2 runs
// the repair, passwords and wallet modules of the same WebAssembly with public vectors, then the
// self-check of every module at both tiers, with a WebAssembly whose vectors were damaged, and the
// package's worker.js in this process, with Argon2 builds that do not start or are of another
// build. Part 3 checks the package's manifest, versions and scripts, that its WebAssembly names no
// folder of the machine that built it, and its build against another one.
// Part 4 checks the page-side classes against a stand-in worker, whose self-checks run the real
// WebAssembly in this process. The real worker runs in a browser test
// (scripts/verify-browsers.mjs).
//
// The parts live in scripts/package-check/, one module per group of checks, and run here in this
// order; the package under test and the values they share are in package.mjs and test-values.mjs.
import { checkArgon2Faults, checkSelfTestFaults } from "./package-check/argon2-faults.mjs";
import { checkClassSelfChecks } from "./package-check/class-self-checks.mjs";
import { checkCoreClient } from "./package-check/core-client.mjs";
import {
  checkCoreThroughBuild,
  checkFullSizeEncryption,
  checkPackageFacts,
} from "./package-check/core-operations.mjs";
import { checkWorkerInProcess } from "./package-check/in-process-worker.mjs";
import { checkErrorCodes, checkPackageManifest } from "./package-check/manifest.mjs";
import {
  checkLibraryMessages,
  checkPasswordsModule,
  checkRandomSourceProbes,
  checkRepairModule,
  checkWalletModule,
} from "./package-check/module-bindings.mjs";
import { checkModuleClasses } from "./package-check/module-classes.mjs";
import { builds } from "./package-check/package.mjs";
import { checkClientLimits, loadClasses } from "./package-check/page-classes.mjs";
import { checkPhraseWipes } from "./package-check/phrase-wipes.mjs";
import { checkModuleSelfChecks } from "./package-check/self-checks.mjs";
import { installStandInWorker } from "./package-check/stand-in-worker.mjs";

// Part 1: the core module and the Argon2 bridge.
checkPackageFacts();
for (const [name, createModule] of Object.entries(builds)) {
  await checkCoreThroughBuild(name, createModule);
}
if (process.argv.includes("--full")) await checkFullSizeEncryption();
await checkArgon2Faults();
checkSelfTestFaults();

// Part 2: the modules without Argon2.
checkRepairModule();
checkPasswordsModule();
checkWalletModule();
const libraryMessages = await checkLibraryMessages();
checkPhraseWipes();
checkRandomSourceProbes();

// Part 2b: the self-check of each module, as its class runs it in a worker.
const damagedBindings = await checkModuleSelfChecks();

// Part 2c: the package's worker.js in this process, and the error codes of every part.
const workerRefusals = await checkWorkerInProcess();
checkErrorCodes();

// Part 3: the manifest, the versions, and no network code.
const otherBuildId = await checkPackageManifest();

// Part 4: the page-side classes, with a stand-in worker.
const classes = await loadClasses();
checkClientLimits();
installStandInWorker();
const client = await checkCoreClient(classes, libraryMessages);
const walletClient = await checkModuleClasses(classes, client, libraryMessages);

// Part 4b: the self-checks of the classes.
await checkClassSelfChecks({
  classes,
  client,
  walletClient,
  damagedBindings,
  otherBuildId,
  workerRefusals,
});

// The threaded build keeps its lane workers alive; end the process explicitly.
process.exit(0);
