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
import assert from "node:assert/strict";

import { checkArgon2Faults, checkSelfTestFaults } from "./argon2-faults.mjs";
import { checkOptionContainers, checkWishListBoundaries } from "./argument-boundaries.mjs";
import { checkClassSelfChecks } from "./class-self-checks.mjs";
import { checkCheckpointGates } from "./checkpoint-gates.mjs";
import { checkCoreClient } from "./core-client.mjs";
import {
  checkCoreThroughBuild,
  checkFullSizeEncryption,
  checkPackageFacts,
} from "./core-operations.mjs";
import { checkWorkerInProcess } from "./in-process-worker.mjs";
import { checkPageProtocol } from "./protocol-values.mjs";
import { checkSecretOwners } from "./secret-owners.mjs";
import { checkErrorCodes, checkPackageManifest } from "./manifest.mjs";
import {
  checkLibraryMessages,
  checkPasswordsModule,
  checkRandomSourceProbes,
  checkRepairModule,
  checkWalletModule,
} from "./module-bindings.mjs";
import { checkModuleClasses } from "./module-classes.mjs";
import { builds, parameters } from "./package.mjs";
import { checkClientLimits, loadClasses, wasm } from "./page-classes.mjs";
import { checkPhraseWipes } from "./phrase-wipes.mjs";
import { checkRawPreflight } from "./preflight.mjs";
import { checkInputText, checkInputTextClients } from "./input-text.mjs";
import { checkUtilityClassBoundaries } from "./utility-input-boundaries.mjs";
import { checkStartupReportBoundaries } from "./startup-report-boundaries.mjs";
import {
  checkNumericRefusals,
  checkPageProgress,
  checkReferenceRefusals,
} from "./refusal-contracts.mjs";
import { checkModuleSelfChecks } from "./self-checks.mjs";
import { installStandInWorker } from "./stand-in-worker.mjs";

/** Runs the Node package checks; full adds one full-size encryption. */
export async function checkBrowserPackage(full) {
  // Part 1: the core module and the Argon2 bridge.
  checkPackageFacts();
  checkRawPreflight();
  for (const [name, createModule] of Object.entries(builds)) {
    await checkCoreThroughBuild(name, createModule);
  }
  if (full) await checkFullSizeEncryption();
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
  await checkInputText(classes.runtime, parameters.maxInputTextBytes);
  checkProtocolReports(classes.runtime);
  await checkSecretOwners(classes.runtime);
  checkClientLimits();
  installStandInWorker();
  await checkStartupReportBoundaries(classes);
  await checkOptionContainers(classes);
  await checkWishListBoundaries(classes);
  await checkInputTextClients(classes);
  await checkUtilityClassBoundaries(classes);
  await checkCheckpointGates(classes.runtime);
  await checkPageProtocol(classes.runtime);
  const client = await checkCoreClient(classes, libraryMessages);
  const walletClient = await checkModuleClasses(classes, client, libraryMessages);
  await checkReferenceRefusals(client);
  await checkNumericRefusals(
    walletClient,
    new classes.MhfePasswords({ workerSource: "passwords worker", wasm }),
    client,
  );
  await checkPageProgress(classes);

  // Part 4b: the self-checks of the classes.
  await checkClassSelfChecks({
    classes,
    client,
    walletClient,
    damagedBindings,
    otherBuildId,
    workerRefusals,
  });
}

/** Self-check protocol readers reject null/partial payloads before page code uses their fields. */
function checkProtocolReports(runtime) {
  for (const value of [
    null,
    3,
    {},
    { version: 3, components: [] },
    { version: "synthetic", components: null },
    { version: "synthetic", components: [], ids: [3] },
    { version: "synthetic", components: [{ id: "part", outcome: "passed" }] },
    { version: "synthetic", components: [{ id: "part", label: "Part", outcome: "unknown" }] },
  ]) {
    assert.throws(() => runtime.readSetReport(value), { code: "PACKAGE_MISMATCH" });
  }
  const good = {
    version: "synthetic",
    tier: "startup",
    passed: true,
    ids: ["part"],
    components: [{ id: "part", label: "Part", outcome: "passed" }],
  };
  assert.deepEqual(runtime.readSetReport(good), good);
  for (const value of [
    { ...good, tier: undefined },
    { ...good, tier: "other" },
    { ...good, passed: undefined },
    { ...good, ids: [] },
    { ...good, ids: ["part", "part"] },
    { ...good, ids: [""] },
    { ...good, ids: ["another"] },
    { ...good, components: [...good.components, ...good.components] },
    { version: null, components: [] },
  ]) {
    assert.throws(() => runtime.readSetReport(value), { code: "PACKAGE_MISMATCH" });
  }
}
