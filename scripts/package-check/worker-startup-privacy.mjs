// The real worker's Argon2 factory boundary: unknown failures disclose no exception text, while
// a package mismatch stays fatal and never selects the fallback build.
import assert from "node:assert/strict";

import { BUILD_ID } from "./package.mjs";
import { part } from "./self-checks.mjs";

/** Exercises both synchronous throws and rejected promises through the worker's public requests. */
export async function checkArgon2StartupPrivacy(send) {
  const marker = "synthetic private factory marker";
  const singleFailure = "the single-threaded Argon2 build did not start";
  const ready = { type: "ready", buildId: BUILD_ID };
  const request = {
    module: "core",
    operation: "selfCheck",
    tier: "startup",
    skip: [],
    argon2: true,
  };
  const unreadable = new Error();
  Object.defineProperty(unreadable, "message", {
    get() {
      throw new Error(marker);
    },
  });
  for (const create of [
    () => Promise.reject(new Error(marker)),
    () => {
      throw new Error(marker);
    },
    () => Promise.reject(unreadable),
  ]) {
    const globals = { createArgon2St: create, ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID };
    const posted = await send(globals, request);
    assert.deepEqual(posted[0], ready);
    assert.equal(posted.at(-1).type, "result");
    const report = posted.at(-1).result;
    assert.equal(report.passed, true);
    assert.deepEqual(
      report.components.filter(({ id }) => id === "argon2"),
      [part("argon2", "notAvailable", `Argon2id could not run: ${singleFailure}`)],
    );
    assert.equal(JSON.stringify(posted).includes(marker), false);
    assert.deepEqual(await send(globals, { module: "core", operation: "selfTest" }), [
      ready,
      { type: "error", error: { code: "INTERNAL_ERROR", message: singleFailure } },
    ]);
  }
  let fallbackCalls = 0;
  const globals = {
    ARGON2_THREADED_BUILD_ID: BUILD_ID,
    ARGON2_SINGLE_THREADED_BUILD_ID: BUILD_ID,
    createArgon2Mt: () => Promise.reject(new Error(`PACKAGE_MISMATCH: ${marker}`)),
    createArgon2St: () => {
      fallbackCalls += 1;
      throw new Error(marker);
    },
  };
  for (const operation of [request, { module: "core", operation: "selfTest" }]) {
    assert.deepEqual(await send(globals, operation), [
      ready,
      {
        type: "error",
        error: {
          code: "PACKAGE_MISMATCH",
          message:
            "the Argon2 build reported a package mismatch: take every file of the package from one build.",
        },
      },
    ]);
  }
  assert.equal(fallbackCalls, 0, "a package mismatch never falls back to another build");
}
