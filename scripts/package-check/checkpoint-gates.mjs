// Completed failures outlive interrupted checks; ordinary operational failures remain retryable.
import assert from "node:assert/strict";

const FAILED = {
  id: "synthetic-known-answer",
  label: "Synthetic known answer",
  outcome: "failed",
  detail: "the public synthetic answer differs",
};
const TRANSPORT = Object.assign(new Error("synthetic worker stopped"), { code: "WORKER_FAILED" });
const PASSED = { ...FAILED, outcome: "passed" };
const answer = (components = [PASSED], tier = "full", ids = [PASSED.id]) => ({
  version: "synthetic",
  tier,
  passed: components.every(({ outcome }) => outcome !== "failed"),
  ids,
  components,
});
const startupAnswer = (skip) => answer(skip.includes(PASSED.id) ? [] : [PASSED], "startup");
const stop = async () => {
  throw TRANSPORT;
};

/** A fresh check owner over exactly the compiled code supplied by a boundary control. */
function checkOwner({ PackageCheck, BUILD_ID }, wasm) {
  return new PackageCheck({
    wasm,
    classFile: "synthetic-check",
    classBuildId: BUILD_ID,
    secrets: false,
  });
}

/** Independent minimal compiled code gives these controls an initially empty pass cache. */
async function freshGates(runtime) {
  const compiled = await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
  return () => checkOwner(runtime, { source: compiled, get: async () => compiled });
}

/** Check the real PackageCheck owner with finite synthetic worker-boundary outcomes. */
export async function checkCheckpointGates(runtime) {
  const make = await freshGates(runtime);
  const closed = async (gate) => {
    let retried = false;
    await assert.rejects(
      gate.require(() => {
        retried = true;
        return gate.startup("default", async (skip) => startupAnswer(skip));
      }),
      (error) => {
        assert.equal(error.code, "SELF_CHECK_FAILED");
        assert.ok(error.report.components.some(({ outcome }) => outcome === "failed"));
        return true;
      },
    );
    assert.equal(retried, false, "a completed failure closes before a retry");
  };
  for (const streamed of [false, true]) {
    const gate = make();
    await assert.rejects(
      gate.full([
        {
          run: async (_skip, handlers) => {
            if (streamed) await handlers.component(FAILED);
            return answer([FAILED]);
          },
        },
        { run: stop },
      ]),
      { code: "WORKER_FAILED" },
    );
    await closed(gate);
  }
  await checkInterruptedCallbacks(make, closed);
  const inconsistent = make();
  const report = await inconsistent.full([
    {
      run: async (_skip, handlers) => {
        await handlers.component(FAILED);
        return answer([], "full");
      },
    },
  ]);
  assert.equal(report.passed, false, "final omission cannot erase a completed failure");
  await closed(inconsistent);
  for (const outcome of ["passed", "warning", "notAvailable", "notRun"]) {
    const retryable = make();
    await assert.rejects(
      retryable.full([
        {
          run: async (_skip, handlers) => {
            const component = { ...FAILED, outcome };
            await handlers.component(component);
            return answer([component]);
          },
        },
        { run: stop },
      ]),
      { code: "WORKER_FAILED" },
    );
    await retryable.require(() => retryable.startup("retry", async (skip) => startupAnswer(skip)));
  }
  const earlyCallback = make();
  await assert.rejects(
    earlyCallback.full([], () => {
      throw TRANSPORT;
    }),
    {
      code: "CALLBACK_FAILED",
    },
  );
  await earlyCallback.require(() =>
    earlyCallback.startup("retry", async (skip) => startupAnswer(skip)),
  );
  await checkConcurrentFailure(make, closed);
  await checkImmutableCache(runtime);
  await checkFinalCompleteness(runtime);
}

/** Streamed identities and captured skips cannot be excused by later shared cache updates. */
async function checkFinalCompleteness(runtime) {
  const make = await freshGates(runtime);
  for (const streamed of [[PASSED, PASSED], [{ ...PASSED, id: "undeclared" }]]) {
    await assert.rejects(
      make().full([
        {
          run: async (_skip, handlers) => {
            for (const component of streamed) await handlers.component(component);
            return answer();
          },
        },
      ]),
      { code: "PACKAGE_MISMATCH" },
    );
  }
  let release;
  let began;
  const running = new Promise((resolve) => {
    began = resolve;
  });
  const first = make().startup("waiting", async (skip) => {
    assert.deepEqual(skip, []);
    began();
    return new Promise((resolve) => {
      release = () => resolve(answer([], "startup"));
    });
  });
  const refused = assert.rejects(first, { code: "PACKAGE_MISMATCH" });
  await running;
  try {
    assert.equal((await make().startup("other", async (skip) => startupAnswer(skip))).passed, true);
  } finally {
    release();
  }
  await refused;
  await assert.rejects(
    make().startup("repeated", async (skip) => {
      assert.deepEqual(skip, [PASSED.id]);
      return answer(undefined, "startup");
    }),
    { code: "PACKAGE_MISMATCH" },
  );
}

/** A late successful check cannot clear a failure that another check completed first. */
async function checkConcurrentFailure(make, closed) {
  const gate = make();
  let resume;
  let started;
  const running = new Promise((resolve) => {
    started = resolve;
  });
  const pending = gate.full([
    {
      run: async () => {
        started();
        return new Promise((resolve) => {
          resume = () => resolve(answer());
        });
      },
    },
  ]);
  await running;
  await assert.rejects(
    gate.full([
      {
        run: async (_skip, handlers) => {
          await handlers.component(FAILED);
          return answer([FAILED]);
        },
      },
      { run: stop },
    ]),
    { code: "WORKER_FAILED" },
  );
  resume();
  assert.equal((await pending).passed, true, "the independent run itself completed normally");
  await closed(gate);
}

/** Failures from page-owned steps and streamed worker results latch before notifying a callback. */
async function checkInterruptedCallbacks(make, closed) {
  for (const streamed of [false, true]) {
    const gate = make();
    const steps = streamed
      ? [
          {
            run: async (_skip, handlers) => {
              await handlers.component(FAILED);
              return answer([FAILED]);
            },
          },
        ]
      : [{ components: [FAILED] }];
    await assert.rejects(
      gate.full(steps, ({ outcome }) => {
        if (outcome === "failed") throw TRANSPORT;
      }),
    );
    await closed(gate);
  }
}

/** Only classes receiving the same compiled module may inherit its successful component. */
async function checkImmutableCache(runtime) {
  const { CompiledModule } = runtime;
  // A valid module with one arbitrary custom-section byte: changing it gives a distinct module.
  const bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 0, 0]);
  const firstOwner = new CompiledModule(bytes, "synthetic");
  const firstModule = await firstOwner.get();
  const make = (wasm) => checkOwner(runtime, wasm);
  const passed = { ...FAILED, outcome: "passed" };
  await make(firstOwner).startup("initial", async (skip) => {
    assert.deepEqual(skip, []);
    return answer([passed], "startup");
  });
  bytes[bytes.length - 1] = 1;
  for (const source of [bytes, bytes.slice()]) {
    await make(new CompiledModule(source, "synthetic")).startup("new-code", async (skip) => {
      assert.deepEqual(skip, [], "newly compiled code inherits no prior result");
      return answer([passed], "startup");
    });
  }
  await make(new CompiledModule(firstModule, "synthetic")).startup("shared", async (skip) => {
    assert.deepEqual(skip, [passed.id], "one immutable module retains cross-class sharing");
    return answer([], "startup", [passed.id]);
  });
  assert.equal(await firstOwner.get(), firstModule, "existing owner keeps its compiled code");
  const inconsistentModule = await WebAssembly.compile(bytes);
  const inconsistent = make(new CompiledModule(inconsistentModule, "synthetic"));
  const report = await inconsistent.startup("contradictory", async (_skip, handlers) => {
    await handlers.component(FAILED);
    return answer([passed], "startup");
  });
  assert.equal(report.passed, false);
  await make(new CompiledModule(inconsistentModule, "synthetic")).startup(
    "independent",
    async (skip) => {
      assert.deepEqual(skip, [], "a contradictory success cannot seed another class's cache");
      return answer([passed], "startup");
    },
  );
}
