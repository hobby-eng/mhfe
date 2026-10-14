// AUD-024 browser-isolation check: a page callback that fails after its operation has ended is not
// swallowed. For news such as onProgress, WorkerJob.callPage lets the page's rejection stay
// unhandled once the job has ended (web/runtime.js); the same must hold for the callbacks that
// answer a question of the worker, such as a rekey's owner callback (WorkerJob.#answer). Both cases
// cancel() the operation from inside the callback and then fail. Exits 1 when the owner callback's
// failure disappears, or when the onProgress control does not reach unhandledrejection.
// Reduced-cost Argon2 (in-process-worker.mjs); public test data only.
import { MhfeClient, PASSWORD, REDUCED_COST_CONTAINER, outcome, sources } from "./in-process-worker.mjs";

const unhandled = [];
process.on("unhandledRejection", (reason) => unhandled.push(String(reason?.message ?? reason)));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let failed = false;

// Control: onProgress fails after cancel().
{
  const client = new MhfeClient(sources());
  let cancelled = false;
  const result = await outcome(
    client.decrypt({
      container: REDUCED_COST_CONTAINER,
      password: PASSWORD,
      onProgress: async () => {
        if (cancelled) return;
        cancelled = true;
        client.cancel();
        await sleep(10);
        throw new Error("onProgress failed after cancel()");
      },
    }),
  );
  await sleep(100);
  const ok = unhandled.includes("onProgress failed after cancel()");
  if (!ok) failed = true;
  console.log(`${ok ? "ok  " : "FAIL"} control: onProgress failing after cancel() is not swallowed`);
  console.log(`     ${result}; unhandled rejections: ${JSON.stringify(unhandled)}`);
}
unhandled.length = 0;
// The case: the owner callback of a rekey fails after cancel().
{
  const client = new MhfeClient(sources());
  const result = await outcome(
    client.rekey({
      container: REDUCED_COST_CONTAINER,
      words: 12,
      password: PASSWORD,
      newPassword: "AUD024 harness new password",
      newPasswordRepeat: "AUD024 harness new password",
      walletHasPassphrase: false,
      confirmation: {
        owner: async () => {
          client.cancel();
          await sleep(10);
          throw new Error("owner callback failed after cancel()");
        },
      },
    }),
  );
  await sleep(100);
  const ok = unhandled.some((message) => message.includes("owner callback failed after cancel()"));
  if (!ok) failed = true;
  console.log(`${ok ? "ok  " : "FAIL"} the owner callback failing after cancel() is not swallowed`);
  console.log(`     ${result}; unhandled rejections: ${JSON.stringify(unhandled)}`);
}
process.exit(failed ? 1 : 0);
