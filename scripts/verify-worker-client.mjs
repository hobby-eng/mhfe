import { MhfeWorkerClient } from '../dist/client.js';

class FakeWorker {
  #listeners = new Map();

  addEventListener(type, listener) {
    this.#listeners.set(type, listener);
  }

  postMessage() {}

  terminate() {}
}

let unhandled = null;
const onUnhandled = (reason) => {
  unhandled = reason;
};
process.once('unhandledRejection', onUnhandled);

const cancelledBeforeReady = new MhfeWorkerClient(new FakeWorker(), new Uint8Array([0]));
cancelledBeforeReady.cancel();
await new Promise((resolve) => setImmediate(resolve));
process.removeListener('unhandledRejection', onUnhandled);
if (unhandled !== null) throw unhandled;

const bounded = new MhfeWorkerClient(new FakeWorker(), new Uint8Array([0]));
for (const pim of [32, 2 ** 32, 2 ** 32 + 31, -1, 0.5, Number.NaN]) {
  try {
    bounded.encryptAscii('unused', 'unused', pim);
    throw new Error(`Worker client accepted invalid PIM ${String(pim)}.`);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
  }
}
bounded.cancel();

console.log('Verified Worker-client PIM bounds and cancellation before readiness.');
