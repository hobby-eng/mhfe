// Characterize async callback handling; this is a documented-scope recommendation, not a KDF test.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const source = readFileSync(new URL('../../../web/client.js', import.meta.url), 'utf8');
const { MhfeClient } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const unhandled = [];
process.on('unhandledRejection', error => unhandled.push(error.message));
class StandInWorker {
  static last;
  constructor() { StandInWorker.last = this; }
  postMessage() { queueMicrotask(() => this.onmessage({ data: { type: 'progress', round: 1, rounds: 12 } })); }
  terminate() { this.terminated = true; }
}
globalThis.Worker = StandInWorker;
const client = new MhfeClient({ workerSource: 'public fixture', argon2Threaded: 'fixture', argon2SingleThreaded: 'fixture', coreWasm: new Uint8Array([0]) });
const pending = client.decrypt({ container: 'public fixture', password: 'public password', onProgress: async () => { throw new Error('synthetic async failure'); } });
await new Promise(resolve => setTimeout(resolve, 20));
assert.deepEqual(unhandled, ['synthetic async failure']);
assert.notEqual(StandInWorker.last.terminated, true);
StandInWorker.last.onmessage({ data: { type: 'result', result: { completed: true } } });
assert.deepEqual(await pending, { completed: true });
console.log('Async callback rejection is unobserved by the client; the operation still resolves. Synchronous throws are covered separately.');
