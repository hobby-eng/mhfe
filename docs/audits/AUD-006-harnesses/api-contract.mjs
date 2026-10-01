// Public metadata methods require no worker, KDF, or private inputs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const root = new URL('../../../', import.meta.url);
const source = readFileSync(new URL('web/client.js', root), 'utf8');
const { MhfeClient } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const client = new MhfeClient({ workerSource: 'fixture', argon2Threaded: 'fixture', argon2SingleThreaded: 'fixture', coreWasm: new Uint8Array([0]) });
const values = { mode: client.mode(), maxSupportedMemLevel: client.maxSupportedMemLevel(), cancel: client.cancel() };
for (const [name, value] of Object.entries(values)) console.log(name, typeof value, String(value), 'Promise:', value instanceof Promise);
for (const file of ['API.md', 'web/README.md']) {
  const docs = readFileSync(new URL(file, root), 'utf8');
  assert.ok(!docs.includes('Every method returns a promise') || Object.values(values).every(value => value instanceof Promise),
    `${file}: the unconditional Promise claim contradicts the three synchronous public methods`);
}
