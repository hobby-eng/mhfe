import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { MhfeEngine, initSync, suiteParametersJson } from '../dist/wasm/mhfe.js';

const wasmPath = fileURLToPath(new URL('../dist/wasm/mhfe_bg.wasm', import.meta.url));
initSync({ module: readFileSync(wasmPath) });

const parameters = JSON.parse(suiteParametersJson());
const expected = {
  apiVersion: 1,
  suiteId: 'MHFE-BIP39-256-EXPERIMENTAL-2',
  roundCount: 12,
  memoryKib: 524288,
  basePasses: 12,
  lanes: 4,
  maxPim: 31,
  supportedSourceWords: [12, 15, 18, 21, 24],
};

for (const [key, value] of Object.entries(expected)) {
  if (JSON.stringify(parameters[key]) !== JSON.stringify(value)) {
    throw new Error(`Unexpected ${key}: ${JSON.stringify(parameters[key])}`);
  }
}

try {
  new MhfeEngine(32);
  throw new Error('PIM 32 was unexpectedly accepted.');
} catch (error) {
  if (!String(error).includes('INVALID_PIM')) throw error;
}

console.log('Verified generated MHFE WASM API and frozen suite parameters.');
