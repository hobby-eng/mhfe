import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { MhfeEngine, initSync, suiteParametersJson } from '../dist/wasm/mhfe.js';

const wasmPath = fileURLToPath(new URL('../dist/wasm/mhfe_bg.wasm', import.meta.url));
initSync({ module: readFileSync(wasmPath) });

const parameters = JSON.parse(suiteParametersJson());
const expected = {
  apiVersion: 2,
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

for (const rejectedPim of [32, 2 ** 32, 2 ** 32 + 31, -1, 0.5, Number.NaN]) {
  try {
    new MhfeEngine(rejectedPim);
    throw new Error(`PIM ${String(rejectedPim)} was unexpectedly accepted.`);
  } catch (error) {
    if (!String(error).includes('INVALID_PIM')) throw error;
  }
}

const sourceWordProbe = new MhfeEngine(0);
try {
  for (const method of ['encryptPreservingFinalWordJson', 'decryptPreservingFinalWordJson']) {
    if (typeof sourceWordProbe[method] !== 'function') throw new Error(`Missing WASM method ${method}.`);
  }
  sourceWordProbe.decryptJson('unused', 2 ** 32 + 12);
  throw new Error('Wrapped sourceWords was unexpectedly accepted.');
} catch (error) {
  if (!String(error).includes('INVALID_SOURCE_WORDS')) throw error;
} finally {
  sourceWordProbe.free();
}

if (process.argv.includes('--operational')) {
  const source = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const password = 'public test password';
  const expectedContainer = 'topple stock shiver enforce hire stumble unique trick mansion relief absent thought thunder price buzz crazy depart robust drastic bunker husband wagon salad book';
  const engine = new MhfeEngine(0);
  try {
    engine.setAsciiPassword(password);
    const encrypted = JSON.parse(engine.encryptJson(source));
    if (encrypted.encryptedMnemonic !== expectedContainer) {
      throw new Error('Operational WASM encryption did not match the published vector.');
    }
    const recovered = JSON.parse(engine.decryptAutoJson(expectedContainer));
    if (recovered.recoveredMnemonic !== source || recovered.recoveryVerifier !== 'matched') {
      throw new Error('Operational WASM automatic decryption did not recover the published vector.');
    }
  } finally {
    engine.clearPassword();
    engine.free();
  }
  console.log('Verified operational MHFE WASM encryption and automatic decryption.');
} else {
  console.log('Verified generated MHFE WASM API and frozen suite parameters.');
}
