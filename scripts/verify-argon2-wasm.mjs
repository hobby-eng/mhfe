// Checks both Emscripten builds of the reference Argon2 code in Node.js, where the
// threaded build runs with real threads. Build them first with build-argon2-wasm.sh.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const builds = {
  threaded: require('../dist/argon2-mt.js'),
  'single-threaded': require('../dist/argon2-st.js'),
};

const KEY_BYTES = 32;
const LANES = 4;
const encoder = new TextEncoder();
const password = encoder.encode('public test password');
const salt = encoder.encode('0123456789abcdef');

// Argon2id tags for the public inputs above, 4 lanes and 32 bytes, computed with
// OpenSSL through Python cryptography 46.0.5 (an independent implementation).
const expectedTags = [
  {
    memoryKib: 1024,
    passes: 1,
    tag: 'e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2',
  },
  {
    memoryKib: 65536,
    passes: 3,
    tag: 'a3931f5728b235c605c02522f3302a8e90d0509a0c3db63ab4d2fcf75f345b5b',
  },
  {
    memoryKib: 262144,
    passes: 2,
    tag: '4a4a094750f2c17fc6507d38825ec9eac65e10fb2de9e9bf5e801d2af53f1efe',
  },
];

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// Minimal caller of argon2id_hash_raw: copy the inputs into the C heap, run, read the tag.
function argon2id(argon2, memoryKib, passes) {
  const passwordPtr = argon2._malloc(password.length) >>> 0;
  const saltPtr = argon2._malloc(salt.length) >>> 0;
  const keyPtr = argon2._malloc(KEY_BYTES) >>> 0;
  try {
    argon2.HEAPU8.set(password, passwordPtr);
    argon2.HEAPU8.set(salt, saltPtr);
    const code = argon2._argon2id_hash_raw(
      passes,
      memoryKib,
      LANES,
      passwordPtr,
      password.length,
      saltPtr,
      salt.length,
      keyPtr,
      KEY_BYTES,
    );
    if (code !== 0) throw new Error(`Argon2 returned error code ${code}`);
    return hex(argon2.HEAPU8.subarray(keyPtr, keyPtr + KEY_BYTES));
  } finally {
    argon2._free(passwordPtr);
    argon2._free(saltPtr);
    argon2._free(keyPtr);
  }
}

for (const [name, createModule] of Object.entries(builds)) {
  const argon2 = await createModule();
  for (const { memoryKib, passes, tag } of expectedTags) {
    const actual = argon2id(argon2, memoryKib, passes);
    if (actual !== tag) {
      throw new Error(
        `${name} build, ${memoryKib} KiB, ${passes} passes: got ${actual}, expected ${tag}`,
      );
    }
  }
  console.log(`The ${name} build matches all ${expectedTags.length} expected Argon2id tags.`);
}

// The threaded build keeps its lane workers alive; end the process explicitly.
process.exit(0);
