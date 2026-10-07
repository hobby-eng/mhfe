// The bridge from the Rust core to the Emscripten build of the reference Argon2 code. It is
// joined into runtime/worker.js by scripts/build-wasm.sh, and the Node.js tests load the same file.
"use strict";

/** Argon2id output length and lane count of MHFE suite 3. */
const ARGON2_KEY_BYTES = 32;
const ARGON2_LANES = 4;
/** ARGON2_MEMORY_ALLOCATION_ERROR in vendor/phc-winner-argon2/include/argon2.h. */
const ARGON2_MEMORY_ALLOCATION_ERROR = -22;

/**
 * The object the Rust core calls once per round (see src/engine/browser.rs). `password`,
 * `salt` and `key` are views into the Rust core's memory, so the password is never copied into
 * a JavaScript array on the way.
 */
function argon2Engine(module) {
  return {
    derive(password, salt, memoryKib, passes, key) {
      // Copy password and salt into the C heap, run Argon2id, copy the key out, then overwrite
      // and free every C-heap copy. Pointers can lie above 2 GiB, hence the unsigned shift.
      const passwordPointer = module._malloc(password.length) >>> 0;
      const saltPointer = module._malloc(salt.length) >>> 0;
      const keyPointer = module._malloc(ARGON2_KEY_BYTES) >>> 0;
      try {
        if (passwordPointer === 0 || saltPointer === 0 || keyPointer === 0) {
          throw new Error("MEMORY_ALLOCATION_FAILED: the browser could not provide memory");
        }
        module.HEAPU8.set(password, passwordPointer);
        module.HEAPU8.set(salt, saltPointer);
        const code = module._argon2id_hash_raw(
          passes,
          memoryKib,
          ARGON2_LANES,
          passwordPointer,
          password.length,
          saltPointer,
          salt.length,
          keyPointer,
          ARGON2_KEY_BYTES,
        );
        if (code === ARGON2_MEMORY_ALLOCATION_ERROR) {
          throw new Error(
            "MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory",
          );
        }
        if (code !== 0) {
          throw new Error(`ARGON2_FAILED: the reference code returned error ${code}`);
        }
        key.set(module.HEAPU8.subarray(keyPointer, keyPointer + ARGON2_KEY_BYTES));
      } finally {
        // Read HEAPU8 again: the call may have grown the memory, which replaces the view.
        const heap = module.HEAPU8;
        wipeAndFree(module, heap, passwordPointer, password.length);
        wipeAndFree(module, heap, saltPointer, salt.length);
        wipeAndFree(module, heap, keyPointer, ARGON2_KEY_BYTES);
      }
    },

    /** Grows the C heap to `memoryKib` once and frees it again (src/engine/browser.rs). */
    reserve(memoryKib) {
      const pointer = module._malloc(memoryKib * 1024) >>> 0;
      if (pointer === 0) {
        throw new Error(
          "MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory",
        );
      }
      module._free(pointer);
    },
  };
}

function wipeAndFree(module, heap, pointer, length) {
  if (pointer !== 0) {
    heap.fill(0, pointer, pointer + length);
    module._free(pointer);
  }
}
