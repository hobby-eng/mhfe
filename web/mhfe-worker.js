// MHFE worker: runs exactly one operation, after which the client terminates it. Terminating
// the worker frees all of its memory, including the Argon2 memory, which WebAssembly can grow but
// never shrink.
//
// The client builds this worker from one Blob that holds, in this order: one Emscripten build of
// the reference Argon2 code (argon2-mt.js or argon2-st.js), the Rust core's wasm-bindgen glue,
// web/argon2-engine.js and this file; dist/mhfe-worker.js is the last three joined. Under the
// tools' Content-Security-Policy a worker may not load any further script, so everything arrives
// in that one Blob.
'use strict';

self.onmessage = async (event) => {
  const request = event.data;
  try {
    wasm_bindgen.initSync({ module: request.coreWasm });
    const result = READING_OPERATIONS.has(request.operation)
      ? readWords(request)
      : runOperation(request, argon2Engine(await loadArgon2(request.argon2Script)), onRound);
    self.postMessage({ type: 'result', result });
  } catch (error) {
    self.postMessage({ type: 'error', error: describeError(error) });
  } finally {
    // The Rust core has its own copies, which it wipes; these are the copies in this worker.
    request.password?.fill(0);
    request.passphrase?.fill(0);
  }
};

/** Operations that only read words; they need no Argon2 build. */
const READING_OPERATIONS = new Set(['readPhrase', 'readContainer']);

function onRound(round, rounds) {
  self.postMessage({ type: 'progress', round, rounds });
}

/** The container before its check; the result message comes only after the check passed. */
function onUnverified(container) {
  self.postMessage({ type: 'unverified', container });
}

function readWords(request) {
  if (request.operation === 'readPhrase') {
    const phrase = wasm_bindgen.readPhrase(request.phrase);
    const otherLengths = Array.from(wasm_bindgen.otherDetectedLengths(phrase));
    return { phrase, words: phrase.split(' ').length, otherLengths };
  }
  return { container: wasm_bindgen.checkContainer(request.container) };
}

/** Starts the Argon2 build that was placed in front of this file. */
function loadArgon2(threadedScript) {
  if (typeof createArgon2Mt === 'function') {
    // Without cross-origin isolation the threaded build cannot share its memory with its lane
    // workers, and its start-up would wait forever instead of failing, so refuse it here.
    if (self.crossOriginIsolated !== true) {
      throw new Error('INTERNAL_ERROR: the threaded Argon2 build needs a cross-origin isolated page');
    }
    // The lane workers run this same Argon2 script, which the CSP allows only from a Blob.
    return createArgon2Mt({ mainScriptUrlOrBlob: threadedScript });
  }
  return createArgon2St();
}

function runOperation(request, argon2, onRound) {
  const { pim, memoryLevel } = request;
  switch (request.operation) {
    case 'encrypt':
      return {
        container: wasm_bindgen.encrypt(request.phrase, request.password, pim, memoryLevel, argon2, onRound, onUnverified),
      };
    case 'decrypt':
      return JSON.parse(
        wasm_bindgen.decrypt(request.container, request.password, pim, memoryLevel, request.words, argon2, onRound),
      );
    case 'check':
      return {
        matches: wasm_bindgen.check(
          request.container,
          request.password,
          pim,
          memoryLevel,
          request.referenceKind,
          request.reference,
          request.path,
          request.passphrase,
          argon2,
          onRound,
        ),
      };
    default:
      throw new Error(`INVALID_REQUEST: unknown operation ${String(request.operation)}`);
  }
}

/** Errors from the Rust core read "CODE: message". */
function describeError(error) {
  const text = error instanceof Error ? error.message : String(error);
  const match = /^([A-Z][A-Z0-9_]+): (.*)$/su.exec(text);
  return match === null ? { code: 'INTERNAL_ERROR', message: text } : { code: match[1], message: match[2] };
}
