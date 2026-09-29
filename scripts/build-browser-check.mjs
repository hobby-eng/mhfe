// Builds target/browser-check/index.html: a self-contained page that runs the browser package
// under the same Content-Security-Policy as the offline wallet tools and reports PASS or FAIL
// in its title. Build the package first with scripts/build-wasm.sh.
//
// Open it as a file for the standard mode, or with `mhfe serve target/browser-check/index.html`
// for the fast mode. By default it runs one full-size encryption (2 GiB); add "#all" to the
// address to also decrypt and check. Public test data only.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
/** JSON that is safe inside a script element: "</script" cannot appear in it. */
const inline = (value) => JSON.stringify(value).replaceAll('<', '\\u003c');

const clientModule = read('dist/client.js').toString();
const checks = `
const WORKER_SOURCE = ${inline(read('dist/mhfe-worker.js').toString())};
const ARGON2_THREADED = ${inline(read('dist/argon2-mt.js').toString())};
const ARGON2_SINGLE_THREADED = ${inline(read('dist/argon2-st.js').toString())};
const CORE_WASM_BASE64 = ${inline(read('dist/mhfe_core_bg.wasm').toString('base64'))};

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'public test password';
// The native tool and an independent OpenSSL script give this container for the phrase above.
const EXPECTED_CONTAINER =
  'donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace';

const output = document.getElementById('log');
const log = (line) => {
  output.textContent += line + '\\n';
};
const failures = [];
const expect = (condition, description) => {
  log((condition ? 'ok    ' : 'FAIL  ') + description);
  if (!condition) failures.push(description);
};

async function expectRejection(promise, code, description) {
  try {
    await promise;
    expect(false, description + ' (no error)');
  } catch (error) {
    expect(error.code === code, description + ' -> ' + error.code);
  }
}

function expectThrow(action, code, description) {
  try {
    action();
    expect(false, description + ' (no error)');
  } catch (error) {
    expect(error.code === code, description + ' -> ' + error.code);
  }
}

async function main() {
  const coreWasm = Uint8Array.from(atob(CORE_WASM_BASE64), (character) => character.charCodeAt(0));
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
    coreWasm,
  });
  log('mode: ' + client.mode() + ', protocol: ' + location.protocol);

  // Refusals that need no Argon2 work.
  expectThrow(() => client.encrypt({ phrase: PHRASE, password: 'a\\uD800', passwordRepeat: 'a\\uD800' }), 'INVALID_PASSWORD_TEXT', 'unpaired surrogate refused');
  expectThrow(() => client.encrypt({ phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD, memoryLevel: 1 }), 'MEMORY_LEVEL_NOT_SUPPORTED_HERE', 'memory level 1 refused');
  await expectRejection(client.encrypt({ phrase: 'abandon about', password: PASSWORD, passwordRepeat: PASSWORD }), 'INVALID_PHRASE', 'invalid phrase refused by the worker');

  // Cancelling inside the first round stops the worker at once.
  const started = performance.now();
  const cancelled = client.encrypt({ phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD, onProgress: () => setTimeout(() => client.cancel(), 500) });
  await expectRejection(cancelled, 'CANCELLED', 'cancel inside round 1');
  expect(performance.now() - started < 20000, 'cancel took under 20 s');

  const timer = performance.now();
  const seconds = () => ((performance.now() - timer) / 1000).toFixed(1) + ' s';
  const onProgress = ({ round, rounds }) => log('  round ' + round + '/' + rounds + ' at ' + seconds());
  const { container } = await client.encrypt({ phrase: PHRASE, password: PASSWORD, passwordRepeat: PASSWORD, onProgress });
  expect(container === EXPECTED_CONTAINER, 'full-size encryption gives the native container (' + seconds() + ')');

  if (location.hash.includes('all')) {
    const recovery = await client.decrypt({ container, password: PASSWORD, onProgress });
    const candidate = recovery.candidates[0];
    expect(recovery.kind === 'phrase' && candidate.phrase === PHRASE && candidate.words === 12 && candidate.verified,
      'full-size decryption recovers the verified 12-word phrase (' + seconds() + ')');
    const { matches } = await client.check({ container, password: PASSWORD, reference: { address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' }, onProgress });
    expect(matches === true, 'rehearsal check with the address matches (' + seconds() + ')');
  }
}

main()
  .catch((error) => failures.push('page error: ' + (error.code ?? '') + ' ' + error.message))
  .finally(() => {
    log(failures.length === 0 ? 'SUMMARY: PASS' : 'SUMMARY: FAIL ' + failures.join('; '));
    document.title = failures.length === 0 ? 'PASS' : 'FAIL';
  });
`;
const script = clientModule + '\n' + checks;
const scriptHash = createHash('sha256').update(script, 'utf8').digest('base64');
const policy = [
  "default-src 'none'",
  `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
  "style-src 'unsafe-inline'",
  "img-src 'none'",
  "font-src 'none'",
  "connect-src 'none'",
  'worker-src blob:',
  "object-src 'none'",
  "frame-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${policy}" />
    <title>running</title>
  </head>
  <body>
    <pre id="log"></pre>
    <script type="module">${script}</script>
  </body>
</html>
`;
mkdirSync(new URL('target/browser-check/', root), { recursive: true });
writeFileSync(new URL('target/browser-check/index.html', root), page);
console.log(`Wrote target/browser-check/index.html (${page.length} bytes)`);
