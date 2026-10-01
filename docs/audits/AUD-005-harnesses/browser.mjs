// Runs the real client and workers under normal CSP with a test-only 256 KiB KDF wrapper.
// Generated pages remain in ignored evidence; no production file is edited.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = new URL('../../../', import.meta.url);
const require = createRequire(new URL('../multi-chain-wallet-tools/package.json', root));
const { chromium, firefox } = require('playwright');
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const inline = (value) => JSON.stringify(value).replaceAll('<', '\\u003c');
const wrap = `
const originalEngine = argon2Engine;
argon2Engine = (module) => {
  const original = originalEngine(module);
  return { derive(p, s, m, t, k) {
    if (m !== 2097152 || t !== 12) throw Error('Unexpected suite parameters');
    return original.derive(p, s, 256, 1, k);
  }};
};
`;
const script = read('dist/client.js') + `
const source = {
  workerSource: ${inline(read('dist/mhfe-worker.js') + wrap)},
  argon2Threaded: ${inline(read('dist/argon2-mt.js'))},
  argon2SingleThreaded: ${inline(read('dist/argon2-st.js'))},
  coreWasm: Uint8Array.from(atob(${inline(readFileSync(new URL('dist/mhfe_core_bg.wasm', root)).toString('base64'))}), x => x.charCodeAt(0)),
};
const client = new MhfeClient(source);
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public test password';
const expected = 'slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet';
const results = [];
function expect(ok, name) { if (!ok) throw Error(name); results.push(name); }
async function reject(promise, code) {
  try { await promise; } catch (error) { expect(error.code === code, code); return; }
  throw Error('Missing rejection: ' + code);
}
async function main() {
  const readBack = await client.readPhrase(phrase.toUpperCase());
  expect(readBack.phrase === phrase && readBack.words === 12 && readBack.otherLengths.length === 0, 'readPhrase');
  await reject(client.encrypt({ phrase, password: 'a\\tb', passwordRepeat: 'a\\tb' }), 'CONTROL_CHARACTER_IN_PASSWORD');
  const steps = [];
  const {container} = await client.encrypt({ phrase, password, passwordRepeat: password, onProgress: p => steps.push(p.round) });
  expect(container === expected && steps.length === 24, 'reduced encrypt');
  const recovered = await client.decrypt({ container, password });
  expect(recovered.kind === 'phrase' && recovered.candidates[0].phrase === phrase && recovered.candidates[0].verified, 'reduced decrypt');
  expect((await client.check({container,password,reference:{fingerprint:'73c5da0a'}})).matches, 'rehearsal');
  const pending = client.decrypt({container,password});
  client.cancel();
  await reject(pending, 'CANCELLED');
  expect((await client.readContainer(container)).container === container, 'restart after cancel');
  const midRound = client.decrypt({container,password,onProgress:p=>{if(p.round === 2) client.cancel();}});
  await reject(midRound, 'CANCELLED');
  expect((await client.readPhrase(phrase)).phrase === phrase, 'restart after active cancellation');
  window.audit = {ok:true, mode:client.mode(), results};
}
main().catch(error => window.audit = {ok:false,error:String(error),results}).finally(() => {
  document.querySelector('pre').textContent = JSON.stringify(window.audit, null, 2);
});
`;
const digest = createHash('sha256').update(script).digest('base64');
const policy = `default-src 'none'; script-src 'sha256-${digest}' 'wasm-unsafe-eval'; connect-src 'none'; worker-src blob:; base-uri 'none'; form-action 'none'`;
const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><title>AUD-005 bounded browser probe</title><pre>running</pre><script type="module">${script}</script></html>`;
const path = fileURLToPath(new URL('docs/audits/AUD-005-evidence/bounded-browser.html', root));
writeFileSync(path, html);
const server = createServer((request, response) => {
  response.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Content-Security-Policy': "frame-ancestors 'none'",
  });
  response.end(html);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  for (const [name, type] of [['chromium', chromium], ['firefox', firefox]]) {
    const browser = await type.launch({ headless: true, chromiumSandbox: true });
    try {
      for (const mode of ['standard', 'fast']) {
        const page = await browser.newPage();
        const requests = [], errors = [];
        page.on('request', request => requests.push(request.url()));
        page.on('pageerror', error => errors.push(String(error)));
        const url = mode === 'standard' ? pathToFileURL(path).href : `http://127.0.0.1:${server.address().port}/`;
        await page.goto(url);
        await page.waitForFunction(() => window.audit !== undefined, { timeout: 20000 });
        const result = await page.evaluate(() => window.audit);
        console.log(JSON.stringify({ browser: name, version: browser.version(), mode, result, errors, requests }));
        assert.equal(result.ok, true);
        assert.equal(result.mode, mode);
        assert.deepEqual(errors, []);
        assert.ok(requests.every(value => value === url || value.startsWith('blob:')));
        await page.close();
      }
    } finally { await browser.close(); }
  }
} finally { await new Promise(resolve => server.close(resolve)); }
