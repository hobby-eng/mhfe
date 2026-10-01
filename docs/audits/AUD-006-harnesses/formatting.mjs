// Verify that existing files in the formatting commit have the same canonical formatted form.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const require = createRequire(new URL('../../../package.json', import.meta.url));
const prettier = require('prettier');
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' });
const commit = 'ff8365c';
const files = git('diff', '--name-only', '--diff-filter=M', `${commit}^`, commit).trim().split('\n').filter(file => /\.(?:mjs|js|ts)$/.test(file));
let count = 0;
for (const file of files) {
  const before = git('show', `${commit}^:${file}`);
  const after = git('show', `${commit}:${file}`);
  assert.equal(await prettier.format(before, { filepath: file, printWidth: 100, proseWrap: 'preserve' }),
    await prettier.format(after, { filepath: file, printWidth: 100, proseWrap: 'preserve' }), file);
  count++;
}
console.log(`${count} modified files have identical canonical formatting before and after ff8365c.`);
