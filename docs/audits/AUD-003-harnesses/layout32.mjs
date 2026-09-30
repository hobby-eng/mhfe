// wasm32 supplies 32-bit usize/isize semantics. This is not a native i686 engine execution.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const output = 'docs/audits/AUD-003-evidence/layout32.wasm';
const built = spawnSync('rustc', ['--edition=2021', '--target', 'wasm32-unknown-unknown', '--crate-type', 'cdylib', '-O', 'docs/audits/AUD-003-harnesses/layout32.rs', '-o', output], {stdio:'inherit'});
assert.equal(built.status, 0);
const {instance} = await WebAssembly.instantiate(readFileSync(output));
const accepted = instance.exports.default_layout_supported();
console.log('32-bit Rust Layout accepts the advertised native 2 GiB work area:', Boolean(accepted));
assert.equal(accepted, 1, '32-bit native level 0 cannot reach allocation through this Layout predicate');
