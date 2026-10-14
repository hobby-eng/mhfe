# AUD-024 harness: secret owner types in the browser package (TS-07)

The baseline at b6fca69 had no JavaScript secret owner. Its retained probe and logs showed that
field-name lists missed arbitrary names, deeper nesting and arrays. Those historical findings and
logs are unchanged. The current remediation probe exercises the replacement interface.

It imports the reviewed page runtime, compares the classic worker's deliberate copy of the owner
classes, and checks that SecretBytes and SecretRequest transfer and wipe each buffer under a named
field, an arbitrary field, one and two levels down, and inside an array. Both owners support
explicit wipe() and Symbol.dispose where the runtime provides it. Only public synthetic bytes and
local files are used; the probe performs no network or Argon2 work.

Run from the repository root with the pinned Node toolchain:

```sh
node docs/audits/AUD-024-harnesses/verify-secret-owners/probe.mjs
```

The remediated version prints five `ok:` lines and confirms both owner definitions match, then
exits 0. Missing owners, missing cleanup or transfer, or definition drift fails an assertion. The
package's additional tests cover disposal without the symbol, repeated references, cycles,
detached buffers, cancelled compilation and the existing phrase/memory residue controls.
