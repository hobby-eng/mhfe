# AUD-024 verifier harness: BIP32 path depth

Audit AUD-024, verifier of the candidate finding "a derivation path of any depth is accepted and
derived", reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks: that a BIP32 derivation path deeper than 255 steps (BIP32's one-byte depth) is
refused by

- the library: `DerivationPath::from_str`, `AddressSearch::describe` and `find_address` /
  `find_address_until` with a path (`probe/src/main.rs`, through the public API only; it also prints
  the time to derive paths of depth 256 and 20,000 and whether a cancel already requested stops
  the one-path branch);
- the browser package: `describeAddress` of the built `dist/runtime/mhfe.wasm` with the glue
  `target/wasm-bindgen/mhfe.js` (`wasm_depth.mjs`);
- the command line: `mhfe check --address --coin bitcoin --path <depth 256> --stdin` of the built
  `target/release/mhfe`, with empty standard input, which ends the command before any Argon2 round.

Inputs: public test data only, the "abandon ... about" phrase and BIP-0084's first receiving
address `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`. Needs cargo (Rust 1.99.0) with the crates of
`Cargo.lock` already fetched (`--offline`), node, and the built `dist/`, `target/wasm-bindgen/` and
`target/release/mhfe` of this commit. No full-cost Argon2 runs. `CARGO_TARGET_DIR` is honoured.

## Running

From the repository root, with an optional work directory (default
`${TMPDIR:-/tmp}/aud024-verify-path-depth`):

```sh
docs/audits/AUD-024-harnesses/verify-path-depth/run.sh [work dir]
```

## Expected output at b6fca69

It exits 1. The library part prints `parse depth 256: accepted, 256 steps` and
`parse depth 100000: accepted, 100000 steps`, `find_address depth 256: Ok(None)`,
`find_address_until depth 20000, stopped() always true: Ok(false)` against
`Err(Cancelled)` for the standard search, and ends with `3 path(s) deeper than 255 accepted`. The
browser part prints `describeAddress depth 256: accepted` and `describeAddress depth 100000:
accepted` and ends with `2 path(s) deeper than 255 accepted`. The command-line part prints
`FAIL --path of depth 256 is refused: ✗ Error: Standard input ended before this answer: ...`.

Once the depth is limited to 255 everywhere, every part passes and it exits 0.
