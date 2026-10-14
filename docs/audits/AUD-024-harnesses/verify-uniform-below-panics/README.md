# AUD-024 verifier harness: public library calls that panic on wrong input

Audit AUD-024, role verify-uniform-below-panics (adversarial verifier of the core-crypto candidate
"Library code panics instead of returning an error"), reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch `aud023-remediation`). No Argon2 runs, and
no secret is used: the random source is a public counter and the texts are fixed public strings.

## What it checks

`probe/src/main.rs` calls, each under `catch_unwind`, and prints one line per call:

- `mhfe::random::uniform_below` with the bounds 2, 57, 7,776 and 65,536 (in range: each must
  return `Ok`) and 0, 1, 65,537 and `usize::MAX` (wrong input: each must return `Err`, per RUST-05
  and CORE-22 of the coding guide).
- `mhfe::memory::LockedText::build` and `LockedBytes::build` with a capacity of 4 and a `fill`
  that writes 41 bytes (wrong input: each must return, not panic).

It exits 1 when any call panicked and 0 when every call returned.

## Inputs

The repository at the reviewed commit, Rust 1.99.0 (the repository's `rust-toolchain.toml`), and
the offline Cargo registry with the crates of the repository's `Cargo.lock`. `run.sh` copies
`probe/` to a temporary folder, writes its `Cargo.toml` from `probe/Cargo.toml.in` with a path
dependency on the repository, copies `Cargo.lock` and `rust-toolchain.toml` beside it, and builds
it there into `CARGO_TARGET_DIR`; it writes nothing into the repository.

## Command, from the repository root

```text
CARGO_TARGET_DIR=<a folder outside the repository> \
  docs/audits/AUD-024-harnesses/verify-uniform-below-panics/run.sh
```

## Expected output

At b6fca69 it exits 1 and prints:

```text
uniform_below(n=2): returned Ok(0)
uniform_below(n=57): returned Ok(0)
uniform_below(n=7776): returned Ok(37)
uniform_below(n=65536): returned Ok(37)
uniform_below(n=0): PANICKED: only ranges of 2 to 65,536 are drawn
uniform_below(n=1): PANICKED: only ranges of 2 to 65,536 are drawn
uniform_below(n=65537): PANICKED: only ranges of 2 to 65,536 are drawn
uniform_below(n=18446744073709551615): PANICKED: only ranges of 2 to 65,536 are drawn
LockedText::build(capacity=4, fill writes 41 bytes): PANICKED: assertion `left == right` failed: a locked text outgrew its buffer
  left: 41
 right: 4
LockedBytes::build(capacity=4, fill writes 41 bytes): PANICKED: assertion `left == right` failed: locked bytes outgrew their buffer
  left: 41
 right: 4
6 call(s) panicked instead of returning
```

Once the finding is fixed, every line says `returned` (an `Err` for each wrong input), the last
line says `0 call(s) panicked instead of returning`, and it exits 0. If the fix changes the
signature of a probed function, adapt the probe to the new signature and keep the same inputs.

## Helper scan (a listing, not a pass/fail check)

`scan_asserts.py` lists `assert!`, `assert_eq!`, `assert_ne!`, `unreachable!`, `todo!` and
`unimplemented!` in `src/` outside items gated by `#[cfg(test)]` (comments and strings blanked).
It exits 1 whenever it lists anything, and it does not recognise `#[cfg(all(test, ...))]` or
`const` contexts, so its hits must be read by hand. At b6fca69 it lists 78 hits. Of these, the
ones that can run at run time outside tests are `src/random.rs:71`, `src/repair.rs:99`,
`src/memory.rs:44`, `src/memory.rs:105` and `src/bin/mhfe/check_word.rs:133`. The rest are
compile-time `const` assertions (`src/engine/ffi.rs:64-108`, `src/repair.rs:59`,
`src/bin/mhfe/chosen_words.rs:24`, and `src/self_check.rs:475` in a `const fn` used only in
constants), or test modules gated by `#[cfg(all(test, not(target_arch = "wasm32")))]`
(`src/engine/known_answers.rs:396`, `src/self_check/sets.rs:219`).

```text
python3 docs/audits/AUD-024-harnesses/verify-uniform-below-panics/scan_asserts.py src
```
