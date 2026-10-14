# verify-strength-repeats (audit AUD-024, commit b6fca69)

Checks that the public `mhfe::strength::Strength::of` rates a password that repeats one short group
which is not a word of the lists (such as `1234 1234 1234 1234 1234`, `2024` five times, `abcd`
eight times) as weak, below `WEAK_BELOW_BITS` (50). It also prints, for comparison, the group once,
repeated list words, single-character runs of 46, 47 and 100 characters, and 8,000 bytes of
`zzzz `.

Inputs: public test strings only, written in `probe/src/main.rs`. Needs the repository's locked
dependencies in the local cargo cache (the build runs offline).

Command, from the repository root:

```sh
CARGO_TARGET_DIR=/path/outside/the/repository docs/audits/AUD-024-harnesses/verify-strength-repeats/run.sh
```

Expected output at b6fca69: one line per string with its bits and `weak=`, then
`FAIL: at least one repeated group that is not a list word is rated 50 bits or more`, exit 1. After
a fix it ends with `OK` and exits 0.
