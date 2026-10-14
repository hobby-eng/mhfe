# verify-chosen-word-unlocked

Audit AUD-024, verifier role `verify-chosen-word-unlocked`, at commit b6fca69 (branch
aud023-remediation).

## What it checks

While `mhfe new` asks for the word never to use, the chosen word, a word of the new seed phrase,
must be held only in locked memory: RUST-13 ("Secret values live in types that wipe them on drop,
with their pages locked (mlock) where their size allows") and SECURITY.md ("The secrets the
program keeps beyond a moment are held in locked memory (`mlock`) ... a seed phrase as text").

`chosen_word_unlocked.py` runs the real binary in a pseudo-terminal (the repository's
`scripts/terminal_suite`) with `locked_scan.c` preloaded. The shim records every `mlock` and
`munlock` page by page and, each time the program blocks reading standard input, scans the
program's own writable memory (through `process_vm_readv`) for the chosen word as typed, `ZoO`: the
public BIP39 word "zoo" in a mixed case that no word list holds. For each hit it logs the address,
whether its page is locked, whether it lies in the standard library's standard-input buffer (an
unlocked copy SECURITY.md already names), and the heap chunk's size word when the hit starts a
chunk.

Stages, all before anything is drawn, stopped with Ctrl+C; no Argon2 runs beyond the checks at
start:

- S1, the chosen-word prompt: no copy (control).
- S2, the position prompt after typing `ZoO`: a copy in a LOCKED page (positive control: the shim
  sees the program's locking).
- S3, the never-use prompt: the check. Any UNLOCKED copy outside the standard-input buffer fails.
- S4, back at the first question after the unusable never-use word `zooo`: no copy left (control:
  S3's copy was live and wiped, not freed residue).

## Inputs

- The release binary of b6fca69, built with
  `CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target cargo build --locked --release --bin mhfe`.
- A scratch folder, where the shim is compiled (`gcc`) and its scan log is written.
- Linux with glibc (the shim interposes `read`, `mlock` and `munlock`).

## Command, from the repository root

```sh
python3 docs/audits/AUD-024-harnesses/verify-chosen-word-unlocked/chosen_word_unlocked.py \
    /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe \
    /home/user/Documents/bip_tools/tmp/aud024/verify-chosen-word-unlocked/run
```

## Expected output

On a fixed tree: `PASS: the chosen word is only in locked pages while the never-use prompt waits`,
exit 0. At b6fca69 it prints, with addresses that vary from run to run:

```
S3 never-use prompt: scan 5: ... hits: [0x... UNLOCKED chunk-size-word=0x21 region=[heap]] total 1
S4 first question again: scan 6: ... hits: total 0
FAIL: 1 unlocked copy(ies) of the chosen word while the never-use prompt waits, wiped by S4: ...
```

and exits 1. Exit 2 means a control failed and the probe cannot judge.
