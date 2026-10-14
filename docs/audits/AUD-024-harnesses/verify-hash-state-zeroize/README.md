# AUD-024 verify-hash-state-zeroize harness

Audit AUD-024, verifier role `verify-hash-state-zeroize`, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch aud023-remediation).

## What it checks

Whether the SHA-256, SHA-512, HMAC and BLAKE2b states that mhfe feeds with secrets wipe themselves
when dropped (RUST-13). mhfe pins `blake2 =0.11.0`, `hmac =0.13.0` and `sha2 =0.11.0` without their
`zeroize` features (Cargo.toml:29, 32, 37), and these crates wipe their cores, block buffers and
MAC outputs only under `cfg(feature = "zeroize")`.

1. `drop-probe` builds, with the versions and features mhfe pins, the states of
   `src/feistel.rs` `round_mask` (HMAC-SHA-256 keyed with a stand-in round key, then fed a
   stand-in half R), `round_salt` (BLAKE2b-256 over R), `src/wallet/keys.rs` `from_hmac`
   (HMAC-SHA512 over seed bytes), `src/wallet_check.rs` `tagged_digest` (SHA-256 over seed bytes)
   and the `CtOutput` that `Mac::finalize` returns. It drops each in place in a heap slot and
   compares the slot's bytes before and after the drop. FAIL (exit 1): a state keeps bytes after
   its drop.
2. `residue-probe` links the mhfe library at this commit and calls the public
   `mhfe::wallet_check::phrase_passes` and `mhfe::wallet::master_fingerprint` for BIP39's published
   vector (`abandon` x11 `about`, passphrase `TREZOR`), each on a fresh thread whose stack it first
   clears. It then scans 256 KiB of dead stack below the stack pointer for the padded last block of
   the hash state: the seed bytes that the state's buffer holds followed by the padding byte 0x80,
   which no other copy of the seed has. FAIL (exit 1): the block is found after the call. A
   control at the end checks that the published seed is the one BIP39 computes.

## Inputs

Public test data only. cargo with Rust 1.99.0 and the crates already fetched (`--offline`); the
residue probe reads the stack pointer with x86-64 assembly, so it needs an x86-64 machine.
Nothing uses the network and no Argon2 runs. `CARGO_TARGET_DIR` is honoured; its default is
`${TMPDIR:-/tmp}/aud024-hash-state-target`.

## Running

From the repository root:

```sh
docs/audits/AUD-024-harnesses/verify-hash-state-zeroize/run.sh
docs/audits/AUD-024-harnesses/verify-hash-state-zeroize/run.sh --features wipe
```

The second command is the control: it turns on the `zeroize` features of blake2, hmac and sha2,
which feature unification also applies to mhfe's own copies of these crates.

## Expected output

At b6fca69, the first command exits 1. The drop probe reports all five states with every non-zero
byte unchanged after the drop and the secret pattern still in the slot (`states with bytes left
after drop: 5 of 5`). The residue probe reports the SHA-256 block of `phrase_passes` 2 times after
the call (`states found after their call: 2`); the HMAC-SHA512 block of `master_fingerprint` was
not found (0), since the later elliptic-curve work overwrites that part of the stack. The second
command exits 0: 0 of 5 states keep bytes, and the SHA-256 block is found 0 times.

After the fix (the `zeroize` features of sha2, hmac and blake2 in Cargo.toml), the first command
exits 0.
