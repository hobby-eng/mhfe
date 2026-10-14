# AUD-024 gap-1-aud023-observations-under-current-guide harness

Audit AUD-024, role gap-1-aud023-observations-under-current-guide, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch aud023-remediation).

The role judged the 81 informational observations of AUD-023 again under the current coding guide.
These scripts reproduce the observations that became findings. Each check prints PASS or FAIL. FAIL
means that the defect is present, and the script then exits 1. An exit of 2 means that a check
could not run.

## What it checks

`run.sh` runs the cheap checks in this order:

1. **Hash and MAC states (RUST-13).** `cargo tree -e features -i digest@0.11.3` must show
   `digest feature "zeroize"`. Without it, the SHA-256, SHA-512, HMAC and BLAKE2b states that
   `src/feistel.rs`, `src/wallet/keys.rs` and `src/wallet_check.rs` key with secrets are not wiped
   on drop.
2. **The standard input buffer (RUST-13).** `probe/src/bin/stdin-residue.rs` reads a line one byte
   at a time from `io::stdin().lock()`, as `edit_line` in `src/bin/mhfe/hidden_input.rs` does. It
   then wipes its own copy and scans its heap through `/proc/self/mem`. The control reads the same
   line from file descriptor 0 directly. Linux only.
3. **Ctrl+D (exit.rs).** `ctrl-d.py` types Ctrl+D at the first empty prompt or list of
   `repair-words`, `decrypt` and `encrypt` in a pseudo-terminal, at `TERM=xterm-256color` and
   `TERM=dumb`. `src/bin/mhfe/exit.rs` documents 130 for that key.
4. **Option values in another letter case (CORE-10, CORE-48).** `option-case.sh` gives values in
   another case to `--words`, `--coin`, `--passphrase-used`, `--confirm`, `--new-password` and
   `--same-length`. Standard input comes from `/dev/null`, so an accepted value stops at the first
   answer, before any round.
5. **Address forms (CORE-48).** `probe/src/bin/address-forms.rs` calls `mhfe::wallet::Address::parse`
   on single-key forms of supported coins with the HASH160 of public test addresses: a CashTokens
   token-aware CashAddr (`bitcoincash:z…`), a Zcash ZIP-320 TEX address (`tex1…`) and a Dash Core
   testnet address (`y…`). It also gives a Bitcoin P2SH `3…` address and a Dash Platform testnet
   address, for context. The forms were computed independently by the role's own Python code from
   the self-check addresses `bitcoincash:qqyx49…q6` and `t1XVXW…7F`.
6. **The coin types of the address search in the self-checks (CORE-27).** `coin-type-mutation.sh`
   extracts the crate at a revision (default `HEAD`) into a temporary folder. There it changes
   Litecoin's coin type from 2 to 3 and runs the startup sets, the `addresses` check and the
   `address-search` check at both tiers. As a control, it then runs the unit test that searches
   every row of the address table.
7. **The CORE-25 gate.** `cargo-pin-gate.mjs` reads `cargoFindings` from
   `scripts/verify-code-rules.mjs` as it is. It gives the function manifests that are not exact
   crates.io pins: a `[dependencies.foo]` table with a range, a git source or a wildcard, and an
   exact version from git or from another registry.
8. **WebAssembly stack residue (RUST-13, TS-07).** `wasm-stack-residue.mjs` calls
   `walletFingerprint` on the package's WebAssembly for BIP39's published vector (`abandon … about`,
   passphrase `TREZOR`). It then looks for the master private key and the chain code of the
   published `xprv9s21…UsAF` in the module's memory. As a control, it zeroes the dead shadow stack
   and calls again.
9. **The worker handshake (web/runtime.js).** `worker-handshake.mjs` runs `WorkerJob` against a fake
   Worker that sends a result or news without a `ready`. The controls send a `ready` of another
   build and of this build.
10. **The fast-mode launchers on Ctrl+C.** `launcher-ctrl-c.py` serves a one-line scratch page from
    a temporary folder on 127.0.0.1 with `--no-browser`, through `mhfe serve` and through
    `packaging/mhfe-fast-mode.py`. It sends SIGINT and compares the exit codes and last lines.

`decoy.sh` runs `probe/src/bin/decoy-collision.rs`. The probe computes the master key fingerprint
of every one of the 262,144 candidates of the container phrase `abandon` ×10 with the last two
words missing. It finds the pairs of candidates that share a fingerprint. For each pair, it runs
`ContainerSearch::search_decoy` with the fingerprint of the later candidate, which stands for the
owner's container.

## Inputs

All data is public test data: the `abandon … about` phrase, BIP39's published `TREZOR` vector,
public self-check addresses, the public test password, and phrases derived from `abandon` ×10. The
checks need:

- cargo with Rust 1.99.0 and the crates already fetched (`--offline`);
- python3 and node (26.x);
- for check 8, `dist/runtime/mhfe.wasm` and `target/wasm-bindgen/mhfe.js` from
  `scripts/build-wasm.sh`;
- for check 2, Linux.

Check 10 listens on 127.0.0.1 only. Nothing uses the network, and no Argon2 runs at suite cost.

`CARGO_TARGET_DIR` is honoured. Its default is `${TMPDIR:-/tmp}/aud024-gap1-target`.

## Running

From the repository root:

```sh
docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/run.sh
docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/decoy.sh
```

`decoy.sh` takes about 66 CPU minutes, which is 4.5 minutes on 16 cores.

## Expected output at b6fca69

`run.sh` exits 1. Every check prints FAIL, except that check 2 prints one copy for `std` and none
for `descriptor` before its FAIL:

```text
FAIL: digest 0.11.3, under sha2, hmac, blake2 and sha3, is built without its zeroize feature
FAIL: mhfe reads typed lines through std's stdin buffer, which keeps a copy after the line is wiped
FAIL: Ctrl+D at an empty visible prompt or numbered list does not end with 130 as exit.rs documents; controls: 130, 130
FAIL: 3 values in another case accepted, 4 refused: no one rule
FAIL: single-key forms of supported coins are refused with a reason that is false for them
FAIL: the startup and full self-checks pass with a wrong coin type for Litecoin's address search
FAIL: 5 of 5 manifests that are not exact crates.io pins pass CORE-25
FAIL: the master key and chain code stay in the WebAssembly memory after the call
FAIL: the page takes a worker's result and news before its ready
FAIL: the launchers end differently on Ctrl+C
```

`decoy.sh` exits 1. It finds 8 pairs and ends with:

```text
RESULT: 8 of 8 searches returned another container than the owner's, with no sign that a second candidate matched
```

After a fix, the check of that defect prints PASS.
