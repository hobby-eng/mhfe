# AUD-007 retained harnesses

These scripts retain the implementation review of commit `d1cf47d0960a5023e6e503310802e5e2da438568`
and the contemporaneous, modified specification. They use only public fixtures. They are audit
tools, not tools for real wallets. No full-cost Argon2 replay or release rebuild is required.

Run from the original MHFE checkout. Python 3 is required. `run.py snapshot` records tracked-file
hashes, the specification revision and local diff, and the shared audit-procedure hashes in the
ignored `docs/audits/AUD-007-evidence/` directory. `run.py run LABEL -- COMMAND ...` executes a
read-only check and saves its output and a JSON command record with UTC times, exit code and hash.
It returns the command's exit code. Do not overwrite retained labels when reproducing checks.

```sh
python3 docs/audits/AUD-007-harnesses/run.py snapshot
python3 docs/audits/AUD-007-harnesses/run.py run seed-check -- python3 docs/audits/AUD-007-harnesses/seed_check.py /path/to/bip39/src/language/english.rs
```

The second command independently derives the BIP39 seed of the implementation's public fixture
with passphrase `TREZOR`, using Python's PBKDF2. It confirms the implemented 16-bit check and the
different result caused by omitting `BE32(ENT)` in the supplement. Expected output includes
`byteContractMismatchReproduced: true`; a failed assertion exits nonzero. It does not run Argon2,
generate a funded wallet, change source files, or expose a real secret.

`wallet_bech32_variant.py` compiles `wallet_bech32_variant.rs` against this checkout's existing
debug library and Bech32 dependency. It checks the Cosmos and Injective addresses already present
in `src/wallet.rs`, using the public BIP39 vector shared by BIP84 and BIP86. It re-encodes each
address payload with Bech32m, proves that the resulting string fails a strict Bech32 checksum,
then reproduces the current parser accepting it and matching the public wallet. No Argon2 work or
network access is performed. Python 3, the repository's pinned Rust toolchain and a prior local
`cargo build --locked --lib` are required; all source remains in the authoritative checkout.

```sh
python3 docs/audits/AUD-007-harnesses/run.py run wallet-bech32-variant -- python3 docs/audits/AUD-007-harnesses/wallet_bech32_variant.py
```

The expected output has one line for each coin with `bech32m_reference_accepted=true` and
`invalid_reference_matches=true`. This retained finding probe exits zero when the reviewed bug is
reproduced and fails its assertions after the parser is repaired. Its source was reviewed against
the audit's retained implementation state; the reproduction on
`d1cf47d0960a5023e6e503310802e5e2da438568` uses the same affected wallet parser.

The chain-format requirement is independently documented by the
[Cosmos SDK address codec](https://github.com/cosmos/cosmos-sdk/blob/main/types/bech32/bech32.go)
and its
[Bech32 checksum verifier](https://github.com/cosmos/btcutil/blob/master/bech32/bech32.go),
which requires the original Bech32 residue of 1. Injective's
[account explanation](https://injective.com/blog/from-wallet-to-chain-understanding-transactions-and-accounts-on-injective/)
uses Cosmos Bech32 with the `inj` prefix.

`transcript_reconstruction.py` independently reconstructs the 17 suite 3 and 10 suite 4 positive
transcripts retained in `tests/fixtures/`, checking both directions. It verifies packing, work-factor
parameters, big-endian setting/entropy-width/round messages, BLAKE2b-256 salts, HMAC-SHA-256 masks
and every Feistel state transition. The recorded Argon2 keys are inputs: this does not rerun Argon2,
execute the production code, or establish full-cost vector replay. Its fixture-normalization check
uses Python's reported Unicode version; it does not verify Unicode 17 character acceptance. This
reconstruction belongs to the AUD-007 core review at
`d1cf47d0960a5023e6e503310802e5e2da438568`, whose core source hashes are retained in the audit.

```sh
python3 docs/audits/AUD-007-harnesses/run.py run transcript-reconstruction -- python3 docs/audits/AUD-007-harnesses/transcript_reconstruction.py
```

Expected output is JSON with `positiveTranscripts: 27`, `roundRecordsChecked: 648`, a passing
reconstruction result, the harness hash and all input-file hashes. Any discrepancy exits nonzero.
It needs only Python 3 and this checkout's public fixture JSON; no third-party Python packages or
network access are required.

`terminal_display_probe.py` compiles `terminal_display_probe.rs` using the current CLI terminal
modules. It attaches standard input and standard error to a pseudoterminal while redirecting
standard output to a pipe, then displays only the public BIP39 128-bit zero-entropy mnemonic. It
reproduces the private screen being inactive while `print_phrase` still writes that mnemonic to
the pipe. `memory_lock_probe.py` compiles `memory_lock_probe.rs` against the current debug library.
It first locks one zero-filled allocation twice, then finds two public test `Password` allocations
on the same page. It reproduces one guard's drop unlocking the page beneath the remaining live
guard and password. These probes belong to the AUD-007 CLI and secret-memory review of
`d1cf47d0960a5023e6e503310802e5e2da438568`.

```sh
python3 docs/audits/AUD-007-harnesses/terminal_display_probe.py
python3 docs/audits/AUD-007-harnesses/memory_lock_probe.py
```

Both require Linux, Python 3, the pinned Rust toolchain, and this checkout's existing debug
dependencies from `cargo build --locked --bin mhfe`. The memory probe also requires permission to
lock a small amount of memory, readable `/proc/self/status` and `/proc/self/smaps`, and a 4096-byte
page size. Neither probe runs Argon2 or accesses the network. Executables, logs and command records
are written only in the ignored evidence directory. The terminal probe's expected output begins
`PASS: current enter_to_show returned inactive`; the memory probe reports
`remaining_guard_reports_locked=true` and
`live_password_page_locked_after_other_password_drop=false`. These finding probes exit zero when
the reviewed bugs are reproduced and fail after the corresponding behavior is repaired. Reruns
overwrite their own evidence labels, so preserve the existing records before rerunning.

`validate_report.py` checks the paired AUD-007 Markdown/JSON against the shared audit schema,
rejects duplicate keys, verifies all 32 procedure IDs and finding records, compares command-log
hashes and the reviewed source snapshot, and checks the later Electrum documentation follow-up
separately. It requires Python 3, the existing `jsonschema` package, the paired reports, the shared
procedure files and the local ignored evidence captured by this audit.

```sh
python3 docs/audits/AUD-007-harnesses/validate_report.py
```

Expected output is passing validation JSON with 12 findings and 32 procedure checks. A failed
assertion or schema error exits nonzero. It writes only local `report-validation.json` and
`SHA256SUMS` in the ignored evidence folder; it does not update publication records or production
source.
