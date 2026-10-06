# AUD-007 retained harnesses

## Independent remediation recheck

The follow-up of 2026-10-05 reviewed the initially clean commit
`447c2bd22c91ac25bb4d4e442b6d4a82ee794307`. New command records use `recheck-` labels;
the original snapshot and command ledger are retained. Neither harness below uses Argon2,
network access or real wallet material.

`recheck_bech32_padding.py` builds `recheck_bech32_padding.rs` against the current debug MHFE
and Bech32 libraries. Run `cargo build --locked --bin mhfe` first with the pinned toolchain,
then, from the repository root:

```sh
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- python3 docs/audits/AUD-007-harnesses/recheck_bech32_padding.py
```

It appends a zero or nonzero five-bit data group to the public Cosmos and Injective account
vectors and recomputes their valid Bech32 checksums. Expected reproduction output has four
lines with `data_groups=33; accepted=true; same_reference=true`. Exit zero reproduces FUN003;
after repair the retained finding assertion must fail. Add proper negative regression tests
to the production suite when the parser is repaired. The executable and its input hashes stay
in ignored local evidence; no source checkout is copied.

`recheck_evidence.py` verifies the seven recorded remediation logs and their exit codes,
confirms that the original audit command register and snapshot equal those in `3c2793d`,
and verifies the five commits through `2a5e727` against `~/.ssh/hobby-eng_signing.pub`.
It requires local AUD-007 evidence and that public key; it never accesses a private key or
changes Git configuration. Its allowed-signers file is local ignored evidence. Run:

```sh
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- python3 docs/audits/AUD-007-harnesses/recheck_evidence.py
```

Expected output verifies seven log records and five good signatures; any discrepancy is
nonzero. `validate_report.py` also validates the remediation and independent-recheck command
registers, their log hashes, the recheck source snapshot and the extended report IDs. The
original baseline coverage ledger is not rewritten into a new release-acceptance result.

## Owner-authorized remediation

The subsequent owner-authorized fixes were first uncommitted and bound by the local
`AUD-007-evidence/remedy-final-source.json` manifest. Until the commit binding below existed,
`validate_report.py` verified those exact working-source hashes; it still verifies the manifest
itself and the separate `ownerAuthorizedRemediation` command register. These records use `remedy-`
labels and preserve the earlier reproduction and failed-publication logs.

For the repaired account parser, run the production regression suite:

```sh
cargo test --locked --lib wallet::tests
```

Use the pinned toolchain/environment from AGENTS.md. Expected result is 19 passed wallet tests,
including the formerly accepted Cosmos/Injective references in lower and upper case. The retained
padding finding probe now reports `accepted=false` and exits nonzero, as its reproduction
assertion requires. No full-cost Argon2 replay or Windows runtime check is implied by this result.

## Commit binding

The fixes were later committed together with other work, so no commit holds the manifest's exact
bytes. The `commitBinding` record of 2026-10-06 names the signed commits that carry them (mhfe
`db56fdd4028f27012ae2c10cdafb672139645a5a` and `711c8f596a7f5548270288de4f07c5011c5784cb`, mhfe_spec `bbc1320f2da9eef1c377b20d3fcbf141ab523bb7`) and verifies the MHFE fixes on the released commit
`5a3729385ca2d6c6677a84e9618b8875564cc7f6`. `validate_report.py` checks that each named commit is
signed, is part of the checked-out history of its repository, and covers every owner-authorized fix.
Its commands use `binding-` labels; to rerun them at that commit, from the repository root:

```sh
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- cargo test --locked --lib wallet::tests
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- gh run view 37432125420 --job 112165201404 --log
```

The first expects 19 passed wallet tests, including `cosmos_accounts_refuse_redundant_data_groups`.
The second saves the canonical release job log; it has no LockedText warning, and its remaining
mhfe warnings are part of the observation AUD-007-BLD002. The second command reads GitHub Actions
and needs an authenticated `gh`; nothing else uses the network.

`cross_clippy.sh` runs the canonical build's Clippy checks for `aarch64-unknown-linux-gnu` and
`x86_64-pc-windows-gnu` on a source tree it reads as a tar stream, inside the `dependencies` stage
of `packaging/Dockerfile.reproducible`, without network. Build that stage once, then run it on the
reviewed commit and on the fix:

```sh
docker build --target dependencies -f packaging/Dockerfile.reproducible -t mhfe-deps:local .
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- bash -c "git archive 52b6b36 | docs/audits/AUD-007-harnesses/cross_clippy.sh"
python3 docs/audits/AUD-007-harnesses/run.py run YOUR-UNUSED-LABEL -- bash -c "git archive 40f1193 | docs/audits/AUD-007-harnesses/cross_clippy.sh"
```

The first fails with exit code 101 on the BLD002 warnings; the second passes for both targets.

## Original baseline harnesses

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

`wallets_private_session.py` belongs to the remediation update of 2026-10-05, not to the review
of `d1cf47d0960a5023e6e503310802e5e2da438568`. It verifies AUD-007-SEC005 at commit
`ba75301b91e2cb2715c8c442a3f7907d6881d81e` with one real `mhfe wallets` session at full cost on
the public zero-12 suite 3 container: the container's own public password is refused by rule I29
and its message stays readable, a synthetic password opens a 24-word wallet, and the main screen,
everything outside the terminal's alternate screen, shows no wallet, no wallet number and no
question about another one. `mhfe decrypt` with the synthetic password must then give the shown
wallet, unverified. It needs Linux or macOS, Python 3 and a release build
(`cargo build --locked --release`, or a program path as its argument). It runs the self-test and
three recoveries at 2 GiB, about four minutes, so run it in a memory-capped unit:

```sh
python3 docs/audits/AUD-007-harnesses/run.py run remediation-wallets-private-session -- systemd-run --user --wait --pipe --quiet -p MemoryMax=3500M --working-directory="$PWD" /usr/bin/python3 "$PWD/docs/audits/AUD-007-harnesses/wallets_private_session.py"
```

Expected output ends with two `OK:` lines and exits zero; a failed assertion exits nonzero. The
remediation update also reran the FUN001 and SEC002 probes above, which now fail as expected, and
records every command, exit code and log hash in the report.

`validate_report.py` checks the paired AUD-007 Markdown/JSON against the shared audit schema,
rejects duplicate keys, verifies all 32 procedure IDs and finding records, compares command-log
hashes and the reviewed source snapshot, and checks the later Electrum documentation follow-up
separately. It requires Python 3, the existing `jsonschema` package, the paired reports, the shared
procedure files and the local ignored evidence captured by this audit.

```sh
python3 docs/audits/AUD-007-harnesses/validate_report.py
```

Since the remediation update it accepts every status of the audit standard; a finding's status
must agree in the register, the remediation table and the JSON, and every named fix or
verification commit must exist in this repository. Expected output is passing validation JSON with
12 findings and 32 procedure checks. A failed
assertion or schema error exits nonzero. It writes only local `report-validation.json` and
`SHA256SUMS` in the ignored evidence folder; it does not update publication records or production
source.
