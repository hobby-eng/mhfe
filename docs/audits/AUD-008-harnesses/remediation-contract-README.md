# AUD-008 option, documentation and terminal remediation checks

These focused follow-ups check fixes after `e854d6ed582321636d44b6423cf965df5b42e32d`.
The final UI patch is uncommitted and is bound by the source hashes in the new evidence.
They use public fixtures only, call no Argon2, do not rebuild the project, and never overwrite
the original audit records. Build a current debug executable and production rlib through the
repository's existing Cargo configuration before compiling or running them.

`remediation-contract-check.py` imports the retained original UI probe's PTY and text-grid helpers.
It checks 44 `rekey --words` combinations, repeated arrows at 40/60/80 columns, resized menus and
choice lists, and short-height Help dispatch and Escape restoration. It checks the same-length
length guard before typing any password. Current-width row checks on choice lists assume normal
terminal reflow; they do not erase or copy any phrase above the choice. The short-height cases
check dispatch and cancellation, not whether all menu entries fit simultaneously. A reconstructed
text grid is not a live graphical-terminal screenshot.

```sh
python3 -B docs/audits/AUD-008-harnesses/record-command.py --label remediation-contract-new --timeout 120 -- python3 -B docs/audits/AUD-008-harnesses/remediation-contract-check.py target/debug/mhfe docs/audits/AUD-008-evidence/remediation-contract-new.json
```

`remediation-public-contract.rs` links to the actual production rlib. It rejects all five retained
Dash padding aliases and their uppercase forms, keeps canonical controls, reproduces the wrong-card
example that can give a different checksum-valid container, and checks both public source-check
fixtures with their crossed negative controls. It also compiles the public empty-passphrase
`Reference::WalletCheck` variant. Compile with the workspace Cargo/Rustup homes, then record the
execution under a new evidence label:

```sh
rustc --edition=2021 docs/audits/AUD-008-harnesses/remediation-public-contract.rs --extern mhfe=target/debug/libmhfe.rlib -L dependency=target/debug/deps -o docs/audits/AUD-008-evidence/remediation-public-contract-new
python3 -B docs/audits/AUD-008-harnesses/record-command.py --label remediation-public-contract-new --timeout 30 -- docs/audits/AUD-008-evidence/remediation-public-contract-new
```

The original `wallet-challenge-probe.rs` and `wallet-challenge-run.py` can be compiled and run in the
same way, passing a new output pathname. They now pass all 34 strict mainnet/testnet padding,
checksum-kind, case, path and search-limit cases rather than reproducing the original aliases.
The scripts are retained unchanged; only fresh binaries and new output records are used.

`remediation-doc-contract.py` checks the three documentation findings against the current
counterpart specification and independently reproduces both complete public SHA-256 digests with
Python's PBKDF2. It verifies that the relocated measurements link targets the corresponding source
document. It does not claim that a browser package was rebuilt or that the remote link was fetched.

```sh
python3 -B docs/audits/AUD-008-harnesses/record-command.py --label remediation-doc-contract-new --timeout 30 -- python3 -B docs/audits/AUD-008-harnesses/remediation-doc-contract.py docs/audits/AUD-008-evidence/remediation-doc-contract-new.json
```

Each follow-up exits zero only when its assertions pass. Use a fresh evidence pathname and label
for every replay. The initial failed resize reproduction and an initial probe compile that used a
private module path remain recorded separately; they are not successful verification runs.
