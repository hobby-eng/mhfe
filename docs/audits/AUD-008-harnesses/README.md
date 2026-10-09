# AUD-008 — MHFE pre-release audit harnesses

These scripts reproduce scoped checks from the eleven-reviewer audit of MHFE 0.5.0 at
`632af98b6ce06a73dd2e27ed606e0a4212daed09`, including the captured dirty source bytes.
The product fingerprint is
`9e5357c0b085c7f68ec3c30b6940147b2aaaf89bb8f6dcbf9ea0d2d6593c790a`.
The read-only counterpart specification is at
`28e50e049d48cf1d5a8a529380192b6371458a57`.
This folder contains audit material, not release runtime code. No commits or publication
were authorized by the audit.

Run from the authoritative `mhfe` repository root. Follow the workspace and repository
AGENTS instructions, using the existing Rust/Cargo homes, Node 26.10.0 and Python 3.14.4.
All inputs are public vectors, synthetic buffers and fixed public loopback markers.
Never substitute a real wallet phrase or password. Evidence and binaries belong only in the
ignored sibling `AUD-008-evidence/` folder. Do not reformat or overwrite retained evidence.

## Shared execution and record checks

`record-command.py --label <new-label> --timeout <seconds> -- <argv...>` records an exact
command, UTC timing, exit code and log SHA-256. It refuses an existing label and bounds only
its own subprocess group. Use a new label for every replay, including a failed setup.

```sh
python3 docs/audits/AUD-008-harnesses/capture-snapshot.py
python3 docs/audits/AUD-008-harnesses/record-command.py --label example-new --timeout 30 -- python3 --version
```

`capture-snapshot.py` first captures tracked non-audit file hashes, HEAD, procedure hashes
and dirty patches for MHFE and its specification. If a snapshot already exists, it verifies
current product bytes without replacing that baseline. Exit 0 means unchanged; exit 1 means
a changed source/HEAD. It deliberately excludes audit files from the product fingerprint.

`coverage-plan.json` retains the assignment of all 32 procedure items before execution.
The final report distinguishes applicable scoped checks, failures, partial coverage and
inapplicable features. It does not claim the long full-cost vector replay was performed.

After all specialist records exist, the following commands assemble and validate the canonical
Markdown/JSON pair. They need the local evidence contributions and the shared schema under
`../multi-chain-wallet-tools`; Python `jsonschema` is already available in this environment.
Use them only for this audit, not to regenerate earlier published audit records.

```sh
python3 docs/audits/AUD-008-harnesses/assemble-report.py
python3 docs/audits/AUD-008-harnesses/validate-report.py
```

Assembly prints the finding/reviewer/coverage counts and writes the report pair. Validation
returns 0 only if the schema, duplicate-key rules, paired findings, 11-agent ledger, all 32
checks, source/procedure hashes, command logs, index links and ignored/unstaged evidence
agree. It writes local `report-validation.json`. Final local `SHA256SUMS` excludes itself
and includes completed command logs, records, scripts and the report pair. Assembly and
validation are record checks; passing them does not mean the product findings are fixed.

## Protocol and wallet arithmetic

`crypto-static-protocol.py` needs the English BIP39 list from the pinned `bip39-3.0.0`
Cargo registry source already installed in the workspace. It checks published transcript
arithmetic using retained Argon2 keys, not a full KDF replay:

```sh
python3 docs/audits/AUD-008-harnesses/crypto-static-protocol.py --wordlist /home/user/Documents/bip_tools/workingspace/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bip39-3.0.0/src/language/english.rs
```

Expected baseline: 27 positive transcripts, 648 forward/inverse rounds, source/checksum,
repair and password-check vectors agree; exit 0. No Argon2 is computed.
`crypto-api-probe.rs` is compiled with the exact current debug `mhfe` rlib and dependency
directory named in the local `crypto-api-compile.command.json`. It demonstrates that a
wrong repair card can return a different checksum-valid plate, and the generic API accepts
short entropy. Exit 0 means its diagnostic assertions matched, not that the misleading
repair rejection promise is true. It executes no Argon2.

`wallet-api-probe.rs` similarly uses the current production rlib. `wallet-independent.py`
uses installed `cryptography` 46.0.5/OpenSSL for EC arithmetic, its own BIP39/BIP32/hashes
and address codecs, and literal public addresses in `src/wallet.rs`:

```sh
python3 docs/audits/AUD-008-harnesses/wallet-independent.py --root /home/user/Documents/bip_tools/mhfe --probe /home/user/Documents/bip_tools/mhfe/docs/audits/AUD-008-evidence/wallet-api-probe --output /home/user/Documents/bip_tools/mhfe/docs/audits/AUD-008-evidence/wallet-new-replay.json
node docs/audits/AUD-008-harnesses/wallet-bech32-reference.mjs /home/user/Documents/bip_tools /home/user/Documents/bip_tools/mhfe/docs/audits/AUD-008-evidence/wallet-new-replay.json
```

The second command uses the existing pinned `@scure/base` 2.4.0 installation in wallet tools
as an independent strict padding decoder. No dependencies are installed by these probes.
At baseline 43 literal addresses agree; 138 API cases expose exactly five malformed Dash
padding aliases. Diagnostic exit 0 confirms this expected reproduction, not strict parser
conformance. The separate [wallet challenge guide](wallet-challenge-README.md) documents
the 34-case mainnet/testnet challenge and its expected failure interpretation.

## Specialist probes

| Scope                                               | Entry point / guide                                                      | Baseline interpretation                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Native isolation, moving allocator, retained locks  | [secrets-README.md](secrets-README.md)                                   | Exit 1 reproduces the current product defect; exit 2 is a blocked diagnostic.                               |
| Actual JS lifecycle with stand-ins                  | [browser-README.md](browser-README.md)                                   | Scoped lifecycle assertions; not full-cost crypto or complete memory erasure.                               |
| Fresh WASM callback seams and inactive stack copies | [browser-independent-README.md](browser-independent-README.md)           | Clarified diagnostic passes; original overstrict failure retained.                                          |
| CLI rekey dispatch and hidden input                 | [qa-README.md](qa-README.md)                                             | Six length-guard failures with four controls; unchanged capable-terminal gate separately passes.            |
| Documentation and relocated links                   | [doc-README.md](doc-README.md)                                           | Current prose/link defects yield nonzero; no algorithm modification.                                        |
| Independent architecture seams                      | [architecture-independent-README.md](architecture-independent-README.md) | Source/export/constant checks pass; existing formatter defect is not duplicated.                            |
| Wallet reference and recovery challenge             | [wallet-challenge-README.md](wallet-challenge-README.md)                 | Ten padding failures are one root cause; 24 controls pass.                                                  |
| Terminal colors, narrow width and split TTY         | `ui-terminal-probe.py`                                                   | 29/33 final assertions pass; four failures represent two causes. Original cleanup race retained separately. |
| Artifact inventory/provenance                       | `devops-artifacts.py`, `devops-static.py`                                | Cached/uncached byte checks pass; signing-policy preparation gap remains explicit.                          |
| Ranked optional research                            | `research-static.py`, [research-README.md](research-README.md)           | Citation/source bindings pass; seven proposals are not implemented protections.                             |
| Skeptic challenge                                   | `skeptic-snapshot.py`, `skeptic-devops-static.py`                        | Exact-source bindings and scoped challenge; final dispositions in local final-skeptic-review.json.          |

The UI probe uses fresh `target/release/mhfe`, public repair data, PTYs and bounded terminal
grids; it generates no real wallet and runs no Argon2. The early `new` split-terminal check
stops at settings. Later secret-output implications are source-traced, not a generated-wallet
runtime result. See its local exact command and final interface contribution for all cases.

The Linux io_uring probe must be run under host policy permitting the facility and the public
loopback receiver. A task sandbox denying the initial receiver cannot establish that the
product seccomp boundary is safe. The audit retained both that sandbox failure and a narrowly
authorized host reproduction. No remote endpoint is used.

## Release artifacts

`artifacts.py` validates the four freshly built canonical archives, their SHA256SUMS,
legal files, source metadata, browser runtime hashes and test-only marker exclusion. It
extracts only the native executable into ignored evidence to run `--version`; it creates
no additional source checkout. It can compare two release folders:

```sh
python3 docs/audits/AUD-008-harnesses/artifacts.py canonical-output-aud008cached/release canonical-output-aud008uncached/release
```

Expected: four matching archive hashes and `cachedAndUncachedMatch: true`, exit 0. The
independent DevOps artifact probe stream-reads the same archives without extraction.
Canonical build commands and their logs are retained locally; do not start those heavy
builds in parallel with Argon2 or other agents' heavy work. The user explicitly excluded
hours-long Rust/Python full vector replays. Reproducible bytes do not prove native runtime
acceptance on Windows, ARM or macOS, which was not performed in this audit.

## Authorized remediation verification

The report preserves the original findings and adds a separate, owner-authorized follow-up.
Its product snapshot identifies exact current source bytes; committing those same bytes does
not invalidate the checks. The coordinator subsequently received authorization to commit.
The original reports and evidence remain retained locally, with their SHA-256 values in the
follow-up. Baseline observations above describe the original source, not current failures.

The scoped follow-up guides are [remediation-security-README.md](remediation-security-README.md)
and [remediation-contract-README.md](remediation-contract-README.md). They cover actual Linux
isolation, four concurrent workers, retained locks and TTY checks; strict wallet decoding,
44 rekey cases, menu/choice resizing and documentation/public-vector correspondence.
`remediation-serve.py` starts the current CLI server with a synthetic, hash-listed HTML file
and checks four concurrent loopback requests, isolation headers and clean shutdown. Run it
with `python3 -B docs/audits/AUD-008-harnesses/remediation-serve.py`; it uses no browser or
remote endpoint. Network and namespace probes need host permission for those local facilities.

The browser package was rebuilt through `scripts/build-wasm.sh`, reusing the retained,
hashed Argon2 outputs, and tested through `node scripts/verify-browser-package.mjs` at reduced
cost in both threaded and single-threaded modes. `remediation-package-guide.py` checks that
the fresh package contains the current guide, resolves its source URL against the local
repository and verifies all seven runtime checksums. It does not check remote availability.

The baseline assembler and `validate-report.py` are historical tools: do not rerun them to
overwrite the remediation report. Current record checks are:

```sh
python3 -B docs/audits/AUD-008-harnesses/remediation-validate.py
python3 -B docs/audits/AUD-008-harnesses/remediation-validator-negative.py
```

They need the retained original and follow-up local evidence plus the shared JSON schema.
Exit 0 means the current source/procedure/harness hashes, preserved historical records,
signed fix ancestors, command ledgers and ten verified statuses agree. The negative helper
must reject twelve deliberate in-memory corruptions. The current validator writes only
`remediation-report-validation.json`; the original `report-validation.json` is not replaced.
This follow-up is not a new full audit or final release approval. Full-cost vector replays,
canonical archive rebuilds and non-Linux native acceptance were not repeated.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: b6993bb1c11834a01847d1812b31a24145ab1f18 -> 632af98b6ce06a73dd2e27ed606e0a4212daed09.
