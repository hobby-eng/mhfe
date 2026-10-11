# AUD-019 native review probes

Time zone: UTC (+00:00)

Privacy-only documentation update: this is not a new audit. No checks were rerun; recorded results and evidence are unchanged.

These review-only probes belong to AUD-019 and the clean MHFE 0.6.0 commit `66f142566464255e331763966b00ea1681c2dabd`. They inspect native Rust/C source, the Python fast-mode fallback, terminal rendering and original AUD-015/AUD-016 findings. They edit no production, test, fixture, dependency or workflow file. Evidence remains local-only under the ignored `docs/audits/AUD-019-evidence/` folder. The exact reviewer model and reasoning effort are unknown.

Run from the repository root with Python 3 on Linux. `probes.py` imports retained AUD-018/AUD-016 terminal helpers in place without changing their bytes or writing bytecode. PTY probes require the published fixture `tests/fixtures/suite3-vectors/zero-12.json`, `/proc`, a UTF-8 host locale and a terminal width policy giving U+754C and U+1F680 two cells. Subprocesses use public/synthetic inputs, cap address space at 512 MiB, disable core dumps and stop before any KDF completes. Python refusal probes also cap CPU time at five seconds and apply a six-second deadline.

```sh
python3 docs/audits/AUD-019-harnesses/run.py native-source-scan python3 docs/audits/AUD-019-harnesses/native/probes.py source-scan
python3 docs/audits/AUD-019-harnesses/run.py native-python-packaging python3 docs/audits/AUD-019-harnesses/native/probes.py python-controls packaging/mhfe-fast-mode.py --raw-label native-python-packaging
python3 docs/audits/AUD-019-harnesses/run.py native-platform-style python3 docs/audits/AUD-019-harnesses/native/probes.py platform-style
```

The source scan hashes every current Rust/C/header/assembly file below `src`, the native build entry, every vendored Argon2 file, all four native launchers and the two terminal-width/terminal-suite scripts. It verifies equality with HEAD, checks all 22 documented vendor hashes and records I/O/environment/entropy/diagnostic candidates for manual data-flow review. Lexical matches are candidates, not findings. It optionally compares the retained local AUD-018 inventory when that evidence is available. The JSON inventory contains exact examined hashes, line numbers and candidate text.

The Python cases cover a missing checksum under a parent directory containing OSC 52, an OSC 52 checksum name, an invalid option containing OSC 52, invalid UTF-8 in the checksum file, and a C1 CSI checksum name. OSC 52 carries only the public text `PUBLIC-SYNTHETIC`. Every case must refuse with exit 2, empty stdout, no raw ESC/C1 control in stderr and no traceback. They stop before listener construction. Raw stdout and stderr are captured only as `.bin` evidence; JSON prints lengths, hashes and control counts without rendering the payload. This checks original AUD-015-SEC002 and its related parser-error boundary.

The platform-style case calls the current terminal suite's report helper with unavailable isolation/input marks and a passed hash mark. It verifies grey unavailable marks and bold green passes, including wrapped lines, and checks the matching production `ComponentOutcome::NotAvailable` mapping. It does not emulate or execute macOS.

Wait for the coordinator to bind the current binary to the reviewed source and verify its version/hash before these commands. A new Cargo invocation may reuse previously compiled artifacts; it does not establish an uncached rebuild:

```sh
python3 docs/audits/AUD-019-harnesses/run.py native-version target/release/mhfe --version
python3 docs/audits/AUD-019-harnesses/run.py native-python-dist python3 docs/audits/AUD-019-harnesses/native/probes.py python-controls dist/core/mhfe-fast-mode.py --raw-label native-python-dist
python3 docs/audits/AUD-019-harnesses/run.py native-fingerprint python3 docs/audits/AUD-019-harnesses/native/probes.py fingerprint
python3 docs/audits/AUD-019-harnesses/run.py native-path-controls python3 docs/audits/AUD-019-harnesses/native/probes.py path-controls
python3 docs/audits/AUD-019-harnesses/run.py native-unicode-original python3 docs/audits/AUD-019-harnesses/native/probes.py unicode-original
python3 docs/audits/AUD-019-harnesses/run.py native-unicode-rocket python3 docs/audits/AUD-019-harnesses/native/probes.py unicode-rocket
python3 docs/audits/AUD-019-harnesses/run.py native-low-memlock python3 docs/audits/AUD-019-harnesses/native/probes.py low-memlock
python3 docs/audits/AUD-019-harnesses/run.py native-cli-options python3 docs/audits/AUD-019-harnesses/native/probes.py cli-options
```

Fingerprint probes require that neither a published mnemonic nor a synthetic password entered in the wrong public field reaches an error. Rust path probes require literal escaped path controls. Both Unicode cases require column 23 after the two-cell character plus ASCII deletion; they address original AUD-016-UI001. The low-memory-lock case sets a 4096-byte quota and requires a truthful deferred summary, an actual-buffer warning after the public phrase is accepted and restored terminal settings; it addresses AUD-016-SEC002. CLI option probes verify public option contracts and refuse invalid choices before secret work. The PTY helper cancels with exit 130 and verifies restored terminal settings.

Passing probes exit 0; assertions or unavailable prerequisites exit nonzero and retain their original log. The source-scan and raw-byte files use exclusive creation. For a rerun use a fresh runner label and a fresh `--raw-label`; a rerun of the source scan also uses a fresh `--inventory-label`. No historical harness is modified.

The first source scan incorrectly assumed vendor-prefixed paths in the checksum documentation and failed its count assertion. Its retained log is a harness failure. The corrected scan reads the actual relative paths and passes, with no production change. The local `python3 scripts/generate-cell-widths.py --check` refuses the installed Unicode 16 database; shared CI evidence from the reviewed commit verifies the generated table against the pinned Unicode 17 database instead. This local gap remains explicit.

The independent skeptic supplement reads the core/browser source, the published specification paragraph and retained coordinator evidence. It checks current CI log assertions for detected-length rehearsal and same-recovery retry in all four browser/mode combinations, distinguishes real WASM with reduced-cost C Argon2 from the eight additional stand-in cases, and records the dirty host module identities. It performs no product execution, new browser run, build or KDF. Run it once after the shared evidence exists:

```sh
python3 docs/audits/AUD-019-harnesses/run.py native-skeptic-source python3 docs/audits/AUD-019-harnesses/native/skeptic.py
```

Success exits 0 and creates `native-skeptic-source-bindings.json` in the local evidence folder. A missing assertion, changed published paragraph or missing input fails visibly. The output uses exclusive creation, preserving any earlier evidence. Source/log binding alone does not prove cryptographic security, physical memory erasure, toolchain trust or full foreign host acceptance.
