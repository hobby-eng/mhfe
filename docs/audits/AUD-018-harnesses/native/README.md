# AUD-018 native remediation verification

These bounded public-data probes verify native CLI findings from AUD-015, AUD-016 and AUD-017 against the AUD-018 release candidate. Reviewed HEAD is `3c60594479302827fe40975b04fd07f9f6fd4b3b`; the dirty code fingerprint is `3ef3c5720216af0ed5dc7328c07d910bb82f99a90b28683ef88310af1a31c2b3`. HEAD alone does not contain the fixes. Local source manifests and fresh build records bind the reviewed bytes; verified source behavior does not close a finding on a signed remediation commit.

The script requires Linux, Python 3, PTYs, `/proc`, a host locale with Unicode character widths, the freshly built `target/release/mhfe`, and `tests/fixtures/suite3-vectors/zero-12.json`. It imports the retained AUD-016 PTY/input helpers in place without changing their source or writing bytecode. Inputs are the published zero-12 container and BIP39 phrase, synthetic passwords, and individual Unicode characters. No KDF completes. Child address spaces are capped at 512 MiB, core files at zero, and terminal sessions cancel with SIGINT and verify restored settings. The low-lock probe sets a 4096-byte memory-lock quota.

Wait for the release coordinator's fresh binary, then run from the repository root with fresh labels to retain every record:

```sh
python3 docs/audits/AUD-018-harnesses/run.py native-version target/release/mhfe --version
python3 docs/audits/AUD-018-harnesses/run.py native-fingerprint python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py fingerprint
python3 docs/audits/AUD-018-harnesses/run.py native-path-controls python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py path-controls
python3 docs/audits/AUD-018-harnesses/run.py native-unicode-original python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py unicode-original
python3 docs/audits/AUD-018-harnesses/run.py native-unicode-rocket python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py unicode-rocket
python3 docs/audits/AUD-018-harnesses/run.py native-low-memlock python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py low-memlock
python3 docs/audits/AUD-018-harnesses/run.py native-cli-options python3 docs/audits/AUD-018-harnesses/native/verify-boundaries.py cli-options
```

Each prints JSON diagnostics, including the binary and retained helper hashes. Passing checks exit 0; an unmet assertion exits 1 and preserves its diagnostics and traceback. Original CLI cancellation exits 130, and deliberately invalid options or identifiers exit 2; the harness still exits 0 when those expected refusals satisfy its assertions.

- `fingerprint` verifies that neither the public mnemonic nor a synthetic password mistakenly supplied as a fingerprint appears in the refusal (AUD-016-SEC001).
- `path-controls` replays the crafted parent-directory OSC sequence in a missing-checksum error (original AUD-015-SEC002).
- `unicode-original` replays U+754C plus ASCII deletion (AUD-016-UI001).
- `unicode-rocket` challenges the same width contract with U+1F680; both the Unicode East Asian Width property and host `wcwidth` identify it as two cells. It must place the cursor at column 23, as the CJK reproduction does. The [Unicode East Asian Width data](https://www.unicode.org/Public/UCD/latest/ucd/EastAsianWidth.txt) classifies U+1F680..U+1F6C5 as Wide.
- `low-memlock` verifies the startup summary's status and the actual buffer warning, stopping after the public original phrase and before accepting any password (AUD-016-SEC002). The flow defers its summary until cancellation; the actual allocation warning arrives when a line is accepted. The separate pre-input observation is retained, without assuming the summary was already visible.
- `cli-options` verifies the new non-secret command options and rejects invalid public choices before secret reads (AUD-017-UI001).

The retained AUD-017 static probes can also be replayed without a build:

```sh
python3 docs/audits/AUD-018-harnesses/run.py native-cli-static python3 docs/audits/AUD-017-harnesses/r2-cli/static_cli_rules.py
python3 docs/audits/AUD-018-harnesses/run.py native-scan-gap-static python3 docs/audits/AUD-017-harnesses/r4-build-docs/typed_defaults.py
```

These static probes check single-source wording, library-owned rekey eligibility, option presence and the shared scan-gap declaration. Source review separately traces the `Zeroizing` found-word output, recovery outside the confirmation loop, library-provided owner lengths, and the documented decrypt third-line passphrase/stderr outcome contract. Coordinator test and terminal-suite evidence supplies broader execution coverage; these checks do not duplicate it. Raw logs and generated results remain local-only in the ignored `docs/audits/AUD-018-evidence/` folder. No production, test, fixture, dependency or workflow file is edited by these harnesses.

The fresh reviewed CLI reports `mhfe 0.5.1`, SHA-256 `3db809ef6e2c0972ef323079bea1aa7fea9b1969edfdf22d26927d3e8110a316`. Fingerprint, parent-path, original CJK, final low-lock, options and both static probes pass. The rocket probe fails with expected column 23 and emitted column 22; AUD-016-UI001 therefore remains open as an incomplete fix, low severity and nonblocking. It has no new finding ID.

The first low-lock run omitted the length-choice answer and timed out at that menu. The next run required the summary warning before input, although the flow defers its summary. Both failed runs are retained under `native-low-memlock` and `native-low-memlock-rerun`. The final harness uses `--same-length` to answer that public choice and separately records before-input observations, the final truthful summary and the actual accepted-buffer warning; `native-low-memlock-final` passes. These harness corrections do not change production behavior or replace earlier logs.

The parallel source review also checks the Python fast-mode fallback against original AUD-015-SEC002. Run its small public-data probe once, after `dist/core/mhfe-fast-mode.py` exists:

```sh
python3 docs/audits/AUD-018-harnesses/run.py native-python-path-controls python3 docs/audits/AUD-018-harnesses/native/verify-python-path-controls.py
```

This requires Linux and Python 3, caps each child's address space at 512 MiB and CPU time at three seconds, and gives it a five-second deadline. It uses a synthetic parent-directory name and synthetic checksum entry containing an OSC 52 sequence for the public text `PUBLIC-SYNTHETIC`. Both cases refuse before any socket or browser is created. Raw stdout and stderr are saved only as local `.bin` evidence and are never displayed; JSON reports hashes, lengths and whether the sequence is present. Evidence files use exclusive creation. A rerun uses a fresh runner label and also passes a fresh raw-evidence label as the harness's optional argument, preserving the original files.

All four cases, for the packaging and freshly generated dist fallback, exit 2 with empty stdout and one raw OSC 52 sequence in stderr. The harness exits 0 when it reproduces that residual. Both scripts have SHA-256 `400db463129314dbc57e81ca742de51bfe011fe4f9df25e6f4974683cfdc1a28`. Original AUD-015-SEC002 therefore remains open as a partial fix: the Rust server's tested trigger is eliminated, but the shipped Python fallback still prints raw controls. This remains low severity and nonblocking; the review found no evidence that this pre-existing defect was introduced with malicious intent.
