# AUD-016 native boundary probes

These small, public-data probes review the native CLI, terminal input and memory-locking status. They belong to AUD-016, reviewed HEAD `3c60594479302827fe40975b04fd07f9f6fd4b3b` and the pre-existing dirty source fingerprint `0c282ddd47edbe418644f19a5ae136fedd68fc13cb1e3b61972dc7f7e6d74f41`. No production, test or fixture file was changed by this reviewer.

The coordinator rebuilt the release CLI from that source. Its SHA-256 is `8f114cd22a6aa6d7cfc4df03f65ac6cb526f23d5ff1c21820ac05c3e8914e4a1` and `--version` reports `mhfe 0.5.1`. Earlier artifact probes had the same binary hash; repeated probes add no independent coverage. The fresh build record is local-only in `docs/audits/AUD-016-evidence/build-native.command.json`.

`boundary-probes.py` needs Linux, Python 3, PTYs, `/proc`, and that existing release binary. It reads the published `tests/fixtures/suite3-vectors/zero-12.json` container (SHA-256 `ae05b76a2f8baed5634206631a1ed015dcaaf029cee226f05147a3c650eb036c`), the public BIP39 phrase `abandon` eleven times followed by `about`, and synthetic password text. It never completes a cryptographic operation. Each child has a 512 MiB address-space limit and a zero core-file limit. PTY cases cancel with SIGINT before expensive work and check that terminal settings were restored. The missing-checksum probe creates and removes one disposable directory; it serves no page and opens no browser.

Run from the repository root. Use fresh evidence labels so retained records are not overwritten:

```sh
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-version target/release/mhfe --version
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-path python3 docs/audits/AUD-016-harnesses/native/boundary-probes.py path-controls
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-fingerprint python3 docs/audits/AUD-016-harnesses/native/boundary-probes.py fingerprint-redaction
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-unicode python3 docs/audits/AUD-016-harnesses/native/boundary-probes.py unicode-cursor
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-dumb python3 docs/audits/AUD-016-harnesses/native/boundary-probes.py dumb-container
```

The final probe needs the existing release library and a tiny directly linked witness. The following command uses the workspace toolchain and does not run Cargo or rebuild MHFE. The rlib filename binds this execution to the reviewed build; if it is unavailable, obtain a coordinator-authorized build and record its source and library hash before adapting the filename.

```sh
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-lock-compile ../workingspace/rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/bin/rustc --edition=2021 -C panic=abort -C opt-level=2 -L dependency=target/release/deps --extern mhfe=target/release/deps/libmhfe-c086f5778ff03b66.rlib docs/audits/AUD-016-harnesses/native/lock-claim.rs -o docs/audits/AUD-016-evidence/native-lock-claim
python3 docs/audits/AUD-016-harnesses/run.py native-rerun-lock python3 docs/audits/AUD-016-harnesses/native/boundary-probes.py low-memlock
```

`lock-claim.rs` calls the production `LockProbe` and builds a production `LockedText` with the CLI's 8192-byte input capacity. It copies no allocator or locking implementation. The Python wrapper applies `RLIMIT_MEMLOCK=4096` separately to the witness and the CLI, then checks the CLI summary and `VmLck` while one public word is being typed. The reviewed witness reports a passed probe with `typedBufferLocked=false`; the CLI claims secrets are locked while `VmLck` is zero. It measures no swap write or disclosure. This is AUD-016-SEC002, a misleading guarantee, distinct from historical lock lifetime and lock coverage findings.

The version and witness compilation commands exit 0. The current baseline produces these failed assertions, each exiting 1 and retaining JSON diagnostics plus a traceback:

- `fingerprint-redaction`: an invalid public fingerprint field repeats the entire public phrase in stderr (AUD-016-SEC001).
- `low-memlock`: the locking summary overstates the actual input-buffer state (AUD-016-SEC002).
- `unicode-cursor`: deleting ASCII `a` after wide character U+754C emits column 22 where column 23 is needed (AUD-016-UI001).
- `path-controls`: a missing checksum error emits an OSC title sequence from its parent directory path (original AUD-015-SEC002, still incomplete).
- `dumb-container`: ciphertext is displayed on the main screen with `TERM=dumb`. This is a visibility/documentation observation, not demonstrated spending-authority exposure; containers are intentionally shareable encrypted output.

After remediation, the relevant assertion should pass with exit 0. The `TERM=dumb` assertion expresses the stronger private-display expectation and must be evaluated against the documented intended ciphertext policy. The initial `native-dumb-container-existing` run had a harness prompt-matching error because SGR codes divided its prompt; the corrected rerun and current run reproduced the display behavior. Initial lock witnesses ended with an assertion abort; the final witness exits 1 cleanly. All original records are retained, without replacing failures. Raw evidence and compiled witnesses stay local-only in the ignored evidence folder; this folder contains the rerunnable source.
