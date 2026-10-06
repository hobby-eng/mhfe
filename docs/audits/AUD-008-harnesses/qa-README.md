# AUD-008 QA probes

These probes belong to the QA contribution to MHFE pre-release audit AUD-008, reviewing
commit `b6993bb1c11834a01847d1812b31a24145ab1f18` with the dirty source snapshot recorded locally in
`docs/audits/AUD-008-evidence/snapshot.json`. They modify no product, test, fixture or workflow file.
The existing checkout and its already built `target/release/mhfe` are the only product inputs.

`qa-pty-probe.py` imports the existing POSIX PTY helper from `scripts/verify-hidden-input.py`, using
only the published suite 3 zero-12 and suite 4 same-length-zero fixtures in `tests/fixtures/` and one
synthetic invalid password. Python 3 and Linux/macOS PTY support are required. No external package
or network is used. The rekey cases stop at the old-password prompt or input rejection; no password
is entered and no Argon2 operation is reached. The fallback case checks hidden input, rejection of a
TAB, cancellation and terminal restoration with `TERM=dumb`.

From the repository root, run:

```sh
python3 docs/audits/AUD-008-harnesses/qa-pty-probe.py target/release/mhfe
```

It prints ten case records and writes the local-only `qa-pty-probe.json`, including public PTY
transcripts, source/binary hashes and zero Argon2 calls. A conforming implementation exits zero.
The audited baseline exits 1 for six rekey cases: mismatched or invalid `--words` options are
silently ignored for a short container. The two positive short-container cases, the suite 3 invalid
length control, and the terminal fallback case pass.

The separate diagnostic command below reruns the complete unchanged production PTY gate in a
capable terminal. It exits zero on the audited binary. The original inherited-`TERM=dumb` failure
remains retained in the coordinator's `check-release-host.log`; the rerun is a distinct result.

```sh
env TERM=xterm-256color python3 scripts/verify-hidden-input.py target/release/mhfe
```

To retain exact command, time, exit code and log hash without overwriting older evidence, wrap a
command with the audit's shared `record-command.py` and a new label:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py \
  --label qa-pty-rerun --timeout 90 -- \
  python3 docs/audits/AUD-008-harnesses/qa-pty-probe.py target/release/mhfe
```

This harness tests CLI option dispatch and terminal behavior. It does not establish full-cost
encryption/rekey correctness or replace Windows/macOS runtime and full-vector replay evidence.
