# Response-deadline tests against a lost timeout (AUD-024, verifier)

Audit AUD-024, commit b6fca69. Checks that the two fast-mode launchers' response-deadline tests
fail, within a time limit, when the response timeout they guard is lost, as the required
verification of AUD-023-ARC017 asks for the Python launcher.

`response_deadline_guard.sh` extracts the committed tree (`git archive HEAD`) twice into a scratch
folder and runs one test in each copy under `timeout`:

- control: `scripts/verify-fast-mode-script.py`
  `Server.test_a_client_that_does_not_read_is_dropped_at_the_response_deadline`, unchanged; it must
  pass;
- Python mutant: the same test with `connection.settimeout(None)` in `answer()` of
  `packaging/mhfe-fast-mode.py`;
- Rust mutant: `serve::tests::a_client_that_does_not_read_is_dropped_at_the_response_deadline`
  with `stream.set_write_timeout(None)` in `write_until()` of `src/bin/mhfe/serve.rs`.

Inputs: a scratch folder and a time limit in seconds (default 60). Needs Python 3, Rust (the
pinned toolchain) and coreutils `timeout`. `CARGO_TARGET_DIR` is used when set, otherwise
`<scratch>/target`. No Argon2 runs; no network.

Command, from the repository root:

```sh
CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target/verifier-arc017-deadline-hang \
  docs/audits/AUD-024-harnesses/verifier-arc017-deadline-hang/response_deadline_guard.sh \
  /home/user/Documents/bip_tools/tmp/aud024/verifier-arc017-deadline-hang/harness 60
```

Exit 0 when the control passes and both mutants fail within the limit; 1 otherwise; 2 when a
mutation could not be applied or the Rust copy did not build.

Expected output at b6fca69 (exit 1):

```text
control (unchanged Python test): exit 0
Python mutant ran 60 s
Python answer() with settimeout(None): NOT GUARDED (the test is still running after 60 s)
Rust mutant ran 60 s
Rust write_until() with set_write_timeout(None): NOT GUARDED (the test is still running after 60 s)
```
