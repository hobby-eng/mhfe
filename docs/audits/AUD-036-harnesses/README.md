# AUD-036 native fixture fidelity

This focused follow-up retains automatic CI run `39189322671` of signed commit
`c059b1afb00584d9a99fefe37247448b5ec7f3cd`. It covers Windows observer privileges and the signing
policy of intentionally damaged macOS known-answer fixtures. Production hardening and all
protection, refusal and report assertions remain unchanged.

From the repository root, with the pinned workspace tools active:

```sh
MHFE_CHECK_RSS_LIMIT_KIB=524288 python3 docs/audits/AUD-033-harnesses/run.py \
  aud036-local-fixtures 120 bash docs/audits/AUD-036-harnesses/checks.sh
```

Choose a fresh result label when rerunning. The existing recorder retains source, helper and
log hashes, exit codes, a finite deadline, process-group RSS and a 3 GiB machine reserve. The
local controls run formatting/standards/copies checks and import the real Python `damaged_copy`
helper with a synthetic byte fixture. Signing calls are explicitly mocked on Linux: the Darwin
branch must use the shared runtime-signing helper, the Linux branch must not sign, and a signer
refusal must abort. One bit changes in the copy and the source fixture stays intact. Normal
success prints `PASS` and exits zero; Python optimization is refused with a nonzero exit.

The retained baseline exercises the helper definitions from the exact Git object, in memory,
without another project checkout:

```sh
python3 docs/audits/AUD-036-harnesses/fixture-signing.py --baseline
```

It must exit nonzero on the former bare `codesign` call. This is a dispatch regression control,
not native macOS signature verification. The actual damaged known answers must still fail
startup/menu/full self-test with the exact original expectations after the shared script has
signed and verified the modified Mach-O file.

Native Windows acceptance requires the ordinary test:

```sh
cargo test --locked --bin mhfe protect::windows::tests::windows_process_protections_are_enforced -- --exact
```

It must run exactly one passing test. Both external observer children now require no thread
impersonation or SYSTEM context, disable only their own `SeDebugPrivilege`, and read back its
absence or disabled state through bounded token metadata before requesting fresh `VM_READ`
and `WRITE_DAC`. Both unprotected grants and both protected denials remain mandatory. A helper
failure remains a test failure. No production, target-process or host token policy is changed.
Successful child output can be captured by the test harness; a passing run does not establish
that its inherited debugger privilege was enabled before preparation.

Native macOS acceptance uses the optimized, runtime-signed CLI:

```sh
cargo build --locked --release --bin mhfe
scripts/harden-macos.sh target/release/mhfe
python3 scripts/verify-hidden-input.py target/release/mhfe
```

The ordinary paired attachment test remains required separately. Do not change the packaging
verifier's deliberately unsigned negative control. Full-cost vectors and canonical release
packaging are outside this scoped follow-up; these changes add no application startup work.
