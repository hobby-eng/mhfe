# AUD-018 release-verification harnesses

These scripts belong to the 2026-10-09 UTC remediation follow-up and pre-release
verification of MHFE 0.5.1. Reviewed HEAD is
`3c60594479302827fe40975b04fd07f9f6fd4b3b` plus uncommitted changes, identified by
non-audit source-manifest SHA-256
`3ef3c5720216af0ed5dc7328c07d910bb82f99a90b28683ef88310af1a31c2b3`.
The specification's corresponding fingerprint is
`741baa99527ce090b2124d6244ec755304427b1ad284534e95cbbd324d79c5c9`.
No production, test, fixture, dependency or workflow changes are part of this
verification. No commit, tag or publication is authorized by these scripts.

## Inputs and dependencies

- The existing authoritative checkout, public test fixtures and retained
  [AUD-016 harnesses](../AUD-016-harnesses/README.md). `run.py` imports the historical
  runner without modifying it; the report pins its bytes. Preserve that dependency.
- Workspace Rust 1.99.0, Node 26.10.0, wasm-bindgen 0.2.129, Emscripten 6.0.10,
  Python 3.14.4, installed pinned Prettier/Playwright and Docker 29.8.2/BuildKit.
- Set `CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo` and
  `RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup`, replacing the
  anonymized home prefix with the actual workspace path. Host builds use
  `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=2`, `EMCC_CORES=1`.
- The user session's systemd/cgroup-v2 controller for the 4 GiB/no-swap heavy units.
  Small reviewer probes use 512 MiB limits. See [native](native/README.md) and
  [core](core/README.md); browser probes reuse immutable AUD-016 code.
- Original local `AUD-018-evidence` for report assembly; `jsonschema` for validation.

## Execution and retained evidence

```sh
python3 docs/audits/AUD-018-harnesses/run.py snapshot new-snapshot-label
python3 docs/audits/AUD-018-harnesses/run.py new-command-label node scripts/verify-no-copies.mjs
```

Use a new label for every attempt. Exact argv, UTC times, environment, exit and log
SHA-256 remain in ignored local evidence. The imported runner's sampled
process-group RSS excludes daemon-owned units: it is not the memory peak of the
workload. Heavy units use verified kernel cgroup limits instead; browser/canonical
`MemoryPeak` is captured by their unit stop hook. The report distinguishes these.

`bounded.sh` runs inside a transient unit, checks `MemoryMax=4294967296` and
`MemorySwapMax=0` before work, and records the actual group. The exact transient-unit
commands are retained in the report JSON. Heavy work runs one at a time. Runtime
caps keep a check from becoming an unlimited job.

`docker-cgroup.py` uses a tiny cached Alpine build and host `/proc` to prove that
BuildKit `RUN` processes descend from the bounded group. BuildKit hides cgroup
files inside its build container; the initial inside-container read failed and
was retained. The successful host witness supports `--cgroup-parent` inheritance.
The probe produces no release asset and copies no project tree.

`canonical.sh [output-name]` delegates to the repository's
`scripts/build-reproducible.sh`, adding only the task's cgroup parent. The default
output is `canonical-output-aud018`; the required second build sets
`REPRODUCIBLE_NO_CACHE=1` and uses `canonical-output-aud018_uncached`. Both are ignored
artifact directories. Default Docker build concurrency and pinned toolchains are
preserved; the older `canonical-output` and first comparison assets are retained.
The first uncached attempt used an output name with a forbidden extra hyphen and
was refused before Docker; the corrected attempt uses an allowed suffix. The
wrapper's first-build bytes are retained locally before adding the optional output
argument. `compare-canonical.py` checks exact four-file coverage, each directory's
checksum list and the archive bytes. Only equal archives establish the documented
cached/uncached comparison.

`metadata.py [label]` binds tool/repository identities and local/generated assets,
without rebuilding. Labels cannot be reused. `artifacts.py` verifies the four
canonical archives, their SHA-256 list, license bytes, dirty-source BUILD-INFO and
browser internal sums, reading archives without extraction. It records host versus
container comparisons without assuming every host compiler produces canonical
bytes.

`supply-chain.py` performs read-only build/config inventory and downloads the three
pinned tooling tarballs from `registry.npmjs.org` into memory. It verifies their
lockfile SHA-512 and compares archive files with the installed packages; it never
installs or runs them. Its strict directory inventory exits 1 on this installation
because three package-manager-generated `.bin` wrappers are extra files. The
separate `shim-review.json` records their full source, targets and local pnpm
template consistency. The final assessment classifies those extras separately;
it does not conceal a mismatching archive file or certify the package manager.

The native/browser malicious-code reviewers use source inventory and data-flow
traces, with hashes of the exact scoped files and static WASM import inventories.
The native [Python control-path probe](native/README.md) captures raw diagnostic
bytes without rendering OSC commands, and exits before constructing a listener.

After all reviewers and commands finish:

```sh
python3 docs/audits/AUD-018-harnesses/run.py snapshot closeout-final
python3 docs/audits/AUD-018-harnesses/assemble.py
node_modules/.bin/prettier --ignore-path /dev/null --write docs/audits/audit-18-2026-10-09.md docs/audits/audit-18-2026-10-09.json
python3 docs/audits/AUD-018-harnesses/validate.py
```

Format harness READMEs before assembly so their published hashes bind the final
bytes. Preserve the existing audit index and add AUD-018 before validation.
`assemble.py` needs all named local reviewer/command records. `validate.py` checks
the schema, pair, 32-item coverage, classifications, procedure/harness/log/source/
artifact hashes, current live non-audit source, links, privacy, UTC and ignored
evidence; it writes the local validation result and evidence `SHA256SUMS`. A
changed source or binding makes validation fail rather than silently blending
different snapshots. Do not overwrite earlier command attempts to obtain green.

## Scope and expected outcome

Full-cost MHFE/Argon2 vector replays are explicitly excluded by the owner, who
reports they were just checked. They are not counted as newly executed or as
skipped failures. Normal fast known-answer, negative, metadata and reduced-cost
tests remain part of the repository's mandatory checks.

`scripts/check.sh` and both-engine/both-mode real-browser verification are expected
to pass on this snapshot. Focused protocol/cleanup and native secret/cancel probes
pass. The rocket-width probe still reproduces original AUD-016-UI001, a Low
nonblocking incomplete fix. Historical specification commit references and the
stale browser-host handover remain separate release-readiness issues. A clean test
run does not close those issues or create a signed remediation commit.

The Python fast-mode helper retains original AUD-015-SEC002 control-path variants;
the Rust-only control test passes. This is an existing incomplete remediation,
not a confirmed malicious insertion. The scoped code/byte review found no
confirmed malicious payload; whole-machine compromise is outside its evidence.

Run report assembly and validation only after command completion; neither reruns
product suites. The report retains original IDs and distinguishes runtime/source
verification from formal signed-commit closure. Expected JSON/schema/hash/link
validation exits zero, even when the truthful overall release verdict is FAIL.
