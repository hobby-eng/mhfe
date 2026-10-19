# AUD-033 remediation controls

Run from the MHFE repository root with its pinned tools and public fixtures only.
This follows AUD-032 at base commit `575cbd1b7634646f6e19a2501ed9ea164a6a7acd`;
that commit alone does not identify the dirty working source. The AUD-033 report
binds the reviewed source, package and command identities. Historical AUD-032
controls and evidence are preserved.

Build the current browser package with `scripts/build-wasm.sh`, then run:

```sh
node docs/audits/AUD-033-harnesses/utility-boundaries.mjs
node docs/audits/AUD-033-harnesses/startup-reports.mjs
```

The first checks exact/excess raw UTF-8 and byte-view bounds, retained caller
ownership, growable shared-buffer extent admission, framed chosen/excluded
entries, actual class transport and cancellation while metadata is pending.
The second checks incomplete/duplicate final reports, captured shared-cache
identity and races, streamed failures, legitimate skipped checks, real class
inspection dispatch and its actual raw Rust inspection result. The worker is a
stand-in; these are not real-browser, malicious-producer authentication or
full-cost cryptographic controls. Both exit zero only when their assertions pass.

Build the current CLI with `cargo build --locked --bin mhfe`, then on Unix:

```sh
python3 docs/audits/AUD-033-harnesses/cli-retries.py target/debug/mhfe
```

`pinned-cli.py` runs the same controls against `target/debug/mhfe`, printing and
checking its SHA-256 before and after the complete run. The published control
also refuses optimized Python before starting any child:

```sh
python3 docs/audits/AUD-033-harnesses/pinned-cli.py
```

This exercises invalid UTF-8 visible answers, raw 1,024/1,025-byte BIP39
passphrases, retained earlier answers, script fail-fast behavior, and the normal
password/private-screen cancellation group. On Linux, accepted public-input
cases cap their child address space before a 2 GiB memory reservation, so they
perform no recovery. Elsewhere they cancel before accepting the final secret.
These do not substitute for native Windows console or macOS package execution.

All fixtures are public or synthetic. Commands must run without Python `-O`.
Run heavy builds/checks sequentially after coordinating the machine budget;
keep a 3 GiB host reserve. Generated results belong only in ignored local
`docs/audits/AUD-033-evidence/`. The complete standard package/browser checks
remain `node scripts/verify-browser-package.mjs` and
`node scripts/verify-browsers.mjs`; no full-cost vector replay is required by
these bounded remediation controls.

## Process-local Linux protection refusal

Build the tiny preload shim into ignored evidence, then run the current CLI
against it. This requires a dynamically linked Linux executable that honors
`LD_PRELOAD`; a static or secure-execution binary cannot exercise this shim.
This changes only the child process's `madvise(MADV_DONTDUMP)`
response, never a host setting. No secret input is supplied. The PTY control
must see a fatal `MEMORY_PROTECTION_FAILED` before the first secret prompt,
exit 1 and restored terminal settings. It exits nonzero if the old ignored
refusal behavior returns.

```sh
mkdir -p docs/audits/AUD-033-evidence
cc -shared -fPIC -O2 -Wall -Wextra -Werror -o docs/audits/AUD-033-evidence/refuse-dontdump.so docs/audits/AUD-033-harnesses/refuse-dontdump.c -ldl
python3 docs/audits/AUD-033-harnesses/dump-protection.py --shim docs/audits/AUD-033-evidence/refuse-dontdump.so
```

This is a synthetic protection-refusal test, not an actual core-dump exploit.
`cargo test --locked dump_protection`,
`cargo test --locked a_work_area_owns_and_confirms_every_dump_excluded_page`
and `cargo test --locked page_rounding_does_not_enlarge_the_extent_given_to_c`
exercise bounded metadata reads, whole-range policy readback and the logical
C extent separately, using tiny public buffers.

## Local evidence recorder

On Linux, `run.py LABEL TIMEOUT COMMAND [ARGUMENTS]` records the actual command,
UTC times, source manifests, helper hashes, output hash, sampled process-tree
RSS and the minimum host available memory under the ignored evidence folder.
A used label is refused. `MHFE_CHECK_RSS_LIMIT_KIB` sets a ceiling no greater
than 2.5 GiB; the fixed host reserve is 3 GiB. Cargo builds/tests and Emscripten
use one job. Source changes during a command are recorded, not hidden.
The timeout must be finite and positive before the command can start. The guard
terminates the process group, including surviving children after its leader
exits, when its sampled budget or timeout is exceeded. Receipts retain the
child's actual `exitCode`; `wrapperExitCode` is nonzero after any forced stop,
even when a signal handler makes the child exit zero. Sampling is not a kernel
memory cap, and daemon work such as Docker
is outside the client's process tree. Earlier receipts used the retained
private precursor; their exact helper hashes
and paths remain local, and are not replaced with this adapted public runner.
The precursor's receipts were checked for invalid timeouts and forced stops
misreported as success; neither occurred in the retained remediation runs.

The public recorder's controls include invalid timeout rejection, ordinary
success, a signal handler that exits zero, and a signal-resistant child left
behind by its leader. They use tiny synthetic processes and unique labels:

```sh
python3 docs/audits/AUD-033-harnesses/recorder-controls.py UNIQUE_PREFIX
```

For example, after receiving the exclusive heavy-check window:

```sh
MHFE_CHECK_RSS_LIMIT_KIB=1572864 python3 docs/audits/AUD-033-harnesses/run.py fast 600 scripts/check-fast.sh
```
