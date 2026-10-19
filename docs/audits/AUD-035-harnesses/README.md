# AUD-035 native policy follow-up

These public controls accompany the focused follow-up of CI run `39187816798`, built from
signed commit `8ebba34a2bcfaad3dbc4cd6f094e60b28516b8e2`. The report identifies the candidate
source files by SHA-256. No wallet input, privileged host setting or cryptographic parameter
is changed by these controls.

## Synthetic-signal control on Linux

With the workspace's pinned Rust 1.99.0 and Node 26.10.0 active, run from the repository root:

```sh
node docs/audits/AUD-035-harnesses/signal-control.mjs ../tmp/mhfe-aud035/signal-control
```

Choose a fresh executable path under workspace `tmp/`; an existing file is refused. The harness
compiles the standalone, dependency-free `signal.rs` for Linux x64, then starts two disposable
public children with core-file limits of zero. The first confirms that Rust's handler consumes
one synthetic `SIGSEGV` and resets itself. The second restores the default disposition and must
actually terminate with `SIGSEGV`. The command prints `PASS`, the source and executable hashes,
and exits zero only when both observations hold. It checks the active Rust version against
`rust-toolchain.toml` and records `rustc -vV`. Compilation is bounded to 45 seconds, the version
query and execution to 10 seconds each. An outer memory-budget recorder is still required:

```sh
MHFE_CHECK_RSS_LIMIT_KIB=524288 python3 docs/audits/AUD-033-harnesses/run.py \
  aud035-signal-control 75 node docs/audits/AUD-035-harnesses/signal-control.mjs \
  ../tmp/mhfe-aud035/signal-control-recorded
```

This Linux control demonstrates the Rust signal-handler mechanism; it does not establish
macOS `ptrace` enforcement. It raises a synthetic signal only in the explanatory children.
The actual macOS attachment test never raises a replacement signal to manufacture success.

## Native acceptance

On a macOS test host authorized for noninteractive sudo:

```sh
MHFE_PUBLIC_MACOS_ATTACH_PROBE_SUDO=1 cargo test --locked --bin mhfe \
  protect::macos::tests::macos_debugger_attachment_is_refused -- --exact
```

The existing ordinary test launches a fixed monitor. Its public tracing children restore and
read back default `SIGSEGV` handling. The unprotected attach/stop/detach control must pass;
the protected tracer must then terminate with the actual kernel signal. `EBUSY` alone, an
unavailable control, a panic and a missing exact test never establish protection. Only the
monitor and its named public probes are elevated; Cargo and production commands are not.

On Windows, run the actual process-protection and startup cases:

```sh
cargo test --locked --bin mhfe protect::windows::tests::windows_process_protections_are_enforced -- --exact
cargo test --locked --bin mhfe startup::tests::every_part_passes_at_start -- --exact
```

The disposable process starts with a successful external access-rights control, calls the real `harden`
entry point once, checks the complete stored DACL against the wanted descriptor, and requires
fresh external `PROCESS_VM_READ` and `WRITE_DAC` requests to fail. The SYSTEM grant uses the
process-specific full-access mask. Strict comparison and the owner grant remain intact. Each
exact command must report one passing test; zero selected tests are not acceptance. Hosted
CI additionally runs the complete reduced-cost native suites and optimized CLI builds. Full-cost
vectors, canonical packaging and release acceptance are outside this focused follow-up.
