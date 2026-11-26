# Targets of mhfe

What each target is for the program and its library, and how CI, the release and an audit check
it, beyond the workspace's audit guide, version 2, whose section 17, "Rust crates and native
targets", applies here. The audit reconciles this file with `rust-toolchain.toml`,
`packaging/Dockerfile.reproducible`, the workflows [ci.yml](../../.github/workflows/ci.yml),
[release.yml](../../.github/workflows/release.yml) and [audit.yml](../../.github/workflows/audit.yml),
and the [README](../../README.md), and reports a mismatch. A report records the SHA-256 of this
file.

## Target matrix

Whether a target is released, whether a release audit must run it, and what CI does now stay apart.
A result belongs to the report, never to this file.

| Target | Support | Release audit runs it | CI now | Runner and minimum cases |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Released program | Required | `scripts/check.sh`: gates, Clippy, every test, the release build, the terminal suite, the browser build and its checks, the fast-mode launcher; the fuzz targets linted | Native Linux: the self-test, isolation and its stop, hidden input in a pseudo-terminal, every command's prompts. |
| `aarch64-unknown-linux-gnu` | Released program | Required | Clippy, tests, build and the terminal suite on `ubuntu-24.04-arm` | ARM64 Linux: the cases of the x86-64 row, the seccomp filter's AArch64 table. |
| `x86_64-pc-windows-gnu` | Released program, cross-built with MinGW | Required | Clippy, tests, build and the terminal suite on `windows-2025` with the GNU toolchain | Windows: isolation, the console's hidden input, the access lists, error-report exclusions. |
| `x86_64-pc-windows-msvc` | Built by a user from source | Optional | Clippy, tests, build and the terminal suite on `windows-2025` | The cases of the GNU row with Microsoft's toolchain. |
| `aarch64-apple-darwin` | Released program, linked by Zig | Required | Clippy, tests, the hardened-runtime signature, the terminal suite on `macos-15`; the release runs the self-test and the terminal suite of the released program | Apple silicon: the sandbox, the signature with the hardened runtime and its check, hidden input. |
| `x86_64-apple-darwin` | Released program, linked by Zig | Required | Clippy, tests, the hardened-runtime signature and the terminal suite on `macos-15-intel`, the debug build optimized at level 1; the release runs the self-test and the terminal suite of the released program on `macos-15`, under Rosetta | Intel macOS: the cases of the Apple silicon row. |
| `wasm32-unknown-unknown` | Released browser package, with the Emscripten Argon2 module | Required | Clippy of every browser module; the build and `cargo xtask wasm verify dist` | Browsers: `cargo xtask browsers` and `cargo xtask package-check` run the package in the pinned Chrome and Firefox, by hand and for a release. |
| `x86_64-unknown-linux-gnu`, fuzzing | Test only | Required | `release.yml`: each fuzz target for 90 seconds with `nightly-2026-11-13`, cargo-fuzz 0.13.2 and AddressSanitizer | Native Linux: the fuzz targets of `fuzz/` with their own lockfile, which must stay unchanged. |

Not built: 32-bit targets, where mhfe-core's native engine does not compile; musl; and big-endian
Linux.

## Fuzzing and analysis budgets

- The three targets under `fuzz/` (`address`, `phrases`, `passwords`), with their own lockfile, are
  linted by `scripts/check.sh`. `release.yml` runs each for 90 seconds before the release.
- Ordinary audit: each fuzz target for 5 minutes; Miri on the host for the unit tests that make no
  system call.
- Release audit: each fuzz target for 30 minutes, and AddressSanitizer on the Linux x86-64 suite.

## Tests

- `cargo xtask terminal <program>` runs the program in a pseudo-terminal or pseudo-console and
  checks hidden input, the self-test report, a quiet start and damaged copies; count from its
  output that every case ran.
- A command stops before its first question when other programs could read its memory: the
  terminal suite runs only where secret-protection-core confirms that they cannot, which on macOS
  needs the hardened runtime that `cargo xtask macos-binary` signs a program with.
- `cargo xtask hardened` proves the refusal of the task port only on a Mac with System Integrity
  Protection on; GitHub's hosted Macs have it off.

## Permanent gaps

The hidden-input editor of the command-line tool has no fuzz target, as it lives in the binary;
its key handling is covered by the terminal suite. The browser runs in real browsers by hand and
for a release only. The release's Intel macOS run depends on Rosetta on GitHub's Apple silicon
runners.
