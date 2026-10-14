# AUD-024 harnesses: build and release (build-release)

Audit AUD-024, role build-release, reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.
Run every command from the repository root on that commit. The scripts read the repository (and,
for the first one, release archives given on the command line); they write nothing but temporary
files that they remove. Each exits 1 when its check fails, 0 when it passes, and 2 on a wrong
command line where it takes arguments. No script runs Docker or Argon2.

## `mingw-runtime-notices.py`

Whether a Windows release zip carries a notice for the MinGW-w64 runtime code linked into its
`mhfe.exe` (CHECK-BLD-003). It looks in the program for texts only mingw-w64-crt writes (the
pseudo-relocation report, the `_matherr` report, the narrow and wide `(null)` of the printf core,
and the `Infinity` / `NaN` / `0` texts of gdtoa's dtoa) and fails when the program holds such code
while neither the zip's nor the checkout's `THIRD_PARTY_NOTICES.md` names MinGW-w64.

```sh
python3 docs/audits/AUD-024-harnesses/build-release/mingw-runtime-notices.py \
  canonical-output-aud023/release/mhfe-v0.6.0-windows-x86_64.zip
```

Input: one or more Windows release zips (for the audit: the AUD-023 canonical output, the local
v0.6.0 canonical output and the published v0.6.0 zip; the canonical build of b6fca69 itself stops
in its first stage). Expected at b6fca69: `FAIL` for every zip, all four kinds of runtime text
found, exit 1.

## `release-target-runs.py`

Whether every program a release ships is run by some check (CHECK-BLD-002): the targets of
`scripts/package-release.sh` against every `cargo test` of `packaging/Dockerfile.reproducible` and
`.github/workflows/`, with a fixed table of the runners' own targets (ubuntu and windows-2025 are
x86-64, the latter with the MSVC host toolchain; macos-15 is Apple silicon).

```sh
python3 docs/audits/AUD-024-harnesses/build-release/release-target-runs.py
```

No input. Expected at b6fca69: `FAIL` for linux-aarch64 (`aarch64-unknown-linux-gnu`),
macos-x86_64 (`x86_64-apple-darwin`) and windows-x86_64 (`x86_64-pc-windows-gnu`); the checks run
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu`; exit 1.

## `function-length-gates.py`

Whether `clippy.toml` (`too-many-lines-threshold`) and `.oxlintrc.json` (`max-lines-per-function`)
stop at the function length that RUST-01 and CORE-15 of the workspace guide give, read from
`code-rust.instructions.md` and `code-core.instructions.md`.

```sh
python3 docs/audits/AUD-024-harnesses/build-release/function-length-gates.py [<guide folder>]
```

Input: the workspace's `.github/instructions` folder (default: `../.github/instructions` from the
repository root). Expected at b6fca69 with the guide of 2026-10-14 (CORE-15 changed in the
workspace commit f09d363): guide 150, `clippy.toml` 100 and `.oxlintrc.json` 100, the comments
`clippy.toml:5` and `Cargo.toml:106` listed, `FAIL`, exit 1.

## `fast-gate-coverage.py`

Whether the provenance gates that take seconds (`scripts/third-party-licenses.py --check` and
`scripts/verify-vendored-argon2.mjs`) run on a push or a pull request, that is in
`scripts/check-fast.sh`, which `ci.yml` runs there; it also counts the crate versions of
`Cargo.lock` that the generated part of `THIRD_PARTY_NOTICES.md` repeats.

```sh
python3 docs/audits/AUD-024-harnesses/build-release/fast-gate-coverage.py
```

No input. Expected at b6fca69: both gates `check-fast.sh False, check.sh True`, 87 crate versions
repeated, `FAIL`, exit 1.

## `feature-combos.sh`

CHECK-BLD-001: `cargo clippy --lib --target wasm32-unknown-unknown --no-default-features
--features <set> -- -D warnings` for all 15 non-empty sets of the four browser features, which must
pass; the library with no feature and with the helper feature `wasm-bindings` alone is linted too
and only reported.

```sh
CARGO_TARGET_DIR=<scratch target folder> docs/audits/AUD-024-harnesses/build-release/feature-combos.sh
```

Needs the pinned toolchain with the `wasm32-unknown-unknown` target. Expected at b6fca69: 15
`PASS` lines, the two `info:` lines with their dead-code errors, exit 0.
