# Developing MHFE

The command-line tool, Rust library and browser package implement the same algorithm. The
toolchains are pinned as "Build from source" says. The library interfaces are in [API.md](API.md);
browser integration is in [BROWSER-PACKAGE.md](BROWSER-PACKAGE.md).

## Build from source

From the repository root:

```sh
cargo build --release --locked
```

The program is then `target/release/mhfe` (`mhfe.exe` on Windows). The pinned Rust toolchain is
recorded in `rust-toolchain.toml`; Node's version is in `.node-version`. Browser builds also need
the wasm-bindgen command-line tool 0.2.129 and Emscripten 6.0.12, installed as CI installs them:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
git clone --depth 1 --branch 6.0.12 https://github.com/emscripten-core/emsdk.git
emsdk/emsdk install 6.0.12 && emsdk/emsdk activate 6.0.12 && . emsdk/emsdk_env.sh
```

`scripts/bind-wasm.sh` and `scripts/build-argon2-wasm.sh` refuse any other version, and the
canonical build uses the `emscripten/emsdk:6.0.12` image (`packaging/Dockerfile.reproducible`).
`scripts/verify-pinned-versions.mjs` keeps these versions equal to the scripts' own.

Release builds and the scripts below replace the builder's own paths in the native program and
WebAssembly through `packaging/remap-builder-paths.sh`. They refuse `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS`, which would override that remapping. Give extra flags per target, such
as `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.

## Checks

`scripts/cli-questions.json` lists every CLI choice call, its answer families and the scoped
options that supply them. Recovery follow-ups state why an answer must wait for the actual result.
`scripts/verify-cli-questions.mjs` checks call-site coverage in both directions, including new
modules; a CLI unit test checks every mapped option against its actual clap command. This is a
tripwire for unlisted calls and incomplete mappings, not a semantic proof about arbitrary Rust.
Review dynamic answer producers when they change. Python's AST width gate checks the owner's
agreed PEP 8 widths: 99 columns for code, 72 for comment-only lines and docstrings.

Run the smallest check appropriate to a change. The fast tests use a reduced Argon2 cost.
`scripts/check-fast.sh` runs the fast checks that CI runs on every push and pull request:
formatting, the copy and code-rules gates (`scripts/verify-no-copies.mjs`,
`scripts/verify-code-rules.mjs`), the pinned versions (`scripts/verify-pinned-versions.mjs`),
clippy for every build, the fast tests, the browser package's types (`pnpm run check:types`), the
lint (`pnpm run lint`) and Prettier. The complete local check, `scripts/check.sh`, adds the
builds, the browser package, CLI/browser parity and the terminal cases at full size, but not the
full-size vectors; CI runs it for a release tag and by hand:

```sh
cargo test --locked
scripts/check-fast.sh
scripts/check.sh
```

The macOS debugger-attachment test first requires a successful attach/stop/detach control.
On a test host that authorizes noninteractive `sudo`, set
`MHFE_PUBLIC_MACOS_ATTACH_PROBE_SUDO=1` for `cargo test --locked`. This elevates only the fixed
public-data monitor and its named probe subprocesses; Cargo, the rest of the suite and production
commands are not elevated. The monitor
checks the actual protected child's signal before its own result passes through `sudo`. Both
public tracers restore and read back the default `SIGSEGV` disposition, so Rust's stack-overflow
handler cannot consume the kernel's synthetic signal. Their core-file limits stay at zero.
Without that opt-in it runs with the caller's permissions. An unavailable control fails the
test and never establishes protection. The hosted macOS CI job sets the opt-in explicitly.

Markdown and JavaScript use the repository's pinned Prettier. The Node.js tools come through
pnpm, in the version that `packageManager` in `package.json` names (with Corepack:
`corepack enable`). Install the development dependencies from the lockfile and check formatting
with:

```sh
pnpm install --frozen-lockfile && pnpm run format:check
```

The browser checks need their Playwright browsers installed:

```sh
pnpm exec playwright install chromium firefox
```

On Linux use `pnpm exec playwright install --with-deps chromium firefox` to install their
system dependencies too. Both `pnpm run check:browsers` and `node scripts/verify-browsers.mjs`
need these browsers. The complete `scripts/check.sh` also needs Python 3.11 or later, gzip and zip;
GNU tar is needed outside macOS. macOS packaging uses Python's standard-library tar/gzip writer
and the runner's existing tools, without installing Homebrew packages. Its `BUILD-INFO.txt` records
the Python/zlib, compiler and Apple SDK versions. Release macOS binaries are ad-hoc signed with
the hardened runtime; this requires no private signing key and does not provide Apple notarization.

After `scripts/check.sh` has built the browser package, check it in Chromium and Firefox:

```sh
pnpm run check:browsers
```

`node scripts/verify-browsers.mjs --browser firefox --mode fast` checks one browser in one mode,
for example to run a page again and again. A page that stops leaves its partial results, the check
it was in and its console messages in `target/browser-check/`.

The canonical Docker build is:

```sh
scripts/build-reproducible.sh
```

Keep heavy builds and full-size checks sequential. Release preparation, canonical comparisons,
signing and publication are described in [RELEASING.md](RELEASING.md).

## Test vectors and independent verification

`mhfe test-vectors` writes test vectors; `--same-length` selects suite 4. The fixtures live in
`tests/fixtures/suite3-vectors/` and `tests/fixtures/suite4-vectors/`. A format or vector change
must be checked against the companion [specification](https://github.com/hobby-eng/mhfe-spec)
and its vectors too. Version 0.3.0 was the last release to implement suite 2.

Recorded vector reads and checksum generation accept regular files of at most 1 MiB each.
Symlinks, FIFOs, devices and directories are refused. Hashing streams the bounded file instead
of loading it whole. An existing temporary output path is refused rather than overwritten;
after an interrupted write, inspect that path before removing it and retrying.

The native full-size replays take about an hour for suite 3 and half an hour for suite 4:

```sh
cargo test --locked --release --test suite3_vectors -- --ignored --nocapture
cargo test --locked --release --test suite4_vectors -- --ignored --nocapture
```

The independent verifiers use OpenSSL's Argon2 and `unicodedata2`'s Unicode 17.0.0 database.
Their pinned packages and accepted hashes are in `scripts/independent-suite3-requirements.txt`:

```sh
python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt
python3 scripts/independent-suite3.py passwords tests/fixtures/validation-cases.json
python3 scripts/independent-suite4.py validation tests/fixtures/suite4-vectors/validation-cases.json
```

The `passwords` command checks every specification case of the password rule. For each suite,
give `vector` exactly the files listed in its `SHA256SUMS`, including listed negative cases.
Do not give it every JSON file in the directory: verification records and suite 4's separate
`validation-cases.json` are not vector inputs.

```sh
(cd tests/fixtures/suite3-vectors &&
  python3 ../../../scripts/independent-suite3.py vector $(cut -d' ' -f3 SHA256SUMS))
(cd tests/fixtures/suite4-vectors &&
  python3 ../../../scripts/independent-suite4.py vector $(cut -d' ' -f3 SHA256SUMS))
```

These commands are the independent checks used by `.github/workflows/vectors.yml`. Full-size
replays run for a release tag or an explicit workflow request, rather than on a branch push;
the ordinary CI uses the fast checks. See [RELEASING.md](RELEASING.md) for the release sequence.

## Generated tables

Startup self-checks replay published vectors using the round keys recorded in the fixtures.
`scripts/generate-published-rounds.mjs` writes `src/mhfe/published_rounds.rs` from those fixtures;
regenerate it whenever the vectors change:

```sh
node scripts/generate-published-rounds.mjs
node scripts/generate-published-rounds.mjs --check
```

`--check` compares without writing, as `scripts/check.sh` does. The self-check interfaces and
their known-answer catalogue are in [API.md](API.md#self-checks).

The terminal line editor's cell widths, `src/bin/mhfe/cell_widths.rs`, are generated from the
same Unicode 17.0.0 database, supplied by the pinned `unicodedata2` package. Regenerate them
whenever the Unicode version of the password rule changes:

```sh
python3 scripts/generate-cell-widths.py
python3 scripts/generate-cell-widths.py --check
```

The Test vectors workflow runs `--check`; it compares without writing. Do not edit either
generated table by hand.

## Argon2 implementation

The native tool and browser package use the authors' reference C implementation of Argon2,
vendored unchanged. Its source and provenance are described in
[vendor/phc-winner-argon2.md](../vendor/phc-winner-argon2.md), with the SHA-256 of every file.
`node scripts/verify-vendored-argon2.mjs` refuses a folder that differs from that list in any
file, an added one included; `scripts/check.sh` and both stages of the canonical build run it
before compiling.

On x86-64 the native Argon2 code is compiled twice, with SSE2 and SSSE3. The program selects
SSSE3 only when the processor reports it, and otherwise uses SSE2, which every 64-bit x86
processor supports. Both copies produce identical results and the tests exercise both. The
[measurements](measurements/README.md) record the 7 to 10% speed difference; the C interface and
its invariants are in [SECURITY.md](../SECURITY.md#the-c-engine-and-its-interface).

## Further reading

- [API.md](API.md): Rust types, browser interfaces, self-checks and compatibility rules.
- [BROWSER-PACKAGE.md](BROWSER-PACKAGE.md): module integration and browser-specific behavior.
- [SECURITY.md](../SECURITY.md): secret handling, process protections and their limits.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md): bundled licences; the Rust crate list is
  generated by `scripts/third-party-licenses.py`, and every release archive carries the file. Its
  Rust standard library section is written by hand; after a toolchain update,
  `scripts/third-party-licenses.py --check` fails until the section names the new toolchain, the
  SHA-256 of its notice file and the crates its libraries are built from. It compares the crates
  only for the release targets whose standard library is installed, and names the ones it left
  out.
- [Measurements](measurements/README.md): timing records.
- [RELEASING.md](RELEASING.md): release preparation, verification and signing.
