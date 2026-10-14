# Developing MHFE

The command-line tool, Rust library and browser package implement the same algorithm. Use the
toolchains and workspace rules in [AGENTS.md](../AGENTS.md). The library interfaces are in
[API.md](API.md); browser integration is in [BROWSER-PACKAGE.md](BROWSER-PACKAGE.md).

## Build from source

From the repository root:

```sh
cargo build --release --locked
```

The program is then `target/release/mhfe` (`mhfe.exe` on Windows). The pinned Rust toolchain is
recorded in `rust-toolchain.toml`; Node's version is in `.node-version`. Browser builds also need
wasm-bindgen and Emscripten, as [AGENTS.md](../AGENTS.md) describes.

Release builds and the scripts below replace the builder's own paths in the native program and
WebAssembly through `packaging/remap-builder-paths.sh`. They refuse `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS`, which would override that remapping. Give extra flags per target, such
as `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.

## Checks

Run the smallest check appropriate to a change. The fast tests use a reduced Argon2 cost.
`scripts/check-fast.sh` runs the fast checks that CI runs on every push and pull request:
formatting, the copy gate, clippy for every build, the fast tests and Prettier. The complete
local check, `scripts/check.sh`, adds the builds, the browser package, CLI/browser parity and the
terminal cases at full size, but not the full-size vectors; CI runs it for a release tag and by
hand:

```sh
cargo test --locked
scripts/check-fast.sh
scripts/check.sh
```

Markdown and JavaScript use the repository's pinned Prettier. Install the existing development
dependencies from the lockfile and check formatting with:

```sh
npm ci --ignore-scripts && npm run format:check
```

After `scripts/check.sh` has built the browser package, check it in Chromium and Firefox:

```sh
npm run check:browsers
```

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
`scripts/generate-published-rounds.py` writes `src/mhfe/published_rounds.rs` from those fixtures;
regenerate it whenever the vectors change:

```sh
python3 scripts/generate-published-rounds.py
python3 scripts/generate-published-rounds.py --check
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
[measurements](measurements/README.md) record the 7 to 10% speed difference; the C boundary and
its invariants are in [SECURITY.md](../SECURITY.md#the-c-engine-and-its-boundary).

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
