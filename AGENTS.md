# mhfe agent instructions

This repository is part of the `bip_tools` workspace. If a workspace `AGENTS.md` exists one directory above this repository, read and follow it first. Its core rules: edit only this checkout in place, never create another copy or worktree, never delete project directories, use the toolchains it names, use only public test data, do not commit or push without an explicit request, and write everything in English only (code, comments, commits, documentation).

The specification and vectors for this implementation live in `../mhfe_spec`; an algorithm or vector change must be checked against both.

## Commands

- Toolchain: Rust 1.98.1 from `rust-toolchain.toml`, with the `CARGO_HOME` and `RUSTUP_HOME` set in the environment (never the home-directory defaults). Emscripten 6.0.10 from `../workingspace/emsdk` (`source ../workingspace/emsdk/emsdk_env.sh`) for the browser builds.
- Targeted: `cargo test --locked <name>` (fast: the tests use a reduced Argon2 cost); `cargo clippy --locked --all-targets --all-features -- -D warnings`; `cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings`; `cargo fmt --check`; `npm ci --ignore-scripts && npm run format:check` (Prettier for Markdown and JavaScript).
- Browser package: `scripts/build-wasm.sh`, then `node scripts/verify-argon2-wasm.mjs` and `node scripts/verify-browser-package.mjs`; `node scripts/build-browser-check.mjs` writes a page for a real browser.
- Full-size runs (announce first; the user runs full suites): `cargo test --release --lib full_size -- --ignored`; `node scripts/verify-browser-package.mjs --full`; the vector replay `cargo test --locked --release --test suite3_vectors -- --ignored`; `python3 scripts/independent-suite3.py vector tests/fixtures/suite3-vectors/*.json`, with the packages of `scripts/independent-suite3-requirements.txt` installed by `pip --require-hashes`. Each runs once per change of the core, the vectors or the checker; CI (`vectors.yml`) repeats them.
- Release-level (explicit request only): `scripts/check.sh`; `scripts/check-release-artifacts.sh`; `scripts/build-reproducible.sh` and `canonical-output/release/SHA256SUMS`.
- Workflows: `.github/workflows/ci.yml`, `audit.yml`, `vectors.yml`, `release.yml`.

## Documents

`README.md`, `API.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, `web/README.md`, `vendor/*.md`, `docs/`, `measurements/`, `CITATION.cff`.
