# AUD-010 probes: documentation, build and release

Probes of the docs-build-release reviewer of AUD-010, for the MHFE working tree on HEAD
`d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0` with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b` (227 paths,
`../fingerprint.mjs`). Each reads the working tree, builds no release, runs no Docker and no
full-size Argon2, uses public data only and exits non-zero when its check fails. Run them from the
repository root, through `../run-logged.sh` to keep a log in the ignored
`docs/audits/AUD-010-evidence/`:

```sh
docs/audits/AUD-010-harnesses/run-logged.sh docs-build-release-<name> <command>
```

| Script                     | Needs                                                                         | Checks                                                                                                                                    | Result at the reviewed state                                        |
| -------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `wasm-builder-paths.mjs`   | `dist/runtime/mhfe.wasm` or other files given                                 | No absolute path of the builder's folders (home, `CARGO_HOME`, `RUSTUP_HOME`) in a WebAssembly or binary; `/rustc/` paths are allowed     | Fails: 21 paths under the local `CARGO_HOME`                        |
| `dist-freshness.mjs`       | `dist/`, `target/wasm-bindgen/`, cargo's dep-info of the wasm32 release build | `dist/` follows from the working tree: manifest, copies of `web/`, worker, unstamped WebAssembly, recomputed build, source times          | Passes for build `4c948de3a4ee3f03`                                 |
| `feature-matrix.sh`        | Rust 1.99.0 with wasm32, crates fetched; `CARGO_BUILD_JOBS` (default 2)       | `cargo clippy -D warnings` for wasm32 with no feature, `wasm-bindings`, each browser feature, core+wallet, `wasm`; native default and all | Fails for wasm32 without a browser feature (dead code); others pass |
| `doc-checks.mjs`           | git                                                                           | Relative links and anchors, links to this repository on GitHub, no blank line in a list, README anchors of `src/bin/mhfe/readme.rs`       | Passes                                                              |
| `package-readme-links.mjs` | `dist/README.md`                                                              | Every relative link of the packaged README resolves inside the package                                                                    | Fails: three links to `API.md`                                      |
| `cli-options-in-docs.mjs`  | `target/release/mhfe`                                                         | Every `--option` the documents name is in `mhfe <command> --help` (reviewed options of other programs listed in the script)               | Passes                                                              |
| `error-codes.mjs`          | none                                                                          | `src/error.rs` codes, the `docs/API.md` table and `MhfeErrorCode` agree; code names in the documents are known codes                      | Passes                                                              |
| `audit-records.py`         | Python `jsonschema`; the procedure in `../multi-chain-wallet-tools`           | Schema validation of every record, AUD-009 pair, index, unchanged earlier records, ignored evidence, harness READMEs, procedure hashes    | Passes                                                              |
| `argon2-vs-canonical.sh`   | `dist/core/argon2-*.js`, an earlier canonical browser archive                 | The local Argon2 builds, without their appended build constant, equal the canonical Docker ones                                           | Passes against `canonical-output-aud008cached`                      |

`feature-matrix.sh` compiles into `target/`; the others only read. `cli-options-in-docs.mjs` runs
`mhfe <command> --help`, which runs no self-test and reads no secret.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
