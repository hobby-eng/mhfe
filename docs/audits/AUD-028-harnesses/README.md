# AUD-028 audit harnesses

These scripts support the fresh all-files AUD-028 baseline. The reviewed base is `575cbd1b7634646f6e19a2501ed9ea164a6a7acd` with the report's dirty-tree source manifest; that commit alone does not identify the audited source. Use only public fixtures. Run from the MHFE root, in the authoritative checkout.

## Scoped C sanitizer checks

`argon2-sanitized.c` calls the existing vendored public C API through the actual owned portable wrapper and x86 dispatcher. It checks the RFC 9106 section 5.3 Argon2id answer, the existing one-MiB MHFE startup answer, one/four threads, default/custom allocation, zero bytes before custom free, five exact refusal codes and the 64-bit C context layout against the recorded Rust layout. The expected tags are independent literal values. It does not call the Rust FFI, change production parameters or establish erasure of compiler spills.

`sanitizer-tripwire.c` contains two deliberate faults in separate audit executables: a heap access beyond its allocation and signed integer overflow. These are never linked into MHFE. `run-sanitizers.mjs` compiles and runs everything sequentially, requires the intended sanitizer diagnostic and nonzero exit, and also requires each real known-answer executable to reject an altered expected tag.

Prerequisites are Node.js from the workspace toolchain and an existing Linux x86-64 Clang 21 installation at `/usr/lib/llvm-21/bin/clang`, its ASan/UBSan runtimes, `llvm-symbolizer`, libc/pthread headers and linker. No tool is installed by the harness. On other architectures, adapt and separately record the compiler/ABI assumptions rather than counting this audit as platform acceptance. The script explicitly skips SSSE3 when the host lacks it.

```sh
node docs/audits/AUD-028-harnesses/run-sanitizers.mjs ../tmp/mhfe-aud028-sanitizers
```

Success ends with `PASS: scoped C sanitizer acceptance and independently activated failure tripwires` and exit 0. The expected negative diagnostics appear in the output before that line. Unexpected status, diagnostic, known-answer mismatch or source change fails. The output directory receives objects, executables and `receipt.json` with argv, times, statuses and source/artifact hashes. Treat that directory as local evidence; do not commit it.

The coordinator additionally samples descendant RSS with a 512 MiB limit and requires at least 3 GiB machine memory available, with no concurrent heavy job. ASan reserves a large virtual shadow region: do not substitute a 512 MiB virtual-address limit. This finite test covers the reached C paths only. It does not establish race freedom, timing properties, Rust borrow/TLS correctness, production-cost acceptance, other operating systems or canonical release reproducibility.

## Browser self-check and raw wish boundaries

After `scripts/build-wasm.sh`, these probes use the built package and its matching generated wasm-bindgen glue. They do not run Argon2 or generate a wallet:

```sh
node docs/audits/AUD-028-harnesses/partial-self-check.mjs
node docs/audits/AUD-028-harnesses/raw-wishes.mjs
```

The first runs the real `PackageCheck` state machine with a worker-boundary stand-in. It reports a completed failed component followed by `WORKER_FAILED`, then requires a later operation to remain refused as `SELF_CHECK_FAILED`. The second compares an empty wish list and a correctly framed public excluded word, then requires malformed chosen/excluded framing to be refused rather than discarded. On the reviewed baseline, both exit nonzero at their assertions; the report retains the exact source/artifact identities and diagnostics. These probes are expected to exit 0 after their specified behaviors are fixed. They do not establish real worker transport or host-page integration acceptance.

## Native scalar-boundary baseline probes

`native-boundaries.rs` records two public Rust API defects in the baseline. Build the library with the workspace's named Cargo toolchain, then compile the probe with its matching Rust compiler:

```sh
cargo build --locked --lib
rustc --edition=2021 docs/audits/AUD-028-harnesses/native-boundaries.rs \
  --extern mhfe=target/debug/libmhfe.rlib -L dependency=target/debug/deps \
  -o ../tmp/mhfe-aud028-native-boundaries
../tmp/mhfe-aud028-native-boundaries odds
../tmp/mhfe-aud028-native-boundaries index
```

Use the actual Cargo target directory in those paths when it is configured elsewhere. Neither mode creates an Argon2 engine. On the reviewed baseline `odds` prints `0.5` for `u32::MAX` check bits and fails because an added restriction cannot reduce the expected draw count below one. `index` requests the first out-of-range EFF index and panics inside the library, instead of a typed refusal. Both baseline failures exit 101. The index probe describes the baseline's infallible return signature; if that signature is corrected, verify the new typed refusal through the project's regression tests rather than treating this old call as a post-fix verifier.

## Launcher, build operand and Rust literal checks

These finite probes do not start a server, compile WebAssembly or call Argon2:

```sh
python3 docs/audits/AUD-028-harnesses/launcher-arguments.py
node docs/audits/AUD-028-harnesses/rust-strings.mjs
python3 docs/audits/AUD-028-harnesses/bind-target.py ../tmp/mhfe-aud028
```

Create the last command's scratch directory first. The binding probe needs the named Cargo toolchain on PATH. It obtains the actual Cargo target-directory metadata with a per-command configuration environment value, then substitutes only compiler/binder command observers. The binder exits 77 after recording its input, before any artifact is produced. The probe requires that operand to match Cargo metadata; an observed mismatch makes the probe itself exit nonzero.

The launcher probe requires exit 2 and withholds a synthetic unknown option and extra operand. The Rust literal probe uses a 100 ms VM deadline per input: an ordinary string is a positive control; valid block comments, raw strings and character literals must terminate with the expected extracted strings. The baseline repeats both launcher markers, selects the default build directory despite Cargo configuration, and times out on three literal cases. These failures are preserved separately from later fixes. A passing post-fix probe exits 0.

## Development dependency graph

This uses existing PyYAML 6.0.3 and pnpm; neither is installed by the script. Keep the output outside the repository or in an ignored evidence directory:

```sh
pnpm list --depth Infinity --json > ../tmp/mhfe-aud028/pnpm-graph.json
python3 docs/audits/AUD-028-harnesses/dependency-tree.py ../tmp/mhfe-aud028/pnpm-graph.json
```

The script rejects duplicate YAML keys, nonregistry resolutions, malformed SHA-512 pins, missing snapshots, unresolved dependency edges and manifest/version disagreement. It traverses every listed dependency and distinguishes listed optional nodes from manifests actually present on disk. Success prints the measured node/edge counts and exact lockfile digest with exit 0. It does not validate upstream tarball contents, scan Rust dependencies, establish publisher trust or replace an advisory database check.

## Cache identity and remaining gate controls

```sh
node docs/audits/AUD-028-harnesses/mutable-wasm.mjs
node docs/audits/AUD-028-harnesses/module-relative-paths.mjs
python3 docs/audits/AUD-028-harnesses/remap-flags.py
python3 docs/audits/AUD-028-harnesses/private-screen-oracle.py
```

The cache probe uses the real built repair class, worker text, glue and WASM with a deterministic Worker boundary adapter. A healthy class compiles before its caller-owned input bytes change. A second class receives the same now-damaged byte array, while an independent copied-array control must fail known answers. The original compiled class must retain its healthy fingerprint. The baseline second class incorrectly passes and returns another container fingerprint. No Argon2 or real-browser transport is exercised. After the cache fix, the changed module must fail and refuse the repair operation; success exits 0.

The module-path probe runs the actual graph/finding helpers with the actual production-line reader and compares equivalent crate/root-relative import, reexport and expression paths, with an independent no-edge control. The remapping probe runs only the real sourced shell guard: unset variables must pass, while empty or nonempty overriding variables must refuse. It does not compile a release. The private-screen probe extracts the actual helper and markers through Python AST, with assertions explicitly required, and checks five bounded synthetic transcripts without launching a PTY. Each baseline defect makes its probe exit nonzero; corrected behavior exits 0.

The dependency harness additionally accepts `--self-test` after the graph path. It requires the direct importer to resolve into exact package/snapshot nodes and the root graph to contain the manifest's exact direct set/versions; nine independent refusal controls challenge missing nodes, empty evidence, wrong versions, broken edges, duplicate YAML keys and malformed resolutions. The binding observer refuses unknown Cargo commands; deliberate build/check controls use a harmless dispatch sentinel, so a regressed observer cannot start a real compiler.

The final sanitizer receipt binds every local vendored C/header file, all three owned C/header inputs and its audit inputs, including portable `ref.c` and transitive headers. Three independent altered-digest controls must fail before compilation. The external compiler/system runtime identity remains an environment prerequisite rather than a universal reproducible-build claim. Earlier pre-correction/pre-format executions retain their own exact script hashes and are not relabeled as executions of these current harnesses.
