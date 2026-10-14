# AUD-024 harness: guide-lib-core

Audit AUD-024, role guide-lib-core (coding-guide conformance and architecture of the library
outside the wallet and self-check areas), reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch `aud023-remediation`). No Argon2 runs, no
command of the tool runs, and no secret is used: every text is a public test string.

Each check exits 1 when it fails and 0 when it passes. At b6fca69 every check fails, as recorded
below. None writes into the repository: the probes are built in a temporary folder into
`CARGO_TARGET_DIR`.

## Inputs

- The repository at the reviewed commit, Rust 1.99.0 (the repository's `rust-toolchain.toml`) and
  the offline Cargo registry with the crates of the repository's `Cargo.lock`, for the three probes
  and for `unreachable-pub`.
- Python 3 for the static scans (`module-edges`, `unused-api`, `copies`), which read `src/` and
  `tests/` only.
- Linux for `locked-text`, which reads `/proc/self/smaps`.

`run.sh` copies `probe/` to a temporary folder, writes its `Cargo.toml` from `probe/Cargo.toml.in`
with a path dependency on the repository, copies `Cargo.lock` and `rust-toolchain.toml` beside it
and builds one binary. `probe/build.rs` copies the non-test part of the reviewed
`src/engine/cgroup.rs` into the build, so that `cgroup_usage` calls the reviewed functions.

## Commands, from the repository root

```text
CARGO_TARGET_DIR=<a folder outside the repository> \
  docs/audits/AUD-024-harnesses/guide-lib-core/run.sh <check>
```

with `<check>` one of the following.

### locked-text

The public `mhfe::memory` API builds a `LockedText` from a guard of another buffer
(`LockedPages::of_vec`, `LockedText::from_locked`). Fails when the text reports `is_locked()` while
the kernel holds none of the pages of its own buffer locked. Expected at b6fca69 (exit 1):

```text
guard of the other buffer is_locked() = true
LockedText::is_locked() = true
kernel keeps a page of the text's own buffer locked = false
FAIL: the LockedText reports a lock its buffer does not have
```

### cgroup-usage

`src/engine/cgroup.rs` documents `available_bytes` as `None` where the figures cannot be read. The
probe gives the reviewed `available_with` a cgroup v2 group with `memory.max` of 8 GiB and no
readable `memory.current`, and a cgroup v1 group with a limit of 8 GiB and no readable
`memory.usage_in_bytes`. Fails when a figure is answered. Expected at b6fca69 (exit 1):

```text
cgroup v2, memory.max 8 GiB, memory.current unreadable: Some(0)
cgroup v1, limit 8 GiB, memory.usage_in_bytes unreadable: Some(0)
FAIL: an unreadable usage is answered as a figure, not as None
```

### strength-repeats

The public `Strength::of` on one short group repeated, with and without spaces. Fails when
`"1234 1234 1234 1234 1234"` or `"1234"` eight times without spaces is not weak (below 50 bits).
Expected at b6fca69 (exit 1), among other lines:

```text
"1234 1234 1234 1234 1234": 51.76 bits, weak = false (the group once: 6.32)
"12341234123412341234123412341234": 50.56 bits, weak = false (the group once: 6.32)
"2024 2024 2024 2024 2024": 58.36 bits, weak = false (the group once: 7.64)
"abcdabcdabcdabcdabcdabcdabcdabcd": 61.60 bits, weak = false (the group once: 7.70)
FAIL: a repeated group of four characters is not rated weak
```

### unreachable-pub

Runs `cargo clippy --locked --lib -- -W unreachable_pub` and lists, with `unreachable_pub.py`, the
`pub` items of the scope files that are not reachable from the crate root (RUST-06). Expected at
b6fca69 (exit 1): 27 items, `src/feistel.rs` 47, 57, 66, 84, 88, 92, 96, 103, 116, 125 and 142,
`src/packing.rs` 16, 17, 20, 24, 29, 33, 39, 53, 62 and 88, `src/phrase.rs` 40 and 75, and
`src/suite.rs` 13, 15, 20 and 22, then `27 unreachable pub item(s) in scope`.

### module-edges

`module_edges.py` looks, in non-test code, for the dependency edges that tie the independent parts
to the encryption core or to a front end (CORE-04), and for a caller of `check_container`. Expected
at b6fca69 (exit 1):

```text
src/phrase.rs:149: phrase -> container: check_container, whose ContainerFacts reaches mhfe, wallet and rehearsal
src/container.rs:11: container -> mhfe (the encryption core) and wallet
src/memory.rs:283: memory -> engine: mlock comes from the Argon2 FFI module
src/packing.rs:54: packing -> phrase, while phrase -> packing
src/suite.rs:6: suite -> engine, while engine -> suite (WorkFactor)
src/engine/browser.rs:94: engine -> wasm_api: a library module depends on the browser bindings
src/phrase.rs:148: check_container has no caller in src/ (only the re-export at src/lib.rs:88)
6 edge(s) present
```

### module-cycles

`module_cycles.py` builds the dependency graph of the library's top-level modules from the
`crate::` paths and crate-root re-exports of non-test code, and prints every strongly connected
component of more than one module with the line that makes each edge. Expected at b6fca69
(exit 1): one component of 30 modules (`check_word`, `container`, `detection`, `eff`, `engine`,
`error`, `feistel`, `hidden`, `memory`, `mhfe`, `new_password`, `operation`, `packing`,
`password`, `phrase`, `random`, `rehearsal`, `rekey`, `repair`, `search`, `self_check`,
`self_test`, `strength`, `suite`, `validation_fixtures`, `wallet`, `wallet_check`, `wasm_api`,
`word_hints`, `word_wishes`), then `1 cycle(s) of modules`.

### unused-api

`unused_api.py` lists public items, crate-root re-exports and public fields that neither the
command-line tool nor `tests/` uses. Expected at b6fca69 (exit 1): `into_phrase`,
`NewPassword::recipe`, `LockProbe::of`, `LockedText::from_locked`, `LockedPages`,
`Sealed::container_words`, `card_text`, the `NewContainer` fields, `check_phrase`,
`read_phrase`, `check_container` and `other_detected_lengths`, then
`12 public item(s) without an outside user`.

### copies

`copies.py` lists values and messages written more than once in the library, beyond the copy
gate's runs of 50 tokens, split into non-test code and test modules. Expected at b6fca69 (exit 1):
13 entries, among them the Unicode password of the published vectors (3 in code, at
`src/password/known_answers.rs:22`, `src/vectors/inputs.rs:29`, `src/wallet/known_answers.rs:152`),
`"public test password"` in the self-check code at `src/mhfe/known_answers.rs:577` and `:621`, the
messages `"the built-in cases are of another suite"` (`src/mhfe/known_answers.rs:492`, `:526`)
and `"a built-in vector is missing"` (`src/mhfe/known_answers.rs:405`,
`src/mhfe/known_answers/published.rs:96`, `src/self_test.rs:137`), and the known answers retyped
in unit tests; the last line is `13 value(s) or message(s) written more than once`.

## After a fix

Each check exits 0 once its finding is fixed: `locked-text` when the library refuses a foreign
guard or no longer offers it, `cgroup-usage` when an unreadable usage gives `None`,
`strength-repeats` when the repeated groups are rated weak, `unreachable-pub` when the items are
`pub(crate)`, `module-edges` when the edges are gone, `module-cycles` when no group of modules
depends on itself, `unused-api` when the items are private or used, and `copies` when each value
and message has one source. If a fix renames or moves a probed
item, adapt the probe or the pattern and keep the same inputs.
