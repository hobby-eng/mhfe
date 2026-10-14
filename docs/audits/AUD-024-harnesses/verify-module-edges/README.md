# AUD-024 harness: verify-module-edges

Audit AUD-024, adversarial verification of the guide-lib-core candidate on module edges, at commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`. Static only: no build, no Argon2, no secret.

## What it checks

`decisive_edges.py` runs `../guide-lib-core/module_cycles.py`, which reads the `crate::` paths and
crate-root re-exports of the library's non-test code, and keeps only the edges that are neither the
crate-wide error (edges into `error`, the RUST-04 finding) nor the self-check code (edges into
`self_check` or `validation_fixtures`, and edges made in a `known_answers` file), and none of the
front end `wasm_api`'s own edges. It then lists the independent parts (repair words, password
tools, wallet checks, and the shared `phrase`, `memory` and `packing`) that still reach the
encryption core (`mhfe`, `feistel`, `engine`, `wallet`, `rehearsal`, `container`), and the smallest
set of the candidate's six edges whose removal frees all of them. It exits 1 while any part reaches
the core and 0 when none does.

## Inputs

The repository at the reviewed commit (`src/`) and Python 3.

## Command, from the repository root

```text
python3 docs/audits/AUD-024-harnesses/verify-module-edges/decisive_edges.py
```

## Expected output at b6fca69 (exit 1)

Eleven lines `<part> reaches the core: [...]` (repair, check_word, password, new_password, strength,
word_hints, wallet_check, word_wishes, phrase, memory, packing), one line per candidate edge with
its source line, then:

```text
smallest set of candidate edges whose removal frees every part: ('phrase->container', 'memory->engine')
11 part(s) reach the encryption core
```

It exits 0 once `phrase` no longer imports `container` (src/phrase.rs:149) and `memory` no longer
takes its page locking from `engine` (src/memory.rs:283), or once any other change leaves no part
reaching the core.
