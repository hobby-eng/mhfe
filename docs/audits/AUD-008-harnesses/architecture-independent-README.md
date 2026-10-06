# AUD-008 independent architecture source probe

This bounded probe belongs to the independent ARC review of commit
`01978aa01f86cbec7dbc9fb9afd131dfa1a1d650` and the dirty source bytes recorded in its output.
It uses only the authoritative checkout's source, documentation and public EFF wordlist.

Run from the repository root:

```sh
python3 docs/audits/AUD-008-harnesses/architecture-independent-static.py
```

It compares direct worker calls with declared WASM exports, Rust/browser parameter limits,
EFF list dimensions, core error variants with CLI exit mappings, and core error codes with the
API documentation. The JSON output includes each result, source SHA-256 values, and a fingerprint
of their canonical JSON map. Exit code 0 means these five source checks agree; exit code 1 means
at least one disagrees. This does not compile or execute Rust, generated bindings, browsers,
Argon2, vectors, or terminal flows. Its regex-based inventory is not a complete resolved-import
graph or proof of runtime behavior.
