# Public recovered-result mutation witness

AUD-012 reviews dirty MHFE source on HEAD `abb16671b641378c0fc3c4d855f8d126498e754b`;
use the report's fingerprint for exact identity. `public-mutation.rs` demonstrates that
safe external Rust code can grow the public recovered phrase while the private lock guard
still tracks its original allocation. Compilation is the witness, not a runtime swap or
freed-memory test. The documented lock ownership is checked separately in source review.

From the MHFE root, after its ordinary optimized tests/build, use the workspace Rust toolchain:

```sh
CARGO_HOME=../workingspace/cargo RUSTUP_HOME=../workingspace/rustup ../workingspace/cargo/bin/rustc --edition 2021 --crate-type lib docs/audits/AUD-012-harnesses/rust/public-mutation.rs --extern mhfe=target/release/libmhfe.rlib -L dependency=target/release/deps -o docs/audits/AUD-012-evidence/public-mutation.rlib
```

At baseline this compiles (exit 0), proving the public mutation is allowed. Once the buffer
is private and only a read-only accessor is available, this witness must be refused by the
compiler. No binary is executed; no large allocation or Argon2 run occurs. Replace it with
a compile-fail regression when remediation is authorized, not during this read-only audit.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
