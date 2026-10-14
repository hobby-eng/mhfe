//! Replays the suite 3 test vectors in tests/fixtures/suite3-vectors/ at full size and compares
//! every recorded value. They are written with `mhfe test-vectors --output
//! tests/fixtures/suite3-vectors` (`--only TEXT` writes the vectors whose names contain TEXT,
//! `--only negative-cases` the negative cases) and checked independently, with the result
//! recorded next to them, with `python3 scripts/independent-suite3.py vector --record
//! tests/fixtures/suite3-vectors/independent-verification.json <files>`.
//!
//! Expensive, about an hour for the whole set: run on request with
//! `cargo test --locked --release --test suite3_vectors -- --ignored --nocapture`.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

use mhfe::vectors::{self, NEGATIVE_INPUTS, PUBLIC_INPUTS};
use mhfe::SUITE_ID;

// In a folder, so that Cargo does not build it as a test of its own; named by its path, since
// there are no mod.rs files (RUST-03).
#[macro_use]
#[path = "vector_share/replay.rs"]
mod replay;

const SUITE: replay::Suite = replay::Suite {
    folder: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/suite3-vectors"),
    writer: "mhfe test-vectors",
    suite_id: SUITE_ID,
    inputs: &PUBLIC_INPUTS,
    negative_inputs: &NEGATIVE_INPUTS,
    schema: vectors::SCHEMA,
    negative_schema: vectors::NEGATIVE_SCHEMA,
    generate: |mhfe, input| replay::value(vectors::generate(mhfe, input)),
    negative_case: |mhfe, input, container| {
        replay::value(vectors::negative_case(mhfe, input, container))
    },
};

suite_tests!(SUITE, "full-size Argon2: about an hour for the whole set");
