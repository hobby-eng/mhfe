//! Replays the suite 4 test vectors of same-length containers in tests/fixtures/suite4-vectors/
//! at full size and compares every recorded value. They are written with `mhfe test-vectors
//! --same-length --output tests/fixtures/suite4-vectors` (`--only TEXT` writes the vectors whose
//! names contain TEXT, `--only negative-cases` the negative cases) and checked independently,
//! with the result recorded next to them, with `python3 scripts/independent-suite4.py vector
//! --record tests/fixtures/suite4-vectors/independent-verification.json <files>`.
//!
//! Expensive, about half an hour for the whole set: run on request or for a release with
//! `cargo test --locked --release --test suite4_vectors -- --ignored --nocapture`.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

use mhfe::vectors::{self, SAME_LENGTH_INPUTS, SAME_LENGTH_NEGATIVE_INPUTS};
use mhfe::SAME_LENGTH_SUITE_ID;

// In a folder, so that Cargo does not build it as a test of its own; named by its path, since
// there are no mod.rs files (RUST-03).
#[macro_use]
#[path = "vector_share/replay.rs"]
mod replay;

const SUITE: replay::Suite = replay::Suite {
    folder: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/suite4-vectors"),
    writer: "mhfe test-vectors --same-length",
    suite_id: SAME_LENGTH_SUITE_ID,
    inputs: &SAME_LENGTH_INPUTS,
    negative_inputs: &SAME_LENGTH_NEGATIVE_INPUTS,
    schema: vectors::SAME_LENGTH_SCHEMA,
    negative_schema: vectors::SAME_LENGTH_NEGATIVE_SCHEMA,
    generate: |mhfe, input| replay::value(vectors::SameLengthVector::generate(mhfe, input)),
    negative_case: |mhfe, input, container| {
        replay::value(vectors::NegativeCase::generate_same_length(
            mhfe, input, container,
        ))
    },
};

suite_tests!(
    SUITE,
    "full-size Argon2: about half an hour for the whole set"
);
