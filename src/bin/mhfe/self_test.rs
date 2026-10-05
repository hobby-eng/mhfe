//! `mhfe self-test`: two published test vectors at their full cost on this computer, an encryption
//! of suite 3 and a recovery of suite 4. A program that passes computes MHFE as the specification
//! says, here and now; a build or computer fault that the round trip of an encryption cannot see,
//! because it would encrypt and decrypt the same wrong way, shows here. The vectors are public, so
//! no secret is involved.

use anstream::eprintln;
use mhfe::{Password, PhraseLength, Recovery, Suite, WorkFactor};
use serde_json::Value;

use crate::choice;
use crate::exit::{Failure, INTERNAL_ERROR, SUCCESS};
use crate::readme;
use crate::settings;
use crate::style::{self, paint, MUTED};
use crate::terminal::Progress;

/// The public vectors, as the repository and the specification publish them.
const SUITE_3_VECTOR: &str = include_str!("../../../tests/fixtures/suite3-vectors/zero-12.json");
const SUITE_4_VECTOR: &str =
    include_str!("../../../tests/fixtures/suite4-vectors/same-length-zero-12.json");

/// The top of `mhfe self-test --help`.
pub fn about() -> String {
    style::command_about(&[
        "Test this program with the published vectors",
        "Encrypts the public suite 3 vector zero-12 and recovers the public suite 4 vector \
         same-length-zero-12 at their full cost, 2 GiB and 12 rounds each, and compares the \
         results with the published ones. It takes about two minutes and uses no secret.",
    ])
}

/// What a vector gives: its phrase, password and container.
struct Vector {
    name: String,
    phrase: String,
    password: String,
    container: String,
}

fn vector(json: &str) -> Result<Vector, Failure> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| Failure::internal(format!("A built-in vector is damaged: {error}")))?;
    let text = |pointer: &str| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Failure::internal(format!("A built-in vector lacks {pointer}.")))
    };
    Ok(Vector {
        name: text("/name")?,
        phrase: text("/inputs/phrase")?,
        password: text("/inputs/password")?,
        container: text("/container")?,
    })
}

pub fn run() -> Result<i32, Failure> {
    style::title("Test this program");
    let suite_3 = vector(SUITE_3_VECTOR)?;
    let suite_4 = vector(SUITE_4_VECTOR)?;
    // Both vectors use the default settings, PIM 0 and memory level 0.
    let work = WorkFactor::default();
    style::fact(
        "Vectors",
        format!(
            "{} (suite 3) and {} (suite 4) {}",
            suite_3.name,
            suite_4.name,
            paint(MUTED, "public")
        ),
    );
    let (low, high) = work.estimated_seconds();
    style::fact(
        "Time",
        format!(
            "about {} to {} minutes",
            (2 * low).div_ceil(60),
            (2 * high).div_ceil(60)
        ),
    );
    let mut progress = Progress::start();
    let (suite_3_ok, suite_4_ok) = run_vectors(&suite_3, &suite_4, &mut progress)?;

    eprintln!();
    let verdict = |ok: bool| {
        if ok {
            paint(style::GOOD, "as published")
        } else {
            paint(style::BAD, "NOT as published")
        }
    };
    style::fact("Suite 3", format!("encrypts {}", verdict(suite_3_ok)));
    style::fact("Suite 4", format!("recovers {}", verdict(suite_4_ok)));
    eprintln!();
    if suite_3_ok && suite_4_ok {
        style::ok("This program computes MHFE as the published vectors say.");
        Ok(SUCCESS)
    } else {
        style::alarm(
            "This program does not compute MHFE as published.",
            "Do not use it for a real phrase; try another computer or build.",
        );
        style::more(readme::SELF_TEST);
        Ok(INTERNAL_ERROR)
    }
}

/// The self-test that must pass before a wallet derived from a container is shown (the
/// specification asks for it): a fault that derives and recovers the same wrong way would
/// otherwise give a wallet no correct program finds again.
pub fn require_pass() -> Result<(), Failure> {
    let suite_3 = vector(SUITE_3_VECTOR)?;
    let suite_4 = vector(SUITE_4_VECTOR)?;
    let mut progress = Progress::start();
    let passed = run_vectors(&suite_3, &suite_4, &mut progress)? == (true, true);
    if !passed {
        return Err(Failure::internal(
            "This program does not compute MHFE as the published vectors say (mhfe self-test), \
             so it shows no wallet. Try another computer or build.",
        ));
    }
    choice::record("Self-test", "the published vectors match");
    Ok(())
}

/// Encrypts the suite 3 vector and recovers the suite 4 vector at full cost; whether each result
/// is the published one.
fn run_vectors(
    suite_3: &Vector,
    suite_4: &Vector,
    progress: &mut Progress,
) -> Result<(bool, bool), Failure> {
    // Both vectors use the default settings, PIM 0 and memory level 0.
    let mut mhfe = settings::reserve_memory(WorkFactor::default())?;
    let password = Password::new(&suite_3.password)?;
    let encrypted = mhfe.encrypt_unchecked(
        &suite_3.phrase,
        &password,
        Suite::TwentyFourWords,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
    let suite_3_ok = *encrypted.words == suite_3.container;

    progress.next_operation();
    let password = Password::new(&suite_4.password)?;
    let recovered = mhfe.decrypt(
        &suite_4.container,
        &password,
        PhraseLength::Detect,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
    progress.finish();
    let suite_4_ok =
        matches!(&recovered, Recovery::Phrase(phrase) if *phrase.phrase == suite_4.phrase);
    Ok((suite_3_ok, suite_4_ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_vectors_read() {
        let suite_3 = vector(SUITE_3_VECTOR).unwrap();
        assert_eq!(suite_3.name, "zero-12");
        assert_eq!(suite_3.container.split(' ').count(), 24);
        let suite_4 = vector(SUITE_4_VECTOR).unwrap();
        assert_eq!(suite_4.container.split(' ').count(), 12);
        assert_eq!(suite_4.phrase, suite_3.phrase);
    }
}
