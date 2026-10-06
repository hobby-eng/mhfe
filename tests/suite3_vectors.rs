//! Replays the suite 3 test vectors in tests/fixtures/suite3-vectors/ at full size and compares
//! every recorded value. They are written with `mhfe test-vectors --output
//! tests/fixtures/suite3-vectors` (`--only NAME` writes one vector, `--only negative-cases` the
//! negative cases) and checked independently, with the result recorded next to them, with
//! `python3 scripts/independent-suite3.py vector --record
//! tests/fixtures/suite3-vectors/independent-verification.json <files>`.
//!
//! Expensive, about an hour for the whole set: run on request with
//! `cargo test --locked --release --test suite3_vectors -- --ignored --nocapture`.

use std::collections::HashSet;
use std::fs;

use blake2::digest::consts::U32;
use blake2::Blake2b;
use hmac::{Hmac, KeyInit, Mac};
use mhfe::vectors::{self, NEGATIVE_INPUTS, PUBLIC_INPUTS};
use mhfe::{Mhfe, WorkFactor, SUITE_ID};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FOLDER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/suite3-vectors");

fn recorded(name: &str) -> Value {
    let path = format!("{FOLDER}/{name}");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path}: {error}; write the vectors with mhfe test-vectors")
    });
    serde_json::from_str(&text).unwrap()
}

/// A vector written now, in the form it is compared with the recorded one: the version of the
/// program that wrote a file is part of the file but not of what the vector fixes, so a later
/// release keeps the recorded version there. The program's name and its Argon2 implementation
/// are still compared.
fn with_recorded_writer(mut written: Value, recorded: &Value) -> Value {
    if let (Some(now), Some(then)) = (written.get_mut("generator"), recorded.get("generator")) {
        now["version"] = then["version"].clone();
    }
    written
}

/// [`with_recorded_writer`] for a list of negative cases, each with a writer of its own.
fn cases_with_recorded_writer(written: Value, recorded: &Value) -> Value {
    let (written, recorded) = (written.as_array().unwrap(), recorded.as_array().unwrap());
    assert_eq!(
        written.len(),
        recorded.len(),
        "the number of negative cases"
    );
    Value::Array(
        written
            .iter()
            .zip(recorded)
            .map(|(case, recorded)| with_recorded_writer(case.clone(), recorded))
            .collect(),
    )
}

/// Fast: every vector file is present, unchanged since it was written, and made from the public
/// inputs in the source. No Argon2 runs.
#[test]
fn the_vector_files_are_complete_and_unchanged() {
    let sums = fs::read_to_string(format!("{FOLDER}/SHA256SUMS")).expect("SHA256SUMS is missing");
    let mut listed = HashSet::new();
    for line in sums.lines() {
        let (digest, name) = line.split_once("  ").expect("sha256sum line format");
        let bytes = fs::read(format!("{FOLDER}/{name}")).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            digest,
            "{name} changed"
        );
        listed.insert(name.to_owned());
    }
    for input in &PUBLIC_INPUTS {
        let name = format!("{}.json", input.name());
        assert!(listed.contains(&name), "{name} is missing");
        let vector = recorded(&name);
        assert_eq!(vector["inputs"]["phrase"], input.phrase(), "{name}");
        assert_eq!(vector["inputs"]["password"], input.password(), "{name}");
        assert_eq!(vector["inputs"]["pim"], input.pim(), "{name}");
        assert_eq!(
            vector["inputs"]["memory_level"],
            input.memory_level(),
            "{name}"
        );
    }
    let negative = recorded("negative-cases.json");
    assert_eq!(negative.as_array().unwrap().len(), NEGATIVE_INPUTS.len());
    for case in negative.as_array().unwrap() {
        assert_eq!(case["schema"], vectors::NEGATIVE_SCHEMA);
    }

    // The independent check records which files it checked, with the digests it saw; they must
    // be exactly the files of SHA256SUMS, so that the record cannot fall out of step.
    let record = recorded("independent-verification.json");
    let checked: HashSet<String> = record["files"]
        .as_array()
        .expect("independent-verification.json lists its files")
        .iter()
        .map(|file| {
            let name = file["name"].as_str().unwrap();
            let bytes = fs::read(format!("{FOLDER}/{name}")).unwrap();
            assert_eq!(
                file["sha256"].as_str().unwrap(),
                hex::encode(Sha256::digest(&bytes)),
                "{name} changed after its independent check"
            );
            name.to_owned()
        })
        .collect();
    assert_eq!(
        checked, listed,
        "the independent check covers exactly SHA256SUMS"
    );
}

/// Fast: in every round of every vector, the recorded salt input and mask message give the
/// recorded salt and mask, with the recorded Argon2id output as the HMAC key. No Argon2 runs.
#[test]
fn every_round_records_its_salt_and_mask_inputs() {
    let salt_label = format!("{SUITE_ID}/ROUND-SALT");
    let mask_label = format!("{SUITE_ID}/ROUND-MASK");
    for input in &PUBLIC_INPUTS {
        let name = format!("{}.json", input.name());
        let vector = recorded(&name);
        assert_eq!(vector["schema"], vectors::SCHEMA, "{name}");
        for direction in ["encryption", "decryption"] {
            for round in vector[direction]["rounds"].as_array().unwrap() {
                let field = |key: &str| hex::decode(round[key].as_str().unwrap()).unwrap();
                let (salt, mask) = (field("salt_hex"), field("mask_hex"));

                // Both inputs are a domain label followed by the same round message.
                let salt_input = field("salt_input_hex");
                let mask_input = field("mask_input_hex");
                let salt_message = salt_input.strip_prefix(salt_label.as_bytes()).expect(&name);
                let mask_message = mask_input.strip_prefix(mask_label.as_bytes()).expect(&name);
                assert_eq!(salt_message, mask_message, "{name}: one round message");

                // The salt and the mask are the leading bytes of the digest and of the tag.
                // blake2 uses a newer digest crate than sha2, so its own Digest trait is named.
                let digest = <Blake2b<U32> as blake2::Digest>::digest(&salt_input);
                assert_eq!(digest[..salt.len()], salt[..], "{name} {direction}");
                let mut mac = Hmac::<Sha256>::new_from_slice(&field("argon2_key_hex")).unwrap();
                mac.update(&mask_input);
                let tag = mac.finalize().into_bytes();
                assert_eq!(tag[..mask.len()], mask[..], "{name} {direction}");
            }
        }
    }
}

/// Fast: a vector written by a later release matches the recorded one, while any change of what
/// the vector fixes, such as its container, still does not.
#[test]
fn only_the_writer_version_is_set_aside() {
    let recorded = recorded("zero-12.json");
    let mut later = recorded.clone();
    later["generator"]["version"] = Value::from("9.9.9");
    assert_eq!(with_recorded_writer(later.clone(), &recorded), recorded);
    let mut other = later;
    other["container"] = Value::from("abandon abandon abandon");
    assert_ne!(with_recorded_writer(other.clone(), &recorded), recorded);
    let mut renamed = recorded.clone();
    renamed["generator"]["program"] = Value::from("another program");
    assert_ne!(with_recorded_writer(renamed, &recorded), recorded);
}

#[test]
#[ignore = "full-size Argon2: about an hour for the whole set"]
fn every_vector_is_reproduced_exactly() {
    let mut containers = std::collections::HashMap::new();
    for input in &PUBLIC_INPUTS {
        let work = WorkFactor::new(input.pim(), input.memory_level()).unwrap();
        let mut mhfe = Mhfe::new(work).unwrap();
        let vector = vectors::generate(&mut mhfe, input).unwrap();
        let expected = recorded(&format!("{}.json", input.name()));
        assert_eq!(
            with_recorded_writer(serde_json::to_value(&vector).unwrap(), &expected),
            expected,
            "{}",
            input.name()
        );
        containers.insert(input.name(), vector.container.clone());
        println!("{}: reproduced", input.name());
    }

    let expected = recorded("negative-cases.json");
    let mut cases = Vec::new();
    for input in &NEGATIVE_INPUTS {
        let work = WorkFactor::new(input.pim(), input.memory_level()).unwrap();
        let mut mhfe = Mhfe::new(work).unwrap();
        cases.push(
            vectors::negative_case(&mut mhfe, input, &containers[input.container_of()]).unwrap(),
        );
        println!("{}: reproduced", input.name());
    }
    assert_eq!(
        cases_with_recorded_writer(serde_json::to_value(&cases).unwrap(), &expected),
        expected,
        "negative cases"
    );
}
