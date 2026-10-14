//! The replay of a suite's test vectors, shared by tests/suite3_vectors.rs and
//! tests/suite4_vectors.rs: a [`Suite`] names its folder, inputs, schemas and generators, and
//! [`suite_tests!`] gives each suite the same four tests, three fast ones and the full-size replay.
//!
//! A share of the full-size replay lets several processes replay one suite at once on a computer
//! with the memory for it: `MHFE_VECTOR_SHARE=k/n` replays every n-th item of the suite, the
//! vectors then the negative cases, starting at item k (from 0). Without it every item is
//! replayed.

use std::collections::HashSet;
use std::fs;

use blake2::digest::consts::U32;
use blake2::Blake2b;
use hmac::{Hmac, KeyInit, Mac};
use mhfe::engine::NativeEngine;
use mhfe::vectors::{NegativeInput, PublicInput};
use mhfe::{Mhfe, MhfeError};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// One suite of vectors: where its files are and what writes them.
pub struct Suite {
    /// The folder of the vector files, their SHA256SUMS and the independent check's record.
    pub folder: &'static str,
    /// The command that writes the vectors, named when a file is missing.
    pub writer: &'static str,
    /// The suite id that starts the round labels.
    pub suite_id: &'static str,
    /// The public inputs of the vectors, one file each.
    pub inputs: &'static [PublicInput],
    /// The inputs of the negative cases, all in negative-cases.json.
    pub negative_inputs: &'static [NegativeInput],
    /// The schema of a vector file.
    pub schema: &'static str,
    /// The schema of a negative case.
    pub negative_schema: &'static str,
    /// Writes the vector of an input now, at full size.
    pub generate: fn(&mut Mhfe<NativeEngine>, &PublicInput) -> Value,
    /// Writes a negative case now from the container of its vector, at full size.
    pub negative_case: fn(&mut Mhfe<NativeEngine>, &NegativeInput, &str) -> Value,
}

/// A written vector or case as the JSON it is compared in.
pub fn value<T: Serialize>(written: Result<T, MhfeError>) -> Value {
    serde_json::to_value(written.unwrap()).unwrap()
}

/// Whether the item at `index` of the replay belongs to this process.
fn mine(index: usize) -> bool {
    let Ok(share) = std::env::var("MHFE_VECTOR_SHARE") else {
        return true;
    };
    let (part, parts) = share
        .split_once('/')
        .and_then(|(part, parts)| Some((part.parse::<usize>().ok()?, parts.parse::<usize>().ok()?)))
        .filter(|&(part, parts)| parts > 0 && part < parts)
        .unwrap_or_else(|| panic!("MHFE_VECTOR_SHARE must be k/n with k < n, not {share:?}"));
    index % parts == part
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

/// The digest of a file of the folder, in hex.
fn file_digest(folder: &str, name: &str) -> String {
    let bytes = fs::read(format!("{folder}/{name}")).unwrap();
    hex::encode(Sha256::digest(&bytes))
}

impl Suite {
    /// The recorded file `name` of the suite.
    fn recorded(&self, name: &str) -> Value {
        let path = format!("{}/{name}", self.folder);
        let text = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("{path}: {error}; write the vectors with {}", self.writer)
        });
        serde_json::from_str(&text).unwrap()
    }

    /// Every vector file is present, unchanged since it was written, and made from the public
    /// inputs in the source; the independent check covers exactly the files of SHA256SUMS.
    pub fn check_files(&self) {
        let sums = fs::read_to_string(format!("{}/SHA256SUMS", self.folder))
            .expect("SHA256SUMS is missing");
        let mut listed = HashSet::new();
        for line in sums.lines() {
            let (digest, name) = line.split_once("  ").expect("sha256sum line format");
            assert_eq!(file_digest(self.folder, name), digest, "{name} changed");
            listed.insert(name.to_owned());
        }
        for input in self.inputs {
            let name = format!("{}.json", input.name());
            assert!(listed.contains(&name), "{name} is missing");
            let vector = self.recorded(&name);
            let work = input.work().unwrap();
            assert_eq!(vector["inputs"]["phrase"], input.phrase(), "{name}");
            assert_eq!(vector["inputs"]["password"], input.password(), "{name}");
            assert_eq!(vector["inputs"]["pim"], work.pim(), "{name}");
            assert_eq!(
                vector["inputs"]["memory_level"],
                work.memory_level(),
                "{name}"
            );
        }
        let negative = self.recorded("negative-cases.json");
        let negative = negative.as_array().unwrap();
        assert_eq!(negative.len(), self.negative_inputs.len());
        for case in negative {
            assert_eq!(case["schema"], self.negative_schema);
        }

        // The independent check records which files it checked, with the digests it saw; they
        // must be exactly the files of SHA256SUMS, so that the record cannot fall out of step.
        let record = self.recorded("independent-verification.json");
        let checked: HashSet<String> = record["files"]
            .as_array()
            .expect("independent-verification.json lists its files")
            .iter()
            .map(|file| {
                let name = file["name"].as_str().unwrap();
                assert_eq!(
                    file["sha256"].as_str().unwrap(),
                    file_digest(self.folder, name),
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

    /// In every round of every vector, the recorded salt input and mask message give the recorded
    /// salt and mask, with the recorded Argon2id output as the HMAC key.
    pub fn check_rounds(&self) {
        let salt_label = format!("{}/ROUND-SALT", self.suite_id);
        let mask_label = format!("{}/ROUND-MASK", self.suite_id);
        for input in self.inputs {
            let name = format!("{}.json", input.name());
            let vector = self.recorded(&name);
            assert_eq!(vector["schema"], self.schema, "{name}");
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

    /// A vector written by a later release matches the recorded one, while any change of what the
    /// vector fixes, such as its container or the program's name, still does not.
    pub fn check_writer_version(&self) {
        let recorded = self.recorded(&format!("{}.json", self.inputs[0].name()));
        let mut later = recorded.clone();
        later["generator"]["version"] = Value::from("9.9.9");
        assert_eq!(with_recorded_writer(later.clone(), &recorded), recorded);
        let mut other = later;
        other["container"] = Value::from("abandon abandon abandon");
        assert_ne!(with_recorded_writer(other, &recorded), recorded);
        let mut renamed = recorded.clone();
        renamed["generator"]["program"] = Value::from("another program");
        assert_ne!(with_recorded_writer(renamed, &recorded), recorded);
    }

    /// Every vector, then every negative case, written again at full size equals its recorded
    /// file. A negative case reads the container of its vector from the recorded file, which the
    /// replay of that vector compares with what it gives.
    pub fn reproduce(&self) {
        for (index, input) in self.inputs.iter().enumerate() {
            if !mine(index) {
                continue;
            }
            let mut mhfe = Mhfe::new(input.work().unwrap()).unwrap();
            let expected = self.recorded(&format!("{}.json", input.name()));
            let written = with_recorded_writer((self.generate)(&mut mhfe, input), &expected);
            assert_eq!(written, expected, "{}", input.name());
            println!("{}: reproduced", input.name());
        }

        let expected = self.recorded("negative-cases.json");
        let expected = expected.as_array().unwrap();
        assert_eq!(
            expected.len(),
            self.negative_inputs.len(),
            "the number of negative cases"
        );
        for (offset, (input, expected)) in self.negative_inputs.iter().zip(expected).enumerate() {
            if !mine(self.inputs.len() + offset) {
                continue;
            }
            let container = self.recorded(&format!("{}.json", input.container_of()))["container"]
                .as_str()
                .unwrap()
                .to_owned();
            let mut mhfe = Mhfe::new(input.work().unwrap()).unwrap();
            let written = (self.negative_case)(&mut mhfe, input, &container);
            let written = with_recorded_writer(written, expected);
            assert_eq!(written, *expected, "{}", input.name());
            println!("{}: reproduced", input.name());
        }
    }
}

/// The four tests of a suite: `suite_tests!(SUITE, "<why the replay is ignored>")`.
macro_rules! suite_tests {
    ($suite:expr, $replay_cost:literal) => {
        /// Fast: every vector file is present, unchanged since it was written, and made from the
        /// public inputs in the source. No Argon2 runs.
        #[test]
        fn the_vector_files_are_complete_and_unchanged() {
            $suite.check_files();
        }

        /// Fast: in every round of every vector, the recorded salt input and mask message give
        /// the recorded salt and mask, with the recorded Argon2id output as the HMAC key. No
        /// Argon2 runs.
        #[test]
        fn every_round_records_its_salt_and_mask_inputs() {
            $suite.check_rounds();
        }

        /// Fast: a vector written by a later release matches the recorded one, while any change of
        /// what the vector fixes, such as its container, still does not.
        #[test]
        fn only_the_writer_version_is_set_aside() {
            $suite.check_writer_version();
        }

        /// Full size: every vector and negative case is written again and equals its file.
        #[test]
        #[ignore = $replay_cost]
        fn every_vector_is_reproduced_exactly() {
            $suite.reproduce();
        }
    };
}
