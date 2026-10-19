//! The replay of a suite's test vectors, shared by tests/suite3_vectors.rs and
//! tests/suite4_vectors.rs: a [`Suite`] names its folder, inputs, schemas and generators, and
//! [`suite_tests!`] gives each suite four fast tests and one ignored full-size replay.
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
use mhfe::vectors::{self, NegativeInput, PublicInput, CHECKSUM_FILE, NEGATIVE_CASES_STEM};
use mhfe::{Mhfe, MhfeError};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// One suite of vectors: where its files are and what writes them.
pub(crate) struct Suite {
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
pub(crate) fn value<T: Serialize>(written: Result<T, MhfeError>) -> Value {
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
fn file_digest(read: &impl Fn(&str) -> Vec<u8>, name: &str) -> String {
    let bytes = read(name);
    hex::encode(Sha256::digest(&bytes))
}

impl Suite {
    /// The fixture bytes, with the generation command named on a missing input.
    fn bytes(&self, name: &str) -> Vec<u8> {
        let path = format!("{}/{name}", self.folder);
        fs::read(&path).unwrap_or_else(|error| {
            panic!("{path}: {error}; write the vectors with {}", self.writer)
        })
    }

    /// The recorded file `name` of the suite.
    fn recorded(&self, name: &str) -> Value {
        serde_json::from_slice(&self.bytes(name)).unwrap()
    }

    /// Every vector file is present, unchanged since it was written, and made from the public
    /// inputs in the source; the independent check covers exactly the files of SHA256SUMS.
    pub(crate) fn check_files(&self) {
        self.check_files_with(|name| self.bytes(name));
    }

    /// The same integrity check with fixture reads supplied at the filesystem boundary.
    fn check_files_with(&self, read: impl Fn(&str) -> Vec<u8>) {
        let recorded = |name: &str| serde_json::from_slice::<Value>(&read(name)).unwrap();
        let sums = String::from_utf8(read(CHECKSUM_FILE)).unwrap();
        let expected: HashSet<String> = self
            .inputs
            .iter()
            .map(|input| vectors::Vector::file_name(input.name()))
            .chain(std::iter::once(vectors::Vector::file_name(
                NEGATIVE_CASES_STEM,
            )))
            .collect();
        assert_eq!(
            expected.len(),
            self.inputs.len() + 1,
            "source fixture names are unique"
        );
        let mut listed = HashSet::new();
        for line in sums.lines() {
            let (digest, name) = line.split_once("  ").expect("sha256sum line format");
            assert!(expected.contains(name), "unexpected checksum entry {name}");
            assert!(
                listed.insert(name.to_owned()),
                "duplicate checksum entry {name}"
            );
            assert_eq!(file_digest(&read, name), digest, "{name} changed");
        }
        assert_eq!(
            listed, expected,
            "checksums cover every positive and negative fixture"
        );
        for input in self.inputs {
            let name = vectors::Vector::file_name(input.name());
            assert!(listed.contains(&name), "{name} is missing");
            let vector = recorded(&name);
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
        let negative = recorded(&vectors::Vector::file_name(NEGATIVE_CASES_STEM));
        let negative = negative.as_array().unwrap();
        assert_eq!(negative.len(), self.negative_inputs.len());
        for (case, input) in negative.iter().zip(self.negative_inputs) {
            assert_eq!(case["schema"], self.negative_schema);
            assert_eq!(case["suite_id"], self.suite_id);
            assert_eq!(case["name"], input.name());
            assert_eq!(case["password"], input.password());
            let work = input.work().unwrap();
            assert_eq!(case["pim"], work.pim());
            assert_eq!(case["memory_level"], work.memory_level());
            assert_eq!(case["words"], input.words());
            let source = recorded(&vectors::Vector::file_name(input.container_of()));
            assert_eq!(case["container"], source["container"]);
        }

        // The independent check records which files it checked, with the digests it saw; they
        // must be exactly the files of SHA256SUMS, so that the record cannot fall out of step.
        let record = recorded("independent-verification.json");
        let mut checked = HashSet::new();
        for file in record["files"]
            .as_array()
            .expect("independent-verification.json lists its files")
            .iter()
        {
            let name = file["name"].as_str().unwrap();
            assert!(
                expected.contains(name),
                "unexpected independent entry {name}"
            );
            assert!(
                checked.insert(name.to_owned()),
                "duplicate independent entry {name}"
            );
            assert_eq!(
                file["sha256"].as_str().unwrap(),
                file_digest(&read, name),
                "{name} changed after its independent check"
            );
        }
        assert_eq!(
            checked, listed,
            "the independent check covers exactly SHA256SUMS"
        );
    }

    /// Challenged metadata must fail even when both recorded lists agree on the same omission.
    pub(crate) fn check_file_controls(&self) {
        let negative = vectors::Vector::file_name(NEGATIVE_CASES_STEM);
        let original_sums = String::from_utf8(self.bytes(CHECKSUM_FILE)).unwrap();
        let original_record = self.recorded("independent-verification.json");
        self.check_files(); // The unchanged filesystem boundary is a positive control.
        let mut accepted = Vec::new();
        for mode in [
            "omit",
            "duplicate-sum",
            "duplicate-record",
            "rename",
            "extra",
            "negative-input",
            "positive-input",
        ] {
            let mut sums: Vec<(String, String)> = original_sums
                .lines()
                .map(|line| {
                    let (digest, name) = line.split_once("  ").unwrap();
                    (digest.into(), name.into())
                })
                .collect();
            let mut record = original_record.clone();
            let entries = record["files"].as_array_mut().unwrap();
            let entry = entries
                .iter()
                .find(|file| file["name"] == negative)
                .unwrap()
                .clone();
            let sum = sums
                .iter()
                .find(|(_, name)| name == &negative)
                .unwrap()
                .clone();
            let mut changed = std::collections::HashMap::new();
            match mode {
                "omit" => {
                    sums.retain(|(_, name)| name != &negative);
                    entries.retain(|file| file["name"] != negative);
                }
                "duplicate-sum" => sums.push(sum),
                "duplicate-record" => entries.push(entry),
                "rename" | "extra" => {
                    let alias = "unexpected-negative.json";
                    changed.insert(alias.to_owned(), self.bytes(&negative));
                    let mut renamed = entry;
                    renamed["name"] = alias.into();
                    if mode == "rename" {
                        sums.retain(|(_, name)| name != &negative);
                        entries.retain(|file| file["name"] != negative);
                    }
                    sums.push((sum.0, alias.into()));
                    entries.push(renamed);
                }
                "negative-input" | "positive-input" => {
                    let name = if mode == "negative-input" {
                        negative.clone()
                    } else {
                        vectors::Vector::file_name(self.inputs[0].name())
                    };
                    let mut payload = self.recorded(&name);
                    if mode == "negative-input" {
                        payload[0]["password"] = "changed public input".into();
                    } else {
                        payload["inputs"]["password"] = "changed public input".into();
                    }
                    let bytes = serde_json::to_vec(&payload).unwrap();
                    let digest = hex::encode(Sha256::digest(&bytes));
                    for (sum, file) in &mut sums {
                        if file == &name {
                            *sum = digest.clone();
                        }
                    }
                    for file in entries {
                        if file["name"] == name {
                            file["sha256"] = digest.clone().into();
                        }
                    }
                    changed.insert(name, bytes);
                }
                _ => unreachable!(),
            }
            changed.insert(
                CHECKSUM_FILE.to_owned(),
                sums.iter()
                    .map(|(digest, name)| format!("{digest}  {name}\n"))
                    .collect::<String>()
                    .into_bytes(),
            );
            changed.insert(
                "independent-verification.json".to_owned(),
                serde_json::to_vec(&record).unwrap(),
            );
            if std::panic::catch_unwind(|| {
                self.check_files_with(|name| {
                    changed
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| self.bytes(name))
                })
            })
            .is_ok()
            {
                accepted.push(mode);
            }
        }
        assert!(
            accepted.is_empty(),
            "integrity mutations were accepted: {accepted:?}"
        );
    }

    /// In every round of every vector, the recorded salt input and mask message give the recorded
    /// salt and mask, with the recorded Argon2id output as the HMAC key.
    pub(crate) fn check_rounds(&self) {
        let salt_label = format!("{}/ROUND-SALT", self.suite_id);
        let mask_label = format!("{}/ROUND-MASK", self.suite_id);
        for input in self.inputs {
            let name = vectors::Vector::file_name(input.name());
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
    pub(crate) fn check_writer_version(&self) {
        let recorded = self.recorded(&vectors::Vector::file_name(self.inputs[0].name()));
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
    pub(crate) fn reproduce(&self) {
        for (index, input) in self.inputs.iter().enumerate() {
            if !mine(index) {
                continue;
            }
            let mut mhfe = Mhfe::new(input.work().unwrap()).unwrap();
            let expected = self.recorded(&vectors::Vector::file_name(input.name()));
            let written = with_recorded_writer((self.generate)(&mut mhfe, input), &expected);
            assert_eq!(written, expected, "{}", input.name());
            println!("{}: reproduced", input.name());
        }

        let expected = self.recorded(&vectors::Vector::file_name(NEGATIVE_CASES_STEM));
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
            let container = self.recorded(&vectors::Vector::file_name(input.container_of()))
                ["container"]
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

/// The fast integrity/control tests and the ignored full replay of one suite.
macro_rules! suite_tests {
    ($suite:expr, $replay_cost:literal) => {
        /// Fast: every vector file is present, unchanged since it was written, and made from the
        /// public inputs in the source. No Argon2 runs.
        #[test]
        fn the_vector_files_are_complete_and_unchanged() {
            $suite.check_files();
        }

        #[test]
        fn negative_vectors_cannot_be_omitted_from_both_integrity_records() {
            $suite.check_file_controls();
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
