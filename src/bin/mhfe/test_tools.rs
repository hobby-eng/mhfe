//! Test-only commands: `mhfe test-vectors` and `mhfe test-benchmark`.
//!
//! They use only the fixed public inputs in `mhfe::vectors`; nothing a user types is ever
//! used. Vector files contain the password and every round key by design.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Args;
use mhfe::vectors::{
    self, NegativeInput, PublicInput, CHECKSUM_FILE, NEGATIVE_CASES_STEM, NEGATIVE_INPUTS,
    PUBLIC_INPUTS, SAME_LENGTH_INPUTS, SAME_LENGTH_NEGATIVE_INPUTS,
};
use mhfe::{Password, PhraseLength, Suite, WorkFactor, ENCRYPTION_ROUNDS, ROUNDS};
use serde::Serialize;

use crate::exit::{Failure, SUCCESS};
use crate::regular_file::RegularFile;
use crate::settings;
use crate::style::{self, paint, MUTED};
use crate::time_text::{self, duration};

#[derive(Args)]
pub(crate) struct VectorOptions {
    /// Folder for the vector files and their checksum list
    #[arg(long, value_name = "DIR", help = format!("Folder for the JSON files and {CHECKSUM_FILE}"), long_help = output_help())]
    output: PathBuf,

    /// Only names that contain TEXT, or "negative-cases"
    #[arg(long, value_name = "TEXT", long_help = only_help())]
    only: Option<String>,

    /// Suite 4, of same-length containers, instead of suite 3
    #[arg(long)]
    same_length: bool,
}

/// The inputs and negative cases of one suite's vector set.
struct VectorSet {
    suite: &'static str,
    /// The layout of its vector files.
    schema: &'static str,
    inputs: &'static [PublicInput],
    negative: &'static [NegativeInput],
}

const SUITE_3_SET: VectorSet = VectorSet {
    suite: "suite 3",
    schema: vectors::SCHEMA,
    inputs: &PUBLIC_INPUTS,
    negative: &NEGATIVE_INPUTS,
};

const SUITE_4_SET: VectorSet = VectorSet {
    suite: "suite 4",
    schema: vectors::SAME_LENGTH_SCHEMA,
    inputs: &SAME_LENGTH_INPUTS,
    negative: &SAME_LENGTH_NEGATIVE_INPUTS,
};

fn output_help() -> String {
    style::option_help(&[
        &format!("Folder for the JSON files and {CHECKSUM_FILE}."),
        "Created when missing. A file of the same name in it is replaced.",
    ])
}

fn only_help() -> String {
    style::option_help(&[
        "Only names that contain TEXT, or \"negative-cases\".",
        "The names are those of the files in tests/fixtures/suite3-vectors and \
         tests/fixtures/suite4-vectors without .json, such as zero-12 or unicode-password; \
         zero-12 also selects zero-12-pim-1 and the other names that contain it.",
    ])
}

/// The end of `mhfe test-vectors -h` and `--help`.
pub(crate) fn vectors_help() -> String {
    style::examples_with_note(
        &[
            (
                "mhfe test-vectors --output vectors",
                &format!("Write every public vector and {CHECKSUM_FILE} into ./vectors"),
            ),
            (
                "mhfe test-vectors --output vectors --only zero-12",
                "Only the vectors whose names contain zero-12",
            ),
            (
                "mhfe test-vectors --output vectors --only negative-cases",
                "Only the negative cases (wrong passwords, settings and lengths), from the \
                 containers of the vectors already in ./vectors",
            ),
            (
                "mhfe test-vectors --same-length --output vectors4",
                "The suite 4 vectors of same-length containers",
            ),
        ],
        "Vector files hold the public test password and every round key by design. They use \
         only fixed public inputs; nothing typed is ever used.",
    )
}

pub(crate) fn write_vectors(options: VectorOptions) -> Result<i32, Failure> {
    let set = if options.same_length {
        &SUITE_4_SET
    } else {
        &SUITE_3_SET
    };
    style::warn(
        &format!("TEST ONLY: writing the public {} test vectors.", set.suite),
        "",
    );
    check_selection(set, options.only.as_deref())?;
    fs::create_dir_all(&options.output)?;
    let selected = |name: &str| {
        options
            .only
            .as_deref()
            .is_none_or(|text| name.contains(text))
    };

    let mut written = 0;
    let mut containers = HashMap::new();
    for input in set.inputs.iter().filter(|input| selected(input.name())) {
        let work = input.work()?;
        show_vector_estimate(input.name(), work, ENCRYPTION_ROUNDS);
        let mut mhfe = settings::reserve_memory(work)?;
        let started = Instant::now();
        let file = vectors::Vector::file_name(input.name());
        if options.same_length {
            let vector = vectors::SameLengthVector::generate(&mut mhfe, input)?;
            containers.insert(input.name(), vector.container().to_owned());
            write_json(&options.output, &file, &vector)?;
        } else {
            let vector = vectors::Vector::generate(&mut mhfe, input)?;
            containers.insert(input.name(), vector.container().to_owned());
            write_json(&options.output, &file, &vector)?;
        }
        written += 1;
        style::ok(format!(
            "{} {}",
            input.name(),
            paint(MUTED, duration(started.elapsed().as_secs()))
        ));
    }

    // All negative cases share one file, so they are written together: with no --only, or with
    // an --only that matches "negative-cases".
    if selected(NEGATIVE_CASES_STEM) {
        let mut negative_cases = Vec::new();
        for input in set.negative {
            let container = match containers.get(input.container_of()) {
                Some(container) => container.clone(),
                None => recorded_container(&options.output, input.container_of(), set.schema)?,
            };
            let work = input.work()?;
            show_vector_estimate(input.name(), work, ROUNDS);
            let mut mhfe = settings::reserve_memory(work)?;
            let started = Instant::now();
            negative_cases.push(if options.same_length {
                vectors::NegativeCase::generate_same_length(&mut mhfe, input, &container)?
            } else {
                vectors::NegativeCase::generate(&mut mhfe, input, &container)?
            });
            style::ok(format!(
                "{} {}",
                input.name(),
                paint(MUTED, duration(started.elapsed().as_secs()))
            ));
        }
        write_json(
            &options.output,
            &vectors::Vector::file_name(NEGATIVE_CASES_STEM),
            &negative_cases,
        )?;
        written += 1;
    }

    write_checksums(&options.output, set)?;
    style::ok(format!(
        "Wrote {written} files and {CHECKSUM_FILE} to {}",
        style::shown_path(&options.output)
    ));
    Ok(SUCCESS)
}

/// Refuses, before any folder or file is made, an --only that selects nothing: an empty text, or
/// one that no vector's name contains, nor "negative-cases" (AUD-024-API010).
fn check_selection(set: &VectorSet, only: Option<&str>) -> Result<(), Failure> {
    let Some(text) = only else {
        return Ok(());
    };
    let names: Vec<&str> = set
        .inputs
        .iter()
        .map(|input| input.name())
        .chain([NEGATIVE_CASES_STEM])
        .collect();
    if !text.is_empty() && names.iter().any(|name| name.contains(text)) {
        return Ok(());
    }
    Err(Failure::invalid_input(format!(
        "--only selects none of the {} test vectors; their names are {}.",
        set.suite,
        names.join(", ")
    )))
}

/// The most a vector file holds: about 22 KiB.
const MAX_VECTOR_FILE: u64 = 1024 * 1024;

/// The container of the vector `name` written by an earlier run, for negative cases run without
/// it: a file of the set's `schema` and of that name, read to a bound. A missing file is said to
/// be written first; one that cannot be read, or is not that vector, is refused with the cause
/// (AUD-024-API011).
fn recorded_container(folder: &Path, name: &str, schema: &str) -> Result<String, Failure> {
    let path = folder.join(vectors::Vector::file_name(name));
    let shown = style::shown_path(&path);
    let unreadable = |error: &dyn std::fmt::Display| {
        Failure::internal(format!("Could not read {shown}: {error}"))
    };
    let file = match RegularFile::open(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Failure::internal(format!(
                "The negative cases need {shown}; write that vector first."
            )));
        }
        file => file.map_err(|error| unreadable(&error))?,
    };
    let invalid =
        |why: &str| Failure::internal(format!("{shown} is not a valid vector file: {why}"));
    let bytes = file
        .bytes(MAX_VECTOR_FILE)
        .map_err(|error| unreadable(&error))?
        .ok_or_else(|| invalid("it is larger than any vector file"))?;
    let vector: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| invalid(&error.to_string()))?;
    if vector["schema"] != schema || vector["name"] != name {
        return Err(invalid(&format!(
            "it is not the vector {name} of the layout {schema}"
        )));
    }
    vector["container"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("it has no container"))
}

/// Lists every file of the full set that is present in the folder, read back from disk, so that
/// a run with --only, or several runs side by side, still leave a complete SHA256SUMS.
///
/// Runs side by side take turns: each holds a lock on SHA256SUMS while it reads the folder and
/// writes the list, so a later list always includes what an earlier one saw. The file is rewritten
/// in place rather than replaced, because a replaced file would carry a different lock. A crash
/// in the middle leaves a short list, which the vector tests report; the next run writes it again.
fn write_checksums(folder: &Path, set: &VectorSet) -> Result<(), Failure> {
    let mut list = RegularFile::for_update(&folder.join(CHECKSUM_FILE))?;
    list.lock()?;
    let names = set
        .inputs
        .iter()
        .map(|input| input.name())
        .chain([NEGATIVE_CASES_STEM])
        .map(vectors::Vector::file_name);
    let mut sums = String::new();
    for name in names {
        match RegularFile::open(&folder.join(&name)) {
            Ok(file) => {
                let digest = file.sha256(MAX_VECTOR_FILE)?.ok_or_else(|| {
                    Failure::internal("A vector file is larger than the 1 MiB limit.")
                })?;
                sums += &format!("{}  {name}\n", hex::encode(digest));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    list.rewrite(sums.as_bytes())?;
    // Closing the file releases the lock.
    Ok(())
}

/// Writes pretty JSON with a final newline.
fn write_json(folder: &Path, name: &str, value: &impl Serialize) -> Result<(), Failure> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Failure::internal(format!("Could not write {name}: {error}")))?;
    bytes.push(b'\n');
    write_atomically(&folder.join(name), &bytes)
}

/// Writes a temporary file, flushes it to disk and renames it over `path`, so that a crash or a
/// parallel run never leaves a half-written file behind.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let temporary = path.with_extension(format!("tmp{}", std::process::id()));
    // Never follow or truncate a pre-existing temporary path, including a symlink or FIFO.
    let mut file = fs::File::create_new(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[derive(Args)]
pub(crate) struct BenchmarkOptions {
    #[command(flatten)]
    settings: settings::Settings,
}

/// The end of `mhfe test-benchmark -h` and `--help`.
pub(crate) fn benchmark_help() -> String {
    style::examples_with_note(
        &[
            ("mhfe test-benchmark", "Time the default settings"),
            (
                "mhfe test-benchmark --pim 1 --mem 1",
                "Time twice the passes with 3 GiB of memory",
            ),
            (
                "mhfe test-benchmark > timing.json",
                "Save the JSON record for docs/measurements/",
            ),
        ],
        "It encrypts and recovers the public test phrase once and prints a JSON record of the \
         times on standard output.",
    )
}

#[derive(Serialize)]
struct Measurement {
    suite_id: &'static str,
    implementation: String,
    argon2_engine: String,
    target: &'static str,
    pim: u32,
    memory_level: u32,
    argon2_memory_kib: u32,
    argon2_passes: u32,
    work_area_seconds: f64,
    encryption_seconds: f64,
    decryption_seconds: f64,
}

/// Times one encryption and one recovery of the public test phrase and prints a JSON record for
/// docs/measurements/.
pub(crate) fn benchmark(options: BenchmarkOptions) -> Result<i32, Failure> {
    style::warn(
        "TEST ONLY: timing one encryption and one recovery with public test data.",
        "",
    );
    let work = options
        .settings
        .work_factor_for(settings::Operation::Encrypt)?;
    let input = &PUBLIC_INPUTS[0];
    let password = Password::new(input.password())?;

    let started = Instant::now();
    let mut mhfe = settings::reserve_memory(work)?;
    let work_area_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let container = mhfe.encrypt(
        input.phrase(),
        &password,
        Suite::TwentyFourWords,
        &mut |_, _| Ok(()),
    )?;
    let encryption_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    mhfe.decrypt(&container, &password, PhraseLength::Detect, &mut |_, _| {
        Ok(())
    })?;
    let decryption_seconds = started.elapsed().as_secs_f64();

    let record = Measurement {
        suite_id: mhfe::SUITE_ID,
        implementation: format!("mhfe {}", env!("CARGO_PKG_VERSION")),
        argon2_engine: mhfe.engine().description(),
        target: std::env::consts::ARCH,
        pim: work.pim(),
        memory_level: work.memory_level(),
        argon2_memory_kib: work.memory_kib(),
        argon2_passes: work.passes(),
        work_area_seconds,
        encryption_seconds,
        decryption_seconds,
    };
    let text = serde_json::to_string_pretty(&record)
        .map_err(|error| Failure::internal(error.to_string()))?;
    style::out(format_args!("{text}"))?;
    Ok(SUCCESS)
}

/// An estimate for the selected input and the operation that writes it.
fn show_vector_estimate(name: &str, work: WorkFactor, rounds: u32) {
    style::fact(
        "Estimate",
        format!("{name}: {}.", time_text::of_rounds(work, rounds)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_generation_refuses_an_oversized_vector() {
        let folder = std::env::temp_dir().join(format!("mhfe-large-vector-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let file =
            fs::File::create(folder.join(vectors::Vector::file_name(PUBLIC_INPUTS[0].name())))
                .unwrap();
        file.set_len(MAX_VECTOR_FILE + 1).unwrap();
        drop(file);
        let result = write_checksums(&folder, &SUITE_3_SET);
        fs::remove_dir_all(&folder).unwrap();
        assert!(
            result.is_err(),
            "an oversized vector must not enter the checksum list"
        );
    }

    #[cfg(unix)]
    #[test]
    fn vector_readers_and_checksum_output_refuse_links_and_fifos() {
        use std::os::unix::fs::symlink;
        let folder = std::env::temp_dir().join(format!("mhfe-vector-kinds-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let name = PUBLIC_INPUTS[0].name();
        let path = folder.join(vectors::Vector::file_name(name));
        let target = folder.join("public-target.json");
        let text = serde_json::json!({"schema": vectors::SCHEMA, "name": name, "container": "c"})
            .to_string();
        fs::write(&target, &text).unwrap();
        let refuse_readers = || {
            assert!(recorded_container(&folder, name, vectors::SCHEMA).is_err());
            assert!(write_checksums(&folder, &SUITE_3_SET).is_err());
        };
        symlink(&target, &path).unwrap();
        refuse_readers();
        fs::remove_file(&path).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        refuse_readers();
        fs::remove_file(&path).unwrap();
        let sums = folder.join(CHECKSUM_FILE);
        fs::remove_file(&sums).unwrap();
        symlink(&target, &sums).unwrap();
        assert!(write_checksums(&folder, &SUITE_3_SET).is_err());
        fs::remove_file(&sums).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&sums)
            .status()
            .unwrap()
            .success());
        assert!(write_checksums(&folder, &SUITE_3_SET).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), text);
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn an_existing_atomic_temporary_is_never_truncated() {
        let folder = std::env::temp_dir().join(format!("mhfe-vector-temp-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join("public.json");
        let temporary = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&temporary, b"retained public data").unwrap();
        assert!(write_atomically(&path, b"replacement").is_err());
        assert_eq!(fs::read(&temporary).unwrap(), b"retained public data");
        fs::remove_file(&temporary).unwrap();
        #[cfg(unix)]
        {
            let target = folder.join("target.json");
            fs::write(&target, b"retained public data").unwrap();
            std::os::unix::fs::symlink(&target, &temporary).unwrap();
            assert!(write_atomically(&path, b"replacement").is_err());
            assert_eq!(fs::read(&target).unwrap(), b"retained public data");
            fs::remove_file(&temporary).unwrap();
        }
        write_atomically(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_dir_all(folder).unwrap();
    }

    /// An --only that selects nothing is refused before anything is written (AUD-024-API010).
    #[test]
    fn an_only_that_selects_nothing_is_refused() {
        for set in [&SUITE_3_SET, &SUITE_4_SET] {
            assert!(check_selection(set, None).is_ok());
            assert!(check_selection(set, Some(NEGATIVE_CASES_STEM)).is_ok());
            assert!(check_selection(set, Some(set.inputs[0].name())).is_ok());
            for nothing in ["", "AUD026FIRST", "AUD026FIRST\nAUD026SECOND"] {
                let refused = check_selection(set, Some(nothing)).unwrap_err();
                assert_eq!(refused.exit_code(), crate::exit::INVALID_INPUT);
                assert!(
                    refused.message().contains("selects none"),
                    "{}",
                    refused.message()
                );
                assert!(!refused.message().contains("AUD026FIRST"));
                assert!(!refused.message().contains("AUD026SECOND"));
            }
        }
    }

    /// A recorded vector that is missing, unreadable or another file is told apart
    /// (AUD-024-API011).
    #[test]
    fn a_recorded_vector_is_read_only_when_it_is_that_vector() {
        let folder = std::env::temp_dir().join(format!("mhfe-vectors-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let name = "zero-12";
        let refusal = |schema| {
            recorded_container(&folder, name, schema)
                .unwrap_err()
                .into_message()
        };
        assert!(refusal(vectors::SCHEMA).contains("write that vector first"));
        let file = folder.join(vectors::Vector::file_name(name));
        fs::write(&file, "{ not json").unwrap();
        assert!(refusal(vectors::SCHEMA).contains("is not a valid vector file"));
        let other = serde_json::json!({ "schema": "x", "name": name, "container": "c" });
        fs::write(&file, other.to_string()).unwrap();
        assert!(refusal(vectors::SCHEMA).contains("is not the vector zero-12"));
        let right =
            serde_json::json!({ "schema": vectors::SCHEMA, "name": name, "container": "c" });
        fs::write(&file, right.to_string()).unwrap();
        assert_eq!(
            recorded_container(&folder, name, vectors::SCHEMA).unwrap(),
            "c"
        );
        assert!(refusal(vectors::SAME_LENGTH_SCHEMA).contains("is not the vector"));
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        assert!(refusal(vectors::SCHEMA).contains("Could not read"));
        fs::remove_dir_all(&folder).unwrap();
    }
}
