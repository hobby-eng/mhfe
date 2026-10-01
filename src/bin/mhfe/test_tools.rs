//! Test-only commands: `mhfe test-vectors` and `mhfe test-benchmark`.
//!
//! They use only the fixed public inputs in `mhfe::vectors`; nothing a user types is ever
//! used. Vector files contain the password and every round key by design.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anstream::println;
use clap::Args;
use mhfe::vectors::{self, NEGATIVE_INPUTS, PUBLIC_INPUTS};
use mhfe::{Password, PhraseLength, WorkFactor};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::exit::{Failure, SUCCESS};
use crate::settings;
use crate::style::{self, paint, MUTED};
use crate::terminal::duration;

/// The negative cases file without its ".json" extension; also the --only text that selects it.
const NEGATIVE_CASES_STEM: &str = "negative-cases";

#[derive(Args)]
pub struct VectorOptions {
    /// Folder for the JSON files and SHA256SUMS
    #[arg(long, value_name = "DIR", long_help = output_help())]
    output: PathBuf,

    /// Only names that contain TEXT, or "negative-cases"
    #[arg(long, value_name = "TEXT", long_help = only_help())]
    only: Option<String>,
}

fn output_help() -> String {
    style::option_help(&[
        "Folder for the JSON files and SHA256SUMS.",
        "Created when missing. A file of the same name in it is replaced.",
    ])
}

fn only_help() -> String {
    style::option_help(&[
        "Only names that contain TEXT, or \"negative-cases\".",
        "The names are those of the files in tests/fixtures/suite3-vectors without .json, \
         such as zero-12 or unicode-password; zero-12 also selects zero-12-pim-1 and the \
         other names that contain it.",
    ])
}

/// The end of `mhfe test-vectors -h` and `--help`.
pub fn vectors_help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            (
                "mhfe test-vectors --output vectors",
                "Write every public vector and SHA256SUMS into ./vectors",
            ),
            (
                "mhfe test-vectors --output vectors --only zero-12",
                "Only the vectors whose names contain zero-12",
            ),
            (
                "mhfe test-vectors --output vectors --only negative-cases",
                "Only the cases that must be refused",
            ),
        ],
    );
    let note = style::help_note(
        "Vector files hold the public test password and every round key by design. They use \
         only fixed public inputs; nothing typed is ever used.",
    );
    format!("{examples}\n{note}")
}

pub fn write_vectors(options: VectorOptions) -> Result<i32, Failure> {
    style::warn(
        "TEST ONLY: writing the public suite 3 test vectors.",
        "Each takes about two minutes or more at full size.",
    );
    fs::create_dir_all(&options.output)?;
    let selected = |name: &str| {
        options
            .only
            .as_deref()
            .is_none_or(|text| name.contains(text))
    };

    let mut written = 0;
    let mut containers = HashMap::new();
    for input in PUBLIC_INPUTS.iter().filter(|input| selected(input.name())) {
        let work = WorkFactor::new(input.pim(), input.memory_level())?;
        let mut mhfe = settings::reserve_memory(work)?;
        let started = Instant::now();
        let vector = vectors::generate(&mut mhfe, input)?;
        containers.insert(input.name(), vector.container.clone());
        write_json(&options.output, &format!("{}.json", input.name()), &vector)?;
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
        for input in &NEGATIVE_INPUTS {
            let container = match containers.get(input.container_of()) {
                Some(container) => container.clone(),
                None => recorded_container(&options.output, input.container_of())?,
            };
            let work = WorkFactor::new(input.pim(), input.memory_level())?;
            let mut mhfe = settings::reserve_memory(work)?;
            let started = Instant::now();
            negative_cases.push(vectors::negative_case(&mut mhfe, input, &container)?);
            style::ok(format!(
                "{} {}",
                input.name(),
                paint(MUTED, duration(started.elapsed().as_secs()))
            ));
        }
        write_json(
            &options.output,
            &format!("{NEGATIVE_CASES_STEM}.json"),
            &negative_cases,
        )?;
        written += 1;
    }

    write_checksums(&options.output)?;
    style::ok(format!(
        "Wrote {written} files and SHA256SUMS to {}",
        options.output.display()
    ));
    Ok(SUCCESS)
}

/// The container of a vector written by an earlier run, for negative cases run without it.
fn recorded_container(folder: &Path, name: &str) -> Result<String, Failure> {
    let path = folder.join(format!("{name}.json"));
    let missing = || {
        Failure::internal(format!(
            "The negative cases need {}; write that vector first.",
            path.display()
        ))
    };
    let text = fs::read_to_string(&path).map_err(|_| missing())?;
    let vector: serde_json::Value = serde_json::from_str(&text).map_err(|_| missing())?;
    vector["container"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(missing)
}

/// Lists every file of the full set that is present in the folder, read back from disk, so that
/// a run with --only, or several runs side by side, still leave a complete SHA256SUMS.
///
/// Runs side by side take turns: each holds a lock on SHA256SUMS while it reads the folder and
/// writes the list, so a later list always includes what an earlier one saw. The file is rewritten
/// in place rather than replaced, because a replaced file would carry a different lock. A crash
/// in the middle leaves a short list, which the vector tests report; the next run writes it again.
fn write_checksums(folder: &Path) -> Result<(), Failure> {
    let mut list = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(folder.join("SHA256SUMS"))?;
    list.lock()?;
    let names = PUBLIC_INPUTS
        .iter()
        .map(|input| input.name())
        .chain([NEGATIVE_CASES_STEM])
        .map(|stem| format!("{stem}.json"));
    let mut sums = String::new();
    for name in names {
        match fs::read(folder.join(&name)) {
            Ok(bytes) => sums += &format!("{}  {name}\n", hex::encode(Sha256::digest(&bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    list.set_len(0)?;
    list.write_all(sums.as_bytes())?;
    list.sync_all()?;
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
    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[derive(Args)]
pub struct BenchmarkOptions {
    #[command(flatten)]
    settings: settings::Settings,
}

/// The end of `mhfe test-benchmark -h` and `--help`.
pub fn benchmark_help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe test-benchmark", "Time the default settings"),
            (
                "mhfe test-benchmark --pim 1 --mem 1",
                "Time twice the passes with 3 GiB of memory",
            ),
            (
                "mhfe test-benchmark > timing.json",
                "Save the JSON record for measurements/",
            ),
        ],
    );
    let note = style::help_note(
        "It encrypts and recovers the public test phrase once and prints a JSON record of the \
         times on standard output.",
    );
    format!("{examples}\n{note}")
}

#[derive(Serialize)]
struct Measurement {
    suite_id: &'static str,
    implementation: String,
    argon2_engine: &'static str,
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
/// measurements/.
pub fn benchmark(options: BenchmarkOptions) -> Result<i32, Failure> {
    style::warn(
        "TEST ONLY: timing one encryption and one recovery with public test data.",
        "",
    );
    let work = options.settings.work_factor()?;
    let input = &PUBLIC_INPUTS[0];
    let password = Password::new(input.password())?;

    let started = Instant::now();
    let mut mhfe = settings::reserve_memory(work)?;
    let work_area_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let container = mhfe.encrypt(input.phrase(), &password, &mut |_, _| Ok(()))?;
    let encryption_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    mhfe.decrypt(&container, &password, PhraseLength::Detect, &mut |_, _| {
        Ok(())
    })?;
    let decryption_seconds = started.elapsed().as_secs_f64();

    let record = Measurement {
        suite_id: mhfe::SUITE_ID,
        implementation: format!("mhfe {}", env!("CARGO_PKG_VERSION")),
        argon2_engine: if cfg!(all(target_arch = "x86_64", feature = "ssse3")) {
            "reference C, opt.c with SSSE3, 4 threads"
        } else if cfg!(target_arch = "x86_64") {
            "reference C, opt.c with SSE2, 4 threads"
        } else {
            "reference C, ref.c, 4 threads"
        },
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
    println!("{text}");
    Ok(SUCCESS)
}
