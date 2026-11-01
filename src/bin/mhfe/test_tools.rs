//! The test-only command `mhfe test-benchmark`.
//!
//! It uses only the fixed public inputs below; nothing a user types is ever used.

use std::time::Instant;

use clap::Args;
use mhfe::{decrypt, encrypt, PhraseLength, Suite};
use mhfe_core::Password;
use serde::Serialize;

use crate::exit::{Failure, SUCCESS};
use crate::raw_io::println;
use crate::settings;
use crate::style;

/// The phrase and password it times: public test data, the specification's vector zero-12.
const PUBLIC_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PUBLIC_PASSWORD: &str = "public test password";

#[derive(Args)]
pub struct BenchmarkOptions {
    #[command(flatten)]
    settings: settings::Settings,
}

/// The end of `mhfe test-benchmark -h` and `--help`.
pub fn benchmark_help() -> String {
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
/// docs/measurements/.
pub fn benchmark(options: BenchmarkOptions) -> Result<i32, Failure> {
    style::warn(
        "TEST ONLY: timing one encryption and one recovery with public test data.",
        "",
    );
    let work = options.settings.work_factor()?;
    let password = Password::new(PUBLIC_PASSWORD)?;

    let started = Instant::now();
    let mut mhfe = settings::reserve_memory(work)?;
    let work_area_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let container = encrypt(
        &mut mhfe,
        PUBLIC_PHRASE,
        &password,
        Suite::TwentyFourWords,
        &mut |_, _| Ok(()),
        &mut |_| Ok(()),
    )?;
    let encryption_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    decrypt(
        &mut mhfe,
        &container,
        &password,
        PhraseLength::Detect,
        &mut |_, _| Ok(()),
    )?;
    let decryption_seconds = started.elapsed().as_secs_f64();

    let record = Measurement {
        suite_id: mhfe::SUITE_ID,
        implementation: format!("mhfe {}", env!("CARGO_PKG_VERSION")),
        argon2_engine: argon2_engine(),
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
    println!("{text}")?;
    Ok(SUCCESS)
}

/// The Argon2 code that ran, chosen as the engine of mhfe-core chooses it (its
/// `processor_has_ssse3`): x86-64 runs the SSSE3 copy of opt.c where the processor has SSSE3.
fn argon2_engine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return if std::arch::is_x86_feature_detected!("ssse3") {
        "reference C, opt.c with SSSE3, 4 threads"
    } else {
        "reference C, opt.c with SSE2, 4 threads"
    };
    #[cfg(not(target_arch = "x86_64"))]
    "reference C, ref.c, 4 threads"
}
