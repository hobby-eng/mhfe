use clap::{Parser, Subcommand};
use mhfe::{MhfeEngine, MhfeError, NormalizedPassword, SUITE_ID};
use serde::Serialize;
use std::{fs, path::PathBuf, process::ExitCode, time::Instant};

const WARNING: &str = "TEST-ONLY: --test-password is visible in shell history and process \
listings. Use only public test data. MHFE is experimental and has no independent \
cryptography-specialist review.";

#[derive(Parser)]
#[command(
    name = "mhfe",
    version,
    about = "Experimental Memory-Hard Feistel Encryption for BIP39 Mnemonics vector and benchmark CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a valid English BIP39 phrase into a 24-word test container.
    Encrypt {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        test_password: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long)]
        trace: bool,
        #[arg(long)]
        json: bool,
    },
    /// Recover a source phrase, detecting its original word count by default.
    Decrypt {
        #[arg(long)]
        container: String,
        #[arg(long)]
        source_words: Option<usize>,
        #[arg(long)]
        test_password: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long)]
        trace: bool,
        #[arg(long)]
        json: bool,
    },
    /// Generate a public JSON vector, including password bytes and round secrets.
    Vector {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        test_password: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long)]
        output: PathBuf,
    },
    /// Measure one or more exact encrypt/decrypt round trips.
    Benchmark {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        test_password: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long, default_value_t = 1)]
        runs: u32,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Serialize)]
struct Timed<T> {
    elapsed_ms: f64,
    result: T,
}

#[derive(Serialize)]
struct PublicVector {
    warning: &'static str,
    implementation: &'static str,
    suite_id: &'static str,
    source_mnemonic: String,
    test_password_ascii: String,
    password_utf8_hex: String,
    encryption: mhfe::VectorEncryptionResult,
    decryption: mhfe::VectorDecryptionResult,
}

#[derive(Serialize)]
struct BenchmarkRun {
    run: u32,
    allocation_ms: f64,
    encryption_ms: f64,
    decryption_ms: f64,
    round_trip_ms: f64,
}

#[derive(Serialize)]
struct BenchmarkReport {
    warning: &'static str,
    implementation: &'static str,
    suite_id: &'static str,
    pim: u32,
    effective_passes: u32,
    memory_kib: u32,
    lanes: u32,
    rounds: u32,
    measurements: Vec<BenchmarkRun>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    eprintln!("{WARNING}");
    match cli.command {
        Command::Encrypt {
            mnemonic,
            test_password,
            pim,
            trace,
            json,
        } => {
            let password = NormalizedPassword::from_test_ascii(&test_password)?;
            let allocation_started = Instant::now();
            let mut engine = MhfeEngine::new(pim)?;
            let allocation_ms = millis(allocation_started.elapsed());
            let started = Instant::now();
            if trace {
                let result = engine.encrypt_vector(&mnemonic, &password)?;
                let elapsed_ms = millis(started.elapsed());
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&Timed { elapsed_ms, result })?
                    );
                } else {
                    print_encryption_summary(
                        pim,
                        engine.effective_passes(),
                        allocation_ms,
                        elapsed_ms,
                        &result.encrypted_mnemonic,
                    );
                }
            } else {
                let result = engine.encrypt_mnemonic(&mnemonic, &password)?;
                let elapsed_ms = millis(started.elapsed());
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&Timed { elapsed_ms, result })?
                    );
                } else {
                    print_encryption_summary(
                        pim,
                        engine.effective_passes(),
                        allocation_ms,
                        elapsed_ms,
                        &result.encrypted_mnemonic,
                    );
                }
            }
        }
        Command::Decrypt {
            container,
            source_words,
            test_password,
            pim,
            trace,
            json,
        } => {
            let password = NormalizedPassword::from_test_ascii(&test_password)?;
            let allocation_started = Instant::now();
            let mut engine = MhfeEngine::new(pim)?;
            let allocation_ms = millis(allocation_started.elapsed());
            let started = Instant::now();
            if trace {
                let source_words = source_words.ok_or(
                    "--source-words is required with --trace; omit --trace for automatic detection",
                )?;
                let result = engine.decrypt_vector(&container, source_words, &password)?;
                let elapsed_ms = millis(started.elapsed());
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&Timed { elapsed_ms, result })?
                    );
                } else {
                    print_decryption_summary(
                        pim,
                        engine.effective_passes(),
                        allocation_ms,
                        elapsed_ms,
                        result.source_words,
                        result.recovery_verified,
                        &result.recovered_mnemonic,
                    );
                }
            } else {
                let automatic = source_words.is_none();
                let result = match source_words {
                    Some(words) => engine.decrypt_mnemonic(&container, words, &password)?,
                    None => engine.decrypt_mnemonic_auto(&container, &password)?,
                };
                if automatic && !result.recovery_verified {
                    eprintln!(
                        "warning: no short-source verifier matched; the returned 24-word interpretation is unverified. Confirm wallet identity using known public data."
                    );
                }
                let elapsed_ms = millis(started.elapsed());
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&Timed { elapsed_ms, result })?
                    );
                } else {
                    print_decryption_summary(
                        pim,
                        engine.effective_passes(),
                        allocation_ms,
                        elapsed_ms,
                        result.source_words,
                        result.recovery_verified,
                        &result.recovered_mnemonic,
                    );
                }
            }
        }
        Command::Vector {
            mnemonic,
            test_password,
            pim,
            output,
        } => {
            let password = NormalizedPassword::from_test_ascii(&test_password)?;
            let mut engine = MhfeEngine::new(pim)?;
            let encrypt_started = Instant::now();
            let encryption = engine.encrypt_vector(&mnemonic, &password)?;
            let encryption_ms = millis(encrypt_started.elapsed());
            let decrypt_started = Instant::now();
            let decryption = engine.decrypt_vector(
                &encryption.encrypted_mnemonic,
                encryption.source_words,
                &password,
            )?;
            let decryption_ms = millis(decrypt_started.elapsed());
            let canonical_source = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
            if decryption.recovered_mnemonic != canonical_source {
                return Err(Box::new(MhfeError::Internal(
                    "round-trip mnemonic mismatch".to_owned(),
                )));
            }
            let vector = PublicVector {
                warning: WARNING,
                implementation: "mhfe-experimental-rust/0.3.0",
                suite_id: SUITE_ID,
                source_mnemonic: canonical_source,
                test_password_ascii: test_password,
                password_utf8_hex: hex::encode(password.as_bytes()),
                encryption,
                decryption,
            };
            write_json(&output, &vector)?;
            println!("Wrote {}", output.display());
            println!("Encryption: {encryption_ms:.3} ms");
            println!("Decryption: {decryption_ms:.3} ms");
        }
        Command::Benchmark {
            mnemonic,
            test_password,
            pim,
            runs,
            output,
        } => {
            if runs == 0 {
                return Err("--runs must be at least 1".into());
            }
            let password = NormalizedPassword::from_test_ascii(&test_password)?;
            let mut measurements = Vec::with_capacity(runs as usize);
            let mut effective_passes = 0;
            for run in 1..=runs {
                let allocation_started = Instant::now();
                let mut engine = MhfeEngine::new(pim)?;
                let allocation_ms = millis(allocation_started.elapsed());
                effective_passes = engine.effective_passes();
                let encryption_started = Instant::now();
                let encrypted = engine.encrypt_mnemonic(&mnemonic, &password)?;
                let encryption_ms = millis(encryption_started.elapsed());
                let decryption_started = Instant::now();
                let recovered = engine.decrypt_mnemonic(
                    &encrypted.encrypted_mnemonic,
                    encrypted.source_words,
                    &password,
                )?;
                let decryption_ms = millis(decryption_started.elapsed());
                if recovered.recovered_mnemonic
                    != mnemonic.split_whitespace().collect::<Vec<_>>().join(" ")
                {
                    return Err("benchmark round trip failed".into());
                }
                measurements.push(BenchmarkRun {
                    run,
                    allocation_ms,
                    encryption_ms,
                    decryption_ms,
                    round_trip_ms: encryption_ms + decryption_ms,
                });
            }
            let report = BenchmarkReport {
                warning: WARNING,
                implementation: "mhfe-experimental-rust/0.3.0",
                suite_id: SUITE_ID,
                pim,
                effective_passes,
                memory_kib: mhfe::MEMORY_KIB,
                lanes: mhfe::LANES,
                rounds: mhfe::ROUND_COUNT,
                measurements,
            };
            if let Some(path) = output {
                write_json(&path, &report)?;
                println!("Wrote {}", path.display());
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
    }
    Ok(())
}

fn millis(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_encryption_summary(
    pim: u32,
    effective_passes: u32,
    allocation_ms: f64,
    elapsed_ms: f64,
    encrypted_mnemonic: &str,
) {
    println!("Suite: {SUITE_ID}");
    println!("PIM: {pim} (t={effective_passes})");
    println!("Work-area allocation: {allocation_ms:.3} ms");
    println!("Encryption: {elapsed_ms:.3} ms");
    println!("Container: {encrypted_mnemonic}");
}

fn print_decryption_summary(
    pim: u32,
    effective_passes: u32,
    allocation_ms: f64,
    elapsed_ms: f64,
    source_words: usize,
    recovery_verified: bool,
    recovered_mnemonic: &str,
) {
    println!("Suite: {SUITE_ID}");
    println!("PIM: {pim} (t={effective_passes})");
    println!("Work-area allocation: {allocation_ms:.3} ms");
    println!("Decryption: {elapsed_ms:.3} ms");
    println!("Detected source words: {source_words}");
    println!("Recovery verified: {recovery_verified}");
    println!("Mnemonic: {recovered_mnemonic}");
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}
