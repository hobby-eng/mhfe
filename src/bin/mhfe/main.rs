//! The `mhfe` command-line tool.
//!
//! It turns an English BIP39 recovery phrase into a password-protected 24-word container and
//! back, rehearses a recovery without showing the phrase, and makes strong passwords from dice
//! words. Secrets are only ever typed at a hidden prompt or read from standard input, never
//! taken from command-line arguments.
// No unsafe code, except the few terminal calls in hidden_input.rs that switch the echo off.
#![deny(unsafe_code)]

mod check;
mod decrypt;
mod diceware;
mod encrypt;
mod exit;
mod hidden_input;
mod serve;
mod settings;
mod style;
mod terminal;
mod test_tools;

use clap::{Parser, Subcommand};

use crate::exit::Failure;

#[derive(Parser)]
#[command(
    name = "mhfe",
    version,
    styles = style::help_styles(),
    term_width = style::HELP_WIDTH,
    // Broken by hand at 80 columns: without its optional wrapping feature, clap prints text as
    // given, and that feature would add a dependency.
    about = "MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics\n\n\
             Encrypts an English BIP39 recovery phrase of 12 to 24 words into a password-\n\
             protected 24-word container that is itself a valid BIP39 phrase, and recovers\n\
             the original from it. Suite MHFE-BIP39-256-EXPERIMENTAL-3.",
    after_help = main_help(),
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a recovery phrase into a 24-word container
    #[command(after_help = encrypt::help())]
    Encrypt(encrypt::Options),
    /// Recover the original phrase from a container
    #[command(after_help = decrypt::help())]
    Decrypt(decrypt::Options),
    /// Rehearse a recovery without ever showing the phrase
    #[command(after_help = check::help())]
    Check(check::Options),
    /// Make a strong password of random dice words
    #[command(after_help = diceware::help())]
    Password(diceware::Options),
    /// Serve a browser tool on this computer in fast mode
    #[command(after_help = serve::help())]
    Serve(serve::Options),
    /// [test only] Write the public suite 3 test vectors
    TestVectors(test_tools::VectorOptions),
    /// [test only] Time one encryption and one recovery
    TestBenchmark(test_tools::BenchmarkOptions),
}

/// The end of `mhfe --help`: examples and the ground rules.
fn main_help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            (
                "mhfe encrypt",
                "Encrypt a recovery phrase with the default settings",
            ),
            ("mhfe decrypt", "Recover the phrase from a container"),
            (
                "mhfe check",
                "Rehearse a recovery without showing the phrase",
            ),
            ("mhfe password", "Make a strong password of five dice words"),
            (
                "mhfe encrypt --pim 1",
                "Encrypt with twice the default work",
            ),
            (
                "mhfe <COMMAND> --help",
                "Show what a command asks for and its options",
            ),
        ],
    );
    let note = "Secrets are typed at hidden prompts, never passed as arguments. Use MHFE on a \
                trusted computer without a network connection.";
    format!(
        "{examples}\n{}\n{}",
        style::help_note(note),
        style::paint(
            style::WARNING,
            "Experimental: not independently reviewed; do not use it to protect real funds."
        )
    )
}

fn main() {
    terminal::stop_on_ctrl_c();
    // Started without arguments, as by a double-click: explain, and offer the fast mode.
    let result = if std::env::args_os().len() == 1 {
        serve::run_without_arguments()
    } else {
        run(Cli::parse().command)
    };
    let exit_code = match result {
        Ok(code) => code,
        Err(failure) => {
            // An empty message means that the command has already shown it.
            if !failure.message.is_empty() {
                anstream::eprintln!();
                style::error(&failure.to_string());
            }
            failure.exit_code
        }
    };
    std::process::exit(exit_code);
}

fn run(command: Command) -> Result<i32, Failure> {
    match command {
        Command::Encrypt(options) => encrypt::run(options),
        Command::Decrypt(options) => decrypt::run(options),
        Command::Check(options) => check::run(options),
        Command::Password(options) => diceware::run(options),
        Command::Serve(options) => serve::run(options),
        Command::TestVectors(options) => test_tools::write_vectors(options),
        Command::TestBenchmark(options) => test_tools::benchmark(options),
    }
}
