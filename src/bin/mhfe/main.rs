//! The `mhfe` command-line tool.
//!
//! It turns an English BIP39 seed phrase into a password-protected 24-word container and
//! back, rehearses a recovery without showing the phrase, and makes strong passwords from dice
//! words. Secrets are only ever typed at a terminal or read from standard input, never taken from
//! command-line arguments.
// No unsafe code, except the few operating-system calls in hidden_input.rs, which switch the
// terminal's echo off, and in protect.rs, which forbid core dumps.
#![deny(unsafe_code)]

mod check;
mod choice;
mod decrypt;
mod diceware;
mod encrypt;
mod exit;
mod hidden_input;
mod length_choice;
mod menu;
mod protect;
mod readme;
mod serve;
mod settings;
mod strength;
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
             Encrypts an English BIP39 seed phrase of 12 to 24 words into a password-\n\
             protected container that is itself a valid BIP39 phrase: 24 words, or as many\n\
             as a 12- to 21-word original if you choose so. Recovers the original from it.\n\
             Suites MHFE-BIP39-256-EXPERIMENTAL-3 and MHFE-BIP39-LP-EXPERIMENTAL-4.",
    after_help = main_help(),
    // Without a terminal for the menu, `mhfe` alone prints this help.
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a seed phrase into a container
    #[command(
        long_about = encrypt::about(),
        after_help = encrypt::help(),
        after_long_help = encrypt::long_help()
    )]
    Encrypt(encrypt::Options),
    /// Recover the original phrase from a container
    #[command(
        long_about = decrypt::about(),
        after_help = decrypt::help(),
        after_long_help = decrypt::long_help()
    )]
    Decrypt(decrypt::Options),
    /// Rehearse a recovery without ever showing the phrase
    #[command(
        long_about = check::about(),
        after_help = check::help(),
        after_long_help = check::long_help()
    )]
    Check(check::Options),
    /// Make a strong password of random dice words
    #[command(long_about = diceware::about(), after_help = diceware::help())]
    Password(diceware::Options),
    /// Serve a browser tool on this computer in fast mode
    #[command(long_about = serve::about(), after_help = serve::help())]
    Serve(serve::Options),
    /// [test only] Write the public suite 3 or suite 4 test vectors
    #[command(after_help = test_tools::vectors_help())]
    TestVectors(test_tools::VectorOptions),
    /// [test only] Time one encryption and one recovery
    #[command(after_help = test_tools::benchmark_help())]
    TestBenchmark(test_tools::BenchmarkOptions),
}

/// The end of `mhfe --help`: examples and the ground rules.
fn main_help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe", "Choose a command from a menu"),
            ("mhfe encrypt", "Encrypt a phrase with the default settings"),
            (
                "mhfe encrypt --pim 1 --mem 1",
                "Encrypt with twice the passes and 3 GiB",
            ),
            ("mhfe decrypt", "Recover the phrase from a container"),
            (
                "mhfe decrypt --pim 1 --mem 1",
                "Recover a container made with those settings",
            ),
            (
                "mhfe check",
                "Rehearse a recovery without showing the phrase",
            ),
            (
                "mhfe check --address",
                "Rehearse it against a wallet address",
            ),
            ("mhfe password", "Make a strong password of five dice words"),
            (
                "mhfe password --dice --words 6",
                "Make a password of six words from real dice",
            ),
            ("mhfe serve tool.html", "Open a browser tool in fast mode"),
            (
                "mhfe encrypt --help",
                "Every option of a command, more examples",
            ),
        ],
    );
    let note = "Secrets are typed at hidden prompts, never passed as arguments. Use MHFE on a \
                trusted computer without a network connection. -h gives a short summary of a \
                command, --help the full explanation.";
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
    // Before anything else, so that no secret can ever be in a core dump.
    protect::harden_process();
    // Started without arguments in a terminal, as by a double-click or a launcher script: the
    // menu, which runs the same commands, each in an isolated thread of its own.
    let result = if std::env::args_os().len() == 1 && choice::can_run() {
        terminal::stop_on_ctrl_c();
        menu::run()
    } else {
        let command = Cli::parse().command;
        protect::isolate(needs_of(&command));
        terminal::stop_on_ctrl_c();
        run(command)
    };
    let exit_code = match result {
        Ok(code) => code,
        Err(failure) => {
            show_failure(&failure);
            failure.exit_code
        }
    };
    std::process::exit(exit_code);
}

/// Shows why a command stopped. An empty message means that the command has already shown it.
fn show_failure(failure: &Failure) {
    if failure.exit_code == exit::CANCELLED {
        // q in a list: the person stopped on purpose, as with Ctrl+C, which is not an error.
        anstream::eprintln!();
        terminal::show_cancelled();
    } else if !failure.message.is_empty() {
        anstream::eprintln!();
        style::error(&failure.to_string());
    }
}

/// What a command needs that isolation would otherwise forbid (protect.rs).
fn needs_of(command: &Command) -> protect::Needs {
    match command {
        // The fast mode serves a page to a browser it may start, which must write its profile; it
        // handles no secret itself.
        Command::Serve(_) => protect::Needs {
            network: true,
            writes: true,
        },
        // Writes the vector files into the folder it is given.
        Command::TestVectors(_) => protect::Needs {
            network: false,
            writes: true,
        },
        _ => protect::Needs::NOTHING,
    }
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
