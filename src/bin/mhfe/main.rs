//! The `mhfe` command-line tool.
//!
//! It turns an English BIP39 seed phrase into a password-protected 24-word container and
//! back, rehearses a recovery without showing the phrase, and makes strong passwords from dice
//! words. Secrets are only ever typed at a terminal or read from standard input, never taken from
//! command-line arguments.
// No unsafe code, except the few operating-system calls of the modules that allow them at their
// top, each with its reason.
#![deny(unsafe_code)]

mod cell_widths;
mod check;
mod check_word;
mod choice;
mod chosen_words;
mod container_repair;
mod container_search;
mod decrypt;
mod diceware;
mod encrypt;
mod exit;
mod flow;
mod hidden_input;
mod length_choice;
mod made_password;
mod menu;
mod new_wallet;
mod phrase_length;
mod protect;
mod raw_io;
mod readme;
mod rekey;
mod self_test;
mod serve;
mod settings;
mod startup;
mod style;
mod system_random;
mod terminal;
mod test_tools;
mod typed_line;
mod wallets;

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
             as a 12- to 21-word original seed phrase if you choose so. Recovers the\n\
             original seed phrase from it.\n\
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
    /// Generate a new wallet and its container
    #[command(long_about = new_wallet::about(), after_help = new_wallet::help())]
    New(new_wallet::Options),
    /// Encrypt a seed phrase into a container
    #[command(
        long_about = encrypt::about(),
        after_help = encrypt::help(),
        after_long_help = encrypt::long_help()
    )]
    Encrypt(encrypt::Options),
    /// Recover the original seed phrase from a container
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
    /// Change the password or settings of a container
    #[command(long_about = rekey::about(), after_help = rekey::help())]
    Rekey(rekey::Options),
    /// Open hidden wallets with other passwords
    #[command(long_about = wallets::about(), after_help = wallets::help())]
    Wallets(wallets::Options),
    /// Repair a container phrase with its repair words
    #[command(
        long_about = container_repair::repair_about(),
        after_help = container_repair::repair_help()
    )]
    Repair(container_repair::RepairOptions),
    /// Make repair words for a container phrase
    #[command(
        long_about = container_repair::words_about(),
        after_help = container_repair::words_help()
    )]
    RepairWords(container_repair::WordsOptions),
    /// Make a strong password of words or characters
    #[command(long_about = diceware::about(), after_help = diceware::help())]
    Password(diceware::Options),
    /// Test every part of this program
    #[command(long_about = self_test::about(), after_help = self_test::help())]
    SelfTest(self_test::Options),
    /// Serve a browser tool on this computer in fast mode
    #[command(long_about = serve::about(), after_help = serve::help())]
    Serve(serve::Options),
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
            ("mhfe new", "Generate a new wallet and its container"),
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
            (
                "mhfe rekey",
                "Change the password or settings of a container",
            ),
            ("mhfe wallets", "Open hidden wallets with other passwords"),
            (
                "mhfe repair",
                "Repair a container phrase with its repair words",
            ),
            (
                "mhfe repair-words --count 4",
                "Make four repair words for a container phrase",
            ),
            ("mhfe password", "Make a strong password of five dice words"),
            (
                "mhfe password --dice --words 6",
                "Make a password of six words from real dice",
            ),
            (
                "mhfe self-test",
                "Test every part of this program, in seconds",
            ),
            (
                "mhfe self-test --vectors",
                "Also run the published vectors: minutes, 2 GiB",
            ),
            ("mhfe serve tool.html", "Open a browser tool in fast mode"),
            (
                "mhfe encrypt --help",
                "Every option of a command, more examples",
            ),
        ],
    );
    // Commands too long for the two columns above, each with its explanation below it.
    let full = style::help_section(
        "Examples with every option:",
        &[
            (
                "mhfe encrypt --pim 3 --mem 2 --same-length --new-password check-word",
                "PIM 3 and 4 GiB, a container as long as a 12- to 21-word phrase, and a password \
                 that MHFE makes: five words and a check word",
            ),
            (
                "mhfe decrypt --pim 3 --mem 2 --words auto --repair --scan-gap 100",
                "Those settings, the length detected, the repair words asked right after the \
                 container, and without them a search for two missing words over the first 100 \
                 addresses",
            ),
            (
                "mhfe rekey --pim 3 --mem 2 --new-pim 1 --new-mem 0 --new-password words",
                "From PIM 3 and 4 GiB to PIM 1 and 2 GiB, under five dice words that MHFE \
                 makes; --words, --repair and --scan-gap as for decrypt",
            ),
        ],
    );
    let note = "Secrets are typed on a private screen, never passed as arguments. Use MHFE on a \
                trusted computer without a network connection. -h gives a short summary of a \
                command, --help the full explanation.";
    format!("{examples}\n{full}\n{}", style::help_note(note))
}

fn main() {
    // An exception to RUST-09, which hardens the process in the first lines of main: the start
    // menu and the fast mode hold no secret, and prepare hardens a command before it reads one.
    //
    // Started without arguments in a terminal, as by a double-click or a launcher script: the
    // menu, which runs the same commands, each as a process of its own that comes through the
    // other branch. --help and --version, which clap answers in Cli::try_parse, handle nothing
    // secret and run no checks.
    // TERM=dumb takes no colours, whatever CI or CLICOLOR say, unless CLICOLOR_FORCE insists.
    if std::env::var_os("TERM").is_some_and(|term| term == "dumb")
        && std::env::var_os("CLICOLOR_FORCE").is_none()
    {
        anstream::ColorChoice::Never.write_global();
    }
    let result = if std::env::args_os().len() == 1 && choice::can_run() {
        menu::start()
    } else {
        let command = Cli::try_parse()
            .unwrap_or_else(|error| exit_unparsed(error))
            .command;
        prepare(&command).and_then(|()| run(command))
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
        style::error_wrapped(&failure.to_string());
    }
}

/// Ends the tool when clap did not give a command. Help and the version, which clap reports the
/// same way, are printed as clap prints them. A usage error, such as an unknown option, is shown
/// as every other error of the tool, after a red "✗ Error:", with clap's tip and the usage in
/// grey, and exit code 2 (AUD-010).
fn exit_unparsed(error: clap::Error) -> ! {
    use clap::error::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            | ErrorKind::DisplayVersion
    ) {
        error.exit();
    }
    anstream::eprintln!();
    style::usage_error(&refusal_of(&error));
    std::process::exit(exit::INVALID_INPUT);
}

/// What a refused command line says, in clap's form: never a value or an argument as it was given,
/// which may be a phrase pasted in the wrong place (CORE-24). Only the names of options and clap's
/// usage are repeated.
fn refusal_of(error: &clap::Error) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    // Rendered as plain text; mhfe adds its own colours.
    let rendered = error.render().to_string();
    let option = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(name)) => name.as_str(),
        _ => "an option",
    };
    let message = match error.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            format!("invalid value for {option}")
        }
        ErrorKind::UnknownArgument | ErrorKind::TooManyValues => "unexpected argument".to_owned(),
        ErrorKind::InvalidSubcommand => "unknown command".to_owned(),
        // These name options and counts only.
        _ => return rendered,
    };
    let tail = rendered
        .lines()
        .filter(|line| line.starts_with("Usage:") || line.starts_with("For more"))
        .collect::<Vec<_>>()
        .join("\n\n");
    format!("error: {message}\n\n{tail}\n")
}

/// Isolates a command, sets what ends it and runs its checks at start, before it reads anything.
/// The order matters: a process enters its own network namespace only
/// while it has a single thread, the handler of Ctrl+C has a thread of its own, and the Argon2
/// check at start runs on four. The handler comes before the checks, which take a moment, so that
/// a key pressed in them ends the command as it does later. The start menu, which is no command,
/// isolates nothing and runs the same checks but those of isolation before it opens (menu.rs).
fn prepare(command: &Command) -> Result<(), Failure> {
    let (isolated, checks) = isolation_and_checks_of(command);
    // Every command that runs all the checks reads secrets.
    if matches!(checks, startup::Checks::EveryPart) {
        protect::keep_off_swap()?;
    }
    if isolated {
        protect::enter();
    }
    terminal::stop_on_ctrl_c();
    startup::check(checks)
}

/// Whether a command runs isolated (protect.rs), and which checks it runs at its start
/// (startup.rs). Every command is named, so that a new one must be decided here.
fn isolation_and_checks_of(command: &Command) -> (bool, startup::Checks) {
    use startup::Checks;
    match command {
        Command::New(_)
        | Command::Encrypt(_)
        | Command::Decrypt(_)
        | Command::Check(_)
        | Command::Rekey(_)
        | Command::Wallets(_)
        | Command::Repair(_)
        | Command::RepairWords(_)
        | Command::Password(_) => (true, Checks::EveryPart),
        // It runs every check itself and reports each one.
        Command::SelfTest(_) => (true, Checks::Nothing),
        // It compares a page with its SHA-256 before serving it to a browser it may start, which
        // must write its profile, so it stays out of isolation; it handles no secret.
        Command::Serve(_) => (false, Checks::Hashes),
        // It times public test data only.
        Command::TestBenchmark(_) => (true, Checks::Nothing),
    }
}

fn run(command: Command) -> Result<i32, Failure> {
    match command {
        Command::Encrypt(options) => encrypt::run(options),
        Command::Decrypt(options) => decrypt::run(options),
        Command::Check(options) => check::run(options),
        Command::New(options) => new_wallet::run(options),
        Command::Rekey(options) => rekey::run(options),
        Command::Wallets(options) => wallets::run(options),
        Command::Repair(options) => container_repair::run_repair(options),
        Command::RepairWords(options) => container_repair::run_words(options),
        Command::Password(options) => diceware::run(options),
        Command::SelfTest(options) => self_test::run(options),
        Command::Serve(options) => serve::run(options),
        Command::TestBenchmark(options) => test_tools::benchmark(options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(arguments: &[&str]) -> Command {
        let typed = std::iter::once("mhfe").chain(arguments.iter().copied());
        Cli::try_parse_from(typed).unwrap().command
    }

    /// The help of the tool and of every command, short (-h) and long (--help, and `mhfe help`),
    /// fits the help width and ends with examples (AUD-010).
    #[test]
    fn every_help_fits_the_help_width_and_has_examples() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        cli.build();
        let mut helps = vec![
            ("mhfe -h".to_owned(), cli.render_help().to_string()),
            ("mhfe --help".to_owned(), cli.render_long_help().to_string()),
        ];
        // clap's own `help` command lists the commands and has nothing else to show.
        for command in cli.get_subcommands_mut().filter(|c| c.get_name() != "help") {
            let name = command.get_name().to_owned();
            helps.push((format!("{name} -h"), command.render_help().to_string()));
            helps.push((
                format!("{name} --help"),
                command.render_long_help().to_string(),
            ));
        }
        for (help, text) in helps {
            for line in text.lines() {
                assert!(
                    style::visible_width(line) <= style::HELP_WIDTH,
                    "{help}: {line}"
                );
            }
            assert!(text.contains("\nExamples:\n"), "{help} has no examples");
        }
    }

    /// Every command that reads a secret runs isolated and checks every part first; the self-test
    /// checks them itself, the fast mode, the only one out of isolation, its hashes, and the test
    /// tool none.
    #[test]
    fn every_secret_command_checks_every_part_at_start() {
        use startup::Checks;
        for arguments in [
            &["new"][..],
            &["encrypt"],
            &["decrypt"],
            &["check"],
            &["rekey"],
            &["wallets"],
            &["repair"],
            &["repair-words"],
            &["password"],
        ] {
            assert_eq!(
                isolation_and_checks_of(&command(arguments)),
                (true, Checks::EveryPart),
                "{arguments:?}"
            );
        }
        assert_eq!(
            isolation_and_checks_of(&command(&["self-test"])),
            (true, Checks::Nothing)
        );
        assert_eq!(
            isolation_and_checks_of(&command(&["self-test", "--vectors"])),
            (true, Checks::Nothing)
        );
        assert_eq!(
            isolation_and_checks_of(&command(&["serve", "tool.html"])),
            (false, Checks::Hashes)
        );
        assert_eq!(
            isolation_and_checks_of(&command(&["test-benchmark"])),
            (true, Checks::Nothing)
        );
    }
}
