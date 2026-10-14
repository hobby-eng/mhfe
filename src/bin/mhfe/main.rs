//! The `mhfe` command-line tool.
//!
//! It turns an English BIP39 seed phrase into a password-protected 24-word container and
//! back, rehearses a recovery without showing the phrase, and makes strong passwords from dice
//! words. Secrets are only ever typed at a terminal or read from standard input, never taken from
//! command-line arguments.
// No unsafe code, except the few operating-system calls in hidden_input.rs, which switch the
// terminal's echo off, and in protect.rs, which forbid core dumps, and the test binary's
// allocator in typed_line.rs, which looks for unwiped copies.
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
mod time_text;
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
    #[command(
        about = new_wallet::SUMMARY,
        long_about = new_wallet::about(),
        after_help = new_wallet::help()
    )]
    New(new_wallet::Options),
    #[command(
        about = encrypt::SUMMARY,
        long_about = encrypt::about(),
        after_help = encrypt::help(),
        after_long_help = encrypt::long_help()
    )]
    Encrypt(encrypt::Options),
    #[command(
        about = decrypt::SUMMARY,
        long_about = decrypt::about(),
        after_help = decrypt::help(),
        after_long_help = decrypt::long_help()
    )]
    Decrypt(decrypt::Options),
    #[command(
        about = check::SUMMARY,
        long_about = check::about(),
        after_help = check::help(),
        after_long_help = check::long_help()
    )]
    Check(check::Options),
    #[command(about = rekey::SUMMARY, long_about = rekey::about(), after_help = rekey::help())]
    Rekey(rekey::Options),
    #[command(
        about = wallets::SUMMARY,
        long_about = wallets::about(),
        after_help = wallets::help()
    )]
    Wallets(wallets::Options),
    #[command(
        about = container_repair::REPAIR_SUMMARY,
        long_about = container_repair::repair_about(),
        after_help = container_repair::repair_help()
    )]
    Repair(container_repair::RepairOptions),
    #[command(
        about = container_repair::WORDS_SUMMARY,
        long_about = container_repair::words_about(),
        after_help = container_repair::words_help()
    )]
    RepairWords(container_repair::WordsOptions),
    #[command(
        about = diceware::SUMMARY,
        long_about = diceware::about(),
        after_help = diceware::help()
    )]
    Password(diceware::Options),
    #[command(
        about = self_test::SUMMARY,
        long_about = self_test::about(),
        after_help = self_test::help()
    )]
    SelfTest(self_test::Options),
    #[command(about = serve::SUMMARY, long_about = serve::about(), after_help = serve::help())]
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
            ("mhfe new", new_wallet::SUMMARY),
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
                "Run the self-test of every part, in seconds",
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
    format!(
        "{examples}\n{full}\n{}\n{}",
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
    // menu, which runs the same commands, each in an isolated thread of its own. The checks at
    // start run once, before the menu and before any isolation: the menu enters no network
    // namespace of its own, and its commands, which run in threads of it, cannot. --help and
    // --version, which clap answers in Cli::try_parse, handle nothing secret and run none.
    let result = if std::env::args_os().len() == 1 && hidden_input::can_redraw() {
        menu::start()
    } else {
        let command = Cli::try_parse()
            .unwrap_or_else(|error| exit_unparsed(error))
            .command;
        prepare(&command).and_then(|()| {
            terminal::stop_on_ctrl_c();
            run(command)
        })
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
    // Rendered as plain text; mhfe adds its own colours.
    style::usage_error(&error.render().to_string());
    std::process::exit(exit::INVALID_INPUT);
}

/// Isolates a command started directly and runs its checks at start, before it reads anything.
/// The order matters (G10 of the self-check plan): a process enters its own network namespace
/// only while it has a single thread, and the Argon2 check at start runs on four threads. The
/// start menu runs the same checks before it opens, with no network namespace (menu.rs).
fn prepare(command: &Command) -> Result<(), Failure> {
    protect::isolate(needs_of(command));
    startup::check(startup_checks_of(command))
}

/// Which checks a command runs at its start (startup.rs). Every command is named, so that a new
/// one must be decided here.
fn startup_checks_of(command: &Command) -> startup::Checks {
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
        | Command::Password(_) => Checks::EveryPart,
        // It runs every check itself and reports each one.
        Command::SelfTest(_) => Checks::Nothing,
        // It compares a page with its SHA-256 before serving it, and handles no secret.
        Command::Serve(_) => Checks::Hashes,
        // It writes the fixtures that the checks embed: after a deliberate change of the algorithm
        // the checks would fail until the new fixtures are written and built in, so it must run
        // without them. It handles public test data only.
        Command::TestVectors(_) => Checks::Nothing,
        // It times public test data only.
        Command::TestBenchmark(_) => Checks::Nothing,
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
        Command::New(options) => new_wallet::run(options),
        Command::Rekey(options) => rekey::run(options),
        Command::Wallets(options) => wallets::run(options),
        Command::Repair(options) => container_repair::run_repair(options),
        Command::RepairWords(options) => container_repair::run_words(options),
        Command::Password(options) => diceware::run(options),
        Command::SelfTest(options) => self_test::run(options),
        Command::Serve(options) => serve::run(options),
        Command::TestVectors(options) => test_tools::write_vectors(options),
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

    /// Every result reaches standard output through `style::out`, which reports a write that
    /// failed, a closed pipe included, instead of panicking or exiting with success
    /// (AUD-023-FUN001): no other code of the tool prints to standard output.
    #[test]
    fn every_result_is_written_through_one_function() {
        // Every module of the tool, its submodules in their folders included.
        let mut folders =
            vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/mhfe")];
        let mut files = Vec::new();
        while let Some(folder) = folders.pop() {
            for entry in std::fs::read_dir(folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        assert!(files.len() > 30, "the tool's modules are read");
        for path in files {
            let text = std::fs::read_to_string(&path).unwrap();
            // The code, not its tests, which may name the macros.
            let code = text.split("#[cfg(test)]").next().unwrap_or_default();
            let without_errors = code.replace("eprintln!(", "").replace("eprint!(", "");
            for macro_call in ["println!(", "print!("] {
                assert!(
                    !without_errors.contains(macro_call),
                    "{} writes to standard output with {macro_call}",
                    path.display()
                );
            }
        }
    }

    /// The --stdin helps name every line of a script's input and output: the card line of
    /// --repair-words in encrypt, the repair words of --repair in decrypt and check, and where
    /// the dice rolls show (AUD-023-DOC001).
    #[test]
    fn the_script_helps_name_every_line() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        let mut long_help = |name: &str| {
            let command = cli.find_subcommand_mut(name).unwrap();
            let text = command.render_long_help().to_string();
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        };
        assert!(long_help("encrypt")
            .contains("with --repair-words N the repair words on a second line"));
        for name in ["decrypt", "check"] {
            assert!(
                long_help(name).contains(
                    "With --repair, the repair words come on the line right after the container"
                ),
                "{name}"
            );
        }
        let password = long_help("password");
        assert!(password.contains("shown on the private screen"));
        assert!(!password.contains("at a hidden prompt"));
    }

    /// The settings' limits, the password sizes, the repair word counts and the length ranges
    /// that the helps state are their constants': a help that typed one of them again would fail
    /// here when the constant changes (AUD-023-ARC007).
    #[test]
    fn every_help_states_the_limits_of_the_constants() {
        use clap::CommandFactory;
        use mhfe::new_password::{
            DEFAULT_CHARACTERS, DEFAULT_WORDS, MOST_CHARACTERS, MOST_WORDS, RECOMMENDED_WORDS,
        };
        let mut cli = Cli::command();
        let mut help = |name: &str, long: bool| {
            let command = cli.find_subcommand_mut(name).unwrap();
            let text = if long {
                command.render_long_help()
            } else {
                command.render_help()
            };
            text.to_string()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        // Built here from the constants, apart from the helpers that write the helps.
        let ends = |counts: &[usize]| (counts[0], *counts.last().unwrap());
        let first_last = |counts: &[usize]| {
            let (first, last) = ends(counts);
            format!("{first} to {last}")
        };
        let cards: Vec<String> = mhfe::repair::REPAIR_WORD_COUNTS
            .iter()
            .map(ToString::to_string)
            .collect();
        let cards = style::or_list(&cards);
        for long in [false, true] {
            for name in ["encrypt", "decrypt", "check", "rekey", "new"] {
                let text = help(name, long);
                assert!(text.contains(&format!("0 to {}", mhfe::MAX_PIM)), "{name}");
                assert!(
                    text.contains(&format!("0 to {}", mhfe::MAX_MEMORY_LEVEL)),
                    "{name}"
                );
            }
            let password = help("password", long);
            assert!(password.contains(&format!(
                "1 to {MOST_WORDS} (default {DEFAULT_WORDS}; fewer than {RECOMMENDED_WORDS} are weak)"
            )));
            assert!(password.contains(&format!("(default {DEFAULT_CHARACTERS})")));
            assert!(
                help("repair-words", long).contains(&format!("Number of repair words: {cards}"))
            );
        }
        // The short helps of the length; the long ones list every length.
        assert!(help("decrypt", false).contains(&first_last(&mhfe::WORD_COUNTS)));
        let (first, last) = ends(&mhfe::BUILT_IN_CHECK_WORD_COUNTS);
        assert!(help("check", false).contains(&format!("{first}- to {last}-word")));
        assert!(help("check", true).contains(&format!("{first}- to {last}-word")));
        assert!(help("password", true).contains(&format!("1 to {MOST_CHARACTERS}")));
        assert!(help("encrypt", true).contains(&format!("none, or {cards} for a card")));
    }

    /// Each command's summary, which `-h` and the menu show, is the first line of its `--help`
    /// (AUD-023-ARC006).
    #[test]
    fn every_summary_heads_its_long_help() {
        use clap::CommandFactory;
        let cli = Cli::command();
        for command in cli.get_subcommands() {
            let Some(long) = command.get_long_about() else {
                continue;
            };
            let about = command.get_about().expect("every command has a summary");
            assert_eq!(
                long.to_string().lines().next(),
                Some(about.to_string().as_str()),
                "{}",
                command.get_name()
            );
        }
    }

    /// Every command that reads a secret checks every part first; the self-test checks them
    /// itself, the fast mode its hashes, and the test tools none.
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
                startup_checks_of(&command(arguments)),
                Checks::EveryPart,
                "{arguments:?}"
            );
        }
        assert_eq!(startup_checks_of(&command(&["self-test"])), Checks::Nothing);
        assert_eq!(
            startup_checks_of(&command(&["self-test", "--vectors"])),
            Checks::Nothing
        );
        assert_eq!(
            startup_checks_of(&command(&["serve", "tool.html"])),
            Checks::Hashes
        );
        assert_eq!(
            startup_checks_of(&command(&["test-vectors", "--output", "folder"])),
            Checks::Nothing
        );
    }
}
