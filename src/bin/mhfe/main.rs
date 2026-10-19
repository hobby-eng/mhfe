//! The `mhfe` command-line tool.
//!
//! It turns an English BIP39 seed phrase into a password-protected 24-word container and
//! back, rehearses a recovery without showing the phrase, and makes strong passwords from dice
//! words. Secrets are only ever typed at a terminal or read from standard input, never taken from
//! command-line arguments.
// No unsafe code, except the few operating-system calls in hidden_input.rs, which switch the
// terminal's echo off, in standard_input.rs, which reads standard input, and in protect.rs, which
// forbid core dumps, and the test binary's allocator in test_allocator.rs, which looks for
// unwiped copies.
#![deny(unsafe_code)]

/// `eprint!` and `eprintln!` of the tool, through which every message goes: anstream's colours,
/// but a failed write of standard error does not panic, which would abort the tool without its
/// cleanup. The failure is remembered, and a command that otherwise succeeded ends with exit code
/// 1 (style::write_message, AUD-024-FUN009).
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::style::write_message(format_args!($($arg)*))
    };
}

/// [`eprint!`] with a line break after the message.
macro_rules! eprintln {
    () => {
        $crate::style::write_message(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::style::write_message(format_args!("{}\n", format_args!($($arg)*)))
    };
}

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
mod regular_file;
mod rekey;
mod self_test;
mod serve;
mod settings;
mod standard_input;
mod startup;
mod style;
mod system_random;
mod terminal;
#[cfg(test)]
mod test_allocator;
#[cfg(test)]
mod test_support;
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
    about = about(),
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
        after_help = style::help_ending(new_wallet::help())
    )]
    New(new_wallet::Options),
    #[command(
        about = encrypt::SUMMARY,
        long_about = encrypt::about(),
        after_help = style::help_ending(encrypt::examples()),
        after_long_help = style::help_ending(encrypt::long_help())
    )]
    Encrypt(encrypt::Options),
    #[command(
        about = decrypt::SUMMARY,
        long_about = decrypt::about(),
        after_help = style::help_ending(decrypt::examples()),
        after_long_help = style::help_ending(decrypt::long_help())
    )]
    Decrypt(decrypt::Options),
    #[command(
        about = check::SUMMARY,
        long_about = check::about(),
        after_help = style::help_ending(check::examples()),
        after_long_help = style::help_ending(check::long_help())
    )]
    Check(check::Options),
    #[command(about = rekey::SUMMARY, long_about = rekey::about(), after_help = style::help_ending(rekey::help()))]
    Rekey(rekey::Options),
    #[command(
        about = wallets::SUMMARY,
        long_about = wallets::about(),
        after_help = style::help_ending(wallets::help())
    )]
    Wallets(wallets::Options),
    #[command(
        about = container_repair::REPAIR_SUMMARY,
        long_about = container_repair::repair_about(),
        after_help = style::help_ending(container_repair::repair_help())
    )]
    Repair(container_repair::RepairOptions),
    #[command(
        about = container_repair::WORDS_SUMMARY,
        long_about = container_repair::words_about(),
        after_help = style::help_ending(container_repair::words_help())
    )]
    RepairWords(container_repair::WordsOptions),
    #[command(
        about = diceware::SUMMARY,
        long_about = diceware::about(),
        after_help = style::help_ending(diceware::help())
    )]
    Password(diceware::Options),
    #[command(
        about = self_test::SUMMARY,
        long_about = self_test::about(),
        after_help = style::help_ending(self_test::help())
    )]
    SelfTest(self_test::Options),
    #[command(about = serve::SUMMARY, long_about = serve::about(), after_help = style::help_ending(serve::help()))]
    Serve(serve::Options),
    /// [test only] Write the public suite 3 or suite 4 test vectors
    #[command(after_help = style::help_ending(test_tools::vectors_help()))]
    TestVectors(test_tools::VectorOptions),
    /// [test only] Time one encryption and one recovery
    #[command(after_help = style::help_ending(test_tools::benchmark_help()))]
    TestBenchmark(test_tools::BenchmarkOptions),
}

/// The top-level description, from the suites' current length ranges and identifiers.
fn about() -> String {
    style::command_about(&[
        "MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics",
        &format!("Encrypts an English BIP39 seed phrase of {} words into a password-protected \
                  container that is itself a valid BIP39 phrase: 24 words, or as many as a {} \
                  original seed phrase if you choose so. Recovers the original seed phrase from it.",
                  phrase_length::length_range(), phrase_length::short_range_words()),
        &format!("Suites {} and {}.", mhfe::SUITE_ID, mhfe::SAME_LENGTH_SUITE_ID),
    ])
}

/// The end of `mhfe --help`: examples and the ground rules.
fn main_help() -> String {
    use mhfe::new_password::DEFAULT_WORDS;
    use mhfe::repair::RECOMMENDED_REPAIR_WORDS;
    let more_words = DEFAULT_WORDS + 1;
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe", "Choose a command from a menu"),
            ("mhfe new", new_wallet::SUMMARY),
            ("mhfe encrypt", "Encrypt a phrase with the default settings"),
            (
                "mhfe encrypt --pim 1 --mem 1",
                &format!(
                    "Encrypt with twice the passes and {}",
                    settings::memory_text(1)
                ),
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
            ("mhfe rekey", rekey::SUMMARY),
            ("mhfe wallets", wallets::SUMMARY),
            ("mhfe repair", container_repair::REPAIR_SUMMARY),
            (
                &format!("mhfe repair-words --count {RECOMMENDED_REPAIR_WORDS}"),
                &format!(
                    "Make {} repair words for a container phrase",
                    style::number_word(RECOMMENDED_REPAIR_WORDS, false)
                ),
            ),
            (
                "mhfe password",
                &format!(
                    "Make a strong password of {} dice words",
                    style::number_word(DEFAULT_WORDS, false)
                ),
            ),
            (
                &format!("mhfe password --dice --words {more_words}"),
                &format!(
                    "Make a password of {} words from real dice",
                    style::number_word(more_words, false)
                ),
            ),
            (
                "mhfe self-test",
                "Run the self-test of every part, in seconds",
            ),
            (
                "mhfe self-test --vectors",
                &format!(
                    "Also run the published vectors: {}",
                    self_test::vectors_cost()
                ),
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
                &format!(
                    "PIM 3 and {}, a container as long as a {} phrase, and a password \
                 that MHFE makes: {} words and a check word",
                    settings::memory_text(2),
                    phrase_length::short_range_words(),
                    style::number_word(mhfe::check_word::DRAWN_WORDS, false)
                ),
            ),
            (
                "mhfe decrypt --pim 3 --mem 2 --words auto --repair --scan-gap 100",
                "Those settings, the length detected, the repair words asked right after the \
                 container, and without them a search for two missing words over the first 100 \
                 addresses",
            ),
            (
                "mhfe rekey --pim 3 --mem 2 --new-pim 1 --new-mem 0 --new-password words",
                &format!(
                    "From PIM 3 and {} to PIM 1 and {}, under {} dice words that MHFE \
                 makes; --words, --repair and --scan-gap as for decrypt",
                    settings::memory_text(2),
                    settings::memory_text(0),
                    style::number_word(DEFAULT_WORDS, false)
                ),
            ),
        ],
    );
    let note = "Secrets are typed on a private screen, never passed as arguments. -h gives a short summary of a \
                command, --help the full explanation.";
    style::help_ending(format!("{examples}\n{full}\n{}", style::help_note(note)))
}

fn main() {
    // Before anything else, so that no secret can ever be in a core dump.
    protect::harden_process();
    // A panic anywhere leaves the private screen and restores the terminal (AUD-024-FUN009).
    startup::install_panic_hook();
    style::configure_colours();
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
            failure.exit_code()
        }
    };
    std::process::exit(final_exit_code(exit_code, style::message_failed()));
}

/// The exit code of a command that ended with `code`: a message that could not be written to
/// standard error, as on a full disk, fails a command that otherwise succeeded, with exit code 1
/// (AUD-024-FUN009); any other code stands.
fn final_exit_code(code: i32, message_failed: bool) -> i32 {
    if code == exit::SUCCESS && message_failed {
        exit::INTERNAL_ERROR
    } else {
        code
    }
}

/// Shows why a command stopped. An empty message means that the command has already shown it.
fn show_failure(failure: &Failure) {
    if failure.exit_code() == exit::CANCELLED {
        // q in a list: the person stopped on purpose, as with Ctrl+C, which is not an error.
        eprintln!();
        terminal::show_cancelled();
    } else if !failure.message().is_empty() {
        eprintln!();
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
    eprintln!();
    style::usage_error(&usage_error_text(&error));
    std::process::exit(exit::INVALID_INPUT);
}

/// clap's text for a usage error, rendered as plain text, as mhfe adds its own colours. A value or
/// argument the person gave is left out, with every tip that repeats it: it may be a password or
/// a seed phrase typed on the command line by mistake (AUD-024-SEC004). A suggested option may
/// be named, but the unknown option itself is withheld too: its spelling proves no authority.
fn usage_error_text(error: &clap::Error) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if withheld_value(error).is_none() {
        return error.render().to_string();
    }
    // Render only closed parser context. Clap's suggestions can repeat the same input in
    // several forms, including a multiline '-- value'; filtering rendered lines cannot own it.
    let summary = match error.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::TooManyValues => {
            match error.get(ContextKind::InvalidArg) {
                Some(ContextValue::String(argument)) => {
                    format!("error: invalid value for '{argument}'")
                }
                _ => "error: invalid value".to_owned(),
            }
        }
        ErrorKind::InvalidSubcommand => "error: unrecognized subcommand".to_owned(),
        _ => "error: unexpected argument".to_owned(),
    };
    let mut text = format!("{summary}\n\n  tip: {WITHHELD_TIP}");
    // Only this typed, input-free refusal is safe to retain. An arbitrary parser's source may
    // include the supplied value even when its main error context has been withheld.
    if let Some(hint) = std::error::Error::source(error)
        .and_then(|source| source.downcast_ref::<choice::YesNoError>())
    {
        text.push_str(&format!("\n  tip: {hint}"));
    }
    if let Some(ContextValue::String(suggestion)) = error.get(ContextKind::SuggestedArg) {
        text.push_str(&format!(
            "\n  tip: a similar argument exists: '{suggestion}'"
        ));
    }
    if let Some(ContextValue::StyledStr(usage)) = error.get(ContextKind::Usage) {
        text.push_str("\n\n");
        text.push_str(&usage.to_string());
    }
    text
}

/// Why a usage error leaves out what was given.
const WITHHELD_TIP: &str = "what was given is not repeated, as it may be a secret: passwords and \
                            phrases are typed when asked, or given with --stdin";

/// The supplied value or argument that a usage error must withhold.
fn withheld_value(error: &clap::Error) -> Option<&str> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let kind = match error.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::TooManyValues => {
            ContextKind::InvalidValue
        }
        ErrorKind::UnknownArgument => ContextKind::InvalidArg,
        ErrorKind::InvalidSubcommand => ContextKind::InvalidSubcommand,
        _ => return None,
    };
    match error.get(kind) {
        Some(ContextValue::String(given)) if !given.is_empty() => Some(given),
        _ => None,
    }
}

/// Isolates a command started directly and runs its checks at start, before it reads anything.
///
/// The order matters: a process enters its own network namespace
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
        Command::Serve(_) => protect::Needs::new(true, true),
        // Writes the vector files into the folder it is given.
        Command::TestVectors(_) => protect::Needs::new(false, true),
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

    /// The usage error text of a command line that clap refuses.
    fn usage_error_of(arguments: &[&str]) -> String {
        let typed = std::iter::once("mhfe").chain(arguments.iter().copied());
        match Cli::try_parse_from(typed) {
            Ok(_) => panic!("{arguments:?} is a command"),
            Err(error) => usage_error_text(&error),
        }
    }

    /// A usage error names the option, never a phrase or password given by mistake; a mistyped
    /// option name keeps only the closed suggestion (AUD-024-SEC004).
    #[test]
    fn a_usage_error_does_not_repeat_what_was_given() {
        let phrase = "abandon ability able about above absent absorb abstract absurd abuse access \
                      accident";
        let password = "public-test-password";
        let address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let cases: [&[&str]; 9] = [
            &["encrypt", phrase],
            &[phrase],
            &["abandon", "ability"],
            &["check", "--address", "--coin", phrase],
            &["check", "--address", "--path", phrase],
            &["check", "--words", phrase],
            &["encrypt", "--pim", password],
            &["rekey", "--new-pim", password],
            &["check", address, "--address", "--path", password],
        ];
        for arguments in cases {
            let text = usage_error_of(arguments);
            for secret in ["abandon", "ability", password] {
                assert!(!text.contains(secret), "{arguments:?}: {text}");
            }
            assert!(text.contains(WITHHELD_TIP), "{arguments:?}: {text}");
        }
        let text = usage_error_of(&["check", "--words", phrase]);
        assert!(
            text.starts_with("error: invalid value for '--words <N>'"),
            "{text}"
        );
        let typo = usage_error_of(&["encrypt", "--stdn"]);
        assert!(
            !typo.contains("--stdn") && typo.contains("'--stdin'"),
            "{typo}"
        );
        assert!(typo.contains(WITHHELD_TIP));
    }

    #[test]
    fn a_usage_error_withholds_every_line_of_a_refused_argument() {
        for separator in ["", ".", "\n", "\r\n", "\r", "\u{85}", "\u{2028}"] {
            let given = format!("AUD026FIRST{separator}AUD026SECOND");
            let option = format!("--{given}");
            for arguments in [
                vec!["encrypt", "--pim", &given],
                vec!["rekey", "--new-pim", &given],
                vec!["encrypt", &given],
                vec![&given],
                vec!["serve", &option],
            ] {
                let text = usage_error_of(&arguments);
                for part in ["AUD026FIRST", "AUD026SECOND"] {
                    assert!(!text.contains(part), "{arguments:?}: {text}");
                }
                assert!(text.contains(WITHHELD_TIP), "{text}");
            }
        }
    }

    #[test]
    fn yes_no_usage_errors_keep_the_fixed_hint_without_repeating_the_input() {
        let options: &[&[&str]] = &[
            &["new", "--wallet-check"],
            &["new", "--choose-word"],
            &["encrypt", "--same-length"],
            &["check", "--words", "auto", "--passphrase-used"],
        ];
        for prefix in options {
            for given in [
                "maybe",
                "AUD027FIRST\nAUD027SECOND",
                "AUD027FIRST\u{2028}AUD027SECOND",
            ] {
                let mut arguments = prefix.to_vec();
                arguments.push(given);
                let text = usage_error_of(&arguments);
                assert!(text.contains("give yes or no"), "{text}");
                assert!(text.contains(WITHHELD_TIP), "{text}");
                for withheld in [given, "AUD027FIRST", "AUD027SECOND"] {
                    assert!(!text.contains(withheld), "{text}");
                }
            }
        }
    }

    #[test]
    fn an_arbitrary_parser_source_cannot_supply_a_displayed_hint() {
        fn refuses(text: &str) -> Result<String, std::io::Error> {
            Err(std::io::Error::other(format!(
                "AUD027SOURCE give yes or no: {text}"
            )))
        }
        let error = clap::Command::new("probe")
            .arg(clap::Arg::new("value").long("value").value_parser(refuses))
            .try_get_matches_from(["probe", "--value", "AUD027INPUT\nAUD027SECOND"])
            .unwrap_err();
        assert!(std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains("AUD027SOURCE"));
        let text = usage_error_text(&error);
        assert!(text.contains(WITHHELD_TIP), "{text}");
        for withheld in [
            "AUD027SOURCE",
            "AUD027INPUT",
            "AUD027SECOND",
            "give yes or no",
        ] {
            assert!(!text.contains(withheld), "{text}");
        }
    }

    /// The help of the tool and of every command, short (-h) and long (--help, and `mhfe help`),
    /// fits the help width and ends with examples (AUD-010).
    #[test]
    fn every_help_fits_the_help_width_and_has_examples() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        cli.build();
        let mut helps = vec![
            ("mhfe -h".to_owned(), cli.render_help().ansi().to_string()),
            (
                "mhfe --help".to_owned(),
                cli.render_long_help().ansi().to_string(),
            ),
        ];
        // clap's own `help` command lists the commands and has nothing else to show.
        for command in cli.get_subcommands_mut().filter(|c| c.get_name() != "help") {
            let name = command.get_name().to_owned();
            helps.push((
                format!("{name} -h"),
                command.render_help().ansi().to_string(),
            ));
            helps.push((
                format!("{name} --help"),
                command.render_long_help().ansi().to_string(),
            ));
        }
        for (help, text) in helps {
            for line in text.lines() {
                assert!(
                    style::visible_width(line) <= style::HELP_WIDTH,
                    "{help}: {line}"
                );
            }
            assert!(
                style::plain(&text).contains("\nExamples:\n"),
                "{help} has no examples"
            );
            assert!(
                text.trim_end()
                    .ends_with(&style::paint(style::WARNING, style::SAFETY_LINE)),
                "{help} does not end with the yellow safety line"
            );
            assert!(
                text.contains(&style::help_note(
                    "Use MHFE on a trusted computer without a network connection."
                )),
                "{help} lacks its grey note before the safety line"
            );
        }
    }

    /// Every result reaches standard output through `style::out`, which reports a write that
    /// failed, a closed pipe included, instead of panicking or exiting with success
    /// (AUD-023-FUN001). Clap's top-level help/version exit is the one explicit exception;
    /// it handles no operation result. Menu help also uses style::out.
    #[test]
    fn every_result_is_written_through_one_function() {
        let files = tool_files();
        assert!(files.len() > 30, "the tool's modules are read");
        for path in files {
            let text = std::fs::read_to_string(&path).unwrap();
            let mut code = production_code(&text).to_owned();
            if path.file_name().unwrap() == "style.rs" {
                let start = code.find("fn out(").unwrap();
                let end = start + code[start..].find("\n}").unwrap() + 2;
                code.replace_range(start..end, "");
            }
            if path.file_name().unwrap() == "main.rs" {
                // This exact call is guarded by DisplayHelp/DisplayVersion above; no result.
                assert_eq!(code.matches("error.exit();").count(), 1);
                code = code.replace("error.exit();", "");
            }
            assert!(
                !writes_stdout(&code),
                "{} writes to standard output outside style::out",
                path.display()
            );
        }
    }

    fn production_code(text: &str) -> &str {
        text.split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default()
    }

    fn writes_stdout(text: &str) -> bool {
        let code: String = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let code = code.replace("eprintln!(", "").replace("eprint!(", "");
        if [
            "println!(",
            "print!(",
            ".print_help(",
            ".print_long_help(",
            ".exit()",
        ]
        .iter()
        .any(|call| code.contains(call))
        {
            return true;
        }
        let mut receivers = vec!["stdout()".to_owned()];
        // Follow local stdout/lock aliases. Terminal detection and flush-only uses are readers,
        // not writers; this deliberately lexical guard is backed by mutation controls below.
        for statement in code.split(';') {
            let Some((left, right)) = statement.split_once('=') else {
                continue;
            };
            let alias = left
                .rsplit("let")
                .next()
                .unwrap_or_default()
                .trim_start_matches("mut");
            if !alias.is_empty()
                && alias
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '_')
                && receivers.iter().any(|receiver| right.contains(receiver))
                && !right.contains(".is_terminal()")
                && !right.contains(".flush()")
            {
                receivers.push(alias.to_owned());
            }
        }
        receivers.iter().any(|receiver| {
            [
                format!("write!({receiver},"),
                format!("writeln!({receiver},"),
                format!("write!(&mut{receiver},"),
                format!("writeln!(&mut{receiver},"),
                format!("{receiver}.write("),
                format!("{receiver}.write_all("),
                format!("{receiver}.write_fmt("),
            ]
            .iter()
            .any(|call| code.contains(call))
        }) || [
            "write!(io::stdout(),",
            "writeln!(io::stdout(),",
            "write!(std::io::stdout(),",
            "writeln!(std::io::stdout(),",
            "write!(anstream::stdout(),",
            "writeln!(anstream::stdout(),",
        ]
        .iter()
        .any(|call| code.contains(call))
    }

    #[test]
    fn the_stdout_guard_catches_writers_after_test_items_and_through_aliases() {
        for source in [
            "#[cfg(test)] fn probe() {} fn result() { println!(\"lost\"); }",
            "writeln!(io::stdout(), \"lost\");",
            "let mut output = io::stdout(); output.write_all(b\"lost\");",
            "let output = anstream::stdout(); let mut locked = output.lock(); writeln!(locked, \"lost\");",
            "command.print_long_help();",
            "failure.exit();",
        ] { assert!(writes_stdout(production_code(source)), "missed {source}"); }
        assert!(!writes_stdout(
            "io::stdout().is_terminal(); io::stdout().flush(); eprintln!(\"message\");"
        ));
    }

    /// A failed message fails only a command that otherwise succeeded, and no code of the tool
    /// writes to standard error but through its own non-panicking macros (AUD-024-FUN009).
    #[test]
    fn a_failed_message_fails_only_a_command_that_succeeded() {
        assert_eq!(final_exit_code(exit::SUCCESS, true), exit::INTERNAL_ERROR);
        assert_eq!(final_exit_code(exit::SUCCESS, false), exit::SUCCESS);
        assert_eq!(final_exit_code(exit::NO_MATCH, true), exit::NO_MATCH);
        for path in tool_files() {
            let text = std::fs::read_to_string(&path).unwrap();
            let code = production_code(&text);
            for panicking in ["anstream::eprint", "use anstream::{eprint", "std::eprint"] {
                let allowed = path.ends_with("style.rs") && panicking == "std::eprint";
                assert!(
                    allowed || !code.contains(panicking),
                    "{} writes with {panicking}",
                    path.display()
                );
            }
        }
    }

    /// Every module of the tool, its submodules in their folders included.
    fn tool_files() -> Vec<std::path::PathBuf> {
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
        files
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

    /// Each settings argument's own short and long help names its limits; a sibling option
    /// cannot satisfy the check (AUD-024-ARC025).
    #[test]
    fn every_settings_argument_states_its_own_limits() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        cli.build();
        for command in [
            "new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair",
        ] {
            for (option, expected) in [
                ("pim", format!("0 to {}", mhfe::MAX_PIM)),
                ("mem", format!("0 to {}", mhfe::MAX_MEMORY_LEVEL)),
            ] {
                assert_argument_help(&cli, command, option, &expected, true);
                assert_argument_help(&cli, command, option, &expected, false);
            }
            assert_argument_help(&cli, command, "mem", &settings::memory_text(0), true);
        }
        for long in [false, true] {
            assert_argument_help(
                &cli,
                "rekey",
                "new-pim",
                &format!("0 to {}", mhfe::MAX_PIM),
                long,
            );
            assert_argument_help(
                &cli,
                "rekey",
                "new-mem",
                &format!("0 to {}", mhfe::MAX_MEMORY_LEVEL),
                long,
            );
            assert_argument_help(&cli, "rekey", "new-mem", &settings::memory_text(0), long);
        }
    }

    #[test]
    fn every_question_mapping_names_options_of_its_actual_command() {
        use clap::CommandFactory;
        let inventory: serde_json::Value =
            serde_json::from_str(include_str!("../../../scripts/cli-questions.json")).unwrap();
        let mut cli = Cli::command();
        cli.build();
        let bindings = inventory["bindings"].as_object().unwrap();
        assert!(!bindings.is_empty(), "the question inventory is not empty");
        for (name, mappings) in bindings {
            for mapping in mappings.as_array().unwrap() {
                for command in mapping["commands"].as_array().unwrap() {
                    let command = command.as_str().unwrap();
                    let parsed = cli.find_subcommand(command).unwrap();
                    for option in mapping["options"].as_array().unwrap() {
                        let option = option.as_str().unwrap();
                        assert!(
                            parsed
                                .get_arguments()
                                .any(|arg| arg.get_long() == Some(option)),
                            "{name}: {command} --{option} does not exist"
                        );
                    }
                }
            }
        }
    }

    fn normalized(text: impl ToString) -> String {
        text.to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn argument_help(cli: &clap::Command, command: &str, option: &str, long: bool) -> String {
        let command = cli.find_subcommand(command).unwrap();
        let arg = command
            .get_arguments()
            .find(|arg| arg.get_long() == Some(option))
            .unwrap();
        let help = if long {
            arg.get_long_help().or_else(|| arg.get_help())
        } else {
            arg.get_help()
        };
        normalized(help.unwrap())
    }

    fn assert_argument_help(
        cli: &clap::Command,
        command: &str,
        option: &str,
        expected: &str,
        long: bool,
    ) {
        let text = argument_help(cli, command, option, long);
        assert!(
            text.contains(expected),
            "{command} --{option} (long={long}): missing {expected:?} in {text:?}"
        );
    }

    /// Public sizes and lengths appear in the specific argument, about text or example that
    /// describes them, alongside the existing full-page help layout checks.
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

    #[test]
    fn the_password_round_memory_and_example_facts_follow_their_sources() {
        use clap::CommandFactory;
        use mhfe::new_password::{DEFAULT_CHARACTERS, DEFAULT_WORDS};
        let mut cli = Cli::command();
        cli.build();
        for command in ["new", "encrypt", "rekey"] {
            for expected in [
                format!(
                    "words: {} dice words",
                    style::number_word(DEFAULT_WORDS, false)
                ),
                format!(
                    "check-word: {} words",
                    style::number_word(mhfe::check_word::DRAWN_WORDS, false)
                ),
                format!(
                    "chars: {} random characters",
                    style::number_word(DEFAULT_CHARACTERS, false)
                ),
            ] {
                assert_argument_help(&cli, command, "new-password", &expected, true);
            }
        }
        assert_argument_help(
            &cli,
            "rekey",
            "words",
            &phrase_length::length_range(),
            false,
        );
        assert_argument_help(
            &cli,
            "rekey",
            "confirm",
            &phrase_length::short_range_words(),
            true,
        );
        assert_argument_help(
            &cli,
            "self-test",
            "vectors",
            &self_test::vectors_cost(),
            false,
        );
        let test = mhfe::self_test::SelfTest::published().unwrap();
        for name in [test.suite_3_vector(), test.suite_4_vector()] {
            assert_argument_help(&cli, "self-test", "vectors", name, true);
        }
        let about = |name| normalized(cli.find_subcommand(name).unwrap().get_long_about().unwrap());
        assert!(about("encrypt").contains(&format!("{} rounds", mhfe::ENCRYPTION_ROUNDS)));
        for name in ["check", "decrypt"] {
            assert!(
                about(name).contains(&format!("{} rounds", mhfe::ROUNDS)),
                "{name}"
            );
        }
        assert!(about("password").contains(&format!("{} words", mhfe::eff::LIST_SIZE)));
        let examples = normalized(main_help());
        for expected in [
            format!(
                "Make a strong password of {} dice words",
                style::number_word(DEFAULT_WORDS, false)
            ),
            format!("twice the passes and {}", settings::memory_text(1)),
            format!("PIM 3 and {}", settings::memory_text(2)),
        ] {
            assert!(examples.contains(&expected), "{expected}");
        }
        assert!(
            normalized(encrypt::long_help()).contains(&format!("first {} rounds", mhfe::ROUNDS))
        );
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

    #[test]
    fn the_plain_main_examples_follow_their_commands_summaries() {
        use clap::CommandFactory;
        let cli = Cli::command();
        let help = style::plain(&main_help());
        let lines = help.lines().collect::<Vec<_>>();
        for name in ["rekey", "wallets", "repair"] {
            let command = format!("mhfe {name}");
            let start = lines
                .iter()
                .position(|line| {
                    line.trim_start()
                        .strip_prefix(&command)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
                })
                .expect("every plain example is present");
            let row = std::iter::once(lines[start])
                .chain(
                    lines[start + 1..]
                        .iter()
                        .copied()
                        .take_while(|line| !line.trim_start().starts_with("mhfe ")),
                )
                .collect::<Vec<_>>()
                .join(" ");
            let row = row.split_whitespace().collect::<Vec<_>>().join(" ");
            let summary = cli
                .find_subcommand(name)
                .unwrap()
                .get_about()
                .unwrap()
                .to_string();
            assert!(row.contains(&summary), "{name}: {row:?} lacks {summary:?}");
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
