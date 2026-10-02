//! `mhfe decrypt`: recovers the original phrase from a container.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::{check_container, Password, PhraseLength, RecoveredPhrase, Recovery, Suite, WordCount};
use zeroize::Zeroizing;

use crate::exit::{capitalize, Failure, SUCCESS};
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, HEADING, STRONG};
use crate::terminal::{self, show_container_read, Input, Progress, CONTAINER_PROMPT};

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// Length of the original if known: 12, 15, 18, 21 or 24
    #[arg(long, value_name = "N", long_help = words_help())]
    words: Option<usize>,

    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = stdin_help())]
    stdin: bool,
}

fn words_help() -> String {
    style::option_help(&[
        "Length of the original if known: 12, 15, 18, 21 or 24.",
        "Without it the length is detected: a 12- to 21-word original carries a built-in \
         check, and the length whose check passes is shown as verified. When no check passes, \
         the 24-word reading is shown, not verified. When several pass, every candidate is \
         shown.",
        "A chosen short length must pass its check. Choose 24 for a 24-word original that \
         detection reads as shorter, about once in four billion; encryption says so when it \
         happens.",
        "A container of 12 to 21 words keeps the length of its original: it accepts only its \
         own length here, and any other length is refused before anything is computed.",
    ])
}

fn stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the container, then the password, one per line. Output: one line per result, \
         \"<words> <verified|unverified> <phrase>\". Messages go to standard error.",
    ])
}

/// The top of `mhfe decrypt --help`.
pub fn about() -> String {
    style::command_about(&[
        "Recover the original phrase from a container",
        "Runs 12 rounds, one to two minutes at the default settings, and shows the \
         recovered phrase. Use the PIM and memory level of the encryption; at the defaults no option is \
         needed.",
    ])
}

fn examples() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe decrypt", "Detect the length of the original"),
            ("mhfe decrypt --words 24", "The original has 24 words"),
            (
                "mhfe decrypt --pim 1 --mem 1",
                "The settings used for encryption",
            ),
            (
                "mhfe decrypt --pim 1 --mem 1 --words 24",
                "Those settings and a 24-word original",
            ),
            (
                "your-program | mhfe decrypt --stdin",
                "A script: the container and the password from another program",
            ),
        ],
    )
}

/// The end of `mhfe decrypt -h`.
pub fn help() -> String {
    examples()
}

/// The end of `mhfe decrypt --help`.
pub fn long_help() -> String {
    let asks = style::help_section(
        "What it asks for:",
        &[
            (
                "Container",
                "shown while typed; 24 words, or as many as the original for a container of \
                 the same length; four letters per word are enough",
            ),
            ("Password", "hidden"),
        ],
    );
    let note = style::help_note(
        "The recovered phrase is shown on the screen: recover only on a trusted computer \
         without a network connection.",
    );
    format!("{asks}\n{}\n{note}", examples())
}

pub fn run(options: Options) -> Result<i32, Failure> {
    let length = match options.words {
        Some(words) => PhraseLength::Words(WordCount::new(words)?),
        None => PhraseLength::Detect,
    };
    let mut input = Input::new(options.stdin);
    let work = settings::choose(options.settings, &mut input, Operation::Decrypt)?;

    let container = read_container(&mut input)?;
    let password = read_password(&mut input)?;
    let mut mhfe = settings::reserve_memory(work)?;
    style::warn(
        "The recovered phrase will be shown on the screen.",
        "Recover only on a trusted computer without a network connection.",
    );
    eprintln!();

    let mut progress = Progress::start();
    let recovery = mhfe.decrypt(&container, &password, length, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    progress.finish();

    // The result appears on a screen of its own, which is cleared once the person is done.
    let screen = terminal::PrivateScreen::enter(&input);
    match &recovery {
        Recovery::Phrase(phrase) => show_single(phrase, length, &input),
        Recovery::Ambiguous(candidates) => show_ambiguous(candidates, &input),
    }
    if screen.is_active() {
        input.visible("Press Enter when you have written it down; it then leaves the screen.")?;
        drop(screen);
        style::ok("Recovered. The phrase is no longer on the screen.");
        style::hint("When you are done, close this terminal.");
    } else {
        style::hint("When you are done, clear the screen and close this terminal.");
    }
    Ok(SUCCESS)
}

fn read_container(input: &mut Input) -> Result<Zeroizing<String>, Failure> {
    loop {
        let typed = input.visible(CONTAINER_PROMPT)?;
        match check_container(&typed) {
            Ok(container) => {
                show_container_read(&container, input);
                return Ok(Zeroizing::new(container));
            }
            Err(error) if input.can_ask_again() => {
                style::retry(format!(
                    "{}. Please type it again.",
                    capitalize(&error.to_string())
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_password(input: &mut Input) -> Result<Password, Failure> {
    loop {
        let text = input.secret("Password (hidden): ")?;
        match Password::new(&text) {
            Ok(password) => return Ok(password),
            Err(error) if input.can_ask_again() => {
                style::retry(format!(
                    "{}. Please type it again.",
                    capitalize(&error.to_string())
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn show_single(phrase: &RecoveredPhrase, length: PhraseLength, input: &Input) {
    eprintln!();
    if phrase.suite == Suite::SameLength {
        style::warn(
            &format!(
                "Not verified: a {}-word container has no built-in check.",
                phrase.words
            ),
            "Any password gives a valid phrase of the same length, so a wrong one is not \
             detected. Before you rely on it, confirm it against your wallet with mhfe check \
             --fingerprint or --address.",
        );
    } else if phrase.verified {
        style::ok(format!(
            "{} a {}-word phrase that passed its built-in check.",
            paint(style::GOOD, "Verified:"),
            phrase.words
        ));
        // The built-in check confirms the password and settings, never which wallet this is.
        style::hint("This confirms the password and settings, not the wallet: mhfe check --address does that.");
    } else if length == PhraseLength::Detect {
        style::warn(
            "Not verified: no shorter length passed its check, so the result is read as 24 words.",
            "If your original has 24 words, compare this phrase with your wallet. If it has \
             fewer, this usually means a wrong password, PIM, memory level or container.",
        );
    } else {
        style::warn(
            "Not verified: read as 24 words, as you chose.",
            "A 24-word phrase has no built-in check, so any password gives a valid phrase: compare \
             it with your wallet.",
        );
    }
    eprintln!();
    eprintln!(
        "{}",
        paint(HEADING, format!("Recovered phrase, {} words", phrase.words))
    );
    print_result(phrase, input);
}

fn show_ambiguous(candidates: &[RecoveredPhrase], input: &Input) {
    eprintln!();
    style::warn(
        "Several lengths passed their check.",
        "This happens by accident for about one container in four billion. Compare each phrase \
         with your wallet, or run again with --words N if you know the length.",
    );
    for candidate in candidates {
        let status = if candidate.verified {
            "passed its check"
        } else {
            "not verified"
        };
        eprintln!();
        eprintln!(
            "{} {}",
            paint(HEADING, format!("{} words", candidate.words)),
            paint(STRONG, status)
        );
        print_result(candidate, input);
    }
}

fn print_result(phrase: &RecoveredPhrase, input: &Input) {
    if input.is_script() {
        let status = if phrase.verified {
            "verified"
        } else {
            "unverified"
        };
        println!("{} {status} {}", phrase.words, *phrase.phrase);
    } else {
        terminal::print_phrase(&phrase.phrase, input);
    }
}
