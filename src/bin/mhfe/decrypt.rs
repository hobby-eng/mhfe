//! `mhfe decrypt`: recovers the original phrase from a container.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::{wallet_check, PhraseLength, RecoveredPhrase, Recovery, Suite, WordCount};

use crate::exit::{Failure, SUCCESS};
use crate::flow::Flow;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, HEADING, STRONG};
use crate::terminal::{self, Input, Progress};

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
         recovered seed phrase. Use the PIM and memory level of the encryption; at the defaults no option is \
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
        "The recovered seed phrase is shown on the screen: recover only on a trusted computer \
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
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Decrypt.title());
    let work = settings::choose(options.settings, &mut input, Operation::Decrypt)?;

    let (container, _) = terminal::read_container(&mut input, Operation::Decrypt.title())?;
    let password = terminal::read_password(&mut input, Operation::Decrypt)?;
    let mut mhfe = settings::reserve_memory(work)?;
    eprintln!();
    style::warn(
        "The seed phrase will be shown: recover only on a trusted offline computer.",
        "",
    );

    let mut progress = Progress::start();
    let recovery = mhfe.decrypt(&container, &password, length, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    progress.finish();

    // The result appears on a screen of its own, which is cleared once the person is done.
    let screen = terminal::PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(Operation::Decrypt.title());
    }
    match &recovery {
        Recovery::Phrase(phrase) => show_single(phrase, length, &input),
        Recovery::Ambiguous(candidates) => show_ambiguous(candidates, &input),
    }
    if screen.is_active() {
        terminal::wait_to_leave()?;
        drop(screen);
        flow.finish();
        style::ok("Recovered. The seed phrase is no longer on the screen.");
        style::hint("When you are done, close this terminal.");
    } else {
        style::hint("When you are done, clear the screen and close this terminal.");
    }
    Ok(SUCCESS)
}

fn show_single(phrase: &RecoveredPhrase, length: PhraseLength, input: &Input) {
    eprintln!();
    if phrase.suite == Suite::SameLength {
        style::warn_now(
            &format!(
                "Not verified: a {}-word container has no built-in check.",
                phrase.words
            ),
            "Confirm it against your wallet with mhfe check.",
        );
        style::more(readme::DECRYPT);
    } else if phrase.verified {
        style::ok(format!(
            "{} a {}-word phrase that passed its built-in check.",
            paint(style::GOOD, "Verified:"),
            phrase.words
        ));
        // The built-in check confirms the password and settings, never which wallet this is.
        style::hint("It confirms the password, not the wallet: mhfe check does that.");
    } else if length == PhraseLength::Detect {
        style::warn_now(
            "Not verified: read as 24 words.",
            "For a shorter original, the password or a setting is wrong.",
        );
        style::more(readme::DECRYPT);
    } else {
        style::warn_now(
            "Not verified: read as 24 words, as you chose.",
            "Compare it with your wallet.",
        );
        style::more(readme::DECRYPT);
    }
    if passes_check_without_passphrase(phrase) {
        style::ok("It passes its 16-bit check without a BIP39 passphrase.");
    }
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!("Recovered seed phrase, {} words", phrase.words)
        )
    );
    print_result(phrase, input);
}

/// Whether a 24-word phrase passes the check that a new wallet can be made with, without a BIP39
/// passphrase (mhfe::wallet_check). Only a pass is reported: a phrase without the check fails it,
/// so a failure means something only to an owner who knows the wallet was made with it. With a
/// passphrase the check is tested by mhfe check, which asks for it.
fn passes_check_without_passphrase(phrase: &RecoveredPhrase) -> bool {
    // A recovered phrase is always valid, so the test cannot fail; an error would count as no pass.
    phrase.words == 24 && wallet_check::phrase_passes(&phrase.phrase, "").unwrap_or(false)
}

fn show_ambiguous(candidates: &[RecoveredPhrase], input: &Input) {
    eprintln!();
    style::warn_now(
        "Several lengths passed their check, a rare accident.",
        "Compare each with your wallet, or run again with --words N.",
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
