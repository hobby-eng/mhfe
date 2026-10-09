//! `mhfe decrypt`: recovers the original phrase from a container.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::{PhraseLength, RecoveredPhrase, Recovery, RecoveryStatus};

use crate::check;
use crate::container_repair::RepairOption;
use crate::exit::{Failure, SUCCESS};
use crate::flow::Flow;
use crate::phrase_length;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, HEADING, STRONG};
use crate::terminal::{self, Input, Progress, Wallet};

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    #[command(flatten)]
    repair: RepairOption,

    /// Words of the original seed phrase: 12 to 24, or auto
    #[arg(long, value_name = "N", value_parser = phrase_length::parse, long_help = words_help())]
    words: Option<PhraseLength>,

    #[command(flatten)]
    passphrase_used: check::PassphraseUsedOption,

    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = stdin_help())]
    stdin: bool,
}

fn words_help() -> String {
    style::option_help(&[
        &format!(
            "Length of the original seed phrase if known: {}, or auto.",
            phrase_length::length_list()
        ),
        "Without it, or with auto, the length is detected: a 12- to 21-word original seed phrase carries a \
         built-in check, and the length whose check passes is shown as verified. When no check \
         passes, the 24-word reading is shown, not verified. When several pass, every candidate is \
         shown.",
        "A stated length does not replace detection: a built-in check that passes takes \
         precedence, and the tool says so. A stated short length that no check passes is \
         refused: the password or a setting is probably wrong, or the phrase has 24 words. With \
         24 stated and a short check that passes, both readings are shown, the checked one \
         first; a 24-word original seed phrase reads as shorter about once in four billion, and \
         encryption says so when it happens.",
        "A container of 12 to 21 words keeps the length of its original seed phrase: it accepts \
         only its own length here, and any other length is refused before anything is computed.",
    ])
}

fn stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the container, then the password, one per line, and with --passphrase-used yes \
         the BIP39 passphrase of the original seed phrase on a third line, for the 16-bit check \
         of a 24-word reading; without it the check runs with no passphrase. Output: one line \
         per result, \"<words> <verified|unverified> <phrase>\". Messages, the outcome of the \
         16-bit check among them, go to standard error.",
    ])
}

/// The top of `mhfe decrypt --help`.
pub fn about() -> String {
    style::command_about(&[
        "Recover the original seed phrase from a container",
        "Runs 12 rounds, one to two minutes at the default settings, and shows the recovered seed \
         phrase. Use the PIM and memory level of the encryption; at the defaults no option is \
         needed.",
    ])
}

fn examples() -> String {
    style::help_section(
        "Examples:",
        &[
            (
                "mhfe decrypt",
                "Detect the length of the original seed phrase",
            ),
            (
                "mhfe decrypt --words 24",
                "The original seed phrase has 24 words",
            ),
            (
                "mhfe decrypt --pim 1 --mem 1",
                "The settings used for encryption",
            ),
            (
                "mhfe decrypt --pim 1 --mem 1 --words 24",
                "Those settings and a 24-word original seed phrase",
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
                "shown while typed; 24 words, or as many as the original seed phrase for a \
                 container of the same length; four letters per word are enough",
            ),
            ("Password", "on a private screen"),
            (
                "BIP39 passphrase",
                "only when a 24-word reading comes out: whether the original seed phrase has \
                 one, and if so the passphrase, on a private screen, for the 16-bit check of \
                 that reading; --passphrase-used answers the question",
            ),
        ],
    );
    let note = style::help_note(
        "The recovered seed phrase is shown on the screen: recover only on a trusted computer \
         without a network connection.",
    );
    format!("{asks}\n{}\n{note}", examples())
}

pub fn run(options: Options) -> Result<i32, Failure> {
    let length = options.words.unwrap_or(PhraseLength::Detect);
    let mut input = Input::new(options.stdin);
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Decrypt.title());
    let work = settings::choose(options.settings, &mut input, Operation::Decrypt)?;

    let read = terminal::read_container(
        &mut input,
        Operation::Decrypt.title(),
        options.repair.card(Operation::Decrypt, work),
    )?;
    let container = read.facts;
    // Refused before the password is asked, as the recovery would refuse it.
    container.require_length(length)?;
    // A search for missing words asked for the password already.
    let password = match read.password {
        Some(password) => password,
        None => terminal::read_password(&mut input, Operation::Decrypt)?,
    };
    let mut mhfe = settings::reserve_memory(work)?;
    eprintln!();
    style::warn(
        "The seed phrase will be shown: recover only on a trusted offline computer.",
        "",
    );

    let mut progress = Progress::start();
    let recovery = mhfe.decrypt(
        container.words(),
        &password,
        length,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
    progress.finish();
    let readings = match &recovery {
        Recovery::Phrase(phrase) => std::slice::from_ref(phrase),
        Recovery::Ambiguous(candidates) => candidates.as_slice(),
    };
    let passphrase =
        source_check_passphrase(&mut input, readings, options.passphrase_used.given())?;

    // The result appears on a screen of its own, which is cleared once the person is done.
    let screen = terminal::PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(Operation::Decrypt.title());
    }
    match &recovery {
        Recovery::Phrase(phrase) => show_single(phrase, length, &passphrase, &input)?,
        Recovery::Ambiguous(candidates) => show_ambiguous(candidates, &passphrase, &input)?,
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

/// The BIP39 passphrase for the 16-bit source check, which every recovery evaluates on each
/// 24-word reading (the specification's recovery rules): asked, with why, only when such a
/// reading came out, unless `--passphrase-used` answered it (`used`). A script gives it on a line
/// of its own with `--passphrase-used yes`, and otherwise the check runs with no passphrase.
fn source_check_passphrase(
    input: &mut Input,
    readings: &[RecoveredPhrase],
    used: Option<bool>,
) -> Result<LockedText, Failure> {
    if !readings.iter().any(RecoveredPhrase::offers_wallet_check) {
        return Ok(LockedText::copy_of(""));
    }
    if input.is_script() && used != Some(true) {
        return Ok(LockedText::copy_of(""));
    }
    check::ask_passphrase_explained(
        input,
        Operation::Decrypt,
        check::ORIGINAL_SEED_PHRASE,
        check::SOURCE_CHECK_WHY,
        Some(readme::DECRYPT),
        used,
    )
}

/// The outcome of the 16-bit source check of a 24-word reading with `passphrase`; nothing for
/// another length.
fn tell_source_check(phrase: &RecoveredPhrase, passphrase: &str) -> Result<(), Failure> {
    let with = if passphrase.is_empty() {
        "without a BIP39 passphrase"
    } else {
        "with this BIP39 passphrase"
    };
    match phrase.passes_wallet_check(passphrase)? {
        Some(true) => style::ok(format!("It passes the 16-bit check {with}.")),
        Some(false) => {
            style::hint(&format!(
                "It does not pass the 16-bit check {with}. If this phrase was made to pass it, \
                 the password, a setting or the passphrase is wrong."
            ));
        }
        None => {}
    }
    Ok(())
}

fn show_single(
    phrase: &RecoveredPhrase,
    length: PhraseLength,
    passphrase: &str,
    input: &Input,
) -> Result<(), Failure> {
    eprintln!();
    tell_stated_length(phrase);
    match phrase.status(length) {
        RecoveryStatus::NoBuiltInCheck => {
            style::warn_now(
                &format!(
                    "Not verified: a {}-word container has no built-in check.",
                    phrase.words()
                ),
                "Confirm it against your wallet with mhfe check.",
            );
            style::more(readme::DECRYPT);
        }
        RecoveryStatus::Verified => {
            style::ok(format!(
                "{} a {}-word phrase that passed its built-in check.",
                paint(style::GOOD, "Verified:"),
                phrase.words()
            ));
            // The built-in check confirms the password and settings, never which wallet this is.
            style::hint("It confirms the password, not the wallet: mhfe check does that.");
        }
        RecoveryStatus::ReadAs24Detected => {
            style::warn_now(
                "Not verified: read as 24 words.",
                "For a shorter original seed phrase, the password or a setting is wrong.",
            );
            style::more(readme::DECRYPT);
        }
        RecoveryStatus::ReadAs24Chosen => {
            style::warn_now(
                "Not verified: read as 24 words, as you chose.",
                "Compare it with your wallet.",
            );
            style::more(readme::DECRYPT);
        }
    }
    tell_source_check(phrase, passphrase)?;
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!("Recovered seed phrase, {} words", phrase.words())
        )
    );
    print_result(phrase, input);
    Ok(())
}

/// Says when the built-in check found another length than the one stated, which it takes over
/// (the length rules of recovery), and when another length passed too, by chance.
fn tell_stated_length(phrase: &RecoveredPhrase) {
    if let (Some(stated), true) = (phrase.stated_words(), phrase.verified()) {
        style::warn_now(
            &phrase_length::check_finds(phrase.words(), stated),
            &format!(
                "{}; compare it with your wallet.",
                phrase_length::MORE_RELIABLE
            ),
        );
    }
    for other in phrase.other_lengths() {
        style::hint(&format!(
            "The built-in check of {other} words passes too, by chance: you chose {} words.",
            phrase.words()
        ));
    }
}

fn show_ambiguous(
    candidates: &[RecoveredPhrase],
    passphrase: &str,
    input: &Input,
) -> Result<(), Failure> {
    eprintln!();
    // 24 words stated beside a short length whose check passes: that reading comes first, and
    // the 24-word one, the last, after it, as a 24-word phrase passes a short check by chance
    // once in 2^32.
    let read_as_stated = |stated| candidates.last().is_some_and(|last| last.words() == stated);
    match candidates
        .first()
        .map(|first| (first.words(), first.stated_words()))
    {
        Some((found, Some(stated))) if read_as_stated(stated) => style::warn_now(
            &phrase_length::check_finds(found, stated),
            "Both readings follow, the checked one first: a receiving address of your wallet \
             tells them apart.",
        ),
        _ => style::warn_now(
            "Several lengths passed their check, a rare accident.",
            "Compare each with your wallet, or run again with --words N.",
        ),
    }
    for candidate in candidates {
        let status = if candidate.verified() {
            "passed its check"
        } else {
            "not verified"
        };
        eprintln!();
        eprintln!(
            "{} {}",
            paint(HEADING, format!("{} words", candidate.words())),
            paint(STRONG, status)
        );
        tell_source_check(candidate, passphrase)?;
        print_result(candidate, input);
    }
    Ok(())
}

fn print_result(phrase: &RecoveredPhrase, input: &Input) {
    if input.is_script() {
        let status = if phrase.verified() {
            "verified"
        } else {
            "unverified"
        };
        println!("{} {status} {}", phrase.words(), phrase.phrase());
    } else {
        terminal::print_phrase(phrase.phrase(), Wallet::NoPassphrase, input);
    }
}
