//! `mhfe encrypt`: turns an original recovery phrase into a 24-word container.

use std::io::{self, IsTerminal};

use anstream::{eprintln, println};
use clap::Args;
use mhfe::engine::NativeEngine;
use mhfe::{
    other_detected_lengths, read_phrase, Mhfe, MhfeError, NewContainer, Password, WorkFactor,
};
use zeroize::Zeroizing;

use crate::diceware::{dice_word_count, RECOMMENDED_WORDS};
use crate::exit::{capitalize, Failure, SUCCESS};
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, STRONG};
use crate::terminal::{self, Input, Progress};

/// A 24-word original fills the whole state and carries no verifier.
const WORDS_WITHOUT_CHECK: usize = 24;

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// Read the answers from standard input (for scripts)
    #[arg(long)]
    stdin: bool,
}

/// The end of `mhfe encrypt --help`.
pub fn help() -> String {
    let asks = style::help_section(
        "What it asks for:",
        &[
            (
                "Original recovery phrase",
                "hidden; 12 to 24 words; four letters per word are enough",
            ),
            ("Password", "hidden, typed twice"),
        ],
    );
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe encrypt", "Encrypt with the default settings"),
            ("mhfe encrypt --pim 1", "Twice the work of the default"),
            ("mhfe encrypt --mem 1", "3 GiB of memory instead of 2 GiB"),
        ],
    );
    let note = style::help_note(
        "The container appears after the first 12 rounds, marked as not yet verified, while \
         MHFE decrypts it again to check it. Rely on it only after \"Verified\". Output \
         redirected to a file or a program gets the container only after the check.",
    );
    let scripts = style::help_section(
        "For scripts (--stdin):",
        &[
            (
                "Input",
                "the phrase, the password, the password again, one per line",
            ),
            (
                "Output",
                "the container on one line, only after its check has passed",
            ),
        ],
    );
    format!(
        "{asks}\n{}\n{scripts}\n{examples}\n{note}",
        settings::settings_help()
    )
}

pub fn run(options: Options) -> Result<i32, Failure> {
    let work = options.settings.work_factor()?;
    let mut input = Input::new(options.stdin);
    settings::announce(work, Operation::Encrypt);
    settings::check_resources(work)?;

    let original = read_original(&mut input)?;
    let original_words = original.split(' ').count();
    // The rare phrase that also passes the check of another length (warned about while reading).
    let length_must_be_chosen = !other_detected_lengths(&original)?.is_empty();
    let password = read_new_password(&mut input)?;
    let mut mhfe = settings::reserve_memory(work)?;

    let mut progress = Progress::start();
    let new = mhfe.encrypt_unchecked(&original, &password, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    drop(original);
    // Only a person reading a terminal sees the container before its check, with the warning
    // that it is not verified yet. A script, or output redirected to a file or another program,
    // gets it only after the check: a program would take the first container it reads as final.
    let person_reads_output = !input.is_script() && io::stdout().is_terminal();
    if !person_reads_output {
        check(&mut mhfe, &new, &password, &mut progress)?;
        println!("{}", *new.words);
    } else {
        // A person can write the container down while the check runs.
        progress.finish();
        show_before_the_check(&new.words, &input);
        let checked = check(&mut mhfe, &new, &password, &mut progress);
        terminal::set_unverified_container_shown(false);
        match &checked {
            Ok(()) => {}
            Err(MhfeError::VerificationFailed) => {
                eprintln!("\n");
                style::alarm(
                    "The container above is WRONG: it did not turn back into your phrase.",
                    "Do not use it; cross it out if you wrote it down, and encrypt again.",
                );
            }
            Err(_) => {
                eprintln!("\n");
                style::alarm(
                    "The check stopped with an error: the container above is NOT verified.",
                    "Do not rely on it; encrypt again.",
                );
            }
        }
        checked?;
    }
    progress.finish();
    if !input.is_script() {
        style::ok(format!(
            "{} the container turns back into your original phrase.",
            paint(style::GOOD, "Verified:")
        ));
    }
    eprintln!();
    print_what_to_remember(work, original_words, length_must_be_chosen);
    eprintln!();
    style::hint(
        "Use a different password for each container: a shared password is only as safe as the \
         weakest container that uses it.",
    );
    style::hint(&format!(
        "Before relying on the container, rehearse the recovery with {} and keep the original \
         backup until it matches.",
        paint(ACCENT, "mhfe check")
    ));
    Ok(SUCCESS)
}

/// Tells the user what recovery needs besides the container and the password: a setting that
/// differs from its default, and, for the rare phrase that automatic length detection would
/// misread, its word count. Otherwise nothing: the suite is fixed and the length is detected.
fn print_what_to_remember(work: WorkFactor, original_words: usize, length_must_be_chosen: bool) {
    let changed = settings::changed_settings(work);
    if changed.is_none() && !length_must_be_chosen {
        eprintln!(
            "{} the 24 words and the password are enough.",
            paint(STRONG, "Nothing else needs to be kept:")
        );
    }
    if let Some(changed) = changed {
        eprintln!(
            "{} {changed}.",
            paint(STRONG, "You changed the default settings; remember them:")
        );
        style::hint(
            "Recovery needs exactly these values: with others the container turns into a \
             different phrase that looks just as valid.",
        );
    }
    if length_must_be_chosen {
        eprintln!(
            "{} your phrase has {original_words} words.",
            paint(STRONG, "Remember the word count:")
        );
        style::hint(&format!(
            "As warned above, automatic length detection would misread this phrase; recover it \
             with {}.",
            paint(ACCENT, format!("mhfe decrypt --words {original_words}"))
        ));
    }
    if original_words == WORDS_WITHOUT_CHECK {
        style::hint(
            "A 24-word phrase has no built-in check, so recovery will show it as not verified; \
             that is expected. mhfe check with a known address of the wallet confirms it.",
        );
    }
}

/// Rounds 13 to 24: recovers the new container from its words and compares the result with
/// the original.
fn check(
    mhfe: &mut Mhfe<NativeEngine>,
    new: &NewContainer,
    password: &Password,
    progress: &mut Progress,
) -> Result<(), MhfeError> {
    mhfe.check_new_container(new, password, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })
}

/// Shows the container after the first twelve rounds, clearly marked as not yet verified.
fn show_before_the_check(container: &str, input: &Input) {
    eprintln!();
    eprintln!("{}", paint(HEADING, "Container, 24 words"));
    terminal::print_phrase(container, input);
    style::warn(
        "Not verified yet.",
        "MHFE now decrypts the container again to make sure that no memory error or other \
         fault changed it. You can start writing it down, but wait for the result before you \
         rely on it.",
    );
    eprintln!();
    terminal::set_unverified_container_shown(true);
}

/// Reads the original phrase. At a terminal the words read can be shown on request, so that a
/// person who typed short forms can compare them with the backup; they are secret, so the default
/// is not to show them.
fn read_original(input: &mut Input) -> Result<Zeroizing<String>, Failure> {
    loop {
        let typed = input.secret("Original recovery phrase (hidden): ")?;
        match read_phrase(&typed) {
            Ok(phrase) => {
                let words = phrase.split(' ').count();
                style::ok(format!("Accepted a valid {words}-word phrase."));
                if input.can_ask_again()
                    && input.yes_or_no(
                        "Show the words that were read? They will be visible on the screen.",
                        false,
                    )?
                {
                    terminal::show_words("Read the phrase as:", &phrase);
                    if !input.yes_or_no("Is this your phrase?", true)? {
                        style::retry("Please type it again.");
                        continue;
                    }
                }
                warn_if_detection_would_mislead(&phrase, words)?;
                return Ok(phrase);
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

/// About once in four billion phrases, the packed phrase also passes the built-in check of
/// another length. Recovery with automatic detection would then not give this phrase on its own,
/// so the owner is told, before the long computation, to note the length and choose it later.
fn warn_if_detection_would_mislead(phrase: &str, words: usize) -> Result<(), Failure> {
    let others = other_detected_lengths(phrase)?;
    if others.is_empty() {
        return Ok(());
    }
    let others: Vec<String> = others.iter().map(ToString::to_string).collect();
    style::warn(
        &format!("Write down that your phrase has {words} words."),
        &format!(
            "By chance it also passes the built-in check of {} words, which happens to about \
             one phrase in four billion. Recovery with automatic length detection would then \
             show a different reading or several candidates. When you recover, choose the length \
             yourself: mhfe decrypt --words {words}.",
            others.join(" and ")
        ),
    );
    Ok(())
}

/// Asks for the password twice, so that a typing mistake cannot lock the phrase away, and warns
/// when it is weaker than four dice words.
fn read_new_password(input: &mut Input) -> Result<Password, Failure> {
    loop {
        let text = input.secret("Password (hidden): ")?;
        let password = match Password::new(&text) {
            Ok(password) => password,
            Err(error) if input.can_ask_again() => {
                style::retry(format!(
                    "{}. Please choose another.",
                    capitalize(&error.to_string())
                ));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let repeated = input.secret("Repeat the password (hidden): ")?;
        if *repeated != *text {
            if input.can_ask_again() {
                style::retry("The two passwords differ. Please type them again.");
                continue;
            }
            return Err(Failure::invalid_input(
                "The two passwords differ. Nothing was encrypted.",
            ));
        }
        if dice_word_count(&text) < RECOMMENDED_WORDS {
            style::warn(
                "This password is not four or more words from the EFF dice list.",
                &format!(
                    "Unless it was chosen at random, it is probably much weaker than it looks; \
                     {} makes a strong one.",
                    paint(ACCENT, "mhfe password")
                ),
            );
        }
        return Ok(password);
    }
}
