//! `mhfe encrypt`: turns an original recovery phrase into a 24-word container.

use std::io::{self, IsTerminal};

use anstream::{eprintln, println};
use clap::Args;
use mhfe::engine::NativeEngine;
use mhfe::{
    other_detected_lengths, read_phrase, Mhfe, MhfeError, NewContainer, Password, WorkFactor,
};
use zeroize::Zeroizing;

use crate::diceware::{different_dice_words, RECOMMENDED_WORDS};
use crate::exit::{capitalize, Failure, SUCCESS};
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, MUTED, STRONG};
use crate::terminal::{self, Input, Progress};

/// A 24-word original fills the whole state and carries no verifier.
const WORDS_WITHOUT_CHECK: usize = 24;

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = stdin_help())]
    stdin: bool,
}

fn stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the phrase, the password and the password again, one per line. Output: the \
         container on one line, printed only after its check has passed. Messages go to \
         standard error, so standard output holds the container alone.",
    ])
}

/// The top of `mhfe encrypt --help`.
pub fn about() -> String {
    style::command_about(&[
        "Encrypt a recovery phrase into a 24-word container",
        "The container is itself a valid 24-word BIP39 phrase. With the default settings the \
         container and the password are all that recovery needs. Encryption runs 24 rounds: \
         12 to encrypt, then 12 that decrypt the new container again and compare the result \
         with the original. At the default settings this takes about two to four minutes.",
    ])
}

/// The examples at the end of `mhfe encrypt -h`.
fn examples() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe encrypt", "Encrypt with the default settings"),
            ("mhfe encrypt --pim 1", "Twice the work of the default"),
            ("mhfe encrypt --mem 1", "3 GiB of memory instead of 2 GiB"),
            (
                "mhfe encrypt --pim 1 --mem 1",
                "Both: twice the passes, 3 GiB of memory",
            ),
            (
                "your-program | mhfe encrypt --stdin > container.txt",
                "A script: the three answers from another program, the container into a file",
            ),
        ],
    )
}

/// The end of `mhfe encrypt -h`.
pub fn help() -> String {
    examples()
}

/// The end of `mhfe encrypt --help`.
pub fn long_help() -> String {
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
    let note = style::help_note(
        "The container appears after the first 12 rounds, marked as not yet verified, while \
         MHFE decrypts it again to check it. Rely on it only after \"Verified\". Output \
         redirected to a file or a program gets the container only after the check.",
    );
    format!("{asks}\n{}\n{note}", examples())
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
        "Use a different password for each phrase you encrypt, and nowhere else. To make another \
         copy, copy these 24 words exactly.",
    );
    // The check above covered the words this program produced, not the copy the user wrote down.
    style::hint(&format!(
        "Before relying on the container, rehearse the recovery with {}, typing the words from \
         the plate or paper you wrote, not from the screen, and keep the original backup until \
         it matches.",
        paint(ACCENT, "mhfe check")
    ));
    Ok(SUCCESS)
}

/// One line of the advice printed after an encryption, before it is styled.
#[derive(Debug, PartialEq)]
enum Advice {
    /// A sentence with a bold lead-in.
    Statement(&'static str, String),
    /// A quieter hint.
    Hint(String),
    /// A hint that ends with a command, which is shown in the accent colour.
    HintWithCommand(&'static str, String),
}

/// What the owner must keep besides the container and the password: nothing at the default
/// settings, otherwise the changed settings and, if detection would misread the phrase, its length.
fn what_to_remember(
    work: WorkFactor,
    original_words: usize,
    length_must_be_chosen: bool,
) -> Vec<Advice> {
    let mut advice = Vec::new();
    let changed = settings::changed_settings(work);
    if changed.is_none() && !length_must_be_chosen {
        advice.push(Advice::Statement(
            "Nothing else needs to be kept:",
            "the 24 words and the password are enough.".into(),
        ));
    }
    if let Some(changed) = changed {
        advice.push(Advice::Statement(
            "You changed the default settings; remember them:",
            format!("{changed}."),
        ));
        advice.push(Advice::Hint(
            "Recovery needs exactly these values: with others the container turns into a \
             different phrase that looks just as valid."
                .into(),
        ));
    }
    if length_must_be_chosen {
        advice.push(Advice::Statement(
            "Remember the word count:",
            format!("your phrase has {original_words} words."),
        ));
        advice.push(Advice::HintWithCommand(
            "As warned above, automatic length detection would misread this phrase; recover it \
             with ",
            format!("mhfe decrypt --words {original_words}"),
        ));
    }
    if original_words == WORDS_WITHOUT_CHECK {
        advice.push(Advice::Hint(
            "A 24-word phrase has no built-in check, so recovery will show it as not verified; \
             that is expected. mhfe check with a known address of the wallet confirms it."
                .into(),
        ));
    }
    advice
}

fn print_what_to_remember(work: WorkFactor, original_words: usize, length_must_be_chosen: bool) {
    for line in what_to_remember(work, original_words, length_must_be_chosen) {
        match line {
            Advice::Statement(lead, rest) => eprintln!("{} {rest}", paint(STRONG, lead)),
            Advice::Hint(text) => style::hint(&text),
            Advice::HintWithCommand(text, command) => {
                style::hint(&format!("{text}{}.", paint(ACCENT, command)))
            }
        }
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
                    // The words appear on a screen of their own and are gone once answered.
                    let confirmed = {
                        let _screen = terminal::PrivateScreen::enter(input);
                        terminal::show_words("Read the phrase as:", &phrase);
                        input.yes_or_no("Is this your phrase?", true)?
                    };
                    if !confirmed {
                        style::retry("Please type it again.");
                        continue;
                    }
                    style::ok("The words are no longer on the screen.");
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
/// when it is weaker than four different dice words.
fn read_new_password(input: &mut Input) -> Result<Password, Failure> {
    style::hint(
        "Letter case and spaces count: lowercase words with single spaces are the easiest to \
         type again years later.",
    );
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
        if different_dice_words(&text) < RECOMMENDED_WORDS {
            style::warn(
                "This password is not four or more words from the EFF dice list, all different.",
                &format!(
                    "Unless it was chosen at random, it is probably much weaker than it looks; \
                     {} makes a strong one.",
                    paint(ACCENT, "mhfe password")
                ),
            );
        }
        if input.can_ask_again()
            && input.yes_or_no(
                "Show the password that was typed? It will be visible on the screen.",
                false,
            )?
            && !confirm_password(&text, input)?
        {
            style::retry("Please type it again.");
            continue;
        }
        return Ok(password);
    }
}

/// Shows the typed password on a screen of its own and asks whether it is the intended one. Both
/// entries can carry the same slip, such as a wrong keyboard layout, which only seeing it reveals.
fn confirm_password(text: &str, input: &mut Input) -> Result<bool, Failure> {
    let screen = terminal::PrivateScreen::enter(input);
    eprintln!("{}", paint(HEADING, "Read the password as:"));
    eprintln!();
    eprintln!("  {}", paint(STRONG, text));
    eprintln!();
    // Spaces at either end are easy to miss but are part of the password.
    let characters = text.chars().count();
    let words = text.split_whitespace().count();
    eprintln!(
        "{}",
        paint(
            MUTED,
            format!("{characters} characters, {words} words; letter case and spaces count.")
        )
    );
    let confirmed = input.yes_or_no("Is this your password?", true)?;
    if confirmed {
        drop(screen);
        style::ok("The password is no longer on the screen.");
    }
    Ok(confirmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The advice as plain text, one line per entry, without colours.
    fn plain(work: WorkFactor, words: usize, length_must_be_chosen: bool) -> Vec<String> {
        what_to_remember(work, words, length_must_be_chosen)
            .into_iter()
            .map(|advice| match advice {
                Advice::Statement(lead, rest) => format!("{lead} {rest}"),
                Advice::Hint(text) => text,
                Advice::HintWithCommand(text, command) => format!("{text}{command}."),
            })
            .collect()
    }

    fn defaults() -> WorkFactor {
        WorkFactor::new(0, 0).unwrap()
    }

    /// AUD-003-DOC002: the advice for the cases the audit names.
    #[test]
    fn a_short_phrase_at_the_defaults_needs_nothing_else() {
        assert_eq!(
            plain(defaults(), 12, false),
            ["Nothing else needs to be kept: the 24 words and the password are enough."]
        );
    }

    #[test]
    fn a_phrase_that_detection_would_misread_needs_its_word_count() {
        let advice = plain(defaults(), 15, true);
        assert!(!advice.iter().any(|line| line.starts_with("Nothing else")));
        assert_eq!(
            advice[0],
            "Remember the word count: your phrase has 15 words."
        );
        assert!(advice[1].ends_with("recover it with mhfe decrypt --words 15."));
        assert_eq!(advice.len(), 2);
    }

    #[test]
    fn a_24_word_phrase_is_told_why_recovery_shows_it_unverified() {
        let advice = plain(defaults(), 24, false);
        assert!(advice[0].starts_with("Nothing else needs to be kept"));
        assert!(advice[1].starts_with("A 24-word phrase has no built-in check"));
        assert_eq!(advice.len(), 2);
    }

    #[test]
    fn changed_settings_must_be_remembered() {
        let advice = plain(WorkFactor::new(3, 1).unwrap(), 12, false);
        assert!(!advice.iter().any(|line| line.starts_with("Nothing else")));
        assert_eq!(
            advice[0],
            "You changed the default settings; remember them: PIM 3, memory level 1."
        );
        assert!(advice[1].starts_with("Recovery needs exactly these values"));
        let both = plain(WorkFactor::new(1, 0).unwrap(), 24, true);
        assert_eq!(
            both[0],
            "You changed the default settings; remember them: PIM 1."
        );
        assert!(both
            .iter()
            .any(|line| line == "Remember the word count: your phrase has 24 words."));
    }
}
