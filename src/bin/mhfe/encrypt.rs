//! `mhfe encrypt`: turns an original seed phrase into a container: 24 words, or for a 12- to
//! 21-word phrase, on the person's own choice, as many words as the phrase.

use std::io::{self, IsTerminal};

use anstream::{eprintln, println};
use clap::Args;
use mhfe::engine::NativeEngine;
use mhfe::memory::LockedPages;
use mhfe::repair;
use mhfe::{
    other_detected_lengths, read_phrase, Mhfe, MhfeError, NewContainer, Password, Suite, WorkFactor,
};
use zeroize::Zeroizing;

use crate::choice;
use crate::exit::{capitalize, Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::length_choice;
use crate::plate_repair;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::strength;
use crate::style::{self, paint, ACCENT, HEADING, MUTED};
use crate::terminal::{self, Input, Progress};

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// Keep the length of a 12- to 21-word phrase instead of making 24 words
    #[arg(long, long_help = same_length_help())]
    same_length: bool,

    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = stdin_help())]
    stdin: bool,
}

fn same_length_help() -> String {
    style::option_help(&[
        "Keep the length of a 12- to 21-word phrase instead of making 24 words.",
        "Without it, a person at a terminal is asked, and 24 words is the default. A container \
         of the phrase's own length looks like any other phrase, but nothing detects a wrong \
         password: it opens another, empty wallet. The container also shows the phrase's \
         length, and a word copied wrongly passes its shorter checksum more often. A 24-word \
         phrase always gives 24 words.",
    ])
}

fn stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the phrase, the password and the password again, one per line. Output: the \
         container on one line, printed only after its check has passed. Messages go to \
         standard error, so standard output holds the container alone. The container has 24 \
         words unless --same-length is given.",
    ])
}

/// The top of `mhfe encrypt --help`.
pub fn about() -> String {
    style::command_about(&[
        "Encrypt a seed phrase into a container",
        "The container is itself a valid BIP39 phrase: 24 words by default, or for a 12- to \
         21-word phrase, if you choose so, as many words as the phrase. With the default \
         settings the container and the password are all that recovery needs. Encryption runs \
         24 rounds: 12 to encrypt, then 12 that decrypt the new container again and compare the \
         result with the original. At the default settings this takes about two to four minutes.",
    ])
}

/// The examples at the end of `mhfe encrypt -h`.
fn examples() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe encrypt", "Encrypt with the default settings"),
            (
                "mhfe encrypt --same-length",
                "A container as long as the 12- to 21-word phrase",
            ),
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
                "Original seed phrase",
                "hidden; 12 to 24 words; four letters per word are enough",
            ),
            (
                "Container length",
                "for 12 to 21 words: 24 words (default) or the same length; ? explains both",
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
    let mut input = Input::new(options.stdin);
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Encrypt.title());
    let work = settings::choose(options.settings, &mut input, Operation::Encrypt)?;

    let original = read_original(&mut input)?;
    // Kept out of swap until it is wiped, through all of the long computation.
    let _original_locked = LockedPages::of_string(&original);
    let original_words = original.split(' ').count();
    let suite = choose_suite(original_words, options.same_length, &input)?;
    // The rare phrase that also passes the check of another length; only a 24-word container
    // carries such checks.
    let length_must_be_chosen = suite == Suite::TwentyFourWords
        && warn_if_detection_would_mislead(&original, original_words)?;
    let repair_count = plate_repair::ask_when_creating(&mut input)?;
    let password = read_new_password(&mut input, Operation::Encrypt)?;
    let new = seal(
        &input,
        Operation::Encrypt,
        work,
        &original,
        suite,
        &password,
        repair_count,
    )?;
    drop(original);
    flow.finish();
    let container_words = new.words.split(' ').count();
    // The format of the container, which the specification asks to show after creating it.
    style::fact("Format", paint(MUTED, new.suite.id()));
    style::fact(
        "Keep",
        what_to_keep(
            work,
            original_words,
            length_must_be_chosen,
            container_words,
            plate_repair::to_keep(repair_count),
        ),
    );
    // The check above covered the words this program produced, not the copy the user wrote down.
    style::fact(
        "Next",
        format!(
            "rehearse with {} from the backup you wrote",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::ENCRYPT);
    Ok(SUCCESS)
}

/// Encrypts `original` and checks the new container (creation steps 1 to 6). A person reading
/// the terminal sees the container on a private screen while the check runs, marked as not
/// verified yet, and the outcome on both screens; anything else gets the container only once it
/// is checked. Shared by `mhfe encrypt` and `mhfe rekey`.
pub fn seal(
    input: &Input,
    operation: Operation,
    work: WorkFactor,
    original: &str,
    suite: Suite,
    password: &Password,
    repair_count: Option<usize>,
) -> Result<NewContainer, Failure> {
    let mut mhfe = settings::reserve_memory(work)?;
    let mut progress = Progress::start();
    let new = mhfe.encrypt_unchecked(original, password, suite, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    // The repair words of the new plate, shown and written with it (plate_repair.rs).
    let card = repair_count
        .map(|count| repair::repair_words(&new.words, count))
        .transpose()?;
    // Only a person reading a terminal sees the container before its check, with the warning
    // that it is not verified yet. A script, or output redirected to a file or another program,
    // gets it only after the check: a program would take the first container it reads as final.
    let person_reads_output = !input.is_script() && io::stdout().is_terminal();
    if !person_reads_output {
        check(&mut mhfe, &new, password, &mut progress)?;
        progress.finish();
        println!("{}", *new.words);
        // After the check, which has passed here.
        if let Some(card) = &card {
            println!("{card}");
        }
        if !input.is_script() {
            report_check(&Ok(()));
        }
    } else {
        // A person can write the container down while the check runs. It is shown on the private
        // screen, as a recovered phrase is: it is a valid seed phrase too, and should leave no
        // copy in the terminal's history.
        progress.finish();
        let screen = terminal::PrivateScreen::enter_to_show(input);
        if screen.is_active() {
            style::title(operation.title());
        }
        show_before_the_check(&new.words, input);
        let checked = check(&mut mhfe, &new, password, &mut progress);
        terminal::set_unverified_container_shown(false);
        progress.finish();
        report_check(&checked);
        // The card is made from the container once its check has passed (the specification's
        // MHFE-REPAIR-1), below it on the same screen.
        if let (Ok(()), Some(card)) = (&checked, &card) {
            plate_repair::print_card(card, input);
        }
        if screen.is_active() {
            terminal::wait_to_leave()?;
            drop(screen);
            // The main screen gets the outcome too: the private screen and its copy are gone. A
            // command shown one step at a time has kept it for its summary already.
            if !flow::is_active() {
                report_check(&checked);
            }
        }
        checked?;
    }
    Ok(new)
}

/// The container for a phrase of `words` words: 24 words unless the person chooses the same
/// length, at a terminal or with --same-length. A 24-word phrase has no other form.
fn choose_suite(words: usize, same_length: bool, input: &Input) -> Result<Suite, Failure> {
    if words == 24 {
        return if same_length {
            Err(MhfeError::SameLengthNeedsShortPhrase.into())
        } else {
            Ok(Suite::TwentyFourWords)
        };
    }
    if same_length {
        choice::record(
            "Container",
            &format!("{words} words, the same length as yours (--same-length)"),
        );
        length_choice::show_consequences(words);
        return Ok(Suite::SameLength);
    }
    if input.is_script() || !choice::can_run() {
        return Ok(Suite::TwentyFourWords);
    }
    length_choice::choose(words)
}

/// What the owner must keep: the container's words and the password, and only where they are
/// needed the changed settings and the word count, when detection would misread the phrase
/// (AUD-003-DOC002). Why each matters is in the README.
pub fn what_to_keep(
    work: WorkFactor,
    original_words: usize,
    length_must_be_chosen: bool,
    container_words: usize,
    also: &[&str],
) -> String {
    let mut items = vec![
        format!("the {container_words} words"),
        "the password".to_owned(),
    ];
    items.extend(also.iter().map(|item| (*item).to_owned()));
    items.extend(settings::changed_settings(work));
    if length_must_be_chosen {
        items.push(format!("the word count, {original_words}"));
    }
    let last = items.pop().unwrap_or_default();
    format!("{} and {last}", items.join(", "))
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

/// Says whether the container shown turned back into the phrase. A container written down before
/// a failed check must be crossed out.
fn report_check(checked: &Result<(), MhfeError>) {
    match checked {
        Ok(()) => style::ok(format!(
            "{} the container turns back into your original phrase.",
            paint(style::GOOD, "Verified:")
        )),
        Err(MhfeError::VerificationFailed) => {
            eprintln!();
            style::alarm(
                "The container shown is WRONG: it did not turn back into your phrase.",
                "Do NOT use it; cross it out if you wrote it down, and encrypt again.",
            );
        }
        Err(_) => {
            eprintln!();
            style::alarm(
                "The check stopped with an error: the container shown is NOT verified.",
                "Do NOT rely on it; encrypt again.",
            );
        }
    }
}

/// Shows the container after the first twelve rounds, clearly marked as not yet verified.
fn show_before_the_check(container: &str, input: &Input) {
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!("Container, {} words", container.split(' ').count())
        )
    );
    terminal::print_phrase(container, input);
    eprintln!();
    style::warn_here(
        "Not verified yet: write it down, but wait for the check.",
        "",
    );
    eprintln!();
    terminal::set_unverified_container_shown(true);
}

/// Reads the original phrase on the private screen, where it is shown as it is typed. A valid
/// phrase is taken at once, with no question to confirm it: a mistyped word is refused by the
/// word list or the checksum. The screen is then cleared and the summary records the phrase's
/// length.
fn read_original(input: &mut Input) -> Result<Zeroizing<String>, Failure> {
    let screen = terminal::PrivateScreen::enter(input, Operation::Encrypt.title());
    let phrase = loop {
        if screen.is_active() {
            eprintln!();
        }
        let typed = input.secret("Original seed phrase")?;
        match read_phrase(&typed) {
            Ok(phrase) => break phrase,
            Err(error) if input.can_ask_again() => {
                style::retry(format!(
                    "{}. Please type it again.",
                    capitalize(&error.to_string())
                ));
            }
            Err(error) => return Err(error.into()),
        }
    };
    drop(screen);
    let words = phrase.split(' ').count();
    choice::record("Phrase", &format!("{words} words, valid"));
    Ok(phrase)
}

/// About once in four billion phrases, the packed phrase also passes the built-in check of
/// another length. Recovery with automatic detection would then not give this phrase on its own,
/// so the owner is told, before the long computation, to note the length and choose it later.
pub fn warn_if_detection_would_mislead(phrase: &str, words: usize) -> Result<bool, Failure> {
    let others = other_detected_lengths(phrase)?;
    if others.is_empty() {
        return Ok(false);
    }
    let others: Vec<String> = others.iter().map(ToString::to_string).collect();
    // Set apart from the summary above and below it.
    eprintln!();
    style::warn(
        &format!("Write down that your phrase has {words} words."),
        &format!(
            "By rare chance it also reads as {} words: recover it with mhfe decrypt --words \
             {words}.",
            others.join(" and ")
        ),
    );
    eprintln!();
    Ok(true)
}

/// Asks for the password twice on the private screen, so that a typing mistake cannot lock the
/// phrase away, and warns when its estimated strength falls short of four dice words.
pub fn read_new_password(input: &mut Input, operation: Operation) -> Result<Password, Failure> {
    let screen = terminal::PrivateScreen::enter(input, operation.title());
    // A command may ask for a BIP39 passphrase or another password too: say which secret this is.
    let (what, prompt, repeat) = match operation {
        Operation::New => (
            "The container password encrypts the 24 words; it is NOT the BIP39 passphrase.",
            "Container password",
            "Repeat the container password",
        ),
        Operation::Rekey | Operation::RekeyNew => (
            "The new password replaces the old one in the new container.",
            "New container password",
            "Repeat the new container password",
        ),
        Operation::Wallets => (
            "Each password other than the container's own opens a hidden wallet of its own.",
            "Hidden wallet password",
            "Repeat the hidden wallet password",
        ),
        _ => (
            "The container password encrypts your phrase; it is NOT a BIP39 passphrase.",
            "Container password",
            "Repeat the container password",
        ),
    };
    let (password, bits) = loop {
        eprintln!();
        if screen.is_active() {
            style::hint(what);
        }
        style::hint("Letter case and spaces count.");
        let text = input.secret(prompt)?;
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
        let repeated = input.secret(repeat)?;
        if *repeated != *text {
            if input.can_ask_again() {
                style::retry("The two passwords differ. Please type them again.");
                continue;
            }
            return Err(Failure::invalid_input(
                "The two passwords differ. Nothing was encrypted.",
            ));
        }
        break (password, strength::estimated_bits(&text));
    };
    drop(screen);
    choice::record("Password", "typed twice");
    if strength::is_weak(bits) {
        eprintln!();
        style::warn(
            &format!("This password is weak: about {bits:.0} bits, by a rough estimate."),
            &format!("{} makes a strong one.", paint(ACCENT, "mhfe password")),
        );
        style::more(readme::PASSWORD);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> WorkFactor {
        WorkFactor::new(0, 0).unwrap()
    }

    /// AUD-003-DOC002: what to keep in the cases the audit names.
    #[test]
    fn a_short_phrase_at_the_defaults_needs_only_the_words_and_the_password() {
        assert_eq!(
            what_to_keep(defaults(), 12, false, 24, &[]),
            "the 24 words and the password"
        );
        assert_eq!(
            what_to_keep(defaults(), 15, false, 15, &[]),
            "the 15 words and the password"
        );
    }

    #[test]
    fn a_phrase_that_detection_would_misread_needs_its_word_count() {
        assert_eq!(
            what_to_keep(defaults(), 15, true, 24, &[]),
            "the 24 words, the password and the word count, 15"
        );
    }

    #[test]
    fn changed_settings_must_be_kept() {
        assert_eq!(
            what_to_keep(WorkFactor::new(3, 1).unwrap(), 12, false, 24, &[]),
            "the 24 words, the password, PIM 3 and memory level 1"
        );
        assert_eq!(
            what_to_keep(WorkFactor::new(1, 0).unwrap(), 24, true, 24, &[]),
            "the 24 words, the password, PIM 1 and the word count, 24"
        );
    }
}
