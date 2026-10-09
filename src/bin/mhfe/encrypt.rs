//! `mhfe encrypt`: turns an original seed phrase into a container: 24 words, or for a 12- to
//! 21-word phrase, on the person's own choice, as many words as the phrase.

use std::cell::RefCell;

use anstream::{eprintln, println};
use clap::Args;
use mhfe::operation::{Encryption, Keep, KeepItem, Sealed, StageCallback, WalletPassphrase};
use mhfe::{MhfeError, OriginalFacts, Password, Suite, WorkFactor};

use crate::check_word;
use crate::choice;
use crate::container_repair::{self, RepairWordsOption};
use crate::exit::{refused, Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::length_choice;
use crate::made_password::{self, NewPasswordOption, PasswordKind};
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, MUTED};
use crate::terminal::{self, Input, Progress, Wallet};
use mhfe::strength::Strength;
use mhfe::word_hints::WordList;

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// A container as long as the 12- to 21-word phrase
    #[arg(long, long_help = same_length_help())]
    same_length: bool,

    #[command(flatten)]
    new_password: NewPasswordOption,

    #[command(flatten)]
    repair_words: RepairWordsOption,

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
         21-word phrase, if you choose so, as many words as the phrase. With the default settings \
         the container and the password are all that recovery needs. Encryption runs 24 rounds: 12 \
         to encrypt, then 12 that decrypt the new container again and compare the result with the \
         original seed phrase. At the default settings this takes about two to four minutes.",
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
                "on a private screen; 12 to 24 words; four letters per word are enough",
            ),
            (
                "Container length",
                "for 12 to 21 words: 24 words (default) or the same length; ? explains both",
            ),
            (
                "Repair words",
                "at a terminal: none, or 2, 4, 6 or 8 for a card kept apart from the container \
                 phrase",
            ),
            ("Password", "on a private screen, typed twice"),
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
    options.new_password.check(&input)?;
    options.repair_words.check()?;
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Encrypt.title());
    let work = settings::choose(options.settings, &mut input, Operation::Encrypt)?;

    // Read into locked memory: it stays out of swap until it is wiped, through all of the long
    // computation.
    let original = read_original(&mut input)?;
    let original_words = original.word_count();
    let suite = choose_suite(&original, options.same_length, &input)?;
    // The rare phrase that also passes the check of another length.
    warn_if_detection_would_mislead(original.other_lengths_in(suite), original_words);
    let repair_count = options.repair_words.choose(&mut input)?;
    let password = read_new_password(&mut input, Operation::Encrypt, options.new_password.kind())?;
    let new = seal(
        &input,
        Operation::Encrypt,
        work,
        original.words(),
        suite,
        &password,
        repair_count,
    )?;
    drop(original);
    flow.finish();
    // The format of the container, which the specification asks to show after creating it.
    style::fact("Format", paint(MUTED, new.suite().id()));
    // Nothing asks whether the wallet has a BIP39 passphrase: in a tool that encrypts a phrase the
    // question looked suspicious and burdened the person (the owner's decision of 2026-10-08).
    // The list names any passphrase of the wallet instead, at a terminal and in a script alike.
    let keep = new.keep(work, WalletPassphrase::Unknown);
    // Wrapped under its column: the list grows with every item to keep.
    style::fact_wrapped("Keep", &what_to_keep(&keep));
    // The check above covered the words this program produced, not the copy the user wrote down.
    style::fact_wrapped(
        "Next",
        &format!(
            "rehearse with {} from the backup you wrote",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::ENCRYPT);
    Ok(SUCCESS)
}

/// Encrypts `original` into a container of `suite` and checks it (creation steps 1 to 6), with
/// the library's [`Encryption`], shown as [`show_sealing`] shows it. Shared by `mhfe encrypt` and
/// `mhfe new`.
pub fn seal(
    input: &Input,
    operation: Operation,
    work: WorkFactor,
    original: &str,
    suite: Suite,
    password: &Password,
    repair_count: Option<usize>,
) -> Result<Sealed, Failure> {
    let encryption = Encryption::new(original, suite, repair_count)?;
    let mut mhfe = settings::reserve_memory(work)?;
    show_sealing(input, operation, |progress, on_unverified| {
        encryption.run(&mut mhfe, original, password, progress, on_unverified)
    })
}

/// The terminal side of a sealing that the library runs, `sealing`: an encryption and its check,
/// whose rounds it reports as 1 to 24 of 24 to the progress it is given, and whose container it
/// gives to the other callback before the check. A person reading a terminal sees the container
/// on a private screen while the check runs, marked as not verified yet, and the outcome on both
/// screens; anything else gets the container only once it is checked. `mhfe rekey` passes the
/// library's `Rekey::seal` here, `mhfe encrypt` and `mhfe new` an [`Encryption`] ([`seal`]).
pub fn show_sealing(
    input: &Input,
    operation: Operation,
    sealing: impl FnOnce(
        StageCallback<'_>,
        &mut dyn FnMut(&str) -> Result<(), MhfeError>,
    ) -> Result<Sealed, MhfeError>,
) -> Result<Sealed, Failure> {
    // Both callbacks below draw on the one progress line.
    let progress = RefCell::new(Progress::start());
    // Only a person reading a terminal sees the container before its check, with the warning
    // that it is not verified yet. A script, or output redirected to a file, another program or
    // another terminal, gets it only after the check: a program would take the first container it
    // reads as final, and the warning goes to standard error only (AUD-015-SEC005).
    let person_reads_output = !input.is_script() && terminal::output_on_screen();
    let mut screen = None;
    let sealed = sealing(
        &mut |_, round, rounds| {
            progress.borrow_mut().round_starts(round, rounds);
            Ok(())
        },
        &mut |container| {
            if person_reads_output {
                // A person can write the container down while the check runs. It is shown on
                // the private screen, as a recovered phrase is: it is a valid seed phrase too,
                // and should leave no copy in the terminal's history.
                progress.borrow_mut().finish();
                let shown = terminal::PrivateScreen::enter_to_show(input);
                if shown.is_active() {
                    style::title(operation.title());
                }
                show_before_the_check(container, input);
                screen = Some(shown);
            }
            Ok(())
        },
    );
    progress.into_inner().finish();
    let Some(screen) = screen else {
        // Nothing was shown before the check: the container comes out only once it has passed.
        let sealed = sealed?;
        println!("{}", sealed.container());
        if let Some(card) = sealed.repair_words() {
            println!("{card}");
        }
        if !input.is_script() {
            report_check(Ok(()));
        }
        return Ok(sealed);
    };
    terminal::set_unverified_container_shown(false);
    report_check(sealed.as_ref().map(|_| ()));
    // The card is made from the container once its check has passed (the specification's
    // MHFE-REPAIR-1), below it on the same screen.
    if let Some(card) = sealed.as_ref().ok().and_then(Sealed::repair_words) {
        container_repair::print_card(card, input);
    }
    if screen.is_active() {
        terminal::wait_to_leave()?;
        drop(screen);
        // The main screen gets the outcome too: the private screen and its copy are gone. A
        // command shown one step at a time has kept it for its summary already.
        if !flow::is_active() {
            report_check(sealed.as_ref().map(|_| ()));
        }
    }
    Ok(sealed?)
}

/// The container for the original phrase: 24 words unless the person chooses the same length, at
/// a terminal or with --same-length. A 24-word phrase has no other form.
fn choose_suite(
    original: &OriginalFacts,
    same_length: bool,
    input: &Input,
) -> Result<Suite, Failure> {
    let words = original.word_count();
    if same_length {
        Suite::SameLength.require_original(words)?;
        choice::record(
            "Container",
            &format!("{words} words, the same length as yours (--same-length)"),
        );
        length_choice::show_consequences(words);
        return Ok(Suite::SameLength);
    }
    // A 24-word phrase has one container; a script and a terminal without lists take the first.
    if original.container_choices().len() == 1 || input.is_script() || !choice::can_run() {
        return Ok(Suite::TwentyFourWords);
    }
    length_choice::choose(original)
}

/// What the owner must keep, as the summary line says it: the library's [`Keep`] list. Why each
/// item matters is in the README.
pub fn what_to_keep(keep: &Keep) -> String {
    let items: Vec<String> = keep
        .items()
        .iter()
        .map(|item| match item {
            KeepItem::ContainerWords(words) => format!("the {words} words"),
            KeepItem::Password => "the password".to_owned(),
            KeepItem::Passphrase => "the BIP39 passphrase".to_owned(),
            KeepItem::PassphraseIfAny => "any BIP39 passphrase of the wallet".to_owned(),
            KeepItem::RepairWords => "the repair words apart from the container phrase".to_owned(),
            KeepItem::Pim(pim) => format!("PIM {pim}"),
            KeepItem::MemoryLevel(level) => format!("memory level {level}"),
            KeepItem::WordCount(words) => format!("the word count, {words}"),
        })
        .collect();
    style::and_list(&items)
}

/// Says whether the container shown turned back into the phrase. A container written down before
/// a failed check must be crossed out.
fn report_check(checked: Result<(), &MhfeError>) {
    match checked {
        Ok(()) => style::ok(format!(
            "{} the container turns back into your original seed phrase.",
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
    terminal::print_phrase(container, Wallet::Container, input);
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
fn read_original(input: &mut Input) -> Result<OriginalFacts, Failure> {
    let screen = terminal::PrivateScreen::enter(input, Operation::Encrypt.title());
    let phrase = loop {
        if screen.is_active() {
            eprintln!();
        }
        let typed = input.secret_words("Original seed phrase", WordList::Bip39)?;
        if let Some(phrase) = input.accepted(OriginalFacts::read(&typed), terminal::TYPE_AGAIN)? {
            break phrase;
        }
    };
    drop(screen);
    let words = phrase.word_count();
    choice::record("Phrase", &format!("{words} words, valid"));
    Ok(phrase)
}

/// About once in four billion phrases, the packed phrase also passes the built-in check of
/// another length. Recovery with automatic detection would then not give this phrase on its own,
/// so the owner is told, before the long computation, to note the length and choose it later.
pub fn warn_if_detection_would_mislead(others: &[usize], words: usize) {
    if others.is_empty() {
        return;
    }
    let others: Vec<String> = others.iter().map(ToString::to_string).collect();
    let others = style::and_list(&others);
    // Set apart from the summary above and below it.
    eprintln!();
    style::warn(
        &format!("Write down that your phrase has {words} words."),
        &format!(
            "By rare chance it also reads as {} words: recover it with mhfe decrypt --words \
             {words}.",
            others
        ),
    );
    eprintln!();
}

/// The new password of a container: at a terminal the person types their own or takes one that
/// MHFE makes (`made_password`), as `kind` says or as asked; a script types its own.
pub fn read_new_password(
    input: &mut Input,
    operation: Operation,
    kind: Option<PasswordKind>,
) -> Result<Password, Failure> {
    made_password::refuse_kind(input, kind)?;
    let kind = match kind {
        Some(kind) => kind,
        // As the repair words, the question is a list, which a script or a terminal that
        // cannot redraw lines does not get, and a made password needs a private screen.
        None if input.is_script() || !choice::can_run() || !terminal::can_show_privately(input) => {
            PasswordKind::Own
        }
        None => made_password::ask_kind(input, operation)?,
    };
    match kind {
        PasswordKind::Own => read_typed_password(input, operation),
        made => made_password::read_made(input, operation, made),
    }
}

/// Asks for the password twice on the private screen, so that a typing mistake cannot lock the
/// phrase away, and warns when its estimated strength falls short of four dice words.
pub fn read_typed_password(input: &mut Input, operation: Operation) -> Result<Password, Failure> {
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
    let (password, strength, check) = loop {
        eprintln!();
        if screen.is_active() {
            style::hint(what);
        }
        style::hint("Letter case and spaces count.");
        let text = input.password(prompt)?;
        let Some(password) = input.accepted(Password::new(&text), "Please choose another.")? else {
            continue;
        };
        let repeated = input.password(repeat)?;
        // The first entry's rules were checked above, before the repetition was asked.
        let same = mhfe::check_word::require_same(&text, &repeated);
        drop(repeated);
        match same {
            Ok(()) => {}
            Err(error) if input.can_ask_again() => {
                style::retry(refused(&error, "Please type them again."));
                continue;
            }
            Err(error) => {
                return Err(Failure::invalid_input(refused(
                    &error,
                    "Nothing was encrypted.",
                )))
            }
        }
        // Typed twice the same, a word copied wrongly from paper is still caught by the check word.
        let (text, check) = match check_word::review(input, text, &screen)? {
            check_word::Reviewed::Use(text, check) => (text, check),
            check_word::Reviewed::TypeAgain => {
                screen.clear();
                continue;
            }
        };
        // A repaired or corrected password is another text than the one first read.
        let password = match check {
            check_word::Outcome::Repaired(..) | check_word::Outcome::Fits(Some(_)) => {
                Password::new(&text)?
            }
            _ => password,
        };
        break (password, Strength::of(&text), check);
    };
    drop(screen);
    choice::record("Password", &check.record("typed twice"));
    if strength.is_weak() {
        eprintln!();
        style::warn(
            &format!(
                "This password is weak: about {:.0} bits, by a rough estimate.",
                strength.bits()
            ),
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
            what_to_keep(&Keep::new(
                defaults(),
                24,
                WalletPassphrase::Absent,
                false,
                None
            )),
            "the 24 words and the password"
        );
        assert_eq!(
            what_to_keep(&Keep::new(
                defaults(),
                15,
                WalletPassphrase::Absent,
                false,
                None
            )),
            "the 15 words and the password"
        );
    }

    #[test]
    fn a_wallet_with_a_passphrase_keeps_it() {
        assert_eq!(
            what_to_keep(&Keep::new(
                defaults(),
                24,
                WalletPassphrase::Present,
                true,
                None
            )),
            "the 24 words, the password, the BIP39 passphrase and the repair words apart from the \
             container phrase"
        );
    }

    /// `mhfe encrypt` does not ask about the passphrase: its list names any the wallet may have,
    /// in the place of a known one, also among repair words and settings.
    #[test]
    fn an_encryption_names_any_passphrase_of_the_wallet() {
        let unknown = |work, repair_words| {
            what_to_keep(&Keep::new(
                work,
                24,
                WalletPassphrase::Unknown,
                repair_words,
                None,
            ))
        };
        assert_eq!(
            unknown(defaults(), false),
            "the 24 words, the password and any BIP39 passphrase of the wallet"
        );
        assert_eq!(
            unknown(defaults(), true),
            "the 24 words, the password, any BIP39 passphrase of the wallet and the repair words \
             apart from the container phrase"
        );
        assert_eq!(
            unknown(WorkFactor::new(3, 1).unwrap(), false),
            "the 24 words, the password, any BIP39 passphrase of the wallet, PIM 3 and memory \
             level 1"
        );
    }

    /// The longest list, every item, wraps under its column within the text width (AUD-010).
    #[test]
    fn the_longest_keep_line_wraps_within_the_text_width() {
        let everything = Keep::new(
            WorkFactor::new(1023, 21).unwrap(),
            24,
            WalletPassphrase::Unknown,
            true,
            Some(15),
        );
        let lines = style::fact_lines("Keep", &what_to_keep(&everything));
        for line in &lines {
            assert!(style::visible_width(line) <= style::TEXT_WIDTH, "{line}");
        }
        assert!(
            lines.len() > 1,
            "the longest list fits on one line: {lines:?}"
        );
    }

    #[test]
    fn a_phrase_that_detection_would_misread_needs_its_word_count() {
        assert_eq!(
            what_to_keep(&Keep::new(
                defaults(),
                24,
                WalletPassphrase::Absent,
                false,
                Some(15)
            )),
            "the 24 words, the password and the word count, 15"
        );
    }

    #[test]
    fn changed_settings_must_be_kept() {
        assert_eq!(
            what_to_keep(&Keep::new(
                WorkFactor::new(3, 1).unwrap(),
                24,
                WalletPassphrase::Absent,
                false,
                None
            )),
            "the 24 words, the password, PIM 3 and memory level 1"
        );
        assert_eq!(
            what_to_keep(&Keep::new(
                WorkFactor::new(1, 0).unwrap(),
                24,
                WalletPassphrase::Absent,
                false,
                Some(24)
            )),
            "the 24 words, the password, PIM 1 and the word count, 24"
        );
    }
}
