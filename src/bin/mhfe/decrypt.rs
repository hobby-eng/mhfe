//! `mhfe decrypt`: recovers the original phrase from a container.

use std::convert::Infallible;
use std::io;

use anstream::eprintln;
use clap::Args;
use mhfe::engine::{KEY_BYTES, SALT_BYTES};
use mhfe::memory::LockedText;
use mhfe::{decrypt, ContainerFacts, PhraseLength, RecoveredPhrase, Recovery, RecoveryStatus};
use mhfe_core::{Argon2Engine, Mhfe, NativeArgon2, Password, WorkFactor};

use crate::check;
use crate::choice::{Answer, Question};
use crate::container_repair::RepairOption;
use crate::exit::Finished as _;
use crate::exit::{Failure, NOT_ENOUGH_RESOURCES, SUCCESS};
use crate::flow::{self, Flow};
use crate::phrase_length;
use crate::raw_io::println;
use crate::readme;
use crate::scroll::{self, ScrollScreen};
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, HEADING, STRONG};
use crate::terminal::{self, Input, Progress, Wallet};

#[derive(Args)]
pub(crate) struct Options {
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
        "Input: the container, with --repair then its repair words, then the password, one \
         per line, and for a 24-word container with --passphrase-used yes, unless --words states \
         12 to 21, the BIP39 passphrase of the original seed phrase on the next line, for the \
         16-bit check of a 24-word \
         reading; without it the check runs with no passphrase. Output: one line per result, \
         \"<words> <verified|unverified> <phrase>\". Messages, the outcome of the 16-bit check \
         among them, go to standard error.",
    ])
}

/// What the command does, in its help, in the list of commands and in the start menu.
pub(crate) const SUMMARY: &str = "Recover one or more seed phrases from a container";

/// The top of `mhfe decrypt --help`.
pub(crate) fn about() -> String {
    style::command_about(&[
        SUMMARY,
        "Runs 12 rounds, one to two minutes at the default settings, and shows the recovered seed \
         phrase. Use the PIM and memory level of the encryption; at the defaults no option is \
         needed.",
        "Every password recovers a seed phrase: yours with your own password, another one, such \
         as a hidden wallet's, with any other. At a terminal you may type several passwords, \
         each with its settings; every question comes before the work, and each phrase is \
         shown under its password as soon as it is recovered, on one screen that scrolls.",
    ])
}

/// The examples at the end of `mhfe decrypt -h` and `--help`.
pub(crate) fn examples() -> String {
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

/// The end of `mhfe decrypt --help`.
pub(crate) fn long_help() -> String {
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
                "for a 24-word container, right after the password, unless --words states 12 \
                 to 21: whether the original seed phrase has one, and if so the passphrase, on \
                 a private screen, for the 16-bit check of a 24-word reading; \
                 --passphrase-used answers the question",
            ),
            (
                "More passwords",
                "at a terminal, if you choose to add them, each with its settings: each \
                 recovers its own seed phrase; not with --words 12 to 21 on a 24-word \
                 container, whose check every other password fails",
            ),
        ],
    );
    let note = style::help_note(
        "The recovered seed phrase is shown on the screen: recover only on a trusted computer \
         without a network connection.",
    );
    format!("{asks}\n{}\n{note}", examples())
}

pub(crate) fn run(options: Options) -> Result<i32, Failure> {
    let length = options.words.unwrap_or(PhraseLength::Detect);
    let mut input = Input::new(options.stdin);
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Decrypt.title());
    let work = settings::choose(options.settings, &mut input, Operation::Decrypt)?;

    let read = terminal::read_container(
        &mut input,
        Operation::Decrypt.title(),
        options.repair.card(Operation::Decrypt, work),
        // Refused before the password is asked, as the recovery would refuse it.
        |container| container.require_length(length),
    )?;
    let container = read.facts;
    // A search for missing words asked for the first password already.
    let first = ToRecover {
        password: match read.password {
            Some(password) => password,
            None => terminal::read_password(&mut input, Operation::Decrypt)?,
        },
        work,
    };
    // Its first buffer is reserved before any other password, so that whether the system locks
    // it does not depend on how many follow (AUD-007-SEC005).
    let mut shown = ScrollScreen::new(terminal::can_show_privately(&input));
    // A stated length of a built-in check refuses a phrase that fails it, as every password's but
    // the container's own does: only one password is taken then.
    let checked = matches!(length, PhraseLength::Words(words)
        if container.built_in_check_lengths().contains(&words.get()));
    // Every question comes before the work, so that nobody has to stay to answer one. The
    // passphrase belongs to the original seed phrase and comes before any other password, so
    // that the summary reads the same however many follow (AUD-047-SEC002); with a stated length
    // of a built-in check no 24-word reading comes out, which its 16-bit check is for
    // (AUD-047-SEC001).
    let passphrase = if checked {
        LockedText::copy_of("")
    } else {
        source_check_passphrase(&mut input, &container, options.passphrase_used.given())?
    };
    let passwords = if checked {
        vec![first]
    } else {
        add_passwords(&mut input, first)?
    };
    // The memory of the largest level, reserved once before the work: any refusal of it, and
    // Windows' question about it, come before the first phrase too.
    let largest = passwords
        .iter()
        .map(|to_recover| to_recover.work)
        .max_by_key(|work| work.memory_level())
        .unwrap_or(work);
    let (mut engine, reserved) = reserve_largest(largest, work)?;
    eprintln!();
    style::warn(
        "The seed phrase will be shown: recover only on a trusted offline computer.",
        "",
    );

    // Each phrase appears on a private screen as soon as it is recovered, under the progress; the
    // screen is cleared once the person is done.
    let screen = terminal::PrivateScreen::enter_to_show(&input);
    let showing = Showing {
        length,
        passphrase: &passphrase,
        input: &input,
        several: passwords.len() > 1,
    };
    recover_and_show(
        &mut engine,
        reserved,
        container.words(),
        &passwords,
        &showing,
        &mut shown,
    )?;
    if screen.is_active() {
        shown.scroll(Operation::Decrypt.title())?;
        drop(shown);
        drop(screen);
        flow.finish();
        // The same words for any number of passwords, which the main screen does not tell.
        style::ok("Recovered. The screen shows no seed phrase any more.");
        style::hint("When you are done, close this terminal.");
    } else {
        style::hint("When you are done, clear the screen and close this terminal.");
    }
    Ok(SUCCESS)
}

/// The engine for the `largest` memory level among the passwords, with the settings it was
/// reserved for. The first password's memory, `first`, is reserved first and on the record, as
/// for one password, so that its refusal and Windows' notice about it read the same however many
/// passwords follow (AUD-047-SEC002). A larger level is another password's, which the main screen
/// must not show (AUD-007-SEC005): it is tried off the record once the first area is released,
/// and where the system refuses it the first's is reserved again; a password that needs more is
/// then told so under its heading.
fn reserve_largest(
    largest: WorkFactor,
    first: WorkFactor,
) -> Result<(NativeArgon2, WorkFactor), Failure> {
    let engine = settings::reserve_engine(first)?;
    if largest.memory_level() <= first.memory_level() {
        return Ok((engine, first));
    }
    drop(engine);
    let _off_the_record = flow::off_the_record();
    match settings::reserve_engine(largest) {
        Ok(engine) => Ok((engine, largest)),
        // Only the system's refusal of the memory falls back; the person's answer "No" to
        // Windows' question about the page file ends the command, as for one password
        // (AUD-047-UI001).
        Err(refused) if refused.exit_code == NOT_ENOUGH_RESOURCES => {
            Ok((settings::reserve_engine(first)?, first))
        }
        Err(refused) => Err(refused),
    }
}

/// A password to recover with, and the settings that go with it on this container.
struct ToRecover {
    password: Password,
    work: WorkFactor,
}

/// How each recovered phrase is shown.
struct Showing<'a> {
    length: PhraseLength,
    passphrase: &'a str,
    input: &'a Input,
    /// Whether several passwords were typed, each of whose phrases is shown under it.
    several: bool,
}

/// `first`, then one more password each time the person asks for another, with its settings.
/// Only a person whose results appear on a private screen is asked, since there each phrase is
/// shown under its password. The other passwords, their settings, the question and its answer
/// stay out of the summary, so that the main screen does not tell how many passwords were typed
/// (AUD-007-SEC005); for the same reason no option answers the question, as the shell's history
/// would keep it.
fn add_passwords(input: &mut Input, first: ToRecover) -> Result<Vec<ToRecover>, Failure> {
    let work = first.work;
    let mut passwords = vec![first];
    if !terminal::can_show_privately(input) {
        return Ok(passwords);
    }
    let _off_the_record = flow::off_the_record();
    while wants_another(input, passwords.len())? {
        // The settings first, as at the start of the command.
        let work = settings::choose_another(input, work)?;
        let password = terminal::read_password(input, Operation::Decrypt)?;
        passwords.push(ToRecover { password, work });
    }
    Ok(passwords)
}

/// Whether to add another password to the `typed` ones; Enter goes on with those.
fn wants_another(input: &mut Input, typed: usize) -> Result<bool, Failure> {
    // Off the record as the question is (add_passwords): it heads the question's screen only.
    style::warn(
        "With several passwords, all their seed phrases are shown on one screen.",
        "Each appears under its password as soon as it is recovered.",
    );
    let question = Question {
        text: "Recover now, or add another password?",
        explanation: ANOTHER_EXPLAINED,
        more: Some(readme::HIDDEN_WALLETS),
        record: None,
    };
    Ok(input.choose(&question, &another_answers(typed))? == 1)
}

/// Said under the question about another password.
const ANOTHER_EXPLAINED: &[&str] =
    &["Every password recovers a seed phrase of its own, such as a hidden wallet's."];

/// The answers to the question about another password, with the `typed` ones so far.
fn another_answers(typed: usize) -> [Answer; 2] {
    let typed = match typed {
        1 => "with the password typed".to_owned(),
        _ => format!("with the {typed} passwords typed"),
    };
    [
        Answer::new("Recover now", typed),
        Answer::new(
            "Add another password",
            "recovers another seed phrase; settings come next",
        ),
    ]
}

/// Recovers the phrase of each password in turn, at its own settings on `engine`, which holds the
/// memory of `reserved`, and shows it at once, under the progress, so that one can be read while
/// the next is recovered. Everything after the first password's phrase keeps nothing for the
/// summary, which then reads as for one password, also at Ctrl+C (AUD-007-SEC005).
fn recover_and_show(
    engine: &mut NativeArgon2,
    reserved: WorkFactor,
    container: &str,
    passwords: &[ToRecover],
    showing: &Showing<'_>,
    shown: &mut ScrollScreen,
) -> Result<(), Failure> {
    let mut progress = Progress::here();
    let mut off_the_record = None;
    for (index, to_recover) in passwords.iter().enumerate() {
        if index > 0 {
            off_the_record.get_or_insert_with(flow::off_the_record);
            progress.next_operation();
        }
        if showing.several {
            style::hint(&format!("Password {} of {}", index + 1, passwords.len()));
        }
        if to_recover.work.memory_level() > reserved.memory_level() {
            shown.keep_shown(|| -> io::Result<()> {
                show_password(index + 1, &to_recover.password)?;
                style::warn_now(
                    "Not recovered: its settings need more memory than this computer could \
                     reserve now.",
                    "",
                );
                Ok(())
            })?;
            continue;
        }
        let mut mhfe = Mhfe::with_engine(to_recover.work, Lent(&mut *engine));
        let recovery = decrypt(
            &mut mhfe,
            container,
            &to_recover.password,
            showing.length,
            &mut |round, rounds| {
                progress.round_starts(round, rounds);
                mhfe::GO_ON
            },
        )
        .finished()?;
        progress.finish();
        shown.keep_shown(|| show(index + 1, &to_recover.password, &recovery, showing))?;
    }
    drop(off_the_record);
    Ok(())
}

/// An engine lent to the recovery of one password. Argon2 at a lower memory level fills only the
/// start of the larger area, with the same tag as an area of its own size, so one reservation of
/// the largest level serves every password.
struct Lent<'a>(&'a mut NativeArgon2);

impl Argon2Engine for Lent<'_> {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), mhfe_core::Error> {
        self.0.argon2id(password, salt, memory_kib, passes, key)
    }
}

/// The phrase or phrases of one recovery, under the password `number` where several were typed.
fn show(
    number: usize,
    password: &Password,
    recovery: &Recovery,
    showing: &Showing<'_>,
) -> Result<(), Failure> {
    if showing.several {
        show_password(number, password)?;
    }
    let (length, passphrase, input) = (showing.length, showing.passphrase, showing.input);
    match recovery {
        Recovery::Phrase(phrase) => show_single(phrase, length, passphrase, input),
        Recovery::Ambiguous(candidates) => show_ambiguous(candidates, passphrase, input),
    }
}

/// The heading of a result among several: the password itself, shown only on the private screen
/// with the phrase it recovers, so that the person sees which phrase is which.
fn show_password(number: usize, password: &Password) -> io::Result<()> {
    let heading = paint(HEADING, format!("Password {number}:"));
    // Put together in locked memory, as the screen keeps it: the password stays out of any
    // other copy. It holds valid UTF-8.
    let text = String::from_utf8_lossy(password.as_bytes());
    let Ok(line) = LockedText::build::<Infallible>(heading.len() + 1 + text.len(), |line| {
        line.push_str(&heading);
        line.push(' ');
        line.push_str(&text);
        Ok(())
    });
    style::write_line("");
    // Past the standard library's buffers, as a phrase is (raw_io.rs), and kept for the scroll.
    println!("{}", &*line)?;
    scroll::keep(&line);
    Ok(())
}

/// The BIP39 passphrase for the 16-bit wallet check, which every recovery evaluates on each
/// 24-word reading (the specification's recovery rules): asked once, with why, before the work,
/// on a container that can give such a reading, unless `--passphrase-used` answered it (`used`).
/// A script gives it on a line of its own with `--passphrase-used yes`, and otherwise the check
/// runs with no passphrase.
fn source_check_passphrase(
    input: &mut Input,
    container: &ContainerFacts,
    used: Option<bool>,
) -> Result<LockedText, Failure> {
    if !container.offers_wallet_check() {
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

/// The outcome of the 16-bit wallet check of a 24-word reading with `passphrase`; nothing for
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
                "It does not pass the 16-bit check {with}. That matters only for a phrase made \
                 with this check."
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
    style::write_line("");
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
            // The usual result for a 24-word phrase, and every other password's: said calmly,
            // with a wrong password or setting as the case of a shorter phrase only.
            style::warn_now(
                "Not verified: a 24-word phrase has no built-in check.",
                "Compare it with your wallet.",
            );
            style::hint(
                "If your original seed phrase has 12 to 21 words, a wrong password or setting \
                 gives this too.",
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
    style::write_line("");
    style::write_line(&paint(
        HEADING,
        format!("Recovered seed phrase, {} words", phrase.words()),
    ));
    print_result(phrase, input)?;
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
    style::write_line("");
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
            "The readings follow, the checked one first: a receiving address of your wallet \
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
        style::write_line("");
        style::write_line(&format!(
            "{} {}",
            paint(HEADING, format!("{} words", candidate.words())),
            paint(STRONG, status)
        ));
        tell_source_check(candidate, passphrase)?;
        print_result(candidate, input)?;
    }
    Ok(())
}

fn print_result(phrase: &RecoveredPhrase, input: &Input) -> io::Result<()> {
    if input.is_script() {
        let status = if phrase.verified() {
            "verified"
        } else {
            "unverified"
        };
        println!("{} {status} {}", phrase.words(), phrase.phrase())
    } else {
        terminal::print_phrase(phrase.phrase(), Wallet::NoPassphrase, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_question_about_another_password_shows_whole() {
        assert!(crate::choice::fits(ANOTHER_EXPLAINED));
        for typed in [1, 2, 99] {
            assert!(crate::choice::answers_fit(&another_answers(typed)));
        }
    }

    #[test]
    fn a_lent_engine_gives_the_tag_of_its_level_in_a_larger_area() {
        // Argon2id of "public test password" with the salt "0123456789abcdef" at 1 MiB, one pass,
        // four lanes and 32 bytes, as OpenSSL computes it (SMALL in src/engine/known_answers.rs).
        let expected = "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2";
        let mut engine = NativeArgon2::new(4 * 1024).expect("an engine of 4 MiB");
        let mut key = [0u8; KEY_BYTES];
        Lent(&mut engine)
            .argon2id(
                b"public test password",
                b"0123456789abcdef",
                1024,
                1,
                &mut key,
            )
            .expect("Argon2id at 1 MiB");
        let tag: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(tag, expected);
    }
}
