//! `mhfe new`: a new 24-word wallet and its container in one go. The phrase is drawn from the
//! operating system's generator. If the owner chooses, it is drawn until it passes a wallet check
//! with the wallet's BIP39 passphrase (a draft; `mhfe::wallet_check`), so that a recovery with the
//! passphrase recognises the right password. The owner always chooses; the check has costs, which
//! `?` and the README state.

use std::time::Instant;

use anstream::eprintln;
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::wallet_check::{NewPhrase, PhraseDraw};
use mhfe::Suite;

use crate::choice::{self, Answer, Help, Question};
use crate::encrypt;
use crate::exit::{Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::plate_repair;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, GOOD, HEADING, MUTED, STRONG, WARNING};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input, Wallet};
use mhfe::strength::Strength;

#[derive(Args)]
pub struct Options {
    /// The settings of the container
    #[command(flatten)]
    settings: Settings,
}

/// The top of `mhfe new --help`.
pub fn about() -> String {
    style::command_about(&[
        "Generate a new wallet and its container",
        "Draws a new 24-word seed phrase from the operating system's random generator, shows it \
         once for your wallet, and encrypts it into a container under your password. If you \
         choose, the phrase is drawn so that it passes a check with your BIP39 passphrase, \
         which lets a recovery with the passphrase recognise the right password; the check has \
         costs, which ? explains at the question and the README states.",
    ])
}

/// The end of `mhfe new -h` and `--help`.
pub fn help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            (
                "mhfe new",
                "A new wallet and its container, default settings",
            ),
            ("mhfe new --pim 1", "The container with twice the passes"),
            (
                "mhfe new --pim 1 --mem 1",
                "Twice the passes and 3 GiB of memory",
            ),
        ],
    );
    let note = style::help_note(
        "The new phrase is shown once, on a private screen: write it down for your wallet before \
         you go on. It cannot run in a script.",
    );
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; the new phrase is shown only on a private screen,
    // so the command does not start where there can be none (AUD-007-SEC001).
    let mut input = Input::terminal_only();
    if !terminal::can_show_privately(&input) {
        return Err(Failure::invalid_input(
            "mhfe new shows the new phrase only on a private screen: run it at a terminal, with no \
             output redirected.",
        ));
    }
    // Every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::New.title());
    let work = settings::choose(options.settings, &mut input, Operation::New)?;
    // A wallet check exists only with a passphrase, so its question comes only after one.
    let passphrase = read_new_passphrase(&mut input)?;
    let checked = !passphrase.is_empty() && ask_for_check()?;
    if checked {
        let strength = Strength::of(&passphrase);
        let bits = strength.bits();
        eprintln!();
        if strength.is_weak() {
            style::warn(
                &format!(
                    "This passphrase is weak: about {bits:.0} bits; the check is as strong as it."
                ),
                "",
            );
        }
        style::warn(
            "Keep all funds under this passphrase; the wallet without it stays empty.",
            "",
        );
        style::more(readme::NEW);
    }

    let repair_count = plate_repair::ask_when_creating(&mut input)?;
    // Held locked from here on; the drawn phrase is wiped at once.
    let phrase = LockedText::copy_of(draw_phrase(checked.then_some(&*passphrase))?.phrase());
    show_new_phrase(&input, &phrase, &passphrase)?;
    let check = if checked { ", with a check" } else { "" };
    choice::record("Phrase", &format!("24 words, new{check}"));
    encrypt::warn_if_detection_would_mislead(&phrase, 24)?;

    let password = encrypt::read_new_password(&mut input, Operation::New)?;
    let new = encrypt::seal(
        &input,
        Operation::New,
        work,
        &phrase,
        Suite::TwentyFourWords,
        &password,
        repair_count,
    )?;
    flow.finish();
    style::fact("Format", paint(MUTED, new.suite().id()));
    // A passphrase belongs to the wallet, checked or not.
    let keep = new.keep(work, !passphrase.is_empty());
    style::fact_wrapped("Keep", &encrypt::what_to_keep(&keep));
    style::fact_wrapped(
        "Next",
        &format!(
            "rehearse with {} from the backup you wrote",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::NEW);
    Ok(SUCCESS)
}

/// Asks whether the new phrase gets a wallet check with the passphrase. Nothing is preselected
/// (AUD-010): each choice has its costs, which `?` shows, and a hurried Enter, perhaps typed ahead
/// after the repeated passphrase, must not decide a property the phrase keeps for ever.
fn ask_for_check() -> Result<bool, Failure> {
    let answers = [
        Answer::new("No check", "every password opens a valid wallet"),
        Answer::new(
            "A phrase + passphrase check",
            "a recovery recognises a wrong password",
        ),
    ];
    let question = Question {
        text: "Do you want a check that confirms the password at recovery?",
        // The cost in entropy, stated calmly above both answers: 240 bits are far beyond any search.
        explanation: &["A check takes 16 of the 256 bits of entropy; 240 remain, still plenty."],
        more: Some(readme::NEW),
        record: Some("Check"),
    };
    let chosen = choice::choose_without_default(
        &question,
        &answers,
        Some(Help {
            hint: "? explains both",
            show: &explain,
        }),
    )?;
    match chosen {
        Some(choice) => Ok(choice == 1),
        None => Err(mhfe::MhfeError::Cancelled.into()),
    }
}

/// What each choice gives and costs, shown when the person presses ?.
fn explain() {
    let good = |text: &str| eprintln!("  {} {text}", paint(GOOD, "✓"));
    let bad = |text: &str| eprintln!("  {} {text}", paint(WARNING, "!"));
    eprintln!("{}", paint(STRONG, "No check"));
    good("Every password gives an equally valid wallet; decoys work.");
    bad("A recovery cannot tell a wrong password.");
    eprintln!();
    eprintln!("{}", paint(STRONG, "A phrase + passphrase check"));
    good("A wrong password or passphrase passes once in about 65,536.");
    good("A password guess is tested only with a passphrase guess.");
    good("About 240 of the 256 bits remain: far beyond any search.");
    bad("Keep all funds under it; the wallet without it stays unused.");
    bad("A decoy password or passphrase passes after about 65,536 tries.");
    bad("Only mhfe check with the passphrase tests it.");
    eprintln!();
    style::hint("A draft, for new wallets only. A pass is evidence, not proof.");
}

/// The BIP39 passphrase of the new wallet on the private screen: Enter alone for none, otherwise
/// typed twice.
fn read_new_passphrase(input: &mut Input) -> Result<LockedText, Failure> {
    let screen = terminal::PrivateScreen::enter(input, Operation::New.title());
    let passphrase = loop {
        eprintln!();
        style::hint("Part of the wallet, as a 25th word; it is NOT the container password.");
        let passphrase = input.secret("BIP39 passphrase of the new wallet, or Enter for none")?;
        if passphrase.is_empty() {
            break passphrase;
        }
        let repeated = input.secret("Repeat the passphrase")?;
        if *repeated == *passphrase {
            break passphrase;
        }
        style::retry("The two passphrases differ. Please type them again.");
    };
    drop(screen);
    let what = if passphrase.is_empty() {
        "none"
    } else {
        "typed twice"
    };
    choice::record("Passphrase", what);
    Ok(passphrase)
}

/// A new 24-word phrase from the operating system's generator; with a `passphrase`, drawn on
/// every processor core until one passes the wallet check with it, about 65,536 BIP39 seeds. The
/// library probes the generator first and reads the new phrase back.
fn draw_phrase(passphrase: Option<&str>) -> Result<NewPhrase, Failure> {
    let Some(passphrase) = passphrase else {
        return Ok(PhraseDraw::unchecked().draw(&mut SystemRandom, &mut |_| Ok(()))?);
    };
    let started = Instant::now();
    let draw = PhraseDraw::with_check(passphrase)?;
    flow::step();
    eprintln!();
    style::hint("Drawing a phrase that passes the check, about 65,536 draws.");
    let drawn = draw.draw_on_every_core(|| SystemRandom, &mut |_| Ok(()))?;
    choice::record(
        "Drawn",
        &format!("in {} s", started.elapsed().as_secs().max(1)),
    );
    Ok(drawn)
}

/// Shows the new phrase on a private screen until Enter or Escape clears it.
fn show_new_phrase(input: &Input, phrase: &str, passphrase: &str) -> Result<(), Failure> {
    let screen = terminal::PrivateScreen::enter_to_show(input);
    if !screen.shows_privately() {
        return Err(Failure::internal(
            "No private screen to show the new phrase on.",
        ));
    }
    if screen.is_active() {
        style::title(Operation::New.title());
    }
    eprintln!();
    eprintln!("{}", paint(HEADING, "New seed phrase, 24 words"));
    terminal::print_phrase(phrase, Wallet::NewPassphrase(passphrase), input);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    Ok(())
}
