//! `mhfe new`: a new 24-word wallet and its container in one go. The phrase is drawn from the
//! operating system's generator. If the owner chooses, it is drawn until it passes a wallet check
//! with the wallet's BIP39 passphrase (a draft; `mhfe::wallet_check`), so that a recovery with the
//! passphrase recognises the right password. The owner always chooses; the check has costs, which
//! `?` and the README state.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use anstream::eprintln;
use bip39::{Language, Mnemonic};
use clap::Args;
use mhfe::memory::LockedPages;
use mhfe::wallet_check::{self, NEW_ENTROPY_BYTES};
use mhfe::Suite;
use zeroize::Zeroizing;

use crate::choice::{self, Answer, Help, Question};
use crate::encrypt;
use crate::exit::{Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::locked_text::LockedText;
use crate::plate_repair;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::strength;
use crate::style::{self, paint, ACCENT, GOOD, HEADING, MUTED, STRONG, WARNING};
use crate::terminal::{self, Input, Wallet};

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

pub fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; the new phrase is shown only on a private screen,
    // so the command does not start where there can be none (AUD-007-SEC001).
    let mut input = Input::new(false);
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
        let bits = strength::estimated_bits(&passphrase);
        eprintln!();
        if strength::is_weak(bits) {
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
    let phrase = draw_phrase(checked.then_some(&*passphrase))?;
    let _phrase_locked = LockedPages::of_string(&phrase);
    show_new_phrase(&input, &phrase, &passphrase)?;
    let check = if checked { ", with a check" } else { "" };
    choice::record("Phrase", &format!("24 words, new{check}"));

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
    style::fact("Format", paint(MUTED, new.suite.id()));
    // A passphrase belongs to the wallet, checked or not.
    let mut also: Vec<&str> = Vec::new();
    if !passphrase.is_empty() {
        also.push("the BIP39 passphrase");
    }
    also.extend(plate_repair::to_keep(repair_count));
    style::fact("Keep", encrypt::what_to_keep(work, 24, false, 24, &also));
    style::fact(
        "Next",
        format!(
            "rehearse with {} from the backup you wrote",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::NEW);
    Ok(SUCCESS)
}

/// Asks whether the new phrase gets a wallet check with the passphrase. Nothing is preselected:
/// each choice has its costs, which `?` shows.
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
    let chosen = choice::choose(
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
/// every processor core until one passes the wallet check with it, about 65,536 BIP39 seeds.
fn draw_phrase(passphrase: Option<&str>) -> Result<Zeroizing<String>, Failure> {
    let started = Instant::now();
    let entropy = match passphrase {
        None => {
            let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
            fill_random(&mut entropy[..])?;
            entropy
        }
        Some(passphrase) => {
            flow::step();
            eprintln!();
            style::hint("Drawing a phrase that passes the check, about 65,536 draws.");
            let entropy = draw_checked(passphrase)?;
            choice::record(
                "Drawn",
                &format!("in {} s", started.elapsed().as_secs().max(1)),
            );
            entropy
        }
    };
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy[..])
        .map_err(|error| Failure::internal(error.to_string()))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Draws entropies on every core until one passes the wallet check with `passphrase`. The first
/// found is taken; every passing entropy is equally likely to be it.
fn draw_checked(passphrase: &str) -> Result<Zeroizing<[u8; NEW_ENTROPY_BYTES]>, Failure> {
    let found = AtomicBool::new(false);
    let draws = AtomicU64::new(0);
    let result: Mutex<Option<Result<Zeroizing<[u8; NEW_ENTROPY_BYTES]>, Failure>>> =
        Mutex::new(None);
    let workers = thread::available_parallelism().map_or(1, |cores| cores.get());
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
                while !found.load(Ordering::Relaxed) {
                    draws.fetch_add(1, Ordering::Relaxed);
                    let passed = fill_random(&mut entropy[..]).and_then(|()| {
                        wallet_check::passes(&entropy[..], passphrase).map_err(Failure::from)
                    });
                    match passed {
                        Ok(false) => continue,
                        outcome => {
                            if !found.swap(true, Ordering::SeqCst) {
                                let mut slot = result
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                *slot = Some(outcome.map(|_| entropy.clone()));
                            }
                            return;
                        }
                    }
                }
            });
        }
    });
    result
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .unwrap_or_else(|| Err(Failure::internal("No phrase was drawn.")))
}

fn fill_random(bytes: &mut [u8]) -> Result<(), Failure> {
    getrandom::fill(bytes)
        .map_err(|error| Failure::internal(format!("The system random generator failed: {error}")))
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
