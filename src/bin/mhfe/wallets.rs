//! `mhfe wallets`: the hidden wallets that other passwords open on a 24-word container
//! (specification supplement: "A hidden wallet behind an honest disclosure"). Each password gives
//! its own 24-word wallet, `D_P(Y)`, which the container and the password give again at any time,
//! so nothing is written down and nothing records how many there are. The published vectors are
//! checked first, as the specification asks before a derived wallet is shown.

use anstream::eprintln;
use clap::Args;
use mhfe::{MhfeError, Password, Suite};
use zeroize::Zeroizing;

use crate::check;
use crate::choice::{self, Answer, Question};
use crate::encrypt;
use crate::exit::{Failure, SUCCESS};
use crate::readme;
use crate::self_test;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING};
use crate::terminal::{self, Input, Progress};

#[derive(Args)]
pub struct Options {
    /// The settings of the container
    #[command(flatten)]
    settings: Settings,
}

/// The top of `mhfe wallets --help`.
pub fn about() -> String {
    style::command_about(&[
        "Open hidden wallets on a container with other passwords",
        "Every password other than the container's own opens another valid 24-word wallet on a \
         24-word container. This command shows the wallet of each password you type, after it has \
         checked itself against the published vectors. Nothing records the passwords or how many \
         there are; the container and a password give its wallet again at any time.",
    ])
}

/// The end of `mhfe wallets -h` and `--help`.
pub fn help() -> String {
    style::help_note(
        "Fund a hidden wallet only from sources linked neither to you nor to the main wallet. A \
         new password or new settings for the container (mhfe rekey) changes every hidden wallet.",
    )
}

pub fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; a wallet is only ever shown on a private screen.
    let mut input = Input::new(false);
    let work = settings::choose(options.settings, &mut input, Operation::Wallets)?;
    self_test::require_pass()?;
    eprintln!();
    style::warn(
        "Each other password opens its own 24-word wallet; nothing records them.",
        "",
    );
    style::more(readme::WALLETS);
    eprintln!();

    let (container, suite) = terminal::read_container(&mut input, Operation::Wallets.title())?;
    if suite != Suite::TwentyFourWords {
        return Err(Failure::invalid_input(
            "Hidden wallets are opened on a 24-word container only, for now.",
        ));
    }
    // A hidden wallet that passes the main wallet's check with its passphrase is refused too; the
    // question comes every time, so that it tells nothing about the main wallet.
    let (passphrase, _passphrase_locked) =
        check::read_passphrase_of(&mut input, Operation::Wallets, "the main wallet")?;
    let mut mhfe = settings::reserve_memory(work)?;
    // The passwords of this run, as normalized bytes, so that none is typed twice.
    let mut used: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    loop {
        let number = used.len() + 1;
        let password = read_unused_password(&mut input, &used)?;
        let mut progress = Progress::start();
        let derived =
            mhfe.derive_wallet(&container, &password, &passphrase, &mut |round, rounds| {
                progress.round_starts(round, rounds);
                Ok(())
            });
        progress.finish();
        let wallet = match derived {
            Ok(wallet) => wallet,
            Err(MhfeError::HiddenWalletPassesCheck) => {
                // Rule I29: the container's own password of a short phrase, or a rare chance.
                style::retry("This password opens a phrase that passes a check. Choose another.");
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        used.push(Zeroizing::new(password.as_bytes().to_vec()));
        show_wallet(&input, number, &wallet.phrase)?;
        choice::record(&format!("Wallet {number}"), "24 words, shown and cleared");
        if !another(&mut input)? {
            break;
        }
    }
    style::fact(
        "Next",
        format!(
            "fund them only from sources not linked to you; {} changes them",
            paint(ACCENT, "mhfe rekey")
        ),
    );
    style::more(readme::WALLETS);
    Ok(SUCCESS)
}

/// A password typed twice on the private screen that this run has not used yet.
fn read_unused_password(
    input: &mut Input,
    used: &[Zeroizing<Vec<u8>>],
) -> Result<Password, Failure> {
    loop {
        let password = encrypt::read_new_password(input, Operation::Wallets)?;
        if !used
            .iter()
            .any(|bytes| bytes.as_slice() == password.as_bytes())
        {
            return Ok(password);
        }
        style::retry("This password has opened a wallet already. Choose another.");
    }
}

/// Shows a wallet on a private screen until Enter or Escape clears it.
fn show_wallet(input: &Input, number: usize, phrase: &str) -> Result<(), Failure> {
    let screen = terminal::PrivateScreen::enter_to_show(input);
    if screen.is_active() {
        style::title(Operation::Wallets.title());
    }
    eprintln!();
    eprintln!("{}", paint(HEADING, format!("Wallet {number}, 24 words")));
    terminal::print_phrase(phrase, input);
    if screen.is_active() {
        terminal::wait_to_leave_saying(
            "No need to write it down: the container and this password give it again. Enter or \
             Escape clears this screen.",
        )?;
    }
    Ok(())
}

/// Whether to open another wallet.
fn another(input: &mut Input) -> Result<bool, Failure> {
    let question = Question::new("Open another wallet?", "Another");
    let answers = [
        Answer::new("Yes, with another password", ""),
        Answer::new("No, done", ""),
    ];
    Ok(input.choose(&question, &answers)? == 0)
}
