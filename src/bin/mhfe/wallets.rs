//! `mhfe wallets`: the hidden wallets that other passwords open on a 24-word container
//! (specification supplement: "A hidden wallet behind an honest disclosure"). Each password gives
//! its own 24-word wallet, `D_P(Y)`, which the container and the password give again at any time,
//! so nothing is written down and nothing records how many there are. The README advises running
//! `mhfe self-test --vectors` on the computer before a hidden wallet is funded; it is not repeated
//! here, as it takes minutes.

use anstream::eprintln;
use clap::Args;
use mhfe::{HiddenWallets, MhfeError, Password};

use crate::check;
use crate::choice::{Answer, Question};
use crate::container_repair::RepairOption;
use crate::encrypt;
use crate::exit::{Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING};
use crate::terminal::{self, Input, Progress, Wallet};

#[derive(Args)]
pub struct Options {
    /// The settings of the container
    #[command(flatten)]
    settings: Settings,

    #[command(flatten)]
    repair: RepairOption,
}

/// The top of `mhfe wallets --help`.
pub fn about() -> String {
    style::command_about(&[
        "Open hidden wallets with other passwords",
        "Every password other than the container's own opens another valid 24-word wallet on a \
         24-word container. This command shows the wallet of each password you type. Nothing is \
         created or stored: the container and a password give the same wallet at any time.",
    ])
}

/// The end of `mhfe wallets -h` and `--help`.
pub fn help() -> String {
    style::examples_with_note(
        &[
            ("mhfe wallets", "Open hidden wallets on a container"),
            ("mhfe wallets --pim 1", "On a container made with PIM 1"),
        ],
        "Fund a hidden wallet only from sources linked neither to you nor to the main wallet. A \
         new password or new settings for the container (mhfe rekey) changes every hidden wallet.",
    )
}

pub fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; a wallet is only ever shown on a private screen.
    let mut input = terminal::private_input(NO_PRIVATE_SCREEN)?;
    // Every step on a screen of its own, the summary at the end. The steps lie on the alternate
    // screen, which is what keeps the wallets private: without it the command does not go on.
    let flow = Flow::start(&input, Operation::Wallets.title());
    if !flow::is_active() {
        return Err(Failure::invalid_input(NO_PRIVATE_SCREEN));
    }
    let work = settings::choose(options.settings, &mut input, Operation::Wallets)?;
    style::warn(
        "Nothing is created or stored: the container and each password give the same wallet \
         every time.",
        "",
    );
    style::more(readme::WALLETS);

    // The wallets are opened one password at a time below, so a password that a search for
    // missing words asked for is not kept.
    let read = terminal::read_container(
        &mut input,
        Operation::Wallets.title(),
        options.repair.card(Operation::Wallets, work),
    )?;
    let container = read.facts;
    container.require_hidden_wallets()?;
    // A hidden wallet that passes the main wallet's check with its passphrase is refused too; the
    // question comes every time, so that it tells nothing about the main wallet.
    let passphrase = check::read_passphrase_of(&mut input, Operation::Wallets, "the main wallet")?;
    let mut wallets = HiddenWallets::new(container.words(), &passphrase)?;
    let mut mhfe = settings::reserve_memory(work)?;
    // Every wallet, its password, its progress and the question for another one leave nothing in
    // the summary: nothing on the main screen tells how many wallets were opened (AUD-007-SEC005).
    let off_the_record = flow::off_the_record();
    let mut number = 0;
    loop {
        let password = read_unused_password(&mut input, &wallets)?;
        let mut progress = Progress::start_as("Opening");
        let derived = wallets.open(&mut mhfe, password, &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        });
        progress.finish();
        let wallet = match derived {
            Ok(wallet) => wallet,
            Err(MhfeError::HiddenWalletPassesCheck) => {
                // Rule I29: the container's own password of a short phrase, or a rare chance.
                style::retry_next(
                    "This password opens a phrase that passes a check. Choose another.",
                );
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        number += 1;
        show_wallet(&input, number, wallet.phrase());
        if !another(&mut input)? {
            break;
        }
    }
    drop(off_the_record);
    flow.finish();
    style::fact_wrapped(
        "Next",
        &format!(
            "fund them only from sources not linked to you; {} changes them",
            paint(ACCENT, "mhfe rekey")
        ),
    );
    style::more(readme::WALLETS);
    Ok(SUCCESS)
}

/// A password typed twice on the private screen that this run has not used yet.
fn read_unused_password(input: &mut Input, wallets: &HiddenWallets) -> Result<Password, Failure> {
    loop {
        let password = encrypt::read_typed_password(input, Operation::Wallets)?;
        if !wallets.was_used(&password) {
            return Ok(password);
        }
        style::retry_next("This password has opened a wallet already. Choose another.");
    }
}

/// Why the command does not start: it shows wallets only on a private screen.
const NO_PRIVATE_SCREEN: &str = "mhfe wallets shows wallets only on a private screen: run it at a \
                                 terminal, with no output redirected.";

/// Shows a wallet below its progress, on the step's private screen.
fn show_wallet(input: &Input, number: usize, phrase: &str) {
    eprintln!();
    eprintln!("{}", paint(HEADING, format!("Wallet {number}, 24 words")));
    // The main wallet's passphrase, asked only to refuse wallets that pass its check, is not the
    // hidden wallet's: a hidden wallet should have a passphrase of its own, or none.
    terminal::print_phrase(phrase, Wallet::NoPassphrase, input);
    style::hint("No need to write it down: the container and this password give it again.");
}

/// Whether to open another wallet, asked below the wallet shown.
fn another(input: &mut Input) -> Result<bool, Failure> {
    let question = Question::new("Open another wallet?", "Another");
    let answers = [
        Answer::new("Yes, with another password", ""),
        Answer::new("No, done", ""),
    ];
    Ok(input.choose_here(&question, &answers)? == 0)
}
