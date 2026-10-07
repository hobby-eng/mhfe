//! `mhfe rekey`: the same seed phrase in a new container, under a new password or new settings.
//! The old container is recovered and the phrase is confirmed before it is encrypted again (the
//! re-encryption guard, `Mhfe::recover_confirmed`): by its built-in check at the length the owner
//! states, by an address or the fingerprint of the wallet, or, if the owner chooses it, by the
//! owner comparing the phrase, shown on a private screen, with their backup. Encrypting under the
//! old password and comparing would prove nothing.

use anstream::eprintln;
use clap::Args;
use mhfe::operation::Stage;
use mhfe::rekey::Rekey;
use mhfe::{
    Confirmation, ConfirmationNeeded, ContainerFacts, MhfeError, Password, Suite, WordCount,
    WorkFactor, ENCRYPTION_ROUNDS, ROUNDS,
};

use crate::check::WalletReference;
use crate::choice::{self, Answer, Question};
use crate::encrypt;
use crate::exit::{Failure, NO_MATCH, SUCCESS};
use crate::flow::Flow;
use crate::plate_repair;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, MUTED};
use crate::terminal::{self, Input, Progress, Wallet};

#[derive(Args)]
pub struct Options {
    /// The settings of the old container
    #[command(flatten)]
    old: Settings,

    /// PIM of the new container, 0 to 1023 (default 0)
    #[arg(long = "new-pim", value_name = "N")]
    new_pim: Option<u32>,

    /// New memory level, 0 to 21 (default 0: 2 GiB)
    #[arg(long = "new-mem", value_name = "LEVEL", long_help = new_memory_help())]
    new_memory_level: Option<u32>,

    /// Words of the seed phrase: 12, 15, 18, 21 or 24
    #[arg(long, value_name = "N", long_help = words_help())]
    words: Option<usize>,
}

fn new_memory_help() -> String {
    style::option_help(&[
        "Memory level of the new container, 0 to 21 (default 0: 2 GiB).",
        "Without --new-pim and --new-mem the new settings are asked at a terminal.",
    ])
}

fn words_help() -> String {
    style::option_help(&[
        "Words of the seed phrase: 12, 15, 18, 21 or 24.",
        "Asked when not given, unless the container tells it: a same-length container has the \
         length of its phrase.",
    ])
}

/// The top of `mhfe rekey --help`.
pub fn about() -> String {
    style::command_about(&[
        "Change the password or settings of a container",
        "Recovers the seed phrase from the old container, confirms it, by its built-in check, by \
         a receiving address or the master key fingerprint of the wallet, or by showing it to you \
         to compare with your backup, and encrypts it under a new password or new settings. The \
         old container keeps opening the wallet with the old password until every copy of it is \
         destroyed.",
    ])
}

/// The end of `mhfe rekey -h` and `--help`.
pub fn help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe rekey", "A new password, with the questions as lists"),
            (
                "mhfe rekey --new-pim 1",
                "The same phrase with twice the passes",
            ),
            (
                "mhfe rekey --pim 1 --words 24",
                "From a container made with PIM 1 for a 24-word phrase",
            ),
        ],
    );
    let note = style::help_note(
        "Every wallet that another password opens on the old container changes: move its funds \
         first. Destroy the old plate only once the new one passes mhfe check.",
    );
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; no script reads a phrase back and forth.
    let mut input = Input::terminal_only();
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Rekey.title());
    let old_work = settings::choose(options.old, &mut input, Operation::Rekey)?;
    // Shown to everyone, so that it says nothing about this container (specification: a hidden
    // wallet behind an honest disclosure).
    style::warn(
        "Every wallet that another password opens on the old container will change; move its \
         funds first.",
        "",
    );
    style::more(readme::REKEY);
    confirm_other_wallets_are_safe(&mut input)?;

    let container = terminal::read_container(&mut input, Operation::Rekey.title())?;
    let words = phrase_length(&mut input, options.words, &container)?;
    let password = terminal::read_password(&mut input, Operation::Rekey)?;
    // The rekey's own rules (length, confirmation, a new password that changes the container)
    // are the library's; the owner answered yes about the other wallets above.
    let rekey = Rekey::new(
        container.words(),
        Some(words.get()),
        password,
        old_work,
        true,
    )?;
    // A recovery without a built-in check needs another confirmation. It is chosen, and a
    // reference typed, before the long computation, so the user can walk away while it runs.
    let kind = match rekey.confirmation_needed() {
        ConfirmationNeeded::BuiltInCheck => Kind::BuiltInCheck,
        ConfirmationNeeded::WalletOrOwner => ask_how_to_confirm(&mut input)?,
    };
    // The new container's keep list names the wallet's BIP39 passphrase, so the question is asked
    // once, before any reference: a reference without a passphrase would match the phrase's
    // wallet without one and say nothing about funds under one. Only a wallet with one is then
    // asked for it.
    let wallet_passphrase = encrypt::ask_wallet_passphrase(&mut input, readme::REKEY)?;
    let how = match kind {
        Kind::BuiltInCheck => How::BuiltInCheck,
        Kind::Owner => How::Owner,
        Kind::Address | Kind::Fingerprint => How::Wallet(WalletReference::read_of_wallet(
            &mut input,
            kind == Kind::Fingerprint,
            Operation::Rekey,
            wallet_passphrase,
        )?),
    };

    let mut mhfe = settings::reserve_memory(old_work)?;
    let mut progress = Progress::start();
    let reference = match &how {
        How::Wallet(wallet) => Some(wallet.reference()),
        How::BuiltInCheck | How::Owner => None,
    };
    let confirmation = match (&how, &reference) {
        (How::Wallet(_), Some(reference)) => Confirmation::Wallet(reference),
        (How::Owner, _) => Confirmation::Owner,
        _ => Confirmation::BuiltInCheck,
    };
    // The terminal shows the twelve rounds of the recovery as before; a comparison with the wallet
    // follows them without a round of its own.
    let recovered = rekey.recover(
        &mut mhfe,
        confirmation,
        Some(wallet_passphrase),
        &mut |stage, round, _| {
            if stage == Stage::Recover {
                progress.round_starts(round, ROUNDS);
            }
            Ok(())
        },
    )?;
    let phrase = recovered.phrase();
    progress.finish();
    // The old memory is released before the new settings reserve theirs.
    drop(mhfe);
    let confirmed = match how {
        How::BuiltInCheck => "passed its built-in check",
        How::Wallet(_) => "matches the wallet",
        How::Owner => {
            owner_confirms(&mut input, &phrase.phrase)?;
            "confirmed by you"
        }
    };
    choice::record("Recovered", &format!("{} words, {confirmed}", phrase.words));

    let new_settings = Settings {
        pim: options.new_pim,
        memory_level: options.new_memory_level,
    };
    let new_work = settings::choose(new_settings, &mut input, Operation::RekeyNew)?;
    // A 24-word original too can, by rare chance, read as a shorter phrase after recovery.
    if container.suite() == Suite::TwentyFourWords {
        encrypt::warn_if_detection_would_mislead(&phrase.phrase, phrase.words)?;
    }
    let repair_count = plate_repair::ask_when_creating(&mut input)?;
    let new_password = read_different_password(&mut input, &rekey, new_work)?;

    // Sealed by the library's rekey, which the browser package and the checks at start run too:
    // a container of the old one's kind, and new settings or a new password that change it
    // (AUD-010). The terminal shows it as any encryption.
    let mut mhfe = settings::reserve_memory(new_work)?;
    let new = encrypt::show_sealing(&input, Operation::Rekey, |progress, on_unverified| {
        rekey.seal(
            &mut mhfe,
            &recovered,
            &new_password,
            repair_count,
            // The rekey numbers these rounds 13 to 36 of its 36; the bar shows the encryption's
            // own 1 to 24, as for any encryption.
            &mut |stage, round, _| progress(stage, round - ROUNDS, ENCRYPTION_ROUNDS),
            on_unverified,
        )
    })?;
    flow.finish();
    style::fact("Format", paint(MUTED, new.suite().id()));
    style::fact_wrapped(
        "Keep",
        &encrypt::what_to_keep(&new.keep(new_work, recovered.wallet_has_passphrase())),
    );
    // Rekeying revokes nothing: the old plate and password open the wallet until destroyed.
    style::fact("Old plate", "still opens the wallet with the old password");
    style::fact_wrapped(
        "Next",
        &format!(
            "rehearse the new plate with {}, then destroy the old one",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::REKEY);
    Ok(SUCCESS)
}

/// The confirmation the specification asks of every user before a container is replaced
/// ("Preserving derived wallets"): the same question for everyone, which never asks whether such
/// wallets exist or for their passwords. Only a yes goes on (AUD-007-FUN002).
fn confirm_other_wallets_are_safe(input: &mut Input) -> Result<(), Failure> {
    let question = Question::new(
        "Are the funds of any such wallet moved, or backed up another way?",
        "Others",
    );
    let answers = [
        Answer::new("Yes, go on", "moved, or a verified backup of their own"),
        Answer::new("No, stop", "nothing is encrypted again"),
    ];
    if input.choose(&question, &answers)? == 0 {
        return Ok(());
    }
    // The reason comes first: a cancellation itself is reported only as "Cancelled".
    style::warn(
        "Move the funds of any such wallet first, then run mhfe rekey again.",
        "",
    );
    Err(MhfeError::Cancelled.into())
}

/// How a recovery is confirmed before it is encrypted again.
enum How {
    BuiltInCheck,
    Wallet(WalletReference),
    Owner,
}

/// The kind of confirmation chosen, before its reference is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    BuiltInCheck,
    Address,
    Fingerprint,
    Owner,
}

/// For a recovery without a built-in check: a receiving address, the fingerprint, or the phrase
/// shown to the owner, who compares it with their backup.
fn ask_how_to_confirm(input: &mut Input) -> Result<Kind, Failure> {
    let mut answers = vec![
        Answer::new(
            "A receiving address (recommended)",
            "checks the wallet and its passphrase",
        ),
        Answer::new(
            "The master key fingerprint",
            "eight hex digits; quick, weaker",
        ),
    ];
    // The phrase is shown only on a private screen, so it is offered only where there can be one
    // (AUD-007-SEC001). Said before it appears: a comparison from memory confirms little.
    if terminal::can_show_privately(input) {
        answers.push(Answer::new(
            "Show me the phrase",
            "against a written record, not memory",
        ));
    }
    let question = Question::new(
        "How should the recovered seed phrase be confirmed?",
        "Confirm",
    );
    Ok(match input.choose(&question, &answers)? {
        0 => Kind::Address,
        1 => Kind::Fingerprint,
        _ => Kind::Owner,
    })
}

/// Shows the recovered phrase on a private screen and asks the owner whether it is theirs. Only a
/// yes goes on; the screen is cleared either way.
fn owner_confirms(input: &mut Input, phrase: &str) -> Result<(), Failure> {
    let screen = terminal::PrivateScreen::enter_to_show(input);
    if !screen.shows_privately() {
        return Err(Failure::internal(
            "No private screen to show the phrase on.",
        ));
    }
    if screen.is_active() {
        style::title(Operation::Rekey.title());
    }
    eprintln!();
    eprintln!("{}", paint(HEADING, "Recovered seed phrase"));
    terminal::print_phrase(phrase, Wallet::NoPassphrase, input);
    let question = Question {
        text: "Does it match your written record, word for word?",
        explanation: &[],
        more: None,
        record: None,
    };
    let answers = [
        Answer::new("Yes, every word", ""),
        Answer::new("No, stop", "nothing is encrypted again"),
    ];
    // Asked below the phrase, which stays on the screen until the answer.
    let mine = input.choose_here(&question, &answers)? == 0;
    drop(screen);
    if mine {
        Ok(())
    } else {
        Err(Failure {
            message: "The recovered phrase is not yours: the password, PIM, memory level, word \
                      count or container is wrong. Nothing was encrypted again."
                .to_owned(),
            exit_code: NO_MATCH,
        })
    }
}

/// The length of the seed phrase, which the owner states: a same-length container has its own,
/// and for a 24-word container it comes from --words or is asked. The built-in check of a short
/// phrase is taken at that length only. A length given with --words is checked before the
/// password is asked: one that no phrase has, or one that contradicts a same-length container, is
/// refused (AUD-008-FUN002).
fn phrase_length(
    input: &mut Input,
    given: Option<usize>,
    container: &ContainerFacts,
) -> Result<WordCount, Failure> {
    if let Some(given) = given {
        let words = WordCount::new(given)?;
        // Only its refusal matters here, of a length that a same-length container cannot have:
        // the confirmation itself is chosen once the password is typed.
        container.confirmation_needed(words)?;
        return Ok(words);
    }
    let lengths = container.phrase_lengths();
    if let [only] = lengths {
        return Ok(WordCount::new(*only)?);
    }
    let answers: Vec<Answer> = lengths
        .iter()
        .map(|words| Answer::new(format!("{words} words"), ""))
        .collect();
    let question = Question::new("How many words does your seed phrase have?", "Phrase");
    let chosen = input.choose(&question, &answers)?;
    Ok(WordCount::new(lengths[chosen])?)
}

/// The new password, typed twice. With the same settings it must differ from the old one: the
/// same password would give the same container again.
fn read_different_password(
    input: &mut Input,
    rekey: &Rekey,
    new_work: WorkFactor,
) -> Result<Password, Failure> {
    loop {
        let new = encrypt::read_new_password(input, Operation::Rekey)?;
        match rekey.check_new(&new, new_work) {
            Ok(()) => return Ok(new),
            Err(MhfeError::NewPasswordSameAsOld) => {
                // Said where the new password is typed again.
                style::retry_next(
                    "This is the old password, which gives the old container. Choose another.",
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhfe::WORD_COUNTS;

    /// AUD-008-FUN002: a length given for a same-length container must be its own, and a length
    /// that no phrase has is refused, both before the password is asked.
    #[test]
    fn a_length_given_must_fit_the_container() {
        let mut input = Input::terminal_only();
        // A container of `words` words: a valid phrase of all-zero entropy, as in BIP39's vectors,
        // with 4 bytes of entropy for every 3 words.
        let container = |words: usize| {
            let phrase = mhfe::phrase_from_entropy(&vec![0; words / 3 * 4]).unwrap();
            ContainerFacts::read(&phrase).unwrap()
        };
        let length = |input: &mut Input, given, words| {
            phrase_length(input, given, &container(words)).map(WordCount::get)
        };
        for words in [12, 15, 18, 21] {
            assert_eq!(length(&mut input, None, words).ok(), Some(words));
            assert_eq!(length(&mut input, Some(words), words).ok(), Some(words));
            for other in WORD_COUNTS.into_iter().filter(|&other| other != words) {
                let refused = length(&mut input, Some(other), words).unwrap_err();
                assert!(
                    refused.message.contains("keeps the length"),
                    "{}",
                    refused.message
                );
            }
            for impossible in [0, 13, 25] {
                assert!(length(&mut input, Some(impossible), words).is_err());
            }
        }
        for words in WORD_COUNTS {
            assert_eq!(length(&mut input, Some(words), 24).ok(), Some(words));
        }
        assert!(length(&mut input, Some(13), 24).is_err());
    }
}
