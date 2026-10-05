//! `mhfe rekey`: the same seed phrase in a new container, under a new password or new settings.
//! The old container is recovered and the phrase is confirmed before it is encrypted again (the
//! re-encryption guard, `Mhfe::recover_confirmed`): by its built-in check at the length the owner
//! states, by an address or the fingerprint of the wallet, or, if the owner chooses it, by the
//! owner comparing the phrase, shown on a private screen, with their backup. Encrypting under the
//! old password and comparing would prove nothing.

use anstream::eprintln;
use clap::Args;
use mhfe::{Confirmation, Password, Suite, WordCount};

use crate::check::WalletReference;
use crate::choice::{self, Answer, Question};
use crate::encrypt;
use crate::exit::{Failure, NO_MATCH, SUCCESS};
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, MUTED};
use crate::terminal::{self, Input, Progress};

#[derive(Args)]
pub struct Options {
    /// The settings of the old container
    #[command(flatten)]
    old: Settings,

    /// PIM of the new container, 0 to 1023 (default 0)
    #[arg(long = "new-pim", value_name = "N")]
    new_pim: Option<u32>,

    /// Memory level of the new container, 0 to 21 (default 0: 2 GiB)
    #[arg(long = "new-mem", value_name = "LEVEL")]
    new_memory_level: Option<u32>,

    /// Number of words of the seed phrase: 12, 15, 18, 21 or 24 (asked otherwise)
    #[arg(long, value_name = "N")]
    words: Option<usize>,
}

/// The lengths a seed phrase in a 24-word container may have.
const LENGTHS: [usize; 5] = [12, 15, 18, 21, 24];

/// The top of `mhfe rekey --help`.
pub fn about() -> String {
    style::command_about(&[
        "Change the password or settings of a container, never showing the phrase",
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
    let mut input = Input::new(false);
    let old_work = settings::choose(options.old, &mut input, Operation::Rekey)?;
    // Shown to everyone, so that it says nothing about this container (specification: a hidden
    // wallet behind an honest disclosure).
    style::warn(
        "Every wallet that another password opens on the old container will change; move its \
         funds first.",
        "",
    );
    style::more(readme::REKEY);
    eprintln!();

    let (container, suite) = terminal::read_container(&mut input, Operation::Rekey.title())?;
    let container_words = container.split(' ').count();
    let words = phrase_length(&mut input, options.words, suite, container_words)?;
    let password = terminal::read_password(&mut input, Operation::Rekey.title())?;
    // A recovery without a built-in check needs another confirmation. It is chosen, and a
    // reference typed, before the long computation, so the user can walk away while it runs.
    let has_check = suite == Suite::TwentyFourWords && words.get() < 24;
    let how = if has_check {
        How::BuiltInCheck
    } else {
        ask_how_to_confirm(&mut input)?
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
    let phrase = mhfe.recover_confirmed(
        &container,
        &password,
        words,
        confirmation,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
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
    let length_must_be_chosen = suite == Suite::TwentyFourWords
        && phrase.words < 24
        && encrypt::warn_if_detection_would_mislead(&phrase.phrase, phrase.words)?;
    let new_password = read_different_password(&mut input, &password, old_work == new_work)?;
    drop(password);

    let new = encrypt::seal(
        &input,
        Operation::Rekey,
        new_work,
        &phrase.phrase,
        suite,
        &new_password,
    )?;
    style::fact("Format", paint(MUTED, new.suite.id()));
    style::fact(
        "Keep",
        encrypt::what_to_keep(
            new_work,
            phrase.words,
            length_must_be_chosen,
            container_words,
            &[],
        ),
    );
    // Rekeying revokes nothing: the old plate and password open the wallet until destroyed.
    style::fact(
        "Next",
        format!(
            "rehearse the new plate with {}, then destroy the old one",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::REKEY);
    Ok(SUCCESS)
}

/// How a recovery is confirmed before it is encrypted again.
enum How {
    BuiltInCheck,
    Wallet(WalletReference),
    Owner,
}

/// For a recovery without a built-in check: a receiving address, the fingerprint, or the phrase
/// shown to the owner, who compares it with their backup.
fn ask_how_to_confirm(input: &mut Input) -> Result<How, Failure> {
    let answers = [
        Answer::new(
            "A receiving address (recommended)",
            "checks the wallet and its passphrase",
        ),
        Answer::new(
            "The master key fingerprint",
            "eight hex digits; quick, weaker",
        ),
        // Said before the phrase appears: a comparison from memory confirms little.
        Answer::new("Show me the phrase", "against a written record, not memory"),
    ];
    let question = Question::new(
        "How should the recovered seed phrase be confirmed?",
        "Confirm",
    );
    Ok(match input.choose(&question, &answers)? {
        0 => How::Wallet(WalletReference::read(input, false, Operation::Rekey)?),
        1 => How::Wallet(WalletReference::read(input, true, Operation::Rekey)?),
        _ => How::Owner,
    })
}

/// Shows the recovered phrase on a private screen and asks the owner whether it is theirs. Only a
/// yes goes on; the screen is cleared either way.
fn owner_confirms(input: &mut Input, phrase: &str) -> Result<(), Failure> {
    let screen = terminal::PrivateScreen::enter_to_show(input);
    if screen.is_active() {
        style::title(Operation::Rekey.title());
    }
    eprintln!();
    eprintln!("{}", paint(HEADING, "Recovered seed phrase"));
    terminal::print_phrase(phrase, input);
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
    let mine = input.choose(&question, &answers)? == 0;
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
/// phrase is taken at that length only.
fn phrase_length(
    input: &mut Input,
    given: Option<usize>,
    suite: Suite,
    container_words: usize,
) -> Result<WordCount, Failure> {
    if suite == Suite::SameLength {
        return Ok(WordCount::new(container_words)?);
    }
    if let Some(words) = given {
        return Ok(WordCount::new(words)?);
    }
    let answers = LENGTHS.map(|words| Answer::new(format!("{words} words"), ""));
    let question = Question::new("How many words does your seed phrase have?", "Phrase");
    let chosen = input.choose(&question, &answers)?;
    Ok(WordCount::new(LENGTHS[chosen])?)
}

/// The new password, typed twice. With the same settings it must differ from the old one: the
/// same password would give the same container again.
fn read_different_password(
    input: &mut Input,
    old: &Password,
    same_settings: bool,
) -> Result<Password, Failure> {
    loop {
        let new = encrypt::read_new_password(input, Operation::Rekey)?;
        // Normalized bytes, as the cipher takes them: "é" typed either way is one password.
        if !(same_settings && new.as_bytes() == old.as_bytes()) {
            return Ok(new);
        }
        style::retry("This is the old password, which gives the old container. Choose another.");
    }
}
