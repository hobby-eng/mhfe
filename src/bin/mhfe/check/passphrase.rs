//! The BIP39 passphrases a command asks for, on a private screen, and the questions whether a
//! wallet has one.

use anstream::eprintln;
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::wallet_check::{self, WALLET_CHECK_BITS};

use crate::choice::{self, Answer, Question};
use crate::exit::Failure;
use crate::settings::Operation;
use crate::style;
use crate::terminal::{Input, PrivateScreen};

/// The BIP39 passphrase for the phrase + passphrase check, which the library offers only with one
/// (`wallet_check::require_passphrase`, the rule the browser package follows too): an empty one
/// is refused and asked again.
pub fn read_check_passphrase(
    input: &mut Input,
    operation: Operation,
) -> Result<LockedText, Failure> {
    let passphrase = read_passphrase_until(input, operation, "the wallet", |passphrase| {
        wallet_check::require_passphrase(passphrase)
            .map_err(|_| "Type the passphrase: the phrase + passphrase check needs one.".to_owned())
    })?;
    choice::record("Passphrase", "typed");
    Ok(passphrase)
}

/// The private screen of `operation` on which the BIP39 passphrase of `whose` is typed, with the
/// reminder that it is not the container password.
pub fn passphrase_screen(input: &Input, operation: Operation, whose: &str) -> PrivateScreen {
    let screen = PrivateScreen::enter(input, operation.title());
    if screen.is_active() {
        eprintln!();
        style::hint(&format!(
            "Part of {whose}, as a 25th word; it is NOT the container password."
        ));
    }
    screen
}

/// Reads a BIP39 passphrase on the private screen of `operation`, again until `accept` takes it;
/// `accept` gives the message for one it refuses.
fn read_passphrase_until(
    input: &mut Input,
    operation: Operation,
    whose: &str,
    accept: impl Fn(&str) -> Result<(), String>,
) -> Result<LockedText, Failure> {
    let _screen = passphrase_screen(input, operation, whose);
    loop {
        let passphrase = input.secret(&format!("BIP39 passphrase of {whose}"))?;
        let message = match accept(&passphrase) {
            Ok(()) => return Ok(passphrase),
            Err(message) => message,
        };
        if !input.can_ask_again() {
            return Err(Failure::invalid_input(message));
        }
        style::retry(message);
    }
}

/// The BIP39 passphrase used with `whose`, such as "the container phrase", which the person has
/// said there is: it may not be empty.
pub fn read_passphrase_named(
    input: &mut Input,
    operation: Operation,
    whose: &str,
) -> Result<LockedText, Failure> {
    read_passphrase_until(input, operation, whose, |passphrase| {
        (!passphrase.is_empty())
            .then_some(())
            .ok_or_else(|| format!("Type the passphrase: you said {whose} has one."))
    })
}

/// `--passphrase-used yes|no`: the answer to whether a BIP39 passphrase is used, as an option of
/// the commands that ask it (the owner's rule that every answer that is not a secret is an option
/// too). The passphrase itself is never an option: it is typed, or a script's line.
#[derive(Args)]
pub struct PassphraseUsedOption {
    /// Whether a BIP39 passphrase is used: yes or no
    #[arg(long = "passphrase-used", value_name = "yes|no", value_parser = choice::parse_yes_no)]
    used: Option<bool>,
}

impl PassphraseUsedOption {
    /// The answer given, or `None` to ask at a terminal.
    pub fn given(&self) -> Option<bool> {
        self.used
    }
}

/// Whose BIP39 passphrase a question is about, named in it and in its field.
pub const CONTAINER_PHRASE: &str = "the container phrase";
pub const ORIGINAL_SEED_PHRASE: &str = "the original seed phrase";

/// Asks whether a BIP39 passphrase is used with `whose` and, if so, reads it; empty for none.
pub fn ask_passphrase(
    input: &mut Input,
    operation: Operation,
    whose: &str,
) -> Result<LockedText, Failure> {
    ask_passphrase_explained(input, operation, whose, &[], None, None)
}

/// Why a recovery asks for the passphrase of a 24-word reading: the 16-bit source check, which
/// every recovery evaluates (the specification's recovery rules). Longer than the usual link, as
/// the owner asked (2026-10-09): nothing else on the screen says why a tool that only decrypts
/// wants a passphrase.
pub fn source_check_why() -> [String; 8] {
    [
        format!("A new 24-word phrase can carry a {WALLET_CHECK_BITS}-bit check tied to its BIP39"),
        "passphrase, as mhfe new offers. The container does not show whether".to_owned(),
        "this one does, so MHFE tests every 24-word reading with the passphrase".to_owned(),
        "you give here, or with none.".to_owned(),
        String::new(),
        "A pass makes a right password very likely. A failure means something".to_owned(),
        "only if the wallet was made with the check. The passphrase is used for".to_owned(),
        "this test alone and is not kept.".to_owned(),
    ]
}

/// [`ask_passphrase`] with an explanation under the question and a link to `more`.
pub fn ask_passphrase_explained(
    input: &mut Input,
    operation: Operation,
    whose: &str,
    explanation: &[&str],
    more: Option<&str>,
    given: Option<bool>,
) -> Result<LockedText, Failure> {
    match given {
        Some(false) => return Ok(LockedText::copy_of("")),
        Some(true) => return read_passphrase_named(input, operation, whose),
        None => {}
    }
    let text = format!("Is a BIP39 passphrase used with {whose}?");
    let answers = passphrase_answers(whose);
    let question = Question {
        text: &text,
        explanation,
        more,
        record: None,
    };
    // A step of its own, headed by what comes before it, before any work starts.
    if input.choose(&question, &answers)? == 0 {
        return Ok(LockedText::copy_of(""));
    }
    read_passphrase_named(input, operation, whose)
}

fn passphrase_answers(whose: &str) -> [Answer; 2] {
    [
        Answer::new("No", format!("{whose} alone")),
        Answer::new("Yes", "type it next"),
    ]
}

/// The BIP39 passphrase of the original seed phrase for its own checks: a script gives a line,
/// empty for none; at a terminal `given` (`--passphrase-used`) answers whether one is used, or
/// the person is asked.
pub(super) fn read_own_checks_passphrase(
    input: &mut Input,
    operation: Operation,
    given: Option<bool>,
) -> Result<LockedText, Failure> {
    if input.is_script() {
        return read_passphrase_of(input, operation, ORIGINAL_SEED_PHRASE);
    }
    ask_passphrase_explained(input, operation, ORIGINAL_SEED_PHRASE, &[], None, given)
}

/// The BIP39 passphrase of a wallet named `wallet`, such as "the main wallet", or none.
pub fn read_passphrase_of(
    input: &mut Input,
    operation: Operation,
    wallet: &str,
) -> Result<LockedText, Failure> {
    let screen = passphrase_screen(input, operation, wallet);
    let passphrase = input.secret(&format!(
        "BIP39 passphrase of {wallet}, or Enter if it has none"
    ))?;
    drop(screen);
    let what = if passphrase.is_empty() {
        "none"
    } else {
        "typed"
    };
    choice::record("Passphrase", what);
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_check_explanation_fits_a_list() {
        let why = source_check_why();
        assert!(crate::choice::fits(&why.each_ref().map(String::as_str)));
    }
}
