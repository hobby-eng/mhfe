//! A new container password made by MHFE where one is set: `mhfe encrypt`, `mhfe new` and the new
//! password of `mhfe rekey`. The person types their own, as before, or takes one of the kinds that
//! `mhfe password` makes, from the library's [`PasswordRecipe`]; a password made is shown once on a
//! private screen and then typed back from what was written down, which shows that the copy is
//! right before anything is encrypted with it.

use anstream::eprintln;
use clap::{Args, ValueEnum};
use mhfe::memory::LockedText;
use mhfe::new_password::{
    character_bits, word_bits, PasswordRecipe, DEFAULT_CHARACTERS, DEFAULT_WORDS,
};
use mhfe::{MhfeError, Password};

use crate::choice::{self, Answer, Question};
use crate::exit::Failure;
use crate::readme;
use crate::settings::Operation;
use crate::style::{self, STRONG};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input, PrivateScreen};

/// How a new container password comes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PasswordKind {
    /// Typed by the person, twice.
    Own,
    /// Five random words of the EFF list, as `mhfe password` makes them.
    Words,
    /// Five random words and their check word (MHFE-PASSWORD-CHECK-1).
    CheckWord,
    /// Sixteen random characters.
    Chars,
}

impl PasswordKind {
    /// Every kind, in the order a question lists them: the person's own first.
    const ALL: [Self; 4] = [Self::Own, Self::Words, Self::CheckWord, Self::Chars];
    /// The kinds MHFE makes, in the same order.
    pub const MADE: [Self; 3] = [Self::Words, Self::CheckWord, Self::Chars];

    /// The answer that chooses this kind, with what it gives.
    pub fn answer(self) -> Answer {
        match self {
            Self::Own => Answer::new("Type my own", "typed twice"),
            Self::Words => Answer::new(
                "Five dice words",
                format!("about {} bits, easy to type", word_bits(DEFAULT_WORDS)),
            ),
            Self::CheckWord => Answer::new(
                "Five words and a check word",
                "one mistyped word is repaired",
            ),
            Self::Chars => Answer::new(
                "Sixteen random characters",
                format!("about {} bits", character_bits(DEFAULT_CHARACTERS)),
            ),
        }
    }

    /// The option of `mhfe password` that makes this kind: none for five dice words, its default,
    /// and `--chars` alone for sixteen characters.
    pub fn password_option(self) -> Option<&'static str> {
        match self {
            Self::Own | Self::Words => None,
            Self::CheckWord => Some("--check-word"),
            Self::Chars => Some("--chars"),
        }
    }
}

/// `--new-password` of the commands that set a container password.
#[derive(Args)]
pub struct NewPasswordOption {
    /// New password: own, words, check-word or chars
    #[arg(
        long = "new-password",
        value_name = "KIND",
        hide_possible_values = true,
        long_help = option_help()
    )]
    kind: Option<PasswordKind>,
}

impl NewPasswordOption {
    /// The kind given, or `None` to ask at a terminal.
    pub fn kind(&self) -> Option<PasswordKind> {
        self.kind
    }

    /// Refuses at the start, before anything secret is asked or computed, a kind this run cannot
    /// take ([`refuse_kind`]).
    pub fn check(&self, input: &Input) -> Result<(), Failure> {
        refuse_kind(input, self.kind)
    }
}

/// Refuses a password made by MHFE where it cannot be shown as it must be: a script types its own,
/// and a made password is shown only on a private screen, as a new phrase is, never on the main
/// screen of a terminal that cannot switch (AUD-015-SEC003).
pub fn refuse_kind(input: &Input, kind: Option<PasswordKind>) -> Result<(), Failure> {
    match kind {
        None | Some(PasswordKind::Own) => Ok(()),
        Some(_) if input.is_script() => Err(Failure::invalid_input(
            "A script types its own password: --new-password own, or none.",
        )),
        Some(_) if !terminal::can_show_privately(input) => Err(Failure::invalid_input(
            "A password made by MHFE is shown only on a private screen, which this terminal \
             cannot show: run at a terminal with no output redirected, or type your own with \
             --new-password own.",
        )),
        Some(_) => Ok(()),
    }
}

fn option_help() -> String {
    style::option_help(&[
        "How the new password comes: own, words, check-word or chars.",
        &format!(
            "own: typed twice, as a script always does. words: five dice words, about {} bits. \
             check-word: five words and a check word that repairs one mistyped word. chars: \
             sixteen random characters, about {} bits. A password made is shown once, to be \
             written down and typed back. Asked at a terminal that can show a list when not \
             given; elsewhere the password is typed.",
            word_bits(DEFAULT_WORDS),
            character_bits(DEFAULT_CHARACTERS)
        ),
    ])
}

/// Said under a password made with a check word, wherever one is shown.
pub const CHECK_WORD_NOTE: &str =
    "The last word is the check word; it adds no strength and is just as secret.";
/// Said under every password made, wherever it is shown.
pub const SHOWN_ONCE_NOTE: &str =
    "Shown only once and not stored: write it down, apart from the container.";

/// Asks how the new password comes, at a terminal; the person's own is the first answer.
pub fn ask_kind(input: &mut Input, operation: Operation) -> Result<PasswordKind, Failure> {
    let text = match operation {
        Operation::Rekey | Operation::RekeyNew => "The new container password: yours, or made?",
        _ => "The container password: type your own, or let MHFE make one?",
    };
    let answers = PasswordKind::ALL.map(PasswordKind::answer);
    let question = Question {
        text,
        explanation: &[],
        more: Some(readme::PASSWORD),
        record: None,
    };
    let chosen = input.choose(&question, &answers)?;
    Ok(PasswordKind::ALL[chosen])
}

/// Makes a password of `kind`, shows it once on a private screen and asks for it back as written
/// down, again until the copy is right; Enter alone there shows it again.
pub fn read_made(
    input: &mut Input,
    operation: Operation,
    kind: PasswordKind,
) -> Result<Password, Failure> {
    let recipe = match kind {
        PasswordKind::Words => PasswordRecipe::words(DEFAULT_WORDS)?,
        PasswordKind::CheckWord => PasswordRecipe::check_word(),
        PasswordKind::Chars => PasswordRecipe::characters(DEFAULT_CHARACTERS)?,
        PasswordKind::Own => {
            return Err(MhfeError::InvalidRequest("own passwords are typed".to_owned()).into())
        }
    };
    let made = recipe.make(&mut SystemRandom)?;
    let strength = format!("{}.", recipe.summary());
    loop {
        show(
            input,
            operation,
            made.text(),
            &strength,
            recipe.has_check_word(),
        )?;
        let screen = PrivateScreen::enter(input, operation.title());
        eprintln!();
        style::hint(TYPE_BACK_HINT);
        let typed: LockedText = input.password("Password as you wrote it down")?;
        drop(screen);
        if *typed == *made.text() {
            break;
        }
        if !typed.is_empty() {
            style::retry_next(NOT_AS_SHOWN);
        }
    }
    let password = Password::new(made.text())?;
    choice::record("Password", &format!("made by MHFE: {strength}"));
    Ok(password)
}

/// Said where a password made is typed back.
const TYPE_BACK_HINT: &str = "Type it from what you wrote down; Enter alone shows it once more.";
/// Said when the copy is not the password made.
const NOT_AS_SHOWN: &str = "That is not the password shown: correct your copy from the screen.";

/// Shows the password made on a private screen of its own until the person has written it down.
fn show(
    input: &Input,
    operation: Operation,
    password: &str,
    strength: &str,
    check_word: bool,
) -> Result<(), Failure> {
    let screen = PrivateScreen::enter(input, operation.title());
    eprintln!();
    eprintln!("  {STRONG}{password}{STRONG:#}");
    eprintln!();
    style::hint(strength);
    if check_word {
        style::hint(CHECK_WORD_NOTE);
    }
    style::hint(SHOWN_ONCE_NOTE);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    drop(screen);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kinds_show_whole() {
        assert!(choice::answers_fit(
            &PasswordKind::ALL.map(PasswordKind::answer)
        ));
    }

    #[test]
    fn the_lines_fit_the_screen() {
        for line in [TYPE_BACK_HINT, NOT_AS_SHOWN] {
            assert!(line.len() <= style::TEXT_WIDTH, "{line}");
        }
    }
}
