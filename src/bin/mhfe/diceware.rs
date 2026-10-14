//! `mhfe password`: the terminal side of making a password of random words from the EFF large
//! wordlist, of five words and their check word, or of random characters. What is made, and how,
//! is the library's [`mhfe::new_password`].

use std::io::IsTerminal;

use anstream::eprintln;
use clap::Args;
use mhfe::check_word::DRAWN_WORDS;
use mhfe::new_password::{
    character_bits, word_bits, word_index_of_rolls, PasswordRecipe, CHARACTERS, DEFAULT_CHARACTERS,
    DEFAULT_WORDS, MOST_CHARACTERS, MOST_WORDS, RECOMMENDED_CHARACTERS, RECOMMENDED_WORDS,
};
use zeroize::Zeroizing;

use crate::exit::{self, Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::made_password;
use crate::style::{self, STRONG};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input};

#[derive(Args)]
pub struct Options {
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_WORDS,
        hide_default_value = true,
        help = words_short_help(),
        long_help = words_help()
    )]
    words: usize,

    /// Roll real dice instead of using the computer's randomness
    #[arg(long, long_help = dice_help())]
    dice: bool,

    #[arg(
        long,
        conflicts_with_all = ["words", "chars"],
        help = check_word_short_help(),
        long_help = check_word_help()
    )]
    check_word: bool,

    #[arg(
        help = chars_short_help(),
        long,
        value_name = "N",
        num_args = 0..=1,
        default_missing_value = CHARS_ALONE,
        conflicts_with_all = ["words", "dice"],
        long_help = chars_help()
    )]
    chars: Option<usize>,
}

/// What --chars alone means, DEFAULT_CHARACTERS as clap takes it: text written out here, which a
/// test keeps equal to the library's number.
const CHARS_ALONE: &str = "16";

/// The short helps, built from the library's limits and defaults (AUD-023-ARC007).
fn words_short_help() -> String {
    format!(
        "Number of words, 1 to {MOST_WORDS} (default {DEFAULT_WORDS}; fewer than \
         {RECOMMENDED_WORDS} are weak)"
    )
}

fn check_word_short_help() -> String {
    format!(
        "{} words and a check word that repairs one mistyped word",
        style::number_word(DRAWN_WORDS, true)
    )
}

fn chars_short_help() -> String {
    format!("Random characters instead of words, N of them (default {DEFAULT_CHARACTERS})")
}

fn words_help() -> String {
    style::option_help(&[
        &format!("{}.", words_short_help()),
        &format!(
            "Each word adds about {} bits: {} words give about {} bits, {} about {}, {} about \
             {}. Fewer than {} get a warning.",
            word_bits(1),
            style::number_word(RECOMMENDED_WORDS, false),
            word_bits(RECOMMENDED_WORDS),
            style::number_word(DEFAULT_WORDS, false),
            word_bits(DEFAULT_WORDS),
            style::number_word(DEFAULT_WORDS + 1, false),
            word_bits(DEFAULT_WORDS + 1),
            style::number_word(RECOMMENDED_WORDS, false)
        ),
    ])
}

fn check_word_help() -> String {
    style::option_help(&[
        &format!("{}.", check_word_short_help()),
        &format!(
            "The last word is computed from the {drawn} before it (MHFE-PASSWORD-CHECK-1). When \
             the password is typed, it restores one word that is missing or misspelt and notices \
             one wrong word, before the long wait. It adds no strength: the password keeps about \
             the bits of its {drawn} words, and the check word must stay as secret as the rest.",
            drawn = style::number_word(DRAWN_WORDS, false)
        ),
    ])
}

fn chars_help() -> String {
    style::option_help(&[
        &format!(
            "Random characters instead of words, N of them, 1 to {MOST_CHARACTERS} (default \
             {DEFAULT_CHARACTERS})."
        ),
        &format!(
            "Digits and letters without those easily confused, such as 0 and O or 1 and l: {} \
             characters, about {} bits each. {} give about {} bits, but words are easier to \
             type correctly years later.",
            CHARACTERS.len(),
            character_bits(1),
            style::number_word(DEFAULT_CHARACTERS, true),
            character_bits(DEFAULT_CHARACTERS)
        ),
    ])
}

fn dice_help() -> String {
    style::option_help(&[
        "Roll real dice instead of using the computer's randomness.",
        "For each word, roll five dice and type the five numbers, 1 to 6: they are shown on the \
         private screen, which is cleared afterwards, or hidden where there is none. The \
         computer's random generator is then not used at all.",
    ])
}

/// The one-line summary of the command: `-h`, the first line of `--help`, and its menu entry.
pub const SUMMARY: &str = "Make a strong password of words or characters";

/// The top of `mhfe password --help`.
pub fn about() -> String {
    style::command_about(&[
        SUMMARY,
        "Each word is drawn from the EFF large word list of 7,776 words, the same list that \
         five dice select from. Every word is equally likely.",
    ])
}

/// The end of `mhfe password -h` and `--help`.
pub fn help() -> String {
    let five = format!(
        "{} random words, about {} bits",
        style::number_word(DEFAULT_WORDS, true),
        word_bits(DEFAULT_WORDS)
    );
    let six = format!("Six words, about {} bits", word_bits(6));
    let checked = format!(
        "{} words and a check word, about {} bits",
        style::number_word(DRAWN_WORDS, true),
        word_bits(DRAWN_WORDS)
    );
    let characters = format!(
        "{} random characters, about {} bits",
        style::number_word(DEFAULT_CHARACTERS, true),
        character_bits(DEFAULT_CHARACTERS)
    );
    style::examples_with_note(
        &[
            ("mhfe password", &five),
            ("mhfe password --words 6", &six),
            (
                "mhfe password --dice",
                "Roll real dice instead of using the computer",
            ),
            ("mhfe password --dice --words 6", "Six words from real dice"),
            ("mhfe password --check-word", &checked),
            ("mhfe password --chars", &characters),
        ],
        "The password is shown once and never stored.",
    )
}

pub fn run(options: Options) -> Result<i32, Failure> {
    if let Some(count) = options.chars {
        return run_characters(count);
    }
    let recipe = if options.check_word {
        PasswordRecipe::check_word()
    } else {
        // The library's refusal, in its words (AUD-011-ARC001).
        PasswordRecipe::words(options.words)?
    };
    let mut input = Input::terminal_only();
    let flow = start(&input, &recipe);
    let password = if options.dice {
        // The rolls are typed on a step of their own.
        flow::step();
        let indexes = read_dice(&mut input, recipe.drawn_words())?;
        recipe.make_from_indexes(&mut |number| Ok(indexes[number - 1]))?
    } else {
        recipe.make(&mut SystemRandom)?
    };
    let notes: &[&str] = if recipe.has_check_word() {
        &[made_password::CHECK_WORD_NOTE]
    } else {
        &[]
    };
    show(
        password.text(),
        &format!("{}.", recipe.summary()),
        notes,
        flow,
    )
}

/// Starts `mhfe password` with its title and, over a weak `recipe`, a warning that names the
/// recommended and the default size with their strength. At a terminal the password has a step of
/// its own, cleared once it is written down; the summary says only how strong it is.
fn start(input: &Input, recipe: &PasswordRecipe) -> Flow {
    let flow = Flow::start(input, TITLE);
    style::title(TITLE);
    eprintln!();
    if recipe.is_weak() {
        let (unit, recommended, default, bits): (_, _, _, fn(usize) -> String) =
            if recipe.is_characters() {
                (
                    "characters",
                    RECOMMENDED_CHARACTERS,
                    DEFAULT_CHARACTERS,
                    character_bits,
                )
            } else {
                ("words", RECOMMENDED_WORDS, DEFAULT_WORDS, word_bits)
            };
        style::warn(
            &format!("Fewer than {recommended} {unit} is weak."),
            &format!(
                "{recommended} {unit} give about {} bits, {default} about {}.",
                bits(recommended),
                bits(default)
            ),
        );
        eprintln!();
    }
    flow
}

/// The title of `mhfe password`.
const TITLE: &str = "Make a password";

/// Shows a new password with how strong it is and `notes` about it. At a terminal it is set apart
/// and in bold for writing down, on a step of its own that is cleared when the person is done; a
/// script gets the bare password.
fn show(password: &str, strength: &str, notes: &[&str], flow: Flow) -> Result<i32, Failure> {
    flow::step();
    if std::io::stdout().is_terminal() {
        style::out(format_args!("  {STRONG}{password}{STRONG:#}"))?;
        eprintln!();
    } else {
        style::out(format_args!("{password}"))?;
    }
    style::ok(strength);
    for note in notes {
        style::hint(note);
    }
    style::hint(made_password::SHOWN_ONCE_NOTE);
    if flow::is_active() {
        terminal::wait_to_leave()?;
    }
    flow.finish();
    Ok(SUCCESS)
}

/// `mhfe password --chars N`: N characters drawn evenly from the library's character set.
fn run_characters(count: usize) -> Result<i32, Failure> {
    let recipe = PasswordRecipe::characters(count)?;
    let input = Input::terminal_only();
    let flow = start(&input, &recipe);
    let password = recipe.make(&mut SystemRandom)?;
    show(
        password.text(),
        &format!("{}.", recipe.summary()),
        &[],
        flow,
    )
}

/// Reads five dice digits for each of `words` words, shown on the private screen or hidden where
/// there is none; the list indexes are wiped when dropped.
fn read_dice(input: &mut Input, words: usize) -> Result<Zeroizing<Vec<usize>>, Failure> {
    let mut indexes = Zeroizing::new(Vec::with_capacity(words));
    for number in 1..=words {
        indexes.push(index_from_dice(input, number)?);
    }
    Ok(indexes)
}

/// Reads five dice digits for one word, shown on the private screen or hidden where there is
/// none, and returns the word's index.
fn index_from_dice(input: &mut Input, number: usize) -> Result<usize, Failure> {
    loop {
        let typed = input.secret(&format!(
            "Word {number}: roll five dice and type the five digits"
        ))?;
        match word_index_of_rolls(number, &typed) {
            Ok(index) => return Ok(index),
            Err(error) => {
                style::retry(exit::refused(&error, "Type them again, for example 35142."));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_alone_means_the_default() {
        assert_eq!(CHARS_ALONE.parse::<usize>(), Ok(DEFAULT_CHARACTERS));
    }
}
