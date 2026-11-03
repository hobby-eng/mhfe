//! `mhfe password`: the terminal side of making a password of random words from the EFF large
//! wordlist, of five words and their check word, or of random characters. What is made, and how,
//! is the library's [`mhfe::new_password`].

use anstream::eprintln;
use clap::Args;
use mhfe::new_password::{
    character_bits, word_bits, word_index_of_rolls, PasswordRecipe, CHARACTERS, DEFAULT_CHARACTERS,
    DEFAULT_WORDS, MOST_CHARACTERS, MOST_WORDS, RECOMMENDED_CHARACTERS, RECOMMENDED_WORDS,
};
use zeroize::Zeroizing;

use crate::exit::{self, Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::hidden_input;
use crate::made_password;
use crate::menu;
use crate::raw_io::{self, println};
use crate::style::{self, STRONG};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input, PrivateScreen};

#[derive(Args)]
pub(crate) struct Options {
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_WORDS,
        hide_default_value = true,
        help = words_summary(),
        long_help = words_help()
    )]
    words: usize,

    /// Roll real dice instead of using the computer's randomness
    #[arg(long, long_help = dice_help())]
    dice: bool,

    /// Five words and a check word that repairs one mistyped word
    #[arg(long, conflicts_with_all = ["words", "chars"], long_help = check_word_help())]
    check_word: bool,

    #[arg(
        long,
        value_name = "N",
        num_args = 0..=1,
        default_missing_value = CHARS_ALONE,
        conflicts_with_all = ["words", "dice"],
        help = chars_summary(),
        long_help = chars_help()
    )]
    chars: Option<usize>,

    /// Another password on each Enter, until Escape: the entry of the start menu
    #[arg(long, hide = true)]
    repeat: bool,
}

/// What --chars alone means, DEFAULT_CHARACTERS as clap takes it: text written out here, which a
/// test keeps equal to the library's number.
const CHARS_ALONE: &str = "16";

/// The first sentence of --words' help, which `-h` shows alone.
fn words_summary() -> String {
    format!(
        "Number of words, 1 to {MOST_WORDS} (default {DEFAULT_WORDS}; fewer than \
         {RECOMMENDED_WORDS} are weak)"
    )
}

fn words_help() -> String {
    style::option_help(&[
        &format!("{}.", words_summary()),
        &format!(
            "Each word adds about {} bits: four words give about {} bits, five about {}, six \
             about {}. Fewer than four get a warning.",
            word_bits(1),
            word_bits(4),
            word_bits(5),
            word_bits(6)
        ),
    ])
}

fn check_word_help() -> String {
    style::option_help(&[
        "Five words and a check word that repairs one mistyped word.",
        "The sixth word is computed from the five before it (MHFE-PASSWORD-CHECK-1). When the \
         password is typed, it restores one word that is missing or misspelt and notices one \
         wrong word, before the long wait. It adds no strength: the password keeps about the \
         bits of its five words, and the check word must stay as secret as the rest.",
    ])
}

/// The first sentence of --chars' help, which `-h` shows alone.
fn chars_summary() -> String {
    format!(
        "N random characters instead of words, 1 to {MOST_CHARACTERS} (default \
         {DEFAULT_CHARACTERS})"
    )
}

fn chars_help() -> String {
    style::option_help(&[
        &format!("{}.", chars_summary()),
        &format!(
            "Digits and letters without those easily confused, such as 0 and O or 1 and l: {} \
             characters, about {} bits each. Sixteen give about {} bits, but words are easier to \
             type correctly years later.",
            CHARACTERS.len(),
            character_bits(1),
            character_bits(DEFAULT_CHARACTERS)
        ),
    ])
}

fn dice_help() -> String {
    style::option_help(&[
        "Roll real dice instead of using the computer's randomness.",
        "For each word, roll five dice and type the five numbers, 1 to 6, at a prompt. \
         The computer's random generator is then not used at all.",
    ])
}

/// The top of `mhfe password --help`.
pub(crate) fn about() -> String {
    style::command_about(&[
        "Make a strong password of words or characters",
        "Each word is drawn from the EFF large word list of 7,776 words, the same list that \
         five dice select from. Every word is equally likely.",
    ])
}

/// The end of `mhfe password -h` and `--help`.
pub(crate) fn help() -> String {
    let five = format!("Five random words, about {} bits", word_bits(5));
    let six = format!("Six words, about {} bits", word_bits(6));
    let checked = format!("Five words and a check word, about {} bits", word_bits(5));
    let characters = format!(
        "Sixteen random characters, about {} bits",
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

pub(crate) fn run(options: Options) -> Result<i32, Failure> {
    if !options.repeat {
        return make_one(&options);
    }
    // A private screen belongs to the process that entered it, so the loop of the menu's entry lies
    // here. Each password replaces the one before, and the screen is cleared when the person
    // leaves; the generator wipes its own copy as soon as it has shown it, before a key is read.
    let screen = PrivateScreen::enter_to_show(&Input::terminal_only());
    loop {
        make_one(&options)?;
        eprintln!();
        if !menu::wait_for_enter("Press Enter for another password (Esc returns to the menu).")? {
            return Ok(SUCCESS);
        }
        screen.clear();
    }
}

fn make_one(options: &Options) -> Result<i32, Failure> {
    crate::settings::warn_of_isolation_gaps();
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
    if raw_io::output_is_terminal() {
        let _drawing = hidden_input::drawing();
        println!("  {STRONG}{password}{STRONG:#}")?;
        eprintln!();
    } else {
        println!("{password}")?;
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

/// Reads five dice digits, hidden, for each of `words` words; the list indexes are wiped when
/// dropped.
fn read_dice(input: &mut Input, words: usize) -> Result<Zeroizing<Vec<usize>>, Failure> {
    let mut indexes = Zeroizing::new(Vec::with_capacity(words));
    for number in 1..=words {
        indexes.push(index_from_dice(input, number)?);
    }
    Ok(indexes)
}

/// Reads five dice digits for one word, hidden, and returns the word's index.
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
