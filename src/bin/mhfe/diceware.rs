//! `mhfe password`: the terminal side of making a password of random words from the EFF large
//! wordlist, of five words and their check word, or of random characters. What is made, and how,
//! is the library's [`mhfe::new_password`].

use std::io::IsTerminal;

use anstream::{eprintln, println};
use clap::Args;
use mhfe::eff::index_of_rolls;
use mhfe::new_password::{
    bits_text, PasswordRecipe, DEFAULT_WORDS, MOST_CHARACTERS, MOST_WORDS, RECOMMENDED_CHARACTERS,
    RECOMMENDED_WORDS,
};
use zeroize::Zeroizing;

use crate::exit::{Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::style::{self, STRONG};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input};

#[derive(Args)]
pub struct Options {
    /// Number of words, 1 to 32 (default 5; fewer than 4 are weak)
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_WORDS,
        hide_default_value = true,
        long_help = words_help()
    )]
    words: usize,

    /// Roll real dice instead of using the computer's randomness
    #[arg(long, long_help = dice_help())]
    dice: bool,

    /// Five words and a check word that repairs one mistyped word
    #[arg(long, conflicts_with_all = ["words", "chars"], long_help = check_word_help())]
    check_word: bool,

    /// Random characters instead of words, N of them (default 16)
    #[arg(
        long,
        value_name = "N",
        num_args = 0..=1,
        // --chars alone means sixteen characters.
        default_missing_value = "16",
        conflicts_with_all = ["words", "dice"],
        long_help = chars_help()
    )]
    chars: Option<usize>,
}

fn words_help() -> String {
    style::option_help(&[
        "Number of words, 1 to 32 (default 5; fewer than 4 are weak).",
        "Each word adds about 12.9 bits: four words give about 51.7 bits, five about 64.6, six \
         about 77.5. Fewer than four get a warning.",
    ])
}

fn check_word_help() -> String {
    style::option_help(&[
        "Five words and a check word that repairs one mistyped word.",
        "The sixth word is computed from the five before it (MHFE-PASSWORD-CHECK-1). When the \
         password is typed, it restores one word that is missing or misspelt and notices one \
         wrong word, before the long wait. It adds no strength: the password keeps about 64.6 \
         bits, and the check word must stay as secret as the rest.",
    ])
}

fn chars_help() -> String {
    style::option_help(&[
        "Random characters instead of words, N of them, 1 to 64 (default 16).",
        "Digits and letters without those easily confused, such as 0 and O or 1 and l: 57 \
         characters, about 5.8 bits each. Sixteen give about 93.3 bits, but words are easier to \
         type correctly years later.",
    ])
}

fn dice_help() -> String {
    style::option_help(&[
        "Roll real dice instead of using the computer's randomness.",
        "For each word, roll five dice and type the five numbers, 1 to 6, at a hidden prompt. \
         The computer's random generator is then not used at all.",
    ])
}

/// The top of `mhfe password --help`.
pub fn about() -> String {
    style::command_about(&[
        "Make a strong password of words or random characters",
        "Each word is drawn from the EFF large word list of 7,776 words, the same list that \
         five dice select from. Every word is equally likely.",
    ])
}

/// The end of `mhfe password -h` and `--help`.
pub fn help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe password", "Five random words, about 64.6 bits"),
            ("mhfe password --words 6", "Six words, about 77.5 bits"),
            (
                "mhfe password --dice",
                "Roll real dice instead of using the computer",
            ),
            ("mhfe password --dice --words 6", "Six words from real dice"),
            (
                "mhfe password --check-word",
                "Five words and a check word, about 64.6 bits",
            ),
            (
                "mhfe password --chars",
                "Sixteen random characters, about 93.3 bits",
            ),
        ],
    );
    let note = style::help_note("The password is shown once and never stored.");
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    if let Some(count) = options.chars {
        return run_characters(count);
    }
    let recipe = if options.check_word {
        PasswordRecipe::check_word()
    } else {
        PasswordRecipe::words(options.words).map_err(|_| {
            Failure::invalid_input(format!("Choose between 1 and {MOST_WORDS} words."))
        })?
    };
    let mut input = Input::terminal_only();
    // At a terminal the password has a step of its own, cleared once it is written down; the
    // summary says only how strong it is.
    let flow = Flow::start(&input, TITLE);
    style::title(TITLE);
    eprintln!();
    if recipe.is_weak() {
        style::warn(
            &format!("Fewer than {RECOMMENDED_WORDS} words is weak."),
            "Four words give about 51.7 bits, five about 64.6.",
        );
        eprintln!();
    }
    let password = if options.dice {
        // The rolls are typed on a step of their own.
        flow::step();
        let indexes = read_dice(&mut input, recipe.drawn_words())?;
        recipe.make_from_indexes(&mut |number| Ok(indexes[number - 1]))?
    } else {
        recipe.make(&mut SystemRandom)?
    };
    let strength = bits_text(recipe.millibits());
    if !recipe.has_check_word() {
        return show(
            password.text(),
            &format!(
                "{} words from the EFF list, about {strength} bits.",
                recipe.drawn_words()
            ),
            &[],
            flow,
        );
    }
    show(
        password.text(),
        &format!("5 words from the EFF list and a check word, about {strength} bits."),
        &["The last word is the check word; it adds no strength and is just as secret."],
        flow,
    )
}

/// The title of `mhfe password`.
const TITLE: &str = "Make a password";

/// Shows a new password with how strong it is and `notes` about it. At a terminal it is set apart
/// and in bold for writing down, on a step of its own that is cleared when the person is done; a
/// script gets the bare password.
fn show(password: &str, strength: &str, notes: &[&str], flow: Flow) -> Result<i32, Failure> {
    flow::step();
    if std::io::stdout().is_terminal() {
        println!("  {STRONG}{password}{STRONG:#}");
        eprintln!();
    } else {
        println!("{password}");
    }
    style::ok(strength);
    for note in notes {
        style::hint(note);
    }
    style::hint("Shown only once and not stored: write it down, apart from the container.");
    if flow::is_active() {
        terminal::wait_to_leave()?;
    }
    flow.finish();
    Ok(SUCCESS)
}

/// `mhfe password --chars N`: N characters drawn evenly from the library's character set.
fn run_characters(count: usize) -> Result<i32, Failure> {
    let recipe = PasswordRecipe::characters(count).map_err(|_| {
        Failure::invalid_input(format!(
            "Choose between 1 and {MOST_CHARACTERS} characters."
        ))
    })?;
    let input = Input::terminal_only();
    let flow = Flow::start(&input, TITLE);
    style::title(TITLE);
    eprintln!();
    if recipe.is_weak() {
        style::warn(
            &format!("Fewer than {RECOMMENDED_CHARACTERS} characters is weak."),
            "Twelve characters give about 70.0 bits, sixteen about 93.3.",
        );
        eprintln!();
    }
    let password = recipe.make(&mut SystemRandom)?;
    show(
        password.text(),
        &format!(
            "{count} random characters, about {} bits.",
            bits_text(recipe.millibits())
        ),
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
        match index_of_rolls(&typed) {
            Some(index) => return Ok(index),
            None => {
                style::retry("Type exactly five digits, each from 1 to 6, for example 35142.");
            }
        }
    }
}
